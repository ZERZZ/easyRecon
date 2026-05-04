import subprocess
import re

from utils.output import print


def _append_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return
    if not isinstance(values, list):
        values = [values]
    data_list = recon_data.setdefault(key, [])
    for value in values:
        if value and value not in data_list:
            data_list.append(value)


def run_smbenum(target, show_output=False, recon_data=None):
    print(f"[*] Running SMB enumeration against {target}...")

    results = {
        "connection": False,
        "enumeration": False,
        "error": None,
        "smb_reachable": False,    
        "cme_output": "",
        "users": [],
        "writable_shares": []
    }

    stdout_opt = None if show_output else subprocess.PIPE
    stderr_opt = None if show_output else subprocess.DEVNULL

    # Step 1: Check if SMB is reachable via smbclient
    try:
        smb_list_cmd = [
            "smbclient",
            "-N",
            "-L",
            f"//{target}"
        ]

        smb_proc = subprocess.run(
            smb_list_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        output = smb_proc.stdout or ""

        # multiple checks as it can still respond anonymous login successful but not actually list shares
        if output and (("Sharename" in output or "Disk" in output) or smb_proc.returncode == 0):
            results["smb_reachable"] = True
            print("[+] SMB service is reachable and responding.")
        else:
            results["error"] = "SMB service unreachable or not responding"
            print("[-] SMB service not reachable or not responding to list requests.")

        # extract share names only if SMB is reachable
        if results["smb_reachable"]:
            shares = []
            for line in output.splitlines():
                # match actual share lines
                match = re.match(r"^\s*([A-Za-z0-9\$\-\_]+)\s+Disk", line)
                if match:
                    shares.append(match.group(1))

            if shares:
                results["connection"] = True
                results["enumeration"] = True
                print(f"[+] SMB enumeration successful: found {len(shares)} shares")

                # test read/write access on each share
                for share in shares:
                    try:
                        readable = False
                        writable = False

                        test_cmd = [
                            "smbclient",
                            "-N",
                            f"//{target}/{share}",
                            "-c",
                            "ls"
                        ]

                        test_proc = subprocess.run(
                            test_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True
                        )

                        test_output = test_proc.stdout or ""

                        # check for access denied errors
                        if "NT_STATUS_ACCESS_DENIED" not in test_output and test_proc.returncode == 0:
                            readable = True

                            # test write access
                            write_cmd = [
                                "smbclient",
                                "-N",
                                f"//{target}/{share}",
                                "-c",
                                "put /dev/null easyrecon_write_test.tmp"
                            ]

                            write_proc = subprocess.run(
                                write_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True
                            )

                            write_output = write_proc.stdout or ""

                            if "NT_STATUS_ACCESS_DENIED" not in write_output and write_proc.returncode == 0:
                                writable = True
                                results["writable_shares"].append(share)

                            status = ["READABLE"]
                            if writable:
                                status.append("WRITABLE")

                            print(f"\n[+] {share} - {', '.join(status)}")
                            if show_output:
                                print(test_output)

                    except Exception:
                        pass

                if results["writable_shares"]:
                    print("[!] Writable SMB share detected")
                    print("[!] NTLM Theft via .lnk may be possible (use responder/NTLM_theft.py)")
            else:
                # SMB reachable but no shares retrieved - still log this
                print("[*] SMB reachable but no accessible shares found (may require authentication)")

    except FileNotFoundError:
        print("[!] smbclient not found.")
        results["error"] = "smbclient not found"
        results["smb_reachable"] = False
    except Exception as e:
        print(f"[!] smbclient error: {e}")
        results["error"] = str(e)
        results["smb_reachable"] = False

    # Step 2.2: crackmapexec RID cycling for user enumeration
    if results["smb_reachable"]:
        try:
            print("[*] Attempting RID brute force enumeration (null session)...")
            rid_cmd = [
                "crackmapexec",
                "smb",
                target,
                "-u",
                ".",
                "-p",
                "",
                "--rid-brute"
            ]

            rid_proc = subprocess.run(
                rid_cmd,
                stdout=subprocess.PIPE,
                stderr=stderr_opt,
                text=True,
                timeout=120
            )

            rid_output = rid_proc.stdout or ""

            # Do NOT print massive rid_output or store it all in results (Fixed)

            if rid_output:
                # check for errors FIRST
                ERROR_KEYWORDS = ["STATUS_", "denied", "failed", "error", "Error", "access denied"]
                has_errors = any(err in rid_output for err in ERROR_KEYWORDS)

                if has_errors or rid_proc.returncode != 0:
                    print("[-] RID brute enumeration failed or access denied")
                    results["error"] = "RID brute access denied"
                else:
                    # parse users (diff outputs)
                    users = []
                    
                    for line in rid_output.splitlines():
                        # format 1: "1112: OVERWATCH\Charlie.Moss (SidTypeUser)"
                        match1 = re.search(r"(\d+):\s+[A-Za-z0-9\-_]*\\([A-Za-z0-9\-_.]+)\s+\(SidTypeUser\)", line)
                        if match1:
                            user = match1.group(2)
                        else:
                            # format 2: "user:[username]"
                            match2 = re.search(r"user:\[([A-Za-z0-9\-_.]+)\]", line)
                            if match2:
                                user = match2.group(1)
                            else:
                                continue

                        # Filter out service accounts and built-in accounts
                        if (
                            user.endswith("$")
                            or user.startswith("$")
                            or user.startswith("SM_")
                            or user.startswith("HealthMailbox")
                            or user.startswith("SystemMailbox")
                            or user.startswith("Migration.")
                            or user.startswith("DiscoverySearchMailbox")
                            or user.startswith("FederatedEmail")
                            or user.startswith("Exchange")
                            or user in ["Guest", "DefaultAccount", "krbtgt", "Administrator"]
                        ):
                            continue

                        if user not in users:
                            users.append(user)

                    results["users"] = users

                    if users:
                        results["enumeration"] = True
                        print(f"[+] RID brute enumeration successful: enumerated {len(users)} users")
                        
                        # console output limit: only show first 10 users
                        # rest will be written to users.txt (needs to be put into a report file)
                        for u in users[:10]:
                            print(u)
                        if len(users) > 10:
                            print(f"... and {len(users) - 10} more users")
                    else:
                        print("[*] RID brute completed but no valid users enumerated")
            else:
                print("[*] RID brute returned no output")

            print("[*] RID brute enumeration completed.")

        except subprocess.TimeoutExpired:
            print("[!] RID brute timed out")
            results["error"] = "RID brute timeout"
        except FileNotFoundError:
            print("[!] crackmapexec not found (skipping RID brute).")
        except Exception as e:
            print(f"[!] RID brute error: {e}")
    else:
        print("[*] SMB not reachable - skipping RID brute force")

    # append to recon data 
    if recon_data is not None:
        if results.get("smb_reachable"):
            _append_unique(recon_data, "interesting_findings", "SMB service is reachable on target")
        if results.get("connection"):
            _append_unique(recon_data, "interesting_findings", "SMB null session: shares enumerated")
        if results.get("users"):
            _append_unique(recon_data, "interesting_findings", f"RID brute enumerated {len(results['users'])} users")
        if results.get("writable_shares"):
            _append_unique(recon_data, "interesting_findings", [f"Writable SMB share: {share}" for share in results["writable_shares"]])

    return results