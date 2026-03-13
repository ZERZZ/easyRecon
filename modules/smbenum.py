import subprocess
import re

from utils.output import print


def run_smbenum(target, show_output=False):
    print(f"[*] Running SMB enumeration against {target}...")

    results = {
        "cme_output": "",
        "rid_brute_output": "",
        "anonymous_bind": False,
        "users": []
    }

    stdout_opt = None if show_output else subprocess.PIPE
    stderr_opt = None if show_output else subprocess.DEVNULL

    # crackmapexec share enum 
    try:
        cme_cmd = [
            "crackmapexec",
            "smb",
            target,
            "--shares"
        ]

        cme_proc = subprocess.run(
            cme_cmd,
            stdout=stdout_opt,
            stderr=stderr_opt,
            text=True
        )

        if cme_proc.stdout:
            results["cme_output"] = cme_proc.stdout

        print("[*] crackmapexec share enumeration completed.")

    except FileNotFoundError:
        print("[!] crackmapexec not found.")
    except Exception as e:
        print(f"[!] crackmapexec error: {e}")

    # rid cycling 
    try:
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
            text=True
        )

        if show_output and rid_proc.stdout:
            print(rid_proc.stdout)

        if rid_proc.stdout:
            results["rid_brute_output"] = rid_proc.stdout

            # extract users
            users = []
            for line in rid_proc.stdout.splitlines():
                match = re.search(r"\\([^\\]+)\s+\(SidTypeUser\)", line)
                if match:
                    user = match.group(1)

                    # ignore machine accounts
                    if not user.endswith("$"):
                        users.append(user)

            results["users"] = users

            if users:
                print("[+] Discovered domain users:")
                for u in users:
                    print(f"    {u}")

        print("[*] RID brute enumeration completed.")

    except Exception as e:
        print(f"[!] RID brute error: {e}")

    # smbclient null bind fallback
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

        if smb_proc.stdout:

            # detect successful null bind
            if "Anonymous login successful" in smb_proc.stdout or "Sharename" in smb_proc.stdout:
                results["anonymous_bind"] = True
                print("[+] Anonymous null bind successful.")

                # fallback if CME failed
                if (
                    not results["cme_output"] or
                    "STATUS_USER_SESSION_DELETED" in results["cme_output"] or
                    "Error enumerating shares" in results["cme_output"]
                ):
                    results["cme_output"] = smb_proc.stdout

                    # extract share names
                    shares = []
                    for line in smb_proc.stdout.splitlines():
                        match = re.match(r"^\s*([A-Za-z0-9\$\-\_]+)\s+Disk", line)
                        if match:
                            shares.append(match.group(1))

                    # test read access on each share
                    for share in shares:
                        try:
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

                            if test_proc.stdout and "NT_STATUS_ACCESS_DENIED" not in test_proc.stdout:
                                print(f"\n[+] {share} - READABLE")
                                print(test_proc.stdout)

                        except Exception:
                            pass

            else:
                print("[-] Anonymous bind not allowed.")

    except FileNotFoundError:
        print("[!] smbclient not found.")
    except Exception as e:
        print(f"[!] smbclient error: {e}")

    return results