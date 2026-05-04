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


def run_ldapenum(target, show_output=False, recon_data=None):
    print(f"[*] Running LDAP enumeration against {target}...")

    results = {
        "connection": False,
        "enumeration": False,
        "error": None,
        "ldapsearch_output": "",
        "ldap_users_output": "",
        "getadusers_output": "",
        "users": [],
        "domain": None
    }

    stderr_opt = None if show_output else subprocess.DEVNULL
    ERROR_KEYWORDS = ["operationsError", "Operations error", "failed", "denied", "error", "Error"]

    # step 1: attempt anonymous bind
    try:
        ldap_cmd = [
            "ldapsearch",
            "-x",
            "-H", f"ldap://{target}",
            "-s", "base"
        ]

        ldap_proc = subprocess.run(
            ldap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8
        )

        output = ldap_proc.stdout
        results["ldapsearch_output"] = output

        if show_output and output:
            print(output)

        # Check for explicit success indicator AND absence of errors
        if "result: 0 Success" in output and not any(err in output for err in ERROR_KEYWORDS):
            results["connection"] = True
            print("[+] Anonymous LDAP bind successful.")
        else:
            results["error"] = "Anonymous LDAP bind failed"
            print("[-] Anonymous LDAP bind not allowed.")
            return results

    except FileNotFoundError:
        print("[!] ldapsearch not found.")
        results["error"] = "ldapsearch not found"
        return results
    except subprocess.TimeoutExpired:
        print("[!] ldapsearch timed out.")
        results["error"] = "ldapsearch timeout"
        return results
    except Exception as e:
        print(f"[!] ldapsearch error: {e}")
        results["error"] = str(e)
        return results

    # step 2: if bind successful try enumeration
    if results["connection"]:
        try:
            domain_match = re.search(r"defaultNamingContext:\s*(.*)", results["ldapsearch_output"])
            domain = None
            domain_dn = None

            if domain_match:
                domain_dn = domain_match.group(1).strip()
                domain = domain_dn.replace("DC=", "").replace(",", ".")

            if domain:
                print(f"[*] Domain detected: {domain}")
                results["domain"] = domain

                # step 2.1: enumerate LDAP users
                ldap_user_cmd = [
                    "ldapsearch",
                    "-x",
                    "-H", f"ldap://{target}",
                    "-b", domain_dn,
                    "(objectClass=user)",
                    "sAMAccountName"
                ]

                ldap_user_proc = subprocess.run(
                    ldap_user_cmd,
                    stdout=subprocess.PIPE,
                    stderr=stderr_opt,
                    text=True,
                    timeout=12
                )

                ldap_user_output = ldap_user_proc.stdout or ""

                if ldap_user_output:
                    results["ldap_users_output"] = ldap_user_output

                    if show_output:
                        print(ldap_user_output)

                    # Check for explicit errors BEFORE parsing
                    if any(err in ldap_user_output for err in ERROR_KEYWORDS):
                        results["error"] = f"LDAP user enumeration failed: {[err for err in ERROR_KEYWORDS if err in ldap_user_output]}"
                        print(f"[-] LDAP user enumeration failed: operations denied")
                        return results

                    users = []

                    for line in ldap_user_output.splitlines():
                        match = re.search(r"sAMAccountName:\s*(\S+)", line)
                        if match:
                            user = match.group(1)

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
                                or user in ["Guest", "DefaultAccount"]
                            ):
                                continue

                            users.append(user)

                    results["users"] = users

                    # Only mark enumeration success if we actually got valid users (for AI analysis, can adjust later)
                    if users and ldap_user_proc.returncode == 0:
                        results["enumeration"] = True
                        print("[+] LDAP user enumeration successful.")
                        print("[+] Discovered domain users:")
                        for u in users:
                            print(f"    {u}")
                    else:
                        results["error"] = "No valid LDAP users parsed"
                        print(f"[-] LDAP user enumeration returned no valid users (possible error or no access)")

                else:
                    results["error"] = "LDAP user enumeration returned no output"
                    print("[-] LDAP user enumeration returned no output.")

                # step 2.2: run GetADUsers
                getad_cmd = [
                    "GetADUsers.py",
                    "-no-pass",
                    f"{domain}/",
                    "-dc-ip", target
                ]

                try:
                    getad_proc = subprocess.run(
                        getad_cmd,
                        stdout=subprocess.PIPE,
                        stderr=stderr_opt,
                        text=True,
                        timeout=15
                    )

                    output = getad_proc.stdout or ""

                    if output:
                        results["getadusers_output"] = output

                        if show_output:
                            print(output)

                        # check for errors FIRST
                        if any(err in output for err in ERROR_KEYWORDS) or getad_proc.returncode != 0:
                            results["error"] = f"GetADUsers failed: {[err for err in ERROR_KEYWORDS if err in output]}"
                            print("[-] GetADUsers failed (access denied or error during search).")
                        # only mark success if we have valid table data as below:
                        elif "Name" in output and "PasswordLastSet" in output and len(output.splitlines()) > 3:
                            results["enumeration"] = True
                            print("[+] GetADUsers enumeration successful.")
                        else:
                            results["error"] = "GetADUsers returned no valid user data"
                            print("[*] GetADUsers completed but returned no valid user table.")

                    else:
                        results["error"] = "GetADUsers returned no output"
                        print("[-] GetADUsers returned no output.")

                except FileNotFoundError:
                    print("[!] GetADUsers.py not found (skipping).")
                except subprocess.TimeoutExpired:
                    print("[!] GetADUsers timed out (skipping).")
                except Exception as e:
                    print(f"[!] GetADUsers error: {e} (skipping).")

            else:
                results["error"] = "Could not extract domain from LDAP response"
                print("[*] Could not extract domain from LDAP response.")

        except FileNotFoundError:
            print("[!] Required LDAP tools not found.")
            results["error"] = "LDAP tools not found"
        except subprocess.TimeoutExpired:
            print("[!] LDAP enumeration timed out.")
            results["error"] = "LDAP timeout"
        except Exception as e:
            print(f"[!] LDAP enumeration error: {e}")
            results["error"] = str(e)

    return results
