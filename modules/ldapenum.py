import subprocess
import re

from utils.output import print


def run_ldapenum(target, show_output=False):
    print(f"[*] Running LDAP enumeration against {target}...")

    results = {
        "anonymous_bind": False,
        "ldapsearch_output": "",
        "ldap_users_output": "",
        "getadusers_output": "",
        "users": [],
        "domain": None
    }

    stderr_opt = None if show_output else subprocess.DEVNULL

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

        if "result: 0 Success" in output:
            results["anonymous_bind"] = True
            print("[+] Anonymous LDAP bind successful.")
        else:
            print("[-] Anonymous LDAP bind not allowed.")

    except FileNotFoundError:
        print("[!] ldapsearch not found.")
        return results
    except subprocess.TimeoutExpired:
        print("[!] ldapsearch timed out.")
        return results
    except Exception as e:
        print(f"[!] ldapsearch error: {e}")
        return results

    # step 2: if bind successful try enumeration
    if results["anonymous_bind"]:
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

                ldap_user_output = ldap_user_proc.stdout

                if ldap_user_output:
                    results["ldap_users_output"] = ldap_user_output

                    if show_output:
                        print(ldap_user_output)

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

                    if users:
                        print("[+] Discovered domain users:")
                        for u in users:
                            print(f"    {u}")

                    print("[+] LDAP user enumeration successful.")

                else:
                    print("[-] LDAP user enumeration returned no output.")

                # step 2.2: run GetADUsers
                getad_cmd = [
                    "GetADUsers.py",
                    "-no-pass",
                    f"{domain}/",
                    "-dc-ip", target
                ]

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

                    if "Name" in output and "PasswordLastSet" in output:
                        print("[+] GetADUsers enumeration successful.")
                    elif "operationsError" in output or "failed" in output.lower():
                        print("[-] GetADUsers failed (bind not permitted for search).")
                    else:
                        print("[*] GetADUsers completed.")

                else:
                    print("[-] GetADUsers returned no output.")

            else:
                print("[*] Could not extract domain from LDAP response.")

        except FileNotFoundError:
            print("[!] Required LDAP tools not found.")
        except subprocess.TimeoutExpired:
            print("[!] LDAP enumeration timed out.")
        except Exception as e:
            print(f"[!] LDAP enumeration error: {e}")

    return results