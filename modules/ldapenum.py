import subprocess
import re

from utils.output import print
from utils.findings import add_misconfiguration, add_note
from utils.report import add_user


def run_ldapenum(target, show_output=False, creds=None):
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

    username = None
    password = None

    if creds:
        try:
            username, password = creds.split(":", 1)
        except ValueError:
            print("[!] Invalid creds format. Expected user:pass")
            creds = None

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

            # add misconfiguration finding for anonymous bind allowed
            add_misconfiguration(
                "Anonymous LDAP bind allowed",
                source="ldapenum"
            )

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

                add_note(
                    f"LDAP domain detected: {domain}",
                    source="ldapenum"
                )

                # LDAP ENUMERATION WITH AUTHENTICATED BIND IF CREDS PROVIDED, OTHERWISE ANONYMOUS

                if creds:
                    print("[*] Using AUTHENTICATED LDAP enumeration...")

                    bind_user = f"{username}@{domain}"

                    ldap_user_cmd = [
                        "ldapsearch",
                        "-x",
                        "-H", f"ldap://{target}",
                        "-D", bind_user,
                        "-w", password,
                        "-b", domain_dn,
                        "(&(objectClass=user)(|(description=*)(info=*)(comment=*)))",
                        "sAMAccountName",
                        "description",
                        "info",
                        "comment"
                    ]

                else:
                    print("[*] Using ANONYMOUS LDAP enumeration...")

                    ldap_user_cmd = [
                        "ldapsearch",
                        "-x",
                        "-H", f"ldap://{target}",
                        "-b", domain_dn,
                        "(&(objectClass=user)(|(description=*)(info=*)(comment=*)))",
                        "sAMAccountName",
                        "description",
                        "info",
                        "comment"
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
                        results["error"] = "LDAP user/desc enumeration failed"
                        print("[-] LDAP user/desc enumeration failed: operations denied")
                        return results

                    # Structured output
                    current_user = None
                    user_data = {}

                    print("\n[+] LDAP user/desc enumeration successful.\n")
                    print("[+] Discovered users with descriptions, info or comments:\n")

                    for line in ldap_user_output.splitlines():

                        dn_match = re.match(r"^dn:\s*CN=([^,]+)", line)
                        if dn_match:
                            current_user = dn_match.group(1)
                            user_data[current_user] = {}
                            print(f"    {current_user}")
                            continue

                        if not current_user:
                            continue

                        desc = re.search(r"description:\s*(.+)", line)
                        if desc:
                            user_data[current_user]["description"] = desc.group(1)
                            print(f"      description: {desc.group(1)}")

                        info = re.search(r"info:\s*(.+)", line)
                        if info:
                            user_data[current_user]["info"] = info.group(1)
                            print(f"      info: {info.group(1)}")

                        comment = re.search(r"comment:\s*(.+)", line)
                        if comment:
                            user_data[current_user]["comment"] = comment.group(1)
                            print(f"      comment: {comment.group(1)}")

                    results["users"] = list(user_data.keys())
                    results["enumeration"] = True

                    # NOTES (users + attributes)
                    for user, attrs in user_data.items():
                        add_user(user, source="ldapenum")

                        if "description" in attrs:
                            add_note(
                                f"{user} description: {attrs['description']}",
                                source="ldapenum"
                            )
                        if "info" in attrs:
                            add_note(
                                f"{user} info: {attrs['info']}",
                                source="ldapenum"
                            )
                        if "comment" in attrs:
                            add_note(
                                f"{user} comment: {attrs['comment']}",
                                source="ldapenum"
                            )

                    print()

                else:
                    results["error"] = "LDAP user/desc enumeration returned no output"
                    print("[-] LDAP user/desc enumeration returned no output.")

                # step 2.2: run GetADUsers
                print("[*] Attempting to run GetADUsers....\n")

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
