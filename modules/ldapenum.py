import subprocess
import re

from utils.output import print


def run_ldapenum(target, show_output=False):
    print(f"[*] Running LDAP enumeration against {target}...")

    results = {
        "anonymous_bind": False,
        "ldapsearch_output": "",
        "getadusers_output": ""
    }

    stdout_opt = None if show_output else subprocess.PIPE
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

    # step 2: if bind successful try GetADUsers
    if results["anonymous_bind"]:
        try:
            # try to extract domain naming context
            domain_match = re.search(r"namingContexts:\s*(.*)", results["ldapsearch_output"])
            domain = None

            if domain_match:
                domain_dn = domain_match.group(1).strip()
                domain = domain_dn.replace("DC=", "").replace(",", ".")

            if domain:
                print(f"[*] Domain detected: {domain}")

                getad_cmd = [
                    "GetADUsers.py",
                    "-no-pass",
                    f"{domain}/",
                    "-dc-ip", target
                ]

                getad_proc = subprocess.run(
                    getad_cmd,
                    stdout=stdout_opt,
                    stderr=stderr_opt,
                    text=True,
                    timeout=15
                )

                output = getad_proc.stdout if getad_proc.stdout else ""

                if output:
                    results["getadusers_output"] = output

                    if "operationsError" in output or "failed" in output.lower():
                        print("[-] GetADUsers failed (bind not permitted for search).")
                    elif "Name" in output and "PasswordLastSet" in output:
                        print("[+] GetADUsers enumeration successful.")
                    else:
                        print("[*] GetADUsers completed (no users returned).")
                else:
                    print("[-] GetADUsers returned no output.")

            else:
                print("[*] Could not extract domain from LDAP response.")

        except FileNotFoundError:
            print("[!] GetADUsers.py not found.")
        except subprocess.TimeoutExpired:
            print("[!] GetADUsers timed out.")
        except Exception as e:
            print(f"[!] GetADUsers error: {e}")

    return results