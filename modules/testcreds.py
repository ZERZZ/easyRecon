import subprocess
import re

from utils.output import section, print

## this is repetitive and can definitely be polished; expand to use other services / polish in future

def run_testcreds(target, ports, cred_string, verbose=False):

    section("Credential Reuse Testing")

    if ":" not in cred_string:
        print("[!] Invalid credential format. Use user:pass")
        return

    username, password = cred_string.split(":", 1)

    print(f"[*] Testing credentials: {username}:{password}")

    port_list = [p.get("port") for p in ports]

    # SMB
    if "445" in port_list:
        print("\n[*] Attempting SMB authentication...")

        cmd = [
            "smbclient",
            f"//{target}/IPC$",
            "-U",
            f"{username}%{password}",
            "-c",
            "exit"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                print("[+] SMB authentication successful!")

            else:
                print("[-] SMB authentication failed.")

                if verbose:
                    print(result.stderr)

        except Exception as e:
            print(f"[!] SMB test error: {e}")

    # FTP
    if "21" in port_list:
        print("\n[*] Attempting FTP authentication...")

        cmd = [
            "ftp",
            "-inv",
            target
        ]

        ftp_script = f"user {username} {password}\nquit\n"

        try:
            result = subprocess.run(
                cmd,
                input=ftp_script,
                capture_output=True,
                text=True
            )

            if "230" in result.stdout:
                print("[+] FTP authentication successful!")

            else:
                print("[-] FTP authentication failed.")

                if verbose:
                    print(result.stdout)

        except Exception as e:
            print(f"[!] FTP test error: {e}")

    # LDAP
    if "389" in port_list:
        print("\n[*] Attempting LDAP authentication...")

        cmd = [
            "ldapwhoami",
            "-x",
            "-H",
            f"ldap://{target}",
            "-D",
            username,
            "-w",
            password
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)

            if "dn:" in result.stdout.lower():
                print("[+] LDAP authentication successful!")

            else:
                print("[-] LDAP authentication failed.")

                if verbose:
                    print(result.stderr)

        except Exception as e:
            print(f"[!] LDAP test error: {e}")

    # RPC
    if "135" in port_list:
        print("\n[*] Attempting RPC authentication...")

        cmd = [
            "rpcclient",
            "-U",
            f"{username}%{password}",
            target,
            "-c",
            "exit"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)

            if "Cannot" not in result.stderr:
                print("[+] RPC authentication successful!")

            else:
                print("[-] RPC authentication failed.")

                if verbose:
                    print(result.stderr)

        except Exception as e:
            print(f"[!] RPC test error: {e}")

    # WinRM
    if "5985" in port_list or "5986" in port_list:
        print("\n[*] Attempting WinRM authentication...")

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            username,
            "-p",
            password
        ]

        try:
            result = subprocess.run(
                cmd,
                input="exit\n",
                capture_output=True,
                text=True,
                timeout=10
            )

            if "Evil-WinRM shell" in result.stdout or "PS" in result.stdout:
                print("[+] WinRM authentication successful!")
                print("[+] You can connect using:")
                print(f"    evil-winrm -i {target} -u {username} -p '{password}'")

            else:
                print("[-] WinRM authentication failed.")

                if verbose:
                    print(result.stdout)

        except Exception as e:
            print(f"[!] WinRM test error: {e}")

    print("\n[*] Credential testing completed.")