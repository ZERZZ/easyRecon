import subprocess
import re


def run_smbenum(target, show_output=False):
    print(f"[*] Running SMB enumeration against {target}...")

    results = {
        "cme_output": "",
        "anonymous_bind": False
    }

    stdout_opt = None if show_output else subprocess.PIPE
    stderr_opt = None if show_output else subprocess.DEVNULL

    # run crackmapexec share enum
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

        print("[*] crackmapexec completed.")

    except FileNotFoundError:
        print("[!] crackmapexec not found.")
    except Exception as e:
        print(f"[!] crackmapexec error: {e}")

    # attempt null session list
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
            if "Anonymous login successful" in smb_proc.stdout or "Sharename" in smb_proc.stdout:
                results["anonymous_bind"] = True

        if results["anonymous_bind"]:
            print("[+] Anonymous bind successful.")
        else:
            print("[-] Anonymous bind not allowed.")

    except FileNotFoundError:
        print("[!] smbclient not found.")
    except Exception as e:
        print(f"[!] smbclient error: {e}")

    return results