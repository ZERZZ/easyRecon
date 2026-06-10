from ftplib import FTP, error_perm
from io import BytesIO

from utils.output import print
from utils.findings import add_misconfiguration, add_note


INTERESTING_EXTENSIONS = [
    ".zip",
    ".tar",
    ".tar.gz",
    ".rar",
    ".7z",
    ".gz",
    ".sql",
    ".db",
    ".sqlite",
    ".mdb",
    ".bak",
    ".config",
    ".conf",
    ".ini",
    ".log",
    ".env",
    ".exe"
]

## Add keyword search here in future ? feel like might be too much noise


def is_interesting_file(filename):
    filename_lower = filename.lower()
    for ext in INTERESTING_EXTENSIONS:
        if filename_lower.endswith(ext):
            return True
    return False


def enumerate_directory(ftp, path, results):
    try:
        ftp.cwd(path)
    except error_perm:
        return

    try:
        items = ftp.nlst()
    except Exception:
        # retry once (sometimes flaky)
        try:
            items = ftp.nlst()
        except Exception:
            return

    for item in items:
        if item in [".", ".."]:
            continue

        full_path = f"{path}/{item}" if path != "/" else f"/{item}"

        # try entering it as directory
        current_dir = ftp.pwd()
        try:
            ftp.cwd(item)
            ftp.cwd(current_dir)

            results["directories"].append(full_path)

            enumerate_directory(ftp, full_path, results)

        except error_perm:
            # not a directory, treat as file
            if is_interesting_file(item):
                results["interesting_files"].append(full_path)

# now test write access
def test_write_access(ftp):
    test_filename = ".ftp_write_test"

    try:
        ftp.storbinary(
            f"STOR {test_filename}",
            BytesIO(b"write_test")
        )

        try:
            ftp.delete(test_filename)
        except Exception:
            pass

        return True

    except Exception:
        return False


def run_ftpenum(target, show_output=False):
    print(f"[*] Running FTP enumeration against {target}...")

    results = {
        "connection": False,
        "enumeration": False,
        "writable": False,
        "error": None,
        "directories": [],
        "interesting_files": []
    }

    try:
        ftp = FTP(target, timeout=5)

        # force active mode (for legacy machines)
        ftp.set_pasv(False)

        ftp.login("anonymous", "anonymous@")

        results["connection"] = True

        print("[+] Anonymous FTP login successful.\n")

        add_misconfiguration(
            "Anonymous FTP login allowed",
            source="ftpenum"
        )

        # test write access
        if test_write_access(ftp):
            results["writable"] = True

            print("[!] Anonymous FTP write access allowed.\n")

            add_misconfiguration(
                "Anonymous FTP write access allowed",
                source="ftpenum"
            )

        # list first directories
        try:
            root_items = ftp.nlst()
            dirs = []

            for item in root_items:
                current_dir = ftp.pwd()

                try:
                    ftp.cwd(item)
                    ftp.cwd(current_dir)
                    dirs.append(item)

                except error_perm:
                    continue

            if dirs:
                print("[+] Top-level directories:\n")

                for d in dirs:
                    print(f" - {d}")

                print("")

        except Exception as e:
            print(f"[!] Error listing root directories: {e}")

        enumerate_directory(ftp, "/", results)

        ftp.quit()

        # mark enumeration success only if we found interesting files
        if results["interesting_files"]:
            results["enumeration"] = True

            print("[+] Interesting files found:\n")

            for f in results["interesting_files"]:
                print(f" - {f}")

            print("")

            for path in results["interesting_files"][:10]:
                add_note(
                    f"Interesting FTP file: {path}",
                    source="ftpenum"
                )

        else:
            results["error"] = "No interesting files found"
            print("[-] No interesting files found.\n")

    except error_perm as e:
        results["error"] = f"Anonymous FTP login failed: {e}"
        print(f"[-] Anonymous FTP login failed: {e}")

    except Exception as e:
        results["error"] = str(e)
        print(f"[!] FTP enumeration error: {e}")

    return results