from ftplib import FTP, error_perm


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
    ".env"
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
    except error_perm:
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


def run_ftpenum(target, show_output=False):
    print(f"[*] Running FTP enumeration against {target}...")

    results = {
        "anonymous_login": False,
        "directories": [],
        "interesting_files": []
    }

    try:
        ftp = FTP(target, timeout=5)

        ftp.login("anonymous", "anonymous@")

        results["anonymous_login"] = True
        print("[+] Anonymous FTP login successful.")

        enumerate_directory(ftp, "/", results)

        ftp.quit()

        if results["interesting_files"]:
            print("[+] Interesting files found:")
            for f in results["interesting_files"]:
                print(f" - {f}")
        else:
            print("[-] No interesting files found.")

    except Exception as e:
        print(f"[!] FTP enumeration error: {e}")

    return results