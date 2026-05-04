from ftplib import FTP, error_perm

from utils.output import print


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


def _append_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return
    if not isinstance(values, list):
        values = [values]
    data_list = recon_data.setdefault(key, [])
    for value in values:
        if value and value not in data_list:
            data_list.append(value)

def run_ftpenum(target, show_output=False, recon_data=None):
    print(f"[*] Running FTP enumeration against {target}...")

    results = {
        "connection": False,
        "enumeration": False, 
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

        # mark enumeration success only if we found interesting files (for ai analysis, should probably adjust later.)
        if results["interesting_files"]:
            results["enumeration"] = True
            print("[+] Interesting files found:\n")
            for f in results["interesting_files"]:
                print(f" - {f}")
            print("")
        else:
            results["error"] = "No interesting files found"
            print("[-] No interesting files found.\n")

    except error_perm as e:
        results["error"] = f"Anonymous FTP login failed: {e}"
        print(f"[-] Anonymous FTP login failed: {e}")
    except Exception as e:
        results["error"] = str(e)
        print(f"[!] FTP enumeration error: {e}")

    if recon_data is not None:
        if results.get("connection"):
            _append_unique(recon_data, "interesting_findings", "Anonymous FTP login successful")
        if results.get("interesting_files"):
            results["enumeration"] = True
            _append_unique(recon_data, "interesting_findings", [f"FTP interesting file: {path}" for path in results["interesting_files"]])

    return results
