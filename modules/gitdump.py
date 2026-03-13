import os
import subprocess
import yaml
import re

from utils.output import print

INTERESTING_FILES = [
    ".env",
    ".env.production",
    ".env.dev",
    ".env.local",
    "config.php",
    "config.yml",
    "config.yaml",
    "settings.py",
    "appsettings.json",
    "database.yml",
    "db.php",
    "db_config.php",
    "docker-compose.yml",
    "Dockerfile",
    "kubernetes.yml",
    "nginx.conf",
    "apache.conf",
    "backup.sql",
    "dump.sql",
    "users.sql"
]

def load_config():
    try:
        with open("config/settings.yaml", "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}

def ensure_http(repo_url):
    if not repo_url.startswith("http"):
        repo_url = f"http://{repo_url}"
    return repo_url

def sanitize_name(name):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', name)

def is_interesting_file(filename):
    filename_lower = filename.lower()
    for interesting in INTERESTING_FILES:
        if filename_lower.endswith(interesting.lower()):
            return True
    return False

def scan_repository(repo_path, results):
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if is_interesting_file(file):
                full_path = os.path.join(root, file)
                results["interesting_files"].append(full_path)

def dump_repository(repo_url, dump_directory, show_output=False):
    try:
        if show_output:
            subprocess.run(
                ["git-dumper", repo_url, dump_directory],
                check=True
            )
        else:
            subprocess.run(
                ["git-dumper", repo_url, dump_directory],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] git-dumper error: {e}")
        return False

def clone_remote_repo(remote_url, dump_directory, show_output=False):
    try:
        if show_output:
            subprocess.run(
                ["git", "clone", remote_url, dump_directory],
                check=True
            )
        else:
            subprocess.run(
                ["git", "clone", remote_url, dump_directory],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] git clone error: {e}")
        return False

def extract_remote_repo(repo_output):
    matches = re.findall(r'(https?://[^\s]+\.git)', repo_output)
    if matches:
        return matches[0]
    return None

def run_gitdump(repo_output, show_output=False):
    print("[*] Processing exposed Git repository...")

    # extract .git path
    repo_url = next((line.strip() for line in repo_output.splitlines() if line.strip()), None)
    if not repo_url:
        print("[-] Could not determine repository URL from input")
        return {
            "repo_dumped": False,
            "repo_path": "",
            "interesting_files": []
        }

    repo_url = ensure_http(repo_url)
    repo_url = repo_url.replace(":80", "")
    repo_url = repo_url.rstrip("/")

    # fallback: extract remote if URL ends without .git
    if not repo_url.endswith(".git"):
        remote_repo = extract_remote_repo(repo_output)
        if remote_repo:
            repo_url = remote_repo

    config = load_config()
    dump_base = config.get("gitdump", {}).get("dump_directory")
    if not dump_base:
        dump_base = os.getcwd()  # default to current directory if blank

    repo_folder = sanitize_name(repo_url)
    dump_directory = os.path.join(dump_base, repo_folder)
    os.makedirs(dump_directory, exist_ok=True)

    results = {
        "repo_dumped": False,
        "repo_path": dump_directory,
        "interesting_files": []
    }

    print(f"[*] Attempting git-dumper against {repo_url}")

    success = dump_repository(repo_url, dump_directory, show_output)

    if not success:
        print("[!] git-dumper failed, checking for remote repository...")
        remote_repo = extract_remote_repo(repo_output)

        if remote_repo:
            print(f"[+] Remote repository found: {remote_repo}")
            print("[*] Attempting to clone remote repository...")
            success = clone_remote_repo(remote_repo, dump_directory, show_output)

    if not success:
        print("[-] Git dump failed.")
        return results

    results["repo_dumped"] = True
    print(f"[+] Repository stored in {dump_directory}")

    scan_repository(dump_directory, results)

    if results["interesting_files"]:
        print("[+] Interesting files discovered:")
        for f in results["interesting_files"]:
            print(f" - {f}")
    else:
        print("[-] No interesting files found.")

    return results