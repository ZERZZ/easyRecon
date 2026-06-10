import subprocess
import json
import os
import re
import requests
import random
import string
import yaml
from difflib import SequenceMatcher
from datetime import datetime

from utils.output import print
from utils.report import add_web_endpoint


def load_config():
    try:
        with open("config/settings.yaml", "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


def _parse_json_results(results):
    hits = []
    for result in results:
        hits.append({
            'url': result.get('url', ''),
            'status': result.get('status', 0),
            'lines': result.get('lines', ''),
            'words': result.get('words', '')
        })
    return hits


def _parse_text_results(content):
    hits = []
    line_re = re.compile(r"^\s*(\d{3})\s+\S+\s+(\d+l)\s+(\d+w)\s+\S+\s+(https?://\S+)", re.IGNORECASE)
    
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue


        match = line_re.match(line)
        if match:
            hits.append({
                'url': match.group(4),
                'status': int(match.group(1)),
                'lines': match.group(2),
                'words': match.group(3)
            })
        else:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    hits.append({
                        'url': parts[-1],
                        'status': int(parts[0]),
                        'lines': '',
                        'words': ''
                    })
                except ValueError:
                    continue

    return hits


def _similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def _detect_wildcard(target, hostname=None):
    headers = {}
    if hostname:
        headers["Host"] = hostname

    bodies = []
    lengths = []

    for _ in range(5):
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        url = f"{target}/{rand}"

        try:
            r = requests.get(url, headers=headers, timeout=5, verify=False)
            bodies.append(r.text)
            lengths.append(len(r.text))
        except requests.RequestException:
            return None

    return {
        "length": sum(lengths) // len(lengths),
        "body": bodies[0]
    }


def run_dirbuster(target, hostname=None, show_output=False):
    scan_target = target.rstrip("/")

    print(f"[*] Running feroxbuster against {scan_target}...")      

    timestamp = datetime.now().strftime("%s")
    output_file = f"/tmp/ferox_{timestamp}.json"

    valuable_statuses = {200, 204, 301, 302, 307, 308, 401, 403}

    skip_extensions = {
        '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff', '.woff2', 
        '.ttf', '.svg', '.ico', '.mp4', '.webp', '.eot', '.otf'
    }

    important_extensions = {
        '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.cgi', '.pl', 
        '.html', '.htm', '.xml', '.json', '.env', '.conf', '.config',
        '.txt', '.key', '.pem', '.bak'
    }

    try:
        wildcard = _detect_wildcard(scan_target, hostname)

        stdout_opt = None if show_output else subprocess.DEVNULL
        stderr_opt = None if show_output else subprocess.DEVNULL

        # combine wordlists from config
        config = load_config()

        wordlist_config = config.get('wordlists', {}).get(
            'dirbuster',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt'
        )

        wordlists = (
            wordlist_config if isinstance(wordlist_config, list)
            else [wordlist_config]
        )

        combined_wordlist = f"/tmp/ferox_wordlist_{timestamp}.txt"

        seen = set()
        with open(combined_wordlist, "w") as outfile:
            for wl in wordlists:
                if os.path.exists(wl):
                    with open(wl, "r", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and line not in seen:
                                seen.add(line)
                                outfile.write(line + "\n")

        command = [
            "feroxbuster",
            "-w", combined_wordlist,
            "-u", scan_target,
            "-o", output_file,
            "-f",
            "--depth", "1",
            "-t", "50"
        ]

        if hostname:
            command.extend(["-H", f"Host: {hostname}"])

        if scan_target.startswith("https://"):
            command.append("--insecure")

        subprocess.run(command, check=True, stdout=stdout_opt, stderr=stderr_opt)

        print("[*] Directory scan completed. Parsing results...")
        

        if not os.path.exists(output_file):
            print("[!] Output file not found.")
            return []

        with open(output_file, "r") as f:
            content = f.read().strip()

        try:
            data = json.loads(content)
            results = data if isinstance(data, list) else data.get("results", [])
            hits = _parse_json_results(results)
        except json.JSONDecodeError:
            hits = _parse_text_results(content)

        os.remove(output_file)

        scored = []

        for hit in hits:
            status = hit["status"]
            url = hit["url"]

            score = 0

            if status in {401, 403}:
                score += 100
            if any(url.lower().endswith(ext) for ext in important_extensions):
                score += 80
            if url.endswith("/"):
                score += 60
            if 200 <= status < 400:
                score += 30

            if any(url.lower().endswith(ext) for ext in skip_extensions):
                continue

            # wildcard filter
            if wildcard:
                try:
                    headers = {"Host": hostname} if hostname else {}
                    r = requests.get(url, headers=headers, timeout=5, verify=False)
                    if abs(len(r.text) - wildcard["length"]) < 100:
                        if _similarity(r.text, wildcard["body"]) > 0.90:
                            continue
                except requests.RequestException:
                    continue

            scored.append((score, hit))

        scored.sort(key=lambda x: x[0], reverse=True)
        top_hits = [h for _, h in scored[:10]]

        if top_hits:
            print(f"[+] Top {len(top_hits)} endpoints found:")

            for h in top_hits:
                marker = "[AUTH]" if h["status"] in {401, 403} else "[OK]"
                print(f"  {marker} [{h['status']}] {h['url']}")

                # new reporting integration for web endpoints
                add_web_endpoint(h["url"])

        return top_hits

    except subprocess.CalledProcessError:
        print("[!] Directory scan failed.")
        return []
    except OSError as e:
        print(f"[!] Error: {e}")
        return []