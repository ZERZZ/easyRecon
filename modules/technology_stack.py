import requests
import re
import urllib3
import subprocess
import json
import os

from utils.output import print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def add_tech(tech, versions, name, ver=None):
    """Add a technology, deduplicating by substring match."""
    name_lower = name.lower()

    # check if a shorter/longer variant already exists
    for existing in list(tech):
        existing_lower = existing.lower()
        if name_lower in existing_lower or existing_lower in name_lower:
            # keep the one with a version, or the longer/more descriptive name
            if ver and existing not in versions:
                tech.discard(existing)
                tech.add(name)
                if ver:
                    versions[name] = ver
            return

    tech.add(name)
    if ver:
        versions[name] = ver


def _append_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return
    if not isinstance(values, list):
        values = [values]
    data_list = recon_data.setdefault(key, [])
    for value in values:
        if value and value not in data_list:
            data_list.append(value)


def run_tech_stack(target, hostname, open_ports, recon_data=None):
    print("[*] Running technology stack detection...")

    tech = set()
    versions = {}

    http_ports = [
        p["port"] for p in open_ports
        if p["service"] in ["http", "https"] or p["port"] in ["80", "443"]
    ]

    if not http_ports:
        print("[*] No HTTP services detected.")
        return {}

    # --- HTTP request ---
    headers_override = {"Host": hostname} if hostname else {}

    try:
        resp = requests.get(
            target,
            headers=headers_override,
            timeout=5,
            verify=False,
            allow_redirects=True
        )
    except requests.RequestException as e:
        print(f"[*] Failed HTTP request to {target}: {e}")
        return {}

    headers = resp.headers
    body = resp.text.lower()

    server = headers.get("Server")
    powered = headers.get("X-Powered-By")

    if server:
        if "apache" in server.lower():
            add_tech(tech, versions, "Apache")
        if "nginx" in server.lower():
            add_tech(tech, versions, "Nginx")

        match = re.search(r'([A-Za-z\-]+)/([\d\.]+)', server)
        if match:
            versions[match.group(1)] = match.group(2)

    if powered:
        if "php" in powered.lower():
            add_tech(tech, versions, "PHP")

        match = re.search(r'([A-Za-z\-]+)/([\d\.]+)', powered)
        if match:
            versions[match.group(1)] = match.group(2)

    # CMS / frameworks from body
    if (
        "wp-content" in body or
        "wp-includes" in body or
        "wp-json" in body or
        "xmlrpc.php" in body or
        "wp-login.php" in body
    ):
        add_tech(tech, versions, "WordPress")
        wp_ver = re.search(r'wordpress\s*([\d\.]+)', body)
        if wp_ver:
            versions["WordPress"] = wp_ver.group(1)

    if "drupal.settings" in body:
        add_tech(tech, versions, "Drupal")
    if "joomla" in body:
        add_tech(tech, versions, "Joomla")
    if "laravel" in body:
        add_tech(tech, versions, "Laravel")
    if "csrfmiddlewaretoken" in body:
        add_tech(tech, versions, "Django")
    if "asp.net" in body or "x-aspnet-version" in headers:
        add_tech(tech, versions, "ASP.NET")
    if "express" in body:
        add_tech(tech, versions, "Express")

    # wappalyzer scan 
    scan_file = "wappalyzer_scan.json"
    try:
        cmd = ["wappalyzer", "-i", target, "-oJ", scan_file]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(scan_file, "r") as f:
            wap_data = json.load(f)

        for url_key, techs in wap_data.items():
            for name, info in techs.items():
                ver = info.get("version", "") or None
                add_tech(tech, versions, name, ver)

    except FileNotFoundError:
        print("[!] Wappalyzer scan file not found.")
    except json.JSONDecodeError:
        print("[!] Failed to parse Wappalyzer JSON output.")
    except Exception as e:
        print(f"[!] Wappalyzer error: {e}")
    finally:
        if os.path.exists(scan_file):
            os.remove(scan_file)

    # results summary
    if tech:
        print("[+] Technology detected:")

        # Versioned entries first, one per line
        for t in sorted(tech):
            if t in versions:
                print(f"    - {t} ({versions[t]})")

        # Non-versioned on a single line
        non_versioned = sorted(
            [t for t in tech if t not in versions and "http" not in t.lower()]
        )
        if non_versioned:
            print(f"    - {', '.join(non_versioned)}")

        if recon_data is not None:
            detected = []
            for t in sorted(tech):
                if t in versions:
                    detected.append(f"{t} {versions[t]}")
                else:
                    detected.append(t)
            recon_data.setdefault("notes", []).append(f"Detected technologies: {', '.join(detected)}")
    else:
        print("[*] No identifiable technology detected.")

    return {
        "technologies": list(tech),
        "versions": versions
    }