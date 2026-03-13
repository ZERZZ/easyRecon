import subprocess
import requests
import random
import urllib3
import json

from utils.output import print

# suppress SSL warnings for direct IP HTTPS probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_subdomain_enum(domain, scan_target, ports, show_output=False):
    """Run DNS subdomain enumeration against the target domain."""
    
    # strip prepended subdomain if present 
    parts = domain.split(".")
    if len(parts) > 2:
        domain = ".".join(parts[1:])

    print(f"[*] Running subdomain enumeration for {domain}...")

    # extract scheme from scan_target provided by main.py
    scheme = scan_target.split("://")[0]

    baseline_size = get_baseline_content_length(domain, scheme)
    if baseline_size is None:
        print("[!] Could not determine baseline content length. Skipping subdomain enumeration.")
        return []

    print(f"[*] Baseline content length: {baseline_size}")

    ffuf_cmd = [
        "ffuf",
        "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "-u", f"{scheme}://FUZZ.{domain}",
        "-fs", str(baseline_size),
        "-t", "25",
        "-of", "json"
    ]

    # if HTTPS target disable verification
    if scheme == "https":
        ffuf_cmd.append("-k")

    try:
        result = subprocess.run(
            ffuf_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
    except subprocess.TimeoutExpired:
        print("[!] ffuf scan timed out.")
        return []
    except FileNotFoundError:
        print("[!] ffuf not found. Make sure it's installed.")
        return []

    if show_output:
        print(result.stdout)

    subdomains = parse_ffuf_output(result.stdout, domain)

    if subdomains:
        print(f"[+] Found {len(subdomains)} subdomains:")
        for subdomain in subdomains:
            print(f"    - {subdomain}")
    else:
        print("[*] No subdomains found.")

    return subdomains


def get_baseline_content_length(domain, scheme='http'):
    """Get Content-Length for a random subdomain to detect wildcard responses."""
    fake_sub = f"nonexistent-{random.randint(1, 10000000)}"
    url = f"{scheme}://{fake_sub}.{domain}"

    try:
        resp = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            verify=False
        )

        # Prefer header if present
        if 'Content-Length' in resp.headers:
            return int(resp.headers['Content-Length'])

        # Fallback to actual body length
        return len(resp.content)

    except requests.exceptions.RequestException:
        return None


def parse_ffuf_output(output, domain):
    """Extract discovered subdomains from ffuf output."""
    subdomains = []

    # try JSON parsing first (more reliable)
    try:
        data = json.loads(output)
        for entry in data.get("results", []):
            fuzz_value = entry.get("input", {}).get("FUZZ")
            if fuzz_value:
                subdomain = f"{fuzz_value}.{domain}"
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
        return subdomains
    except json.JSONDecodeError:
        pass

    # fallback
    for line in output.split('\n'):
        line = line.strip()

        if not line:
            continue

        # ffuf standard output line parsing
        parts = line.split()
        for part in parts:
            if part.endswith('.' + domain) and part not in subdomains:
                subdomains.append(part)

    return subdomains