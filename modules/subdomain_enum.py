import subprocess
import requests
import random
import urllib3
import json
import ipaddress

from utils.output import print

# suppress SSL warnings for direct IP HTTPS probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_subdomain_enum(domain, scan_target, ports, show_output=False, scheme="http"):
    """Run DNS subdomain enumeration against the target domain."""
    
    # skip if domain is IP address (obviously wont work. )
    try:
        ipaddress.ip_address(domain)
        print(f"[-] Skipping subdomain enumeration for IP: {domain}")
        return []
    except ValueError:
        pass

    # strip prepended subdomain if present
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        parts = domain.split(".")
        if len(parts) > 2:
            domain = ".".join(parts[1:])

    print(f"[*] Running subdomain enumeration for {domain}...")

    # baseline check (now protocol-agnostic)
    baseline_size = get_baseline_content_length(domain)
    if baseline_size is None:
        print("[!] Could not determine baseline content length. Continuing without filtering.")
    else:
        print(f"[*] Baseline content length: {baseline_size}")

    ffuf_cmd = [
        "ffuf",
        "-w", "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        "-u", f"{scheme}://FUZZ.{domain}",   
        "-mc", "all",
        "-of", "json",
        "-k"
    ]

    print(f"[DEBUG] Running command: {' '.join(ffuf_cmd)}")

    try:
        result = subprocess.run(
            ffuf_cmd,
            capture_output=True,
            text=True,
            timeout=300  
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


def get_baseline_content_length(domain):
    """Try HTTP then HTTPS to determine baseline response size."""
    fake_sub = f"nonexistent-{random.randint(1, 10000000)}"

    for scheme in ["http", "https"]:
        url = f"{scheme}://{fake_sub}.{domain}"
        try:
            resp = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                verify=False
            )

            return len(resp.content)

        except requests.exceptions.RequestException:
            continue

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