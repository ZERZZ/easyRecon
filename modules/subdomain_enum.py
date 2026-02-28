import subprocess
import requests
import socket
import re
import sys
import random
import urllib3

# suppress SSL warnings for direct IP HTTPS probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_subdomain_enum(domain, scan_target, ports, show_output=False):
    """Run subdomain enumeration against the target IP using Host headers."""
    print(f"[*] Running subdomain enumeration for {domain} against {scan_target}...")

    # Get IP to send requests to
    ip_target = None
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', scan_target):
        ip_target = scan_target
    else:
        try:
            ip_target = socket.gethostbyname(scan_target)
        except socket.gaierror:
            ip_target = None

    use_https = any(p.get('port') == '443' for p in (ports or []))
    scheme = 'https' if use_https else 'http'

    baseline_size = get_baseline_content_length(domain, ip_target, scheme)
    if baseline_size is None:
        print("[!] Could not determine baseline content length. Skipping subdomain enumeration.")
        return []

    print(f"[*] Baseline content length: {baseline_size}")

    target_host = ip_target if ip_target else scan_target
    target_url = f"{scheme}://{target_host}/"

    ffuf_cmd = [
        "ffuf",
        "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "-u", target_url,
        "-H", f"Host: FUZZ.{domain}",
        "-fs", str(baseline_size),
        "-t", "25"
    ]

    if use_https and ip_target:
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

    subdomains = parse_ffuf_output(result.stdout, domain)

    if subdomains:
        print(f"[+] Found {len(subdomains)} subdomains:")
        for subdomain in subdomains:
            print(f"    - {subdomain}")
    else:
        print("[*] No subdomains found.")

    return subdomains


def get_baseline_content_length(domain, ip_target, scheme='http'):
    """Get Content-Length for a non-existent subdomain to filter catch-all noise."""
    fake_host = f"nonexistent-{random.randint(1, 10000000)}.{domain}"

    if ip_target:
        url = f"{scheme}://{ip_target}/"
        headers = {"Host": fake_host}
    else:
        try:
            socket.gethostbyname(domain)
            url = f"{scheme}://{domain}/easyrecon-nonexistent-path-baseline"
            headers = {}
        except socket.gaierror:
            return None

    try:
        resp = requests.get(
            url,
            headers=headers,
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