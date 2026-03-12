import subprocess
import requests
import socket
import re
import sys
import random
import urllib3
import json

# suppress SSL warnings for direct IP HTTPS probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_vhost_enum(domain, scan_target, ports, show_output=False):
    """Run vhost enumeration against the target IP using Host headers."""

    # extract scheme / host from main
    scheme = scan_target.split("://")[0]
    host = scan_target.split("://")[1].split("/")[0]

    # Get IP to send requests to
    ip_target = None
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        ip_target = host
    else:
        try:
            ip_target = socket.gethostbyname(host)
        except socket.gaierror:
            ip_target = None

    target_host = domain if domain else host
    target_url = f"{scheme}://{target_host}/"

    baseline_size = get_baseline_content_length(domain, target_url)
    if baseline_size is None:
        print("[!] Could not determine baseline content length. Skipping vhost enumeration.")
        return []

    print(f"[*] Baseline content length: {baseline_size}")
    print(f"[*] Running vhost enumeration for {domain} against {target_url}...")

    ffuf_cmd = [
        "ffuf",
        "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "-u", target_url,
        "-H", f"Host: FUZZ.{domain}",
        "-fs", str(baseline_size),
        "-t", "25",
        "-of", "json"
    ]

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

    vhosts = parse_ffuf_output(result.stdout, domain)

    if vhosts:
        print(f"[+] Found {len(vhosts)} vhosts:")
        for vhost in vhosts:
            print(f"    - {vhost}")
    else:
        print("[*] No vhosts found.")

    return vhosts


def get_baseline_content_length(domain, target_url):
    """Get Content-Length for a non-existent vhost to filter catch-all noise."""

    fake_host = f"nonexistent-{random.randint(1, 10000000)}.{domain}"

    try:
        resp = requests.get(
            target_url,
            headers={"Host": fake_host},
            timeout=5,
            allow_redirects=False,
            verify=False
        )

        if 'Content-Length' in resp.headers:
            return int(resp.headers['Content-Length'])

        return len(resp.content)

    except requests.exceptions.RequestException:
        return None


def parse_ffuf_output(output, domain):
    """Extract discovered vhosts from ffuf output."""
    vhosts = []

    try:
        data = json.loads(output)
        for entry in data.get("results", []):
            fuzz_value = entry.get("input", {}).get("FUZZ")
            if fuzz_value:
                vhost = f"{fuzz_value}.{domain}"
                if vhost not in vhosts:
                    vhosts.append(vhost)
        return vhosts
    except json.JSONDecodeError:
        pass

    for line in output.split('\n'):
        line = line.strip()

        if not line:
            continue

        parts = line.split()
        for part in parts:
            if part.endswith('.' + domain) and part not in vhosts:
                vhosts.append(part)

    return vhosts