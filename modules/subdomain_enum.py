import subprocess
import requests
import socket
import re
import sys
import random


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

    baseline_words = get_baseline_wordcount(domain, ip_target, scheme)
    if baseline_words is None:
        print("[!] Could not determine baseline word count. Skipping subdomain enumeration.")
        return []

    print(f"[*] Baseline word count: {baseline_words}")

    target_host = ip_target if ip_target else scan_target
    target_url = f"{scheme}://{target_host}/"

    ffuf_cmd = [
        "ffuf",
        "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "-u", target_url,
        "-H", f"Host: FUZZ.{domain}",
        "-fw", str(baseline_words),
        "-v",
        "-t", "25"
    ]

    if use_https and ip_target:
        ffuf_cmd.append("-k")

    try:
        result = subprocess.run(ffuf_cmd, capture_output=True, text=True, timeout=300)
        if show_output:
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
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


def get_baseline_wordcount(domain, ip_target, scheme='http'):
    """Get word count for a non-existent subdomain to filter noise."""
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
        resp = requests.get(url, headers=headers, timeout=5, allow_redirects=False, verify=False)
        return len(resp.text.split())
    except requests.exceptions.RequestException:
        return None


def parse_ffuf_output(output, domain):
    """Extract discovered subdomains from ffuf verbose output."""
    subdomains = []

    for line in output.split('\n'):
        line = line.strip()
        
        if 'FUZZ.' in line and domain in line:
            m = re.search(r'FUZZ\.([^\s/]+\.' + re.escape(domain) + r')', line)
            if m:
                candidate = m.group(1)
                if candidate.endswith('.' + domain) and candidate not in subdomains:
                    subdomains.append(candidate)
        
        if 'http://' in line or 'https://' in line:
            try:
                url = line.split()[-1]
                host = re.sub(r'^https?://', '', url).split('/')[0]
                if host.endswith('.' + domain) and host not in subdomains:
                    subdomains.append(host)
            except (IndexError, ValueError):
                pass

    return subdomains
