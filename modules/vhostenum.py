import subprocess
import requests
import socket
import re
import random
import urllib3
import json
import yaml
import base64

from utils.output import print

# suppress SSL warnings for direct IP HTTPS probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_config():
    try:
        with open("config/settings.yaml", "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


def _append_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return

    if not isinstance(values, list):
        values = [values]

    data_list = recon_data.setdefault(key, [])

    for value in values:
        if value and value not in data_list:
            data_list.append(value)


def run_vhost_enum(domain, scan_target, ports, show_output=False, recon_data=None):
    """Run vhost enumeration against the target using Host headers."""

    # skip vhost enumeration for raw IP targets
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        print("[*] Target is an IP address. Skipping vhost enumeration.")
        return []

    # strip prepended subdomain if present
    parts = domain.split(".")
    if len(parts) > 2:
        domain = ".".join(parts[1:])

    # extract scheme / host from scan target
    scheme = scan_target.split("://")[0]
    host = scan_target.split("://")[1].split("/")[0]

    # resolve host to IP if needed
    ip_target = None

    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        ip_target = host
    else:
        try:
            ip_target = socket.gethostbyname(host)
        except socket.gaierror:
            ip_target = None

    # use IP directly if available to avoid DNS resolution issues
    target_host = ip_target if ip_target else host
    target_url = f"{scheme}://{target_host}/"

    baseline_size = get_baseline_content_length(domain, target_url)

    if baseline_size is None:
        print("[!] Could not determine baseline content length. Skipping vhost enumeration.")
        return []

    print(f"[*] Baseline content length: {baseline_size}")
    print(f"[*] Running vhost enumeration for {domain} against {target_url}...")

    config = load_config()

    wordlist = config.get(
        'wordlists',
        {}
    ).get(
        'vhost',
        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
    )

    ffuf_cmd = [
        "ffuf",
        "-w", wordlist,
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

        _append_unique(
            recon_data,
            "interesting_findings",
            [f"Virtual host: {vhost}" for vhost in vhosts]
        )

    else:
        print("[*] No vhosts found.")

    return vhosts


def get_baseline_content_length(domain, target_url):
    """Get baseline response size for a fake vhost."""

    fake_host = f"nonexistent-{random.randint(1, 10000000)}.{domain}"

    try:
        resp = requests.get(
            target_url,
            headers={"Host": fake_host},
            timeout=5,
            allow_redirects=False,
            verify=False
        )

        return len(resp.content)

    except Exception as e:
        print(f"[!] Baseline request failed: {e}")
        return None


def parse_ffuf_output(output, domain):
    """Extract discovered vhosts from ffuf JSON output."""

    vhosts = []

    try:
        data = json.loads(output)

        for entry in data.get("results", []):

            fuzz_value = entry.get("input", {}).get("FUZZ")

            if not fuzz_value:
                continue

            # ffuf may store FUZZ values base64 encoded
            try:
                fuzz_value = base64.b64decode(fuzz_value).decode().strip()
            except Exception:
                fuzz_value = fuzz_value.strip()

            vhost = f"{fuzz_value}.{domain}"

            if vhost not in vhosts:
                vhosts.append(vhost)

        return vhosts

    except json.JSONDecodeError:
        pass

    # fallback plaintext parsing
    for line in output.split('\n'):

        line = line.strip()

        if not line:
            continue

        parts = line.split()

        if parts:
            fuzz_value = parts[0]
            vhost = f"{fuzz_value}.{domain}"

            if vhost not in vhosts:
                vhosts.append(vhost)

    return vhosts