import os
import subprocess
import xml.etree.ElementTree as ET
import re
import requests
import urllib3
import shutil

from utils.output import print
from utils.report import add_open_port, add_service

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _run_rustscan(target, show_output=False):
    """Run RustScan for port discovery and extract open ports."""
    try:
        result = subprocess.run(
            ["rustscan", "-a", target, "--ulimit", "5000"],
            check=True,
            capture_output=True,
            text=True
        )
        
        output = result.stdout if result.stdout else ""
        ports = []
        
        # parse RustScan output
        for line in output.split('\n'):
            line = line.strip()

            if "Open" in line or "open" in line:
        
                # try format: Open 10.0.0.1:3000
                parts = line.replace("Open", "").replace("open", "").strip()

                # extract port from ip:port style
                if ":" in parts:
                    try:
                        port = parts.split(":")[-1].strip()
                        if port.isdigit() and port not in ports:
                            ports.append(port)
                    except:
                        pass

        # fallback: raw number like "3000 open"
        else:
            match = re.findall(r'\b(\d{1,5})\b', parts)
            for m in match:
                if m.isdigit() and m not in ports:
                    ports.append(m)
        
        return ports
    
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def run_portscan(target, show_output=False, dev_mode=False):
    if dev_mode:
        print("[*] DEV MODE: Skipping scan, loading existing scan.xml...")

        if not os.path.exists("scan.xml"):
            print("[!] scan.xml not found. Cannot continue in dev mode.")
            return {"ports": [], "hostname": None, "web_targets": []}

        results = parse_nmap_xml("scan.xml", target)

        ports = [p["port"] for p in results["ports"]]
        services = sorted({p.get("service") for p in results["ports"] if p.get("service")})

        for p in ports:
            add_open_port(p)

        for s in services:
            add_service(None, None, s)

        print("[*] Loaded scan.xml successfully.")
        return results
    
    print(f"[*] Running nmap against {target}...")

    try:
        stdout_opt = None if show_output else subprocess.DEVNULL
        stderr_opt = None if show_output else subprocess.DEVNULL

        # check if RustScan is available for faster port discovery
        rustscan_available = shutil.which("rustscan") is not None
        
        # step 1: Port discovery
        if rustscan_available:
            print("[*] Using RustScan for port discovery...")
            ports = _run_rustscan(target, show_output)
            if not ports:
                print("[!] RustScan failed to discover ports, falling back to Nmap...")
                subprocess.run(
                    ["nmap", "-p-", "--min-rate", "1000", "-T4", "--noninteractive", "-oX", "port_discovery.xml", target],
                    check=True,
                    stdout=stdout_opt,
                    stderr=stderr_opt
                )
                ports = extract_open_ports("port_discovery.xml")
        else:
            subprocess.run(
                ["nmap", "-p-", "--min-rate", "1000", "-T4", "--noninteractive", "-oX", "port_discovery.xml", target],
                check=True,
                stdout=stdout_opt,
                stderr=stderr_opt
            )
            ports = extract_open_ports("port_discovery.xml")

        if not ports:
            print("[!] No open ports discovered.")
            return {"ports": [], "hostname": None, "web_targets": []}

        ports_str = ",".join(ports)

        # step 2: Targeted service detection on discovered ports
        subprocess.run(
            ["nmap", "-sS", "-sV", "-sC", "-T4", "--noninteractive", "-oX", "scan.xml", "-p", ports_str, target],
            check=True,
            stdout=None if show_output else subprocess.DEVNULL,
            stderr=None if show_output else subprocess.DEVNULL
        )

        results = parse_nmap_xml("scan.xml", target)

        ports = [p["port"] for p in results["ports"]]
        services = sorted({p.get("service") for p in results["ports"] if p.get("service")})

        for p in ports:
            add_open_port(p)

        for s in services:
            add_service(None, None, s)

        print("[*] Nmap scan completed.")
        return results

    except subprocess.CalledProcessError:
        print("[!] Nmap scan failed.")
        return {"ports": [], "hostname": None, "web_targets": []}


def extract_open_ports(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    ports = []

    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                ports.append(port.get("portid"))

    return ports


def is_valid_hostname(hostname, target):
    if not hostname:
        return False

    hostname = hostname.strip().lower()

    invalid_exact = [
        "localhost",
        "localhost.localdomain",
        "localhost.local",
        "example.com",
        "test",
        target.lower(),
        "ssl_self_signed_fallback"
    ]

    if hostname in invalid_exact:
        return False

    if hostname.startswith("ip-"):
        return False

    if hostname.endswith(".local") or hostname.endswith(".localdomain"):
        return False
    
    if "." not in hostname:
        return False

    return True


def extract_hostname_from_headers(target, open_ports):
    candidate = None

    http_ports = [p["port"] for p in open_ports if p["port"] in ["80", "443"]]

    for port in http_ports:
        scheme = "https" if port == "443" else "http"
        url = f"{scheme}://{target}"

        try:
            resp = requests.get(url, timeout=3, verify=False)
            headers = resp.headers

            header_keys = [
                "X-Backend-Server",
                "X-Backend",
                "X-Served-By",
                "X-Host",
                "X-Forwarded-Host",
                "X-Forwarded-Server",
                "Server",
                "Via"
            ]

            for key in header_keys:
                value = headers.get(key)
                if value:
                    match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', value)
                    if match:
                        candidate = match.group(1)
                        return candidate

        except requests.RequestException:
            continue

    return candidate


def parse_nmap_xml(xml_file, target):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    open_ports = []
    hostname = None
    domain = None
    ftp_anonymous = None
    git_repo = None
    web_targets = []

    # ports that are commonly web services
    web_ports = {"80", "443", "8080", "8000", "8008","8081", "8443", "8888", "3000", "5000", "7001"}

    # UPDATED DOMAIN EXTRACTION
    # 1. RDP NTLM INFO
    for script in root.findall(".//script[@id='rdp-ntlm-info']"):
        output = script.get("output", "")
        match = re.search(r'DNS_Domain_Name:\s*([^\s]+)', output)
        if match:
            candidate = match.group(1)
            if is_valid_hostname(candidate, target):
                hostname = candidate
        domain_match = re.search(r'DNS_Computer_Name:\s*([^\s]+)', output)
        if domain_match:
            domain = domain_match.group(1)
        if hostname or domain:
            break

    # 2. MSSQL NTLM INFO
    if not hostname or not domain:
        for script in root.findall(".//script[@id='ms-sql-ntlm-info']"):
            output = script.get("output", "")
            if not hostname:
                match = re.search(r'DNS_Domain_Name:\s*([^\s]+)', output)
                if match:
                    candidate = match.group(1)
                    if is_valid_hostname(candidate, target):
                        hostname = candidate
            if not domain:
                domain_match = re.search(r'DNS_Computer_Name:\s*([^\s]+)', output)
                if domain_match:
                    domain = domain_match.group(1)
            if hostname or domain:
                break

    # 3. HTTP TITLE REDIRECT
    if not hostname:
        for script in root.findall(".//script[@id='http-title']"):
            output = script.get("output", "")
            match = re.search(r'http://([a-zA-Z0-9.-]+)', output)
            if match:
                redirect_host = match.group(1)
                if is_valid_hostname(redirect_host, target):
                    hostname = redirect_host
                    break

    # 4. SSL CERT
    if not hostname:
        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    script = port.find("script[@id='ssl-cert']")
                    if script is not None:
                        output = script.get("output", "")
                        match = re.search(r'commonName=([^/,\n]+)', output)
                        if match:
                            candidate = match.group(1)

                            if candidate.lower() == "ssl_self_signed_fallback":
                                continue

                            if is_valid_hostname(candidate, target):
                                hostname = candidate
                                break

            if hostname:
                break

            # Fallback to check other script outputs
            for script in host.findall(".//script"):
                output = script.get("output", "")
                if "commonName=" in output:
                    match = re.search(r'commonName=([^/,\n]+)', output)
                    if match:
                        candidate = match.group(1)

                        if candidate.lower() == "ssl_self_signed_fallback":
                            continue

                        if is_valid_hostname(candidate, target):
                            hostname = candidate
                            break

    # Parse open ports
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")

            if state is not None and state.get("state") == "open":

                port_id = port.get("portid")
                protocol = port.get("protocol")
                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"

                open_ports.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name
                })

                # skip certain ports that may have misleading HTTP responses; bad though to rely on ports, should be relying on service
                if port_id in ["5985", "5986", "47001"]:
                    continue

                if service_name in ["http", "https"]:

                    scheme = "https" if service_name == "https" or port_id in ["443", "8443"] else "http"
                    url = f"{scheme}://{target}:{port_id}" if port_id not in ["80", "443"] else f"{scheme}://{target}"

                    try:
                        r = requests.get(url, timeout=3, verify=False, allow_redirects=True)

                        content_type = r.headers.get("Content-Type", "").lower()
                        server = r.headers.get("Server", "").lower()
                        body_snip = (r.text or "")[:200].lower()

                        is_httpapi = "microsoft-httpapi" in server

                        looks_like_html = ("<html" in body_snip) or ("<!doctype html" in body_snip)
                        content_textlike = ("html" in content_type or "text" in content_type)

                        is_web_response = (
                            r.status_code < 600 and
                            (
                                content_textlike or looks_like_html or
                                r.status_code in [200, 301, 302, 401, 403, 400]
                            )
                            and not (is_httpapi and not content_textlike and not looks_like_html)
                        )

                        if is_web_response:
                            web_targets.append(url)

                    except requests.RequestException:
                        if service_name == "http":
                            web_targets.append(url)

                ftp_anon_script = port.find("script[@id='ftp-anon']")
                if ftp_anon_script is not None:
                    ftp_output = ftp_anon_script.get("output", "")
                    if "Anonymous FTP login allowed" in ftp_output:
                        ftp_anonymous = ftp_output.strip()

    # Detect exposed git repositories via NSE
    for script in root.findall(".//script[@id='http-git']"):
        output = script.get("output", "")
        if "Git repository found!" in output:
            git_repo = output.strip()
            break

    # Validate SSL Hostname
    if not is_valid_hostname(hostname, target):
        hostname = None

    # If no valid hostname from SSL/redirect, try HTTP headers
    if not hostname:
        header_hostname = extract_hostname_from_headers(target, open_ports)
        if is_valid_hostname(header_hostname, target):
            hostname = header_hostname

    return {
        "ports": open_ports,
        "hostname": hostname,
        "domain": domain,
        "ftp_anonymous": ftp_anonymous,
        "git_repo": git_repo,
        "web_targets": web_targets
    }