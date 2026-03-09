import subprocess
import xml.etree.ElementTree as ET
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_portscan(target, show_output=False):
    print(f"[*] Running nmap against {target}...")

    try:
        stdout_opt = None if show_output else subprocess.DEVNULL
        stderr_opt = None if show_output else subprocess.DEVNULL

        subprocess.run(
            ["nmap", "-sS", "-sV", "-sC", "-T4", "--noninteractive", "-oX", "scan.xml", "--top-ports", "1000", target],
            check=True,
            stdout=stdout_opt,
            stderr=stderr_opt
        )

        print("[*] Nmap scan completed.")
        return parse_nmap_xml("scan.xml", target)

    except subprocess.CalledProcessError:
        print("[!] Nmap scan failed.")
        return {"ports": [], "hostname": None}

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
        target.lower()
    ]

    if hostname in invalid_exact:
        return False

    if hostname.startswith("ip-"):
        return False

    if hostname.endswith(".local") or hostname.endswith(".localdomain"):
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
    ftp_anonymous = None

    # attempt to get hostname from http-title redirect (should always be first)
    for script in root.findall(".//script[@id='http-title']"):
        output = script.get("output", "")
        match = re.search(r'http://([a-zA-Z0-9.-]+)', output)
        if match:
            redirect_host = match.group(1)
            if is_valid_hostname(redirect_host, target):
                hostname = redirect_host
                break

    # attempt to get hostname from SSL certificate
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
                            hostname = match.group(1)
                            break
            
            if hostname:
                break

            # Fallback to check other script outputs 
            for script in host.findall(".//script"):
                output = script.get("output", "")
                if "commonName=" in output:
                    match = re.search(r'commonName=([^/,\n]+)', output)
                    if match:
                        hostname = match.group(1)
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

                ftp_anon_script = port.find("script[@id='ftp-anon']")
                if ftp_anon_script is not None:
                    ftp_output = ftp_anon_script.get("output", "")
                    if "Anonymous FTP login allowed" in ftp_output:
                        ftp_anonymous = ftp_output.strip()

    # Validate SSL hostname
    if not is_valid_hostname(hostname, target):
        hostname = None

    # If no valid hostname from SSL/redirect, try HTTP headers
    if not hostname:
        header_hostname = extract_hostname_from_headers(target, open_ports)
        if is_valid_hostname(header_hostname, target):
            hostname = header_hostname

    return {"ports": open_ports, "hostname": hostname, "ftp_anonymous": ftp_anonymous}