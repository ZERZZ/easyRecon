import subprocess
import xml.etree.ElementTree as ET
import re

def run_portscan(target, show_output=False):
    print(f"[*] Running nmap against {target}...")

    try:
        stdout_opt = None if show_output else subprocess.DEVNULL
        stderr_opt = None if show_output else subprocess.DEVNULL

        subprocess.run(
            ["nmap", "-sS", "-sV", "-sC", "--noninteractive", "-oX", "scan.xml", "--top-ports", "1000", target],
            check=True,
            stdout=stdout_opt,
            stderr=stderr_opt
        )

        print("[*] Nmap scan completed.")
        return parse_nmap_xml("scan.xml")

    except subprocess.CalledProcessError:
        print("[!] Nmap scan failed.")
        return {"ports": [], "hostname": None}

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    open_ports = []
    hostname = None

    # attempt to get hostname from SSL certificate
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

        # Fallback- check other script outputs
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

    return {"ports": open_ports, "hostname": hostname}

