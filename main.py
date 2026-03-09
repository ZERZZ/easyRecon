from modules.portscan import run_portscan
from modules.dirbuster import run_dirbuster
from modules.subdomain_enum import run_subdomain_enum
from modules.technology_stack import run_tech_stack
from modules.smbenum import run_smbenum
from modules.ldapenum import run_ldapenum
from modules.rpcenum import run_rpcenum 
from modules.ftpenum import run_ftpenum
import re
import argparse
import requests


def sanitize_target(target):
    """Extract IP or domain from various URL formats."""
    target = re.sub(r'^[a-zA-Z]+://', '', target.strip())
    target = target.split('/')[0]
    target = target.split(':')[0]
    return target.strip()


def main():
    parser = argparse.ArgumentParser(
        description='EasyRecon - Reconnaissance & Enumeration Tool',
        usage='python main.py <target> [options]'
    )
    parser.add_argument(
        'target',
        help='Target IP or domain (e.g., 10.129.5.69, http://example.com)'
    )
    parser.add_argument(
        '-o', '--only',
        choices=['all', 'portscan', 'dirbuster', 'subdomain', 'techstack', 'smbenum', 'ldapenum', 'rpcenum', 'ftpenum'],
        default='all',
        help='Run only a specific module'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show raw tool output'
    )

    args = parser.parse_args()
    target = sanitize_target(args.target)
    only = args.only

    banner = """
    ███████╗ █████╗ ███████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    █████╗  ███████║███████╗ ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ███████╗██║  ██║███████║   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

                                Author: mattsec
                        Reconnaissance & Enumeration Tool
    """

    print(banner)
    print(f"[*] Target: {target}\n")

    ## This logic feels repetitive and needs a revamp - maybe a dict of module names to functions ?

    if only == 'portscan':
        scan_results = run_portscan(target, args.verbose)
        ports = scan_results["ports"]
        ftp_anonymous = scan_results.get("ftp_anonymous")

        print("\n[+] Open ports found:")
        for p in ports:
            print(f" - {p['port']}/{p['protocol']} ({p['service']})")

        if ftp_anonymous:
            print("\n[+] Anonymous FTP login allowed:")
            print(ftp_anonymous)

        return
    
    if only == 'ftpenum':
        scan_results = run_portscan(target, args.verbose)
        ports = scan_results["ports"]

        ftp_open = any(p.get("port") == "21" for p in ports)

        if ftp_open:
            run_ftpenum(target, args.verbose)
        else:
            print("\n[*] Port 21 not detected. FTP not available.")
        return   

    if only == 'subdomain':
        run_subdomain_enum(target, target, None, args.verbose)
        return

    if only == 'techstack':
        scan_results = run_portscan(target, args.verbose)
        ports = scan_results["ports"]
        hostname = scan_results["hostname"]
        run_tech_stack(target, hostname, ports)
        return

    if only == 'smbenum':
        scan_results = run_portscan(target, args.verbose)
        ports = scan_results["ports"]

        smb_open = any(p.get("port") == "445" for p in ports)

        if smb_open:
            run_smbenum(target, args.verbose)
        else:
            print("\n[*] Port 445 not detected. SMB not available.")
        return

    if only == 'ldapenum':
        scan_results = run_portscan(target, args.verbose)
        ports = scan_results["ports"]

        ldap_open = any(p.get("port") == "389" for p in ports)

        if ldap_open:
            run_ldapenum(target, args.verbose)
        else:
            print("\n[*] Port 389 not detected. LDAP not available.")
        return

    if only == 'rpcenum':
        scan_results = run_portscan(target, args.verbose)
        ports = scan_results["ports"]

        rpc_open = any(p.get("port") == "135" for p in ports)

        if rpc_open:
            run_rpcenum(target, args.verbose)
        else:
            print("\n[*] Port 135 not detected. RPC not available.")
        return

    scan_results = run_portscan(target, args.verbose)
    ports = scan_results["ports"]
    hostname = scan_results["hostname"]
    ftp_anonymous = scan_results.get("ftp_anonymous")

    print("\n[+] Open ports found:")
    for p in ports:
        print(f" - {p['port']}/{p['protocol']} ({p['service']})")

    if ftp_anonymous:
        print("\n[+] Anonymous FTP login allowed:")
        print(ftp_anonymous)

    ## ftp detection
    ftp_open = any(p.get("port") == "21" for p in ports)
    if ftp_open:
        print("\n[*] FTP detected on port 21.")
        run_ftpenum(target, args.verbose)
    else:
        print("\n[*] No FTP service detected.")

    # SMB detection
    smb_open = any(p.get("port") == "445" for p in ports)
    if smb_open:
        print("\n[*] SMB detected on port 445.")
        run_smbenum(target, args.verbose)
    else:
        print("\n[*] No SMB service detected.")

    # LDAP detection
    ldap_open = any(p.get("port") == "389" for p in ports)
    if ldap_open:
        print("\n[*] LDAP detected on port 389.")
        run_ldapenum(target, args.verbose)
    else:
        print("\n[*] No LDAP service detected.")

    # RPC detection
    rpc_open = any(p.get("port") == "135" for p in ports)
    if rpc_open:
        print("\n[*] RPC detected on port 135.")
        run_rpcenum(target, args.verbose)
    else:
        print("\n[*] No RPC service detected.")

    # technology stack detection
    run_tech_stack(target, hostname, ports)

    if hostname:
        print(f"\n[+] Hostname: {hostname}")
        run_subdomain_enum(hostname, target, ports, args.verbose)
    else:
        print("\n[*] No hostname found in SSL certificate.")

    # run dirbuster 
    web_targets = []

    for p in ports:
        service = p.get("service", "").lower()
        port = p.get("port")

        if not port:
            continue

        if "https" in service:
            url = f"https://{target}" if port == "443" else f"https://{target}:{port}"
            web_targets.append(url)

        elif "http" in service:
            url = f"http://{target}" if port == "80" else f"http://{target}:{port}"
            web_targets.append(url)

    if web_targets:
        for url in web_targets:
            run_dirbuster(url, hostname, args.verbose)
    else:
        print("\n[*] No HTTP/HTTPS services detected.")


if __name__ == "__main__":
    main()