from modules.portscan import run_portscan
from modules.dirbuster import run_dirbuster
from modules.subdomain_enum import run_subdomain_enum
from modules.technology_stack import run_tech_stack
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
        description='EasyRecon - Web reconnaissance tool',
        usage='python main.py <target>'
    )
    parser.add_argument(
        'target',
        help='Target IP or domain (e.g., 10.129.5.69, http://example.com)'
    )
    parser.add_argument(
        '-o', '--only',
        choices=['all', 'portscan', 'dirbuster', 'subdomain', 'techstack'],
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
                    Web Reconnaissance & Enumeration Tool
    """

    print(banner)
    print(f"[*] Target: {target}\n")

    if only == 'portscan':
        scan_results = run_portscan(target, args.verbose)
        ports = scan_results["ports"]

        print("\n[+] Open ports found:")
        for p in ports:
            print(f" - {p['port']}/{p['protocol']} ({p['service']})")
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

    scan_results = run_portscan(target, args.verbose)
    ports = scan_results["ports"]
    hostname = scan_results["hostname"]

    print("\n[+] Open ports found:")
    for p in ports:
        print(f" - {p['port']}/{p['protocol']} ({p['service']})")


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
            run_dirbuster(url, args.verbose)
    else:
        print("\n[*] No HTTP/HTTPS services detected.")


if __name__ == "__main__":
    main()