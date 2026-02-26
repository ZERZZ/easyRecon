from modules.portscan import run_portscan
from modules.dirbuster import run_dirbuster
from modules.subdomain_enum import run_subdomain_enum
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
        choices=['all', 'portscan', 'dirbuster', 'subdomain'],
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

    # Print banner only after valid target is provided
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

    scan_results = run_portscan(target, args.verbose)
    ports = scan_results["ports"]
    hostname = scan_results["hostname"]

    print("\n[+] Open ports found:")
    for p in ports:
        print(f" - {p['port']}/{p['protocol']} ({p['service']})")

    if hostname:
        print(f"\n[+] Hostname: {hostname}")
        run_subdomain_enum(hostname, target, ports, args.verbose)
    else:
        print("\n[*] No hostname found in SSL certificate.")

    # Try to run dirbuster on web services; probe to find responsive protocol
    requested_proto = None
    if args.target.lower().startswith('https://'):
        requested_proto = 'https'
    elif args.target.lower().startswith('http://'):
        requested_proto = 'http'

    proto_available = set()
    for p in ports:
        if p.get("port") == "80":
            proto_available.add('http')
        elif p.get("port") == "443":
            proto_available.add('https')

    # Build probe list: prefer user-requested protocol if available
    if proto_available:
        if requested_proto in proto_available:
            to_probe = [requested_proto] + [
                p for p in ['https', 'http']
                if p in proto_available and p != requested_proto
            ]
        else:
            to_probe = ['http', 'https'] if 'http' in proto_available else ['https']
    else:
        to_probe = [requested_proto] if requested_proto else ['http', 'https']

    succeeded = False

    for proto in to_probe:
        url = f"{proto}://{target}"
        try:
            requests.get(url, timeout=3, verify=False, allow_redirects=False)
            run_dirbuster(url, args.verbose)
            succeeded = True
            break
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.RequestException:
            continue

    if not succeeded and to_probe:
        run_dirbuster(f"{to_probe[0]}://{target}", args.verbose)


if __name__ == "__main__":
    main()