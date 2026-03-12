from modules.portscan import run_portscan
from modules.dirbuster import run_dirbuster
from modules.vhostenum import run_vhost_enum
from modules.technology_stack import run_tech_stack
from modules.smbenum import run_smbenum
from modules.ldapenum import run_ldapenum
from modules.rpcenum import run_rpcenum
from modules.ftpenum import run_ftpenum
from modules.gitdump import run_gitdump
from modules.subdomain_enum import run_subdomain_enum
import re
import argparse


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
        choices=[
            'all', 'portscan', 'dirbuster', 'vhostenum',
            'subdomains', 'techstack', 'smbenum',
            'ldapenum', 'rpcenum', 'ftpenum'
        ],
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

    scan_results = run_portscan(target, args.verbose)

    ports = scan_results["ports"]
    hostname = scan_results.get("hostname") or target
    ftp_anonymous = scan_results.get("ftp_anonymous")
    git_repo = scan_results.get("git_repo")
    web_targets = scan_results.get("web_targets", [])

    module_dispatch = {
        "portscan": lambda: None,

        "ftpenum": lambda: run_ftpenum(target, args.verbose)
        if any(p.get("port") == "21" for p in ports)
        else print("\n[*] Port 21 not detected. FTP not available."),

        "vhostenum": lambda: run_vhost_enum(hostname, web_targets[0] if web_targets else None, ports, args.verbose),

        "subdomains": lambda: run_subdomain_enum(hostname, web_targets[0] if web_targets else None, ports, args.verbose),

        "techstack": lambda: run_tech_stack(web_targets[0] if web_targets else None, hostname, ports),

        "smbenum": lambda: run_smbenum(target, args.verbose)
        if any(p.get("port") == "445" for p in ports)
        else print("\n[*] Port 445 not detected. SMB not available."),

        "ldapenum": lambda: run_ldapenum(target, args.verbose)
        if any(p.get("port") == "389" for p in ports)
        else print("\n[*] Port 389 not detected. LDAP not available."),

        "rpcenum": lambda: run_rpcenum(target, args.verbose)
        if any(p.get("port") == "135" for p in ports)
        else print("\n[*] Port 135 not detected. RPC not available."),

        "dirbuster": lambda: [run_dirbuster(url, hostname, args.verbose) for url in web_targets]
    }

    if only != "all":
        if only == "portscan":
            print("\n[+] Open ports found:")
            for p in ports:
                print(f" - {p['port']}/{p['protocol']} ({p['service']})")

            if ftp_anonymous:
                print("\n[+] Anonymous FTP login allowed:")
                print(ftp_anonymous)

            if git_repo:
                print("\n[+] Exposed Git repository detected:")
                print(git_repo)

            return

        module_dispatch[only]()
        return

    print("\n[+] Open ports found:")
    for p in ports:
        print(f" - {p['port']}/{p['protocol']} ({p['service']})")

    if ftp_anonymous:
        print("\n[+] Anonymous FTP login allowed:")
        print(ftp_anonymous)

    if git_repo:
        print("\n[+] Exposed Git repository detected:")
        print(git_repo)

        git_path = git_repo.splitlines()[0].strip()
        run_gitdump(git_path)

    if any(p.get("port") == "21" for p in ports):
        print("\n[*] FTP detected on port 21.")
        run_ftpenum(target, args.verbose)
    else:
        print("\n[*] No FTP service detected.")

    if any(p.get("port") == "445" for p in ports):
        print("\n[*] SMB detected on port 445.")
        run_smbenum(target, args.verbose)
    else:
        print("\n[*] No SMB service detected.")

    if any(p.get("port") == "389" for p in ports):
        print("\n[*] LDAP detected on port 389.")
        run_ldapenum(target, args.verbose)
    else:
        print("\n[*] No LDAP service detected.")

    if any(p.get("port") == "135" for p in ports):
        print("\n[*] RPC detected on port 135.")
        run_rpcenum(target, args.verbose)
    else:
        print("\n[*] No RPC service detected.")

    if web_targets:
        run_tech_stack(web_targets[0], hostname, ports)

    if hostname:
        print(f"\n[+] Hostname: {hostname}")
        run_subdomain_enum(hostname, web_targets[0] if web_targets else None, ports, args.verbose)
        run_vhost_enum(hostname, web_targets[0] if web_targets else None, ports, args.verbose)

    if web_targets:
        for url in web_targets:
            run_dirbuster(url, hostname, args.verbose)
    else:
        print("\n[*] No HTTP/HTTPS services detected.")


if __name__ == "__main__":
    main()