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
from modules.asrep_roast import run_asrep_roast
from modules.testcreds import run_testcreds

from utils.output import section, banner as print_banner, print
from utils.banner import main_banner

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
        usage='python main.py <target> [options] [--test-creds user:pass]'
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

    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Enable aggressive actions such as password cracking'
    )

    parser.add_argument(
        '--test-creds',
        help='Test supplied credentials against discovered services (format user:pass)'
    )

    args = parser.parse_args()
    target = sanitize_target(args.target)
    only = args.only

    ## main banner
    main_banner()

    print_banner(target)

    scan_results = run_portscan(target, args.verbose)

    ports = scan_results["ports"]
    hostname = scan_results.get("hostname") or target
    domain = None
    ftp_anonymous = scan_results.get("ftp_anonymous")
    git_repo = scan_results.get("git_repo")
    web_targets = scan_results.get("web_targets", [])

    if args.test_creds:
        run_testcreds(target, ports, args.test_creds, args.verbose)

    # central user store
    users = set()

    module_dispatch = {
        "portscan": lambda: None,

        "ftpenum": lambda: run_ftpenum(target, args.verbose)
        if any(p.get("port") == "21" for p in ports)
        else print("[*] Port 21 not detected. FTP not available."),

        "vhostenum": lambda: run_vhost_enum(hostname, web_targets[0], ports, args.verbose)
        if web_targets else print("[*] No web service detected. Skipping vhost enumeration."),

        "subdomains": lambda: run_subdomain_enum(hostname, web_targets[0], ports, args.verbose)
        if web_targets else print("[*] No web service detected. Skipping subdomain enumeration."),

        "techstack": lambda: run_tech_stack(web_targets[0], hostname, ports)
        if web_targets else print("[*] No web service detected. Skipping technology stack detection."),

        "smbenum": lambda: run_smbenum(target, args.verbose)
        if any(p.get("port") == "445" for p in ports)
        else print("[*] Port 445 not detected. SMB not available."),

        "ldapenum": lambda: run_ldapenum(target, args.verbose)
        if any(p.get("port") == "389" for p in ports)
        else print("[*] Port 389 not detected. LDAP not available."),

        "rpcenum": lambda: run_rpcenum(target, args.verbose)
        if any(p.get("port") == "135" for p in ports)
        else print("[*] Port 135 not detected. RPC not available."),

        "dirbuster": lambda: [run_dirbuster(url, hostname, args.verbose) for url in web_targets]
    }

    if only != "all":
        if only == "portscan":
            section("Open Ports Found")

            for p in ports:
                print(f" - {p['port']}/{p['protocol']} ({p['service']})")

            if ftp_anonymous:
                section("Anonymous FTP Login Allowed")
                print(ftp_anonymous)

            if git_repo:
                section("Exposed Git Repository")
                print(git_repo)

            return

        module_dispatch[only]()
        return

    section("Open Ports Found")
    for p in ports:
        print(f" - {p['port']}/{p['protocol']} ({p['service']})")

    if ftp_anonymous:
        section("Anonymous FTP Login Allowed")
        print(ftp_anonymous)

    if git_repo:
        section("Exposed Git Repository")
        print(git_repo)

        section("Git Dump")
        git_path = git_repo.splitlines()[0].strip()
        run_gitdump(git_path)

    if any(p.get("port") == "21" for p in ports):
        section("FTP Enumeration")
        print("[*] FTP detected on port 21.")
        run_ftpenum(target, args.verbose)
    else:
        print("[*] No FTP service detected.")

    if any(p.get("port") == "445" for p in ports):
        section("SMB Enumeration")
        print("[*] SMB detected on port 445.")
        smb_results = run_smbenum(target, args.verbose)
        if smb_results and smb_results.get("users"):
            users.update(smb_results["users"])
    else:
        print("[*] No SMB service detected.")

    if any(p.get("port") == "389" for p in ports):
        section("LDAP Enumeration")
        ldap_results = run_ldapenum(target, args.verbose)
        if ldap_results:
            if ldap_results.get("users"):
                users.update(ldap_results["users"])
            if ldap_results.get("domain"):
                domain = ldap_results["domain"]
    else:
        print("[*] No LDAP service detected.")

    if any(p.get("port") == "135" for p in ports):
        section("RPC Enumeration")
        rpc_results = run_rpcenum(target, args.verbose)
        if rpc_results and rpc_results.get("users"):
            users.update(rpc_results["users"])
    else:
        print("[*] No RPC service detected.")

    # attempt as rep roasting if any users were discovered
    if users:
        section("AS-REP Roasting")
        run_asrep_roast(domain or hostname, target, list(users), verbose=args.verbose, aggressive=args.aggressive)

    if web_targets:
        section("Technology Stack Detection")
        run_tech_stack(web_targets[0], hostname, ports)

    if hostname:
        section("Web Enumeration w/ Hostname")
        print(f"[+] Hostname: {hostname}")

        if web_targets:
            section("Subdomain Enumeration")
            run_subdomain_enum(hostname, web_targets[0], ports, args.verbose)

            section("VHost Enumeration")
            run_vhost_enum(hostname, web_targets[0], ports, args.verbose)
        else:
            print("[*] No web service detected. Skipping subdomain and vhost enumeration.")

    if web_targets:
        section("Directory Enumeration")
        for url in web_targets:
            run_dirbuster(url, hostname, args.verbose)
    else:
        print("[*] No HTTP/HTTPS services detected.")


if __name__ == "__main__":
    main()