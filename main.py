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
from modules.nfsenum import run_nfsenum
from modules.grpcenum import run_grpcenum

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


# SERVICE DETECTION LAYER (KEEP UPDATING)

SERVICE_MAP = {
    "ftp": ["ftp"],
    "smb": ["microsoft-ds", "netbios-ssn"],
    "ldap": ["ldap", "ldaps"],
    "rpc": ["msrpc", "rpcbind"],
    "nfs": ["nfs"],
    "grpc": ["grpc"],
}


def has_port(ports, port):
    return any(p.get("port") == str(port) for p in ports)


def has_service(ports, service_key):
    return any(
        p.get("service") in SERVICE_MAP.get(service_key, [])
        for p in ports
    )


def has_service_or_port(ports, service_key, port):
    return has_service(ports, service_key) or has_port(ports, port)


def main():
    parser = argparse.ArgumentParser(
        description='EasyRecon - Reconnaissance & Enumeration Tool',
        usage='python main.py <target> [options] [--test-creds user:pass]'
    )

    parser.add_argument('target')
    parser.add_argument(
        '-o', '--only',
        choices=[
            'all', 'portscan', 'dirbuster', 'vhostenum',
            'subdomains', 'techstack', 'smbenum',
            'ldapenum', 'rpcenum', 'ftpenum', 'nfsenum', 'grpcenum'
        ],
        default='all'
    )

    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--aggressive', action='store_true')
    parser.add_argument('--test-creds')

    args = parser.parse_args()
    target = sanitize_target(args.target)
    only = args.only

    main_banner()
    print_banner(target)

    scan_results = run_portscan(target, args.verbose)

    ports = scan_results["ports"]
    hostname = scan_results.get("hostname") or target
    domain = None
    ftp_anonymous = scan_results.get("ftp_anonymous")
    git_repo = scan_results.get("git_repo")
    web_targets = scan_results.get("web_targets", [])

    scheme = "https" if web_targets and web_targets[0].startswith("https://") else "http"

    if args.test_creds:
        run_testcreds(target, ports, args.test_creds, args.verbose)

    users = set()

    # MODULE DISPATCH (NOW SERVICES)
    module_dispatch = {
        "portscan": lambda: None,

        "ftpenum": lambda: run_ftpenum(target, args.verbose)
        if has_service_or_port(ports, "ftp", 21)
        else print("[*] FTP not detected."),

        "vhostenum": lambda: run_vhost_enum(hostname, web_targets[0], ports, args.verbose)
        if web_targets else print("[*] No web service detected."),

        "subdomains": lambda: run_subdomain_enum(hostname, web_targets[0], ports, args.verbose, scheme=scheme)
        if web_targets else print("[*] No web service detected."),

        "techstack": lambda: run_tech_stack(web_targets[0], hostname, ports)
        if web_targets else print("[*] No web service detected."),

        "smbenum": lambda: run_smbenum(target, args.verbose)
        if has_service_or_port(ports, "smb", 445)
        else print("[*] SMB not detected."),

        "ldapenum": lambda: run_ldapenum(target, args.verbose)
        if has_service_or_port(ports, "ldap", 389)
        else print("[*] LDAP not detected."),

        "rpcenum": lambda: run_rpcenum(target, args.verbose)
        if has_service_or_port(ports, "rpc", 135)
        else print("[*] RPC not detected."),

        "nfsenum": lambda: run_nfsenum(target, args.verbose)
        if has_service_or_port(ports, "nfs", 2049)
        else print("[*] NFS not detected."),

        "grpcenum": lambda: run_grpcenum(target, args.verbose)
        if has_service_or_port(ports, "grpc", 50051)
        else print("[*] gRPC not detected."),

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

    # FULL RUN (ALL MODULES) 
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

    if has_service_or_port(ports, "ftp", 21):
        section("FTP Enumeration")
        run_ftpenum(target, args.verbose)
    else:
        print("[*] No FTP service detected.")

    if has_service_or_port(ports, "smb", 445):
        section("SMB Enumeration")
        smb_results = run_smbenum(target, args.verbose)
        if smb_results and smb_results.get("users"):
            users.update(smb_results["users"])
    else:
        print("[*] No SMB service detected.")

    if has_service_or_port(ports, "ldap", 389):
        section("LDAP Enumeration")
        ldap_results = run_ldapenum(target, args.verbose)
        if ldap_results:
            if ldap_results.get("users"):
                users.update(ldap_results["users"])
            if ldap_results.get("domain"):
                domain = ldap_results["domain"]
    else:
        print("[*] No LDAP service detected.")

    if has_service_or_port(ports, "rpc", 135):
        section("RPC Enumeration")
        rpc_results = run_rpcenum(target, args.verbose)
        if rpc_results and rpc_results.get("users"):
            users.update(rpc_results["users"])
    else:
        print("[*] No RPC service detected.")

    if has_service_or_port(ports, "nfs", 2049):
        section("NFS Enumeration")
        run_nfsenum(target, args.verbose)
    else:
        print("[*] No NFS service detected.")

    if has_service_or_port(ports, "grpc", 50051):
        section("gRPC Enumeration")
        run_grpcenum(target, args.verbose)
    else:
        print("[*] No gRPC service detected.")

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
            run_subdomain_enum(hostname, web_targets[0], ports, args.verbose, scheme=scheme)

            section("VHost Enumeration")
            run_vhost_enum(hostname, web_targets[0], ports, args.verbose)
        else:
            print("[*] No web service detected.")

    if web_targets:
        section("Directory Enumeration")
        for url in web_targets:
            run_dirbuster(url, hostname, args.verbose)
    else:
        print("[*] No HTTP/HTTPS services detected.")


if __name__ == "__main__":
    main()