from modules.portscan import run_portscan
from modules.dirbuster import run_dirbuster
from modules.vhostenum import run_vhost_enum
from modules.technology_stack import run_tech_stack
from modules.cve_lookup import run_cve_lookup
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
from modules.mssql_enum import run_mssql_enum
from modules.bloodhound import run_bloodhound
from modules.ai_analysis import analyze_recon, preload_model_async
from modules.certipy import run_certipy_enum
from modules.dns_enum import run_dnsenum

from utils.output import section, banner as print_banner, print
from utils.banner import main_banner
from utils import report, findings

import re
import json
import argparse
import ipaddress


def sanitize_target(target):
    """Extract IP or domain from various URL formats."""
    target = re.sub(r'^[a-zA-Z]+://', '', target.strip())
    target = target.split('/')[0]
    target = target.split(':')[0]
    return target.strip()


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def collect_module_users(results, source):
    """Collect users from module results and register them in report."""
    if not results or not results.get("users"):
        return results

    for u in results["users"]:
        report.add_user(u, source)

    return results


# SERVICE DETECTION LAYER (KEEP UPDATING)

SERVICE_MAP = {
    "ftp": ["ftp"],
    "smb": ["microsoft-ds", "netbios-ssn"],
    "ldap": ["ldap", "ldaps"],
    "rpc": ["msrpc", "rpcbind"],
    "nfs": ["nfs"],
    "grpc": ["grpc"],
    "mssql": ["ms-sql-s", "microsoft-sql-s", "mssql"],
    "dns": ["domain"]
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
        '--only',
        choices=[
            'all', 'dnsenum', 'portscan', 'dirbuster', 'vhostenum',
            'subdomains', 'techstack', 'smbenum',
            'ldapenum', 'rpcenum', 'ftpenum', 'nfsenum', 'grpcenum'
        ],
        default='all',
        help='Only run a single specified module'
    )
    parser.add_argument('-o', '--output-name',
        help='Name the output target directory for users.txt'
    )

    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--aggressive', action='store_true')
    parser.add_argument('--test-creds')
    parser.add_argument('-ai', '--ai-analysis', action='store_true')
    parser.add_argument('--dev', action='store_true', help='Use existing scan.xml instead of running portscan')

    args = parser.parse_args()
    target = sanitize_target(args.target)
    only = args.only
    output_name = args.output_name or target

    # Initialize centralized report system
    report.init_recon_state(target)


    main_banner()
    print_banner(target)

    scan_results = run_portscan(target, args.verbose, dev_mode=args.dev)

    ports = scan_results["ports"]
    hostname = scan_results.get("hostname") or target
    domain = None
    ftp_anonymous = scan_results.get("ftp_anonymous")
    git_repo = scan_results.get("git_repo")
    web_targets = scan_results.get("web_targets", [])

    scheme = "https" if web_targets and web_targets[0].startswith("https://") else "http"

    if args.test_creds:
        run_testcreds(target, ports, args.test_creds, args.verbose)

    # MODULE DISPATCH (NOW SERVICES)
    module_dispatch = {
        "portscan": lambda: None,

        "dnsenum": lambda: run_dnsenum(target, args.verbose)
        if has_service_or_port(ports, "dns", 53)
        else print("[*] DNS not detected."),

        "ftpenum": lambda: run_ftpenum(target, args.verbose)
        if has_service_or_port(ports, "ftp", 21)
        else print("[*] FTP not detected."),

        "vhostenum": lambda: run_vhost_enum(hostname, web_targets[0], ports, args.verbose)
        if web_targets else print("[*] No web service detected."),

        "subdomains": lambda: run_subdomain_enum(hostname, web_targets[0], ports, args.verbose, scheme=scheme)
        if web_targets else print("[*] No web service detected."),

        "techstack": lambda: run_tech_stack(web_targets[0], hostname, ports)
        if web_targets else print("[*] No web service detected."),

        "smbenum": lambda: collect_module_users(run_smbenum(target, args.verbose, args.test_creds), "smbenum")
        if has_service_or_port(ports, "smb", 445)
        else print("[*] SMB not detected."),

        "ldapenum": lambda: collect_module_users(run_ldapenum(target, args.verbose, args.test_creds), "ldapenum")
        if has_service_or_port(ports, "ldap", 389)
        else print("[*] LDAP not detected."),

        "rpcenum": lambda: collect_module_users(run_rpcenum(target, args.verbose), "rpc")
        if has_service_or_port(ports, "rpc", 135)
        else print("[*] RPC not detected."),

        "mssqlenum": lambda: collect_module_users(run_mssql_enum(target, ports, args.test_creds if args.test_creds else None, args.verbose), "mssql")
        if has_service_or_port(ports, "mssql", 1433)
        else print("[*] MSSQL not detected."),

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

            report.write_users_file(output_name)
            report.write_recon_file(output_name)
            return

        module_dispatch[only]()
        report.write_users_file(output_name)
        report.write_recon_file(output_name)
        return

    # FULL RUN (ALL MODULES) 
    section("Open Ports Found")
    for p in ports:
        print(f" - {p['port']}/{p['protocol']} ({p['service']})")

    if has_service_or_port(ports, "dns", 53):
        section("DNS Enumeration")
        run_dnsenum(target, args.verbose)
    else:
        print("[*] No DNS service detected.")

    if ftp_anonymous:
        section("Anonymous FTP Login Allowed")
        print(ftp_anonymous)

    if git_repo:
        section("Exposed Git Repository / Git Dump")
        print(git_repo)

        print()
        git_path = git_repo.splitlines()[0].strip()
        run_gitdump(git_path)

    if has_service_or_port(ports, "ftp", 21):
        section("FTP Enumeration")
        run_ftpenum(target, args.verbose)
    else:
        print("[*] No FTP service detected.")

    if has_service_or_port(ports, "smb", 445):
        section("SMB Enumeration")
        smb_results = collect_module_users(run_smbenum(target, args.verbose, args.test_creds), "smbenum")
    else:
        print("[*] No SMB service detected.")

    if has_service_or_port(ports, "ldap", 389):
        section("LDAP Enumeration")
        ldap_results = collect_module_users(run_ldapenum(target, args.verbose, args.test_creds), "ldapenum")
        if ldap_results and ldap_results.get("domain"):
            domain = ldap_results["domain"]
    else:
        print("[*] No LDAP service detected.")

    if has_service_or_port(ports, "rpc", 135):
        section("RPC Enumeration")
        rpc_results = collect_module_users(run_rpcenum(target, args.verbose), "rpc")
    else:
        print("[*] No RPC service detected.")

    if has_service_or_port(ports, "mssql", 1433):
        section("MSSQL Enumeration")
        mssql_results = collect_module_users(run_mssql_enum(target, ports, args.test_creds if args.test_creds else None, args.verbose), "mssql")
    else:
        print("[*] No MSSQL service detected.")

    sorted_users = report.get_users()
    if sorted_users:
        section("Discovered Users")
        for u in sorted_users:
            print(u)

    try:
        users_path = report.write_users_file(output_name)
        recon_path = report.write_recon_file(output_name)
        print(f"[*] Wrote {len(sorted_users)} users to {users_path}")
        print(f"[*] Wrote recon data to {recon_path}")
        if sorted_users:
            print()
            print("[*] Remember to try usernames as passwords:")
            print("crackmapexec smb [dc] -u output/<name>/users.txt -p output/<name>/users.txt --continue-on-success" + "\n")
    except Exception as e:
        print(f"[!] Failed to write output files: {e}")

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

    users_for_asrep = report.get_users()
    if users_for_asrep:
        section("AS-REP Roasting")
        run_asrep_roast(domain or hostname, target, users_for_asrep, verbose=args.verbose, aggressive=args.aggressive)

    tech_results = {}

    # Shouldnt be used at all until refined heavily. Currently just produces noise. (cve lookup that is)
    if web_targets:
        section("Technology Stack Detection")
        tech_results = run_tech_stack(web_targets[0], hostname, ports)
        #if tech_results.get("versions"):
            #section("CVE / Exploit Suggester")
            #run_cve_lookup(tech_results["versions"], recon_data)

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
    
    if args.test_creds and domain:
        username, password = args.test_creds.split(":", 1)

        run_bloodhound(
            target,
            username,
            password,
            domain,
            args.verbose
        )
    
    if args.test_creds and domain:
        username, password = args.test_creds.split(":", 1)

        run_certipy_enum(
            target,
            domain,
            target,
            username,
            password,
            args.verbose,
        )

    if args.ai_analysis:
        preload_model_async(verbose=args.verbose)

    # Write final recon output and user list
    try:
        report.write_users_file(output_name)
        report.write_recon_file(output_name)
        print(f"\n[*] Final recon data written to output/{output_name}/recon.json")
    except Exception as e:
        print(f"[!] Failed to write final output: {e}")

    report.print_summary()

    if args.ai_analysis:
        analyze_recon(True)

if __name__ == "__main__":
    main()
