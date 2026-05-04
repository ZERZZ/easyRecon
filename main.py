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
from modules.ai_analysis import analyze_recon, preload_model_async

from utils.output import section, banner as print_banner, print
from utils.banner import main_banner

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

# recon data management (remove creds from here / testcreds; should be "successful_logins")
def init_recon_data(target):
    return {
        "target": target,
        "ip": target if is_ip_address(target) else "",
        "open_ports": [],
        "services": [],
        "web_endpoints": [],
        "subdomains": [],
        "users": [],
        "interesting_findings": [],
        "credentials": [],
        "notes": []
    }


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def add_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return

    if not isinstance(values, list):
        values = [values]

    data_list = recon_data.setdefault(key, [])
    for value in values:
        if value and value not in data_list:
            data_list.append(value)


def write_summary(recon_data, target, verbose=False):
    filename = f"{target}.json"
    output_data = dict(recon_data)

    if "users" in output_data and isinstance(output_data["users"], list):
        user_list = output_data["users"]
        if len(user_list) > 3:
            output_data["users"] = user_list[:3] + [f"... and another {len(user_list) - 3} users"]

    with open(filename, "w") as f:
        json.dump(output_data, f, indent=4)

    print(f"[*] JSON summary written to {filename}")
    if verbose:
        print(json.dumps(output_data, indent=4))


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
    parser.add_argument('-ai', '--ai-analysis', action='store_true')

    args = parser.parse_args()
    target = sanitize_target(args.target)
    only = args.only

    recon_data = init_recon_data(target)

    main_banner()
    print_banner(target)

    scan_results = run_portscan(target, args.verbose, recon_data)

    ports = scan_results["ports"]
    hostname = scan_results.get("hostname") or target
    domain = None
    ftp_anonymous = scan_results.get("ftp_anonymous")
    git_repo = scan_results.get("git_repo")
    web_targets = scan_results.get("web_targets", [])

    scheme = "https" if web_targets and web_targets[0].startswith("https://") else "http"

    if args.test_creds:
        run_testcreds(target, ports, args.test_creds, args.verbose, recon_data)

    users = set()

    # MODULE DISPATCH (NOW SERVICES)
    module_dispatch = {
        "portscan": lambda: None,

        "ftpenum": lambda: run_ftpenum(target, args.verbose, recon_data)
        if has_service_or_port(ports, "ftp", 21)
        else print("[*] FTP not detected."),

        "vhostenum": lambda: run_vhost_enum(hostname, web_targets[0], ports, args.verbose, recon_data)
        if web_targets else print("[*] No web service detected."),

        "subdomains": lambda: run_subdomain_enum(hostname, web_targets[0], ports, args.verbose, scheme=scheme, recon_data=recon_data)
        if web_targets else print("[*] No web service detected."),

        "techstack": lambda: run_tech_stack(web_targets[0], hostname, ports, recon_data)
        if web_targets else print("[*] No web service detected."),

        "smbenum": lambda: run_smbenum(target, args.verbose, recon_data)
        if has_service_or_port(ports, "smb", 445)
        else print("[*] SMB not detected."),

        "ldapenum": lambda: run_ldapenum(target, args.verbose, recon_data)
        if has_service_or_port(ports, "ldap", 389)
        else print("[*] LDAP not detected."),

        "rpcenum": lambda: run_rpcenum(target, args.verbose, recon_data)
        if has_service_or_port(ports, "rpc", 135)
        else print("[*] RPC not detected."),

        "nfsenum": lambda: run_nfsenum(target, args.verbose, recon_data)
        if has_service_or_port(ports, "nfs", 2049)
        else print("[*] NFS not detected."),

        "grpcenum": lambda: run_grpcenum(target, args.verbose, recon_data)
        if has_service_or_port(ports, "grpc", 50051)
        else print("[*] gRPC not detected."),

        "dirbuster": lambda: [run_dirbuster(url, hostname, args.verbose, recon_data) for url in web_targets]
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

            write_summary(recon_data, target, args.verbose)
            return

        module_dispatch[only]()
        write_summary(recon_data, target, args.verbose)
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
        run_ftpenum(target, args.verbose, recon_data)
    else:
        print("[*] No FTP service detected.")

    if has_service_or_port(ports, "smb", 445):
        section("SMB Enumeration")
        smb_results = run_smbenum(target, args.verbose, recon_data)
        if smb_results and smb_results.get("users"):
            for u in smb_results["users"]:
                add_unique(recon_data, "users", u)
            users.update(smb_results["users"])
    else:
        print("[*] No SMB service detected.")

    if has_service_or_port(ports, "ldap", 389):
        section("LDAP Enumeration")
        ldap_results = run_ldapenum(target, args.verbose, recon_data)
        if ldap_results:
            if ldap_results.get("users"):
                for u in ldap_results["users"]:
                    add_unique(recon_data, "users", u)
                users.update(ldap_results["users"])
            if ldap_results.get("domain"):
                domain = ldap_results["domain"]
    else:
        print("[*] No LDAP service detected.")

    if has_service_or_port(ports, "rpc", 135):
        section("RPC Enumeration")
        rpc_results = run_rpcenum(target, args.verbose, recon_data)
        if rpc_results and rpc_results.get("users"):
            for u in rpc_results["users"]:
                add_unique(recon_data, "users", u)
            users.update(rpc_results["users"])
    else:
        print("[*] No RPC service detected.")

    if users:
        section("Discovered Users")
        sorted_users = sorted(users)
        for u in sorted_users:
            print(u)
        try:
            with open("users.txt", "w") as f:
                f.write("\n".join(sorted_users) + "\n")
            print(f"[*] Wrote {len(sorted_users)} users to users.txt")
        except Exception as e:
            print(f"[!] Failed to write users.txt: {e}")

    if has_service_or_port(ports, "nfs", 2049):
        section("NFS Enumeration")
        run_nfsenum(target, args.verbose, recon_data)
    else:
        print("[*] No NFS service detected.")

    if has_service_or_port(ports, "grpc", 50051):
        section("gRPC Enumeration")
        run_grpcenum(target, args.verbose, recon_data)
    else:
        print("[*] No gRPC service detected.")

    if users:
        section("AS-REP Roasting")
        run_asrep_roast(domain or hostname, target, list(users), verbose=args.verbose, aggressive=args.aggressive, recon_data=recon_data)

    tech_results = {}
    if web_targets:
        section("Technology Stack Detection")
        tech_results = run_tech_stack(web_targets[0], hostname, ports, recon_data)
        if tech_results.get("versions"):
            section("CVE / Exploit Suggester")
            run_cve_lookup(tech_results["versions"], recon_data)

    if hostname:
        section("Web Enumeration w/ Hostname")
        print(f"[+] Hostname: {hostname}")

        if web_targets:
            section("Subdomain Enumeration")
            run_subdomain_enum(hostname, web_targets[0], ports, args.verbose, scheme=scheme, recon_data=recon_data)

            section("VHost Enumeration")
            run_vhost_enum(hostname, web_targets[0], ports, args.verbose, recon_data)
        else:
            print("[*] No web service detected.")

    if web_targets:
        section("Directory Enumeration")
        for url in web_targets:
            run_dirbuster(url, hostname, args.verbose, recon_data)
    else:
        print("[*] No HTTP/HTTPS services detected.")

    if args.ai_analysis:
        preload_model_async(verbose=args.verbose)

    write_summary(recon_data, target, args.verbose)

    if args.ai_analysis:
        section("AI Analysis") # sections like this should be in each module, so should this print below.
        if args.verbose:
            print("[WARNING] AI analysis is experimental and may be inaccurate. Always verify manually.")
            print()
            print("[AI] Thinking...", flush=True)
        analyze_recon(recon_data, True)

if __name__ == "__main__":
    main()
