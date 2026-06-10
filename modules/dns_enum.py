import subprocess
import re

from utils.output import print
from utils.report import add_subdomain 
from utils.findings import add_note,add_misconfiguration


ERROR_KEYWORDS = [
    "failed",
    "refused",
    "denied",
    "timed out",
    "SERVFAIL",
    "NXDOMAIN",
    "error",
    "Error"
]


def _run_dig(cmd, timeout=10):
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except FileNotFoundError:
        return "", "dig not found", 1


def parse_ptr(output):
    domains = []

    for line in output.splitlines():
        if "PTR" in line:
            match = re.search(r"PTR\s+(\S+)", line)
            if match:
                domains.append(match.group(1).rstrip("."))

    return domains


def parse_axfr(output):
    records = {
        "domains": [],
        "subdomains": [],
        "ns": [],
        "a": [],
        "aaaa": []
    }

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 5:
            continue

        name = parts[0].rstrip(".")
        record_type = parts[3]
        value = parts[4].rstrip(".")

        if record_type == "NS":
            records["ns"].append(value)

        elif record_type == "A":
            records["a"].append(value)

        elif record_type == "AAAA":
            records["aaaa"].append(value)

        elif record_type == "CNAME":
            records["subdomains"].append(name)

        if "." in name and name not in records["domains"]:
            records["domains"].append(name)

    return records


def run_dnsenum(target, verbose=False):
    print(f"[*] Running DNS enumeration against {target} (port 53)...")

    results = {
        "ptr_domains": [],
        "axfr_domains": [],
        "subdomains": [],
        "ns_records": [],
        "a_records": [],
        "aaaa_records": [],
        "zone_transfer": False,
        "error": None
    }

    print("[*] Running PTR reverse lookup...")

    ptr_cmd = ["dig", "@" + target, "-x", target, "+short"]
    stdout, stderr, code = _run_dig(ptr_cmd)

    if verbose:
        print(stdout)

    if stdout and not any(err in stderr.lower() for err in ERROR_KEYWORDS):
        ptrs = parse_ptr(stdout)

        if not ptrs and "PTR" not in stdout:
            ptrs = [stdout.strip().rstrip(".")]

        results["ptr_domains"] = ptrs

        # domain zone discovery (only if we get dommain)
        if ptrs:
            target_domain = ptrs[0].rstrip(".")
            add_note(f"DNS zone discovered: {target_domain}", source="dns_enum")

            print(f"[+] PTR results: {len(ptrs)} domain(s)")
            print(f"[+] DNS zone discovered: {target_domain}")

            print(f"[*] Attempting zone transfer against {target_domain}...")

            # axfr to get more subdomains, 15s timeout
            axfr_cmd = ["dig", "@" + target, "axfr", target_domain]
            stdout, stderr, code = _run_dig(axfr_cmd, timeout=15)

            if verbose:
                print(stdout)

            if stdout and "SOA" in stdout and not any(err in stdout.lower() for err in ERROR_KEYWORDS):
                results["zone_transfer"] = True

                parsed = parse_axfr(stdout)

                results["axfr_domains"] = parsed["domains"]
                results["subdomains"] = parsed["subdomains"]
                results["ns_records"] = parsed["ns"]
                results["a_records"] = parsed["a"]
                results["aaaa_records"] = parsed["aaaa"]

                # add to new reporting system
                for sub in parsed["subdomains"]:
                    add_subdomain(sub)

                for d in parsed["domains"]:
                    add_subdomain(d)

                add_misconfiguration(
                    "DNS zone transfer (AXFR) allowed",
                    "Full zone data exposed via TCP/53",
                    source="dns_enum"
                )

                print("[+] Zone transfer SUCCESSFUL - massive enumeration possible!")
                print(f"[+] Subdomains found: {len(parsed['subdomains'])}")

                if parsed["subdomains"]:
                    print("[+] DNS discovered subdomains:")
                    for sub in parsed["subdomains"]:
                        print(f"    {sub}")
                    print()

            else:
                print("[-] Zone transfer not allowed (normal case).")

    else:
        print("[-] PTR lookup returned no useful data.")

    print("[*] Running lightweight DNS record checks...")

    for record in ["ns", "mx"]:
        cmd = ["dig", "@" + target, record, "+short"]
        stdout, stderr, code = _run_dig(cmd)

        if stdout:
            if verbose:
                print(f"[+] {record.upper()} records:")
                print(stdout)

    if results["zone_transfer"]:
        print("[!] CRITICAL: DNS AXFR allowed - domain fully exposed for enumeration.")

    return results