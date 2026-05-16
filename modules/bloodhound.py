import subprocess
import os
import json
from collections import defaultdict

from utils.output import section, print


INTERESTING_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "AllExtendedRights",
    "Owns"
}


# BLOODHOUND COLLECTION MAIN FUNCTION
def run_bloodhound(target, username, password, domain, verbose=False, recon_data=None):

    section("BloodHound Enumeration")

    if not domain:
        print("[!] No domain supplied. Skipping BloodHound collection.")
        return

    output_dir = f"{domain.lower()}-bh"
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Output directory: {output_dir}")
    print("[*] Running bloodhound-python collection...")

    cmd = [
        "bloodhound-python",
        "-u", username,
        "-p", password,
        "-ns", target,
        "-d", domain,
        "-c", "All"
    ]

    try:
        result = subprocess.run(
            cmd,
            cwd=output_dir,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("[-] BloodHound collection failed.")
            print(result.stderr or result.stdout)
            return

        print("[+] BloodHound collection completed successfully!")

        # RUN ANALYSIS PIPELINE
        findings = run_bloodhound_analysis(output_dir, username)

        if findings:

            if recon_data is not None:
                recon_data.setdefault("interesting_findings", [])
                for f in findings:
                    if f not in recon_data["interesting_findings"]:
                        recon_data["interesting_findings"].append(f)

        else:
            print("[*] No direct privilege escalation edges found.")

    except FileNotFoundError:
        print("[!] bloodhound-python not installed or not in PATH.")

    except Exception as e:
        print(f"[!] BloodHound error: {e}")


# LOAD ALL JSONS
def load_bloodhound_data(output_dir):
    data = defaultdict(list)

    for f in os.listdir(output_dir):
        if not f.endswith(".json"):
            continue

        path = os.path.join(output_dir, f)

        try:
            obj = json.load(open(path))
        except Exception:
            continue

        if "users" in f:
            data["users"].extend(obj.get("data", []))
        elif "groups" in f:
            data["groups"].extend(obj.get("data", []))
        elif "computers" in f:
            data["computers"].extend(obj.get("data", []))
        elif "domains" in f:
            data["domains"].extend(obj.get("data", []))
        elif "ous" in f:
            data["ous"].extend(obj.get("data", []))
        elif "gpos" in f:
            data["gpos"].extend(obj.get("data", []))

    return data


# BUILD USER / GROUP SET
def build_user_group_map(data, username):
    user_sid = None

    for u in data["users"]:
        props = u.get("Properties", {})
        if props.get("samaccountname", "").lower() == username.lower():
            user_sid = u.get("ObjectIdentifier")
            break

    if not user_sid:
        return set()

    attack_sids = {user_sid}

    changed = True
    while changed:
        changed = False

        for g in data["groups"]:
            g_sid = g.get("ObjectIdentifier")
            members = g.get("Members", [])

            for m in members:
                if m.get("ObjectIdentifier") in attack_sids:
                    if g_sid and g_sid not in attack_sids:
                        attack_sids.add(g_sid)
                        changed = True

    return attack_sids


# ACL ANALYSIS ACROSS ALL OBJECTS
def extract_acl_findings(data, attack_sids):
    findings = []

    def scan(objects):
        for obj in objects:
            target = obj.get("Properties", {}).get("name", "UNKNOWN_OBJECT")

            for ace in obj.get("Aces", []):
                sid = ace.get("PrincipalSID")
                right = ace.get("RightName")

                if not sid or not right:
                    continue

                if sid in attack_sids and right in INTERESTING_RIGHTS:
                    findings.append(f"[ACL] {right} over {target}")

    scan(data["users"])
    scan(data["groups"])
    scan(data["computers"])
    scan(data["gpos"])
    scan(data["ous"])

    return list(dict.fromkeys(findings))


# ANALYSIS PIPELINE
def run_bloodhound_analysis(output_dir, username, recon_data=None):

    print("[*] Loading BloodHound dataset...")
    data = load_bloodhound_data(output_dir)

    print("[*] Building attack identity graph...")
    attack_sids = build_user_group_map(data, username)

    print(f"[+] Attack identity nodes: {len(attack_sids)}")

    print("[*] Scanning ACL attack paths...")
    findings = extract_acl_findings(data, attack_sids)

    if findings:
        print("\n=== ATTACK PATHS FOUND ===")
        for f in findings:
            print(f"[!] {f}")

        if recon_data is not None:
            recon_data.setdefault("interesting_findings", [])
            for f in findings:
                if f not in recon_data["interesting_findings"]:
                    recon_data["interesting_findings"].append(f)

    else:
        print("[*] No interesting ACL attack paths found.")

    return findings