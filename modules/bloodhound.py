import subprocess
import os
import json
from collections import defaultdict, deque

from utils.output import section, print
from utils.findings import add_discovery
from utils.report import _get_output_directory, _normalize_path_component, get_recon_state


INTERESTING_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "AllExtendedRights",
    "Owns",
    "WriteSPN",
    "ReadGMSAPassword"
}


# BLOODHOUND COLLECTION MAIN FUNCTION
def run_bloodhound(target, username, password, domain, verbose=False):

    section("BloodHound Enumeration")

    if not domain:
        print("[!] No domain supplied. Skipping BloodHound collection.")
        return

    # now output bloodhound output to output/<target>/bloodhound/ 
    base_dir = _get_output_directory()

    recon_state = get_recon_state()
    target_name = recon_state.get("target") or target

    safe_target = _normalize_path_component(target_name)

    output_dir = os.path.join(base_dir, safe_target, "bloodhound")

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

        if not findings:
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

    edges = defaultdict(list)
    sid_to_name = {}

    def register_objects(objects):
        for obj in objects:
            sid = obj.get("ObjectIdentifier")
            name = obj.get("Properties", {}).get("name", "UNKNOWN_OBJECT")
            if sid:
                sid_to_name[sid] = name

    register_objects(data["users"])
    register_objects(data["groups"])
    register_objects(data["computers"])
    register_objects(data["gpos"])
    register_objects(data["ous"])

    def build_edges(objects):
        for obj in objects:
            target_sid = obj.get("ObjectIdentifier")
            target_name = obj.get("Properties", {}).get("name", "UNKNOWN_OBJECT")

            for ace in obj.get("Aces", []):
                sid = ace.get("PrincipalSID")
                right = ace.get("RightName")

                if not sid or not right or not target_sid:
                    continue

                if right in INTERESTING_RIGHTS:
                    edges[sid].append((target_sid, right, target_name))

    build_edges(data["users"])
    build_edges(data["groups"])
    build_edges(data["computers"])
    build_edges(data["gpos"])
    build_edges(data["ous"])

    queue = deque()
    visited = set(attack_sids)
    parent = {}

    for sid in attack_sids:
        queue.append(sid)

    while queue:
        current_sid = queue.popleft()

        for target_sid, right, target_name in edges.get(current_sid, []):

            if target_sid not in visited:
                visited.add(target_sid)
                queue.append(target_sid)

                parent[target_sid] = (current_sid, right, target_name)

    if not parent:
        return []

    def depth(node):
        d = 0
        while node in parent:
            node = parent[node][0]
            d += 1
        return d

    end_node = max(parent.keys(), key=depth)

    chain_nodes = []
    trace = end_node

    while trace in parent:
        p_sid, r, t_name = parent[trace]
        chain_nodes.append((p_sid, r, t_name))
        trace = p_sid

    chain_nodes = list(reversed(chain_nodes))

    if not chain_nodes:
        return []

    output = []

    root_sid = chain_nodes[0][0]
    output.append(sid_to_name.get(root_sid, root_sid))

    spine = "   |"

    for i, (p_sid, r, t_name) in enumerate(chain_nodes):

        if i == 0:
            output.append(f"{spine}")
            output.append(f"{spine}--[{r}]--> {t_name}")
        else:
            indent = spine + ("   " * i)

            output.append(f"{indent}")
            output.append(f"{indent}--[{r}]--> {t_name}")

    attack_chain_str = "\n".join(output)

    add_discovery(
        "BloodHound Attack Chain Found",
        attack_chain_str,
        source="bloodhound"
    )

    return [attack_chain_str]


# ANALYSIS PIPELINE
def run_bloodhound_analysis(output_dir, username):

    print("[*] Loading BloodHound dataset...")
    data = load_bloodhound_data(output_dir)

    print("[*] Building attack identity graph...")
    attack_sids = build_user_group_map(data, username)

    print(f"[+] Attack identity nodes: {len(attack_sids)}")

    print("[*] Scanning ACL attack paths...")
    findings = extract_acl_findings(data, attack_sids)

    if findings:
        print("\n[+] Attack chain found ...")

        for f in findings:
            print(f)

    else:
        print("[*] No interesting ACL attack paths found.")

    return findings