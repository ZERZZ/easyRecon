import subprocess
import json
import glob
import os

from utils.output import section, print
from utils.findings import add_vulnerability
from utils.report import _get_output_directory, _normalize_path_component, get_recon_state


# find certs with creds
def _run_certipy_find(target, username, password, domain, dc_ip, verbose=False, output_dir=None):
    """
    Runs certipy-ad find and returns parsed JSON output (FROM FILE).
    """

    cmd = [
        "certipy-ad",
        "find",
        "-u", f"{username}@{domain}",
        "-p", password,
        "-dc-ip", dc_ip,
        "-vulnerable",
        "-json"
    ]

    if verbose:
        print("[DEBUG] Running Certipy command:")
        print(" ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            cwd=output_dir, # goes to output/target/certipy
            capture_output=True,
            text=True,
            timeout=120
        )

        if verbose:
            print("[DEBUG] certipy stdout:")
            print(result.stdout)

        if result.returncode != 0:
            print("[-] Certipy execution failed")
            if verbose:
                print(result.stderr)
            return None

        json_data = _load_latest_certipy_json(output_dir)

        if not json_data:
            print("[-] No certipy JSON file found or could not be read")
            return None

        return json_data

    except Exception as e:
        print(f"[!] Certipy error: {e}")
        return None


def _load_latest_certipy_json(output_dir):
    """
    Loads the most recent Certipy JSON output file.
    """

    files = glob.glob(os.path.join(output_dir, "*Certipy*.json"))

    if not files:
        return None

    latest_file = max(files, key=os.path.getmtime)

    try:
        with open(latest_file, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _parse_certipy_find(data):
    """
    Extract ESC findings in structured format.
    """

    findings = []

    if not data:
        return findings

    templates = data.get("Certificate Templates", {})

    if not isinstance(templates, dict):
        return findings

    for _, template in templates.items():

        template_name = template.get("Template Name")
        vulns = template.get("[!] Vulnerabilities", {})

        if not template_name:
            continue

        if vulns:
            for vuln_type, description in vulns.items():

                findings.append({
                    "template": template_name,
                    "type": vuln_type,
                    "description": description
                })

    return findings


def run_certipy_enum(target, domain, dc_ip, username, password, verbose=False):
    """
    ADCS enumeration using Certipy. Main Function.
    """

    section("ADCS Enumeration (Certipy)")

    print(f"[*] Running Certipy against {domain} ({dc_ip})")

    base_dir = _get_output_directory()

    recon_state = get_recon_state()
    target_name = recon_state.get("target") or target

    safe_target = _normalize_path_component(target_name)
    output_dir = os.path.join(base_dir, safe_target, "certipy")

    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Certipy output directory: {output_dir}")

    data = _run_certipy_find(
        target,
        username,
        password,
        domain,
        dc_ip,
        verbose,
        output_dir
    )

    if not data:
        print("[-] No certipy data returned")
        return None

    json_data = _load_latest_certipy_json(output_dir)

    findings = _parse_certipy_find(json_data)

    if not findings:
        print("[*] No vulnerable certificate templates found")
        return data

    print()

    for f in findings:
        msg = f"{f['type']} on template {f['template']}: {f['description']}"

        print(f"[!] {msg}")
        print()

        add_vulnerability(
            f"ADCS {f['type']} on {f['template']}",
            f["description"],
            source="certipy"
        )

    return data