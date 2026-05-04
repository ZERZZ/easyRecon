import requests
import subprocess
import re

from utils.output import print

# NEEDS MAJOR REFACTORING, AS OF RIGHT NOW THE RESPONSES ARE MOSTLY NOISE.

# nvd api endpoint for cves (add more sources in future)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# rigid
CPE_MAPPING = {
    "Apache": "cpe:2.3:a:apache:http_server",
    "Apache HTTP Server": "cpe:2.3:a:apache:http_server",
    "Nginx": "cpe:2.3:a:nginx:nginx",
    "PHP": "cpe:2.3:a:php:php",
    "WordPress": "cpe:2.3:a:wordpress:wordpress",
    "Drupal": "cpe:2.3:a:drupal:drupal",
    "Joomla": "cpe:2.3:a:joomla:joomla",
    "Laravel": "cpe:2.3:a:laravel:laravel",
    "Django": "cpe:2.3:a:djangoproject:django",
    "ASP.NET": "cpe:2.3:a:microsoft:asp.net",
    "Express": "cpe:2.3:a:expressjs:express",
}

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": -1,
}

# we should move this to config but for now this is fine
MAX_CVES = 2
MAX_EXPLOITS = 2
MAX_FINDINGS = MAX_CVES + MAX_EXPLOITS


def _severity_for_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_cve(vuln):
    cve = vuln.get("cve", {})
    cve_id = cve.get("id") or "UNKNOWN"
    descriptions = cve.get("descriptions", [])
    description = ""

    for entry in descriptions:
        if entry.get("lang") == "en":
            description = entry.get("value", "")
            break

    if not description and descriptions:
        description = descriptions[0].get("value", "")

    metrics = cve.get("metrics", {})
    score = None
    severity = "UNKNOWN"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)

        if metric_list and isinstance(metric_list, list) and metric_list:
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", metric)
            score = cvss_data.get("baseScore") or cvss_data.get("score")
            severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
            break

    if score is not None:
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None

    if severity in (None, "", "UNKNOWN"):
        severity = _severity_for_score(score)

    if score is None:
        score_string = "N/A"
    else:
        score_string = f"{score:.1f}"

    description = description.strip() or "No description available."
    description = description[:120] + "..." if len(description) > 120 else description

    return {
        "id": cve_id,
        "score": score,
        "score_string": score_string,
        "severity": severity.upper(),
        "description": description,
    }

# sort by severity first, then score, then ID for consistency 
def _sort_cves(cves):
    return sorted(
        cves,
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severity"], -1),
            -(item["score"] or 0),
            item["id"],
        )
    )


def _query_nvd(cpe_name, tech_name, version):
    full_cpe = f"{cpe_name}:{version}:*:*:*:*:*:*:*"

    params = {
        "cpeName": full_cpe,
        "resultsPerPage": 100,
    }

    try:
        resp = requests.get(
            NVD_API_URL,
            params=params,
            timeout=15,
            headers={"User-Agent": "easyrecon-cve-lookup/1.0"}
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[!] Failed NVD request for {tech_name} {version}: {exc}")
        return []

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return []

    cves = [_extract_cve(vuln) for vuln in vulnerabilities]
    return _sort_cves(cves)[:MAX_CVES]

# remember to add searchsploit to requirements
def _query_exploitdb(tech_name, version):
    try:
        cmd = ["searchsploit", f"{tech_name} {version}"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=20).decode()
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

    # strip colour codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    output = ansi_escape.sub('', output)

    exploits = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("Exploit Title"):
            continue

        # title | path
        if "|" not in line:
            continue

        parts = line.split("|")
        if len(parts) < 2:
            continue

        title = parts[0].strip()
        path = parts[1].strip()

        # extract EDB ID from path (php/webapps/1654.txt -> "1654")
        edb_id = None
        match = re.search(r'/(\d+)\.txt$', path)
        if match:
            edb_id = match.group(1)

        if not edb_id:
            continue

        title = title[:120] + "..." if len(title) > 120 else title
        exploits.append({
            "edb_id": edb_id,
            "title": title,
            "url": f"https://www.exploit-db.com/exploits/{edb_id}",
        })

    return exploits[:MAX_EXPLOITS]


def _append_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return
    if not isinstance(values, list):
        values = [values]
    data_list = recon_data.setdefault(key, [])
    for value in values:
        if value and value not in data_list:
            data_list.append(value)


def run_cve_lookup(versions, recon_data=None):
    if not versions:
        print("[*] No versioned technologies available for CVE lookup.")
        return {}

    results = {}
    for tech_name, version in versions.items():
        cpe_name = CPE_MAPPING.get(tech_name)

        cves = _query_nvd(cpe_name, tech_name, version) if cpe_name else []
        exploits = _query_exploitdb(tech_name, version)

        if cves or exploits:
            results[tech_name] = {
                "version": version,
                "cpe": cpe_name or "N/A",
                "cves": cves,
                "exploits": exploits,
            }

    if not results:
        print("[*] No CVEs or exploits found for detected technologies.")
        return results

    # output formatting (noisy but can be refined)
    for tech_name, data in results.items():
        findings = []
        if data["cves"]:
            for cve in data["cves"]:
                findings.append({
                    "type": "cve",
                    "id": cve["id"],
                    "score_string": cve["score_string"],
                    "severity": cve["severity"],
                    "description": cve["description"],
                })

        if data["exploits"]:
            for exploit in data["exploits"]:
                findings.append({
                    "type": "exploit",
                    "id": exploit["edb_id"],
                    "title": exploit["title"],
                    "url": exploit["url"],
                })

        findings = findings[:MAX_FINDINGS]

        if findings:
            print(f"[+] Top {MAX_FINDINGS} findings for {tech_name} ({data['version']}):")
            for item in findings:

                if item["type"] == "cve":
                    print(
                        f"    - {item['id']} | {item['score_string']} {item['severity']} | {item['description']}"
                    )
                else:
                    print(f"    - EDB-{item['id']} | {item['title']}")
                    print(f"      {item['url']}")

            print()
            
            if recon_data is not None:
                summary_lines = []

                for item in findings:
                    if item["type"] == "cve":
                        summary_lines.append(f"{item['id']} ({item['severity']})")
                    else:
                        summary_lines.append(f"EDB-{item['id']}")

                _append_unique(
                    recon_data,
                    "interesting_findings",
                    f"{tech_name} {data['version']} vulnerabilities: {', '.join(summary_lines)}"
                )

    return results