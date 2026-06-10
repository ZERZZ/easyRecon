from pathlib import Path
import yaml
import json
from utils.output import section, print

_users = {}
_recon_state = {
    "target": None,
    "open_ports": [],
    "services": [],
    "web_endpoints": [],
    "subdomains": [],
    "credentials": [],
    "findings": {
        "discoveries": [],
        "vulnerabilities": [],
        "misconfigurations": [],
        "credentials": [],
        "errors": [],
        "notes": []
    }
}

# findings deduplication (source, category, title) -> index
_findings_index = {}

# Baseline noise patterns to ignore
_BASELINE_NOISE = {
    "SMB service is reachable on target",
    "No open ports discovered",
    "DNS resolution failed",
    "SERVFAIL",
    "NXDOMAIN",
    "timed out",
    "access denied"
}


## ---- LOAD SETTINGS AND GET OUTPUT DIRECTORY
def _load_settings():
    try:
        with open("config/settings.yaml", "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _get_output_directory():
    settings = _load_settings()
    output_dir = settings.get("output", {}).get("directory", "./output")
    return output_dir


def _normalize_path_component(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None

    value = Path(value).name
    value = value.replace("/", "_").replace("\\", "_")
    invalid_chars = '<>:"|?*'
    for ch in invalid_chars:
        value = value.replace(ch, "_")
    return value or None


## recon state initialisation and management
def init_recon_state(target):
    """Initialize a fresh recon state for a new scan."""
    global _recon_state, _findings_index
    _recon_state = {
        "target": target,
        "open_ports": [],
        "services": [],
        "web_endpoints": [],
        "subdomains": [],
        "credentials": [],
        "findings": {
            "discoveries": [],
            "vulnerabilities": [],
            "misconfigurations": [],
            "credentials": [],
            "errors": [],
            "notes": []
        }
    }
    _findings_index = {}
    _users.clear()


def get_recon_state():
    """Return the current recon state (for inspection or export)."""
    return _recon_state

# use with new reporting option
def set_target(target):
    """Set the target name in recon state."""
    _recon_state["target"] = target


def add_service(port, protocol, service_name):
    """Add a discovered service to recon state."""
    if service_name not in _recon_state["services"]:
        _recon_state["services"].append(service_name)


def add_open_port(port):
    """Add an open port to recon state."""
    if port not in _recon_state["open_ports"]:
        _recon_state["open_ports"].append(port)


def add_web_endpoint(url):
    """Add a web endpoint to recon state."""
    if url not in _recon_state["web_endpoints"]:
        _recon_state["web_endpoints"].append(url)


def add_subdomain(subdomain):
    """Add a subdomain to recon state."""
    if subdomain not in _recon_state["subdomains"]:
        _recon_state["subdomains"].append(subdomain)


def add_credential(username, password=None, source=None):
    """Add a discovered credential to recon state."""
    cred = {"username": username}
    if password:
        cred["password"] = password
    if source:
        cred["source"] = source
    
    if cred not in _recon_state["credentials"]:
        _recon_state["credentials"].append(cred)


## findings management (probably need to adjust noise)
def _is_baseline_noise(title):
    """Check if a finding title matches baseline noise patterns."""
    for pattern in _BASELINE_NOISE:
        if pattern.lower() in title.lower():
            return True
    return False


def add_finding(source, category, title, details=None):
    """
    Add a structured finding with deduplication and noise filtering.
    
    Args:
        source: Module that produced the finding (smbenum, ldapenum, etc.)
        category: discoveries|vulnerabilities|misconfigurations|credentials|errors|notes
        title: Short identifier for the finding
        details: Optional longer description
    
    Returns:
        True if finding was added, False if deduplicated or filtered
    """
    if not source or not category or not title:
        return False
    
    # filter baseline noise
    if _is_baseline_noise(title):
        return False
    
    # normalise inputs
    source = source.strip()
    category = category.strip().lower()
    title = title.strip()
    
    # validate category
    if category not in _recon_state["findings"]:
        return False
    
    # Dedup
    dedup_key = (source, category, title)
    if dedup_key in _findings_index:
        return False  # Already added
    
    finding = {
        "source": source,
        "title": title
    }
    if details:
        finding["details"] = str(details).strip()
    
    # add to findings list and index
    finding_index = len(_recon_state["findings"][category])
    _recon_state["findings"][category].append(finding)
    _findings_index[dedup_key] = finding_index
    
    return True


def get_findings(category=None):
    """Get findings by category, or all findings if category is None."""
    if category is None:
        return _recon_state["findings"]
    if category in _recon_state["findings"]:
        return _recon_state["findings"][category]
    return []


## USER MANAGEMENT 
def _normalize_user(username):
    if username is None:
        return None
    if not isinstance(username, str):
        username = str(username)
    username = username.strip()
    return username or None


def add_user(username, source):
    """Add a username and record the source module that produced it."""
    username = _normalize_user(username)
    if not username:
        return False

    source = source or "unknown"
    source = str(source).strip() or "unknown"

    sources = _users.setdefault(username, set())
    sources.add(source)
    return True


def get_users():
    """Return the current unique usernames sorted for output."""
    return sorted(_users.keys())


def get_user_sources(username=None):
    """Return source tracking for one user or all users."""
    if username is not None:
        username = _normalize_user(username)
        if username is None:
            return []
        return sorted(_users.get(username, []))
    return {user: sorted(sources) for user, sources in _users.items()}


## FILE OUTPUT
def write_recon_file(target_name=None):
    """
    Write the complete recon state to output/<target_name>/recon.json.
    """
    if target_name is None:
        target_name = _recon_state.get("target", "default")
    
    if target_name is None:
        target_name = "default"
    
    root = Path(__file__).resolve().parents[1]
    output_dir = _get_output_directory()
    output_base = Path(output_dir)
    
    if not output_base.is_absolute():
        output_base = root / output_base
    
    target_name = _normalize_path_component(target_name) or "default"
    recon_path = output_base / target_name / "recon.json"
    
    # build final recon data
    recon_output = dict(_recon_state)
    recon_output["users"] = get_users()
    
    recon_path.parent.mkdir(parents=True, exist_ok=True)
    with recon_path.open("w", encoding="utf-8") as f:
        json.dump(recon_output, f, indent=2)
    
    return str(recon_path)


def write_users_file(target_name=None, path=None):
    """Write the unique usernames to <output_dir>/<target_name>/users.txt."""
    if path is None:
        root = Path(__file__).resolve().parents[1]
        output_dir = _get_output_directory()
        output_base = Path(output_dir)
        
        if not output_base.is_absolute():
            output_base = root / output_base
        
        target_name = _normalize_path_component(target_name) or "default"
        path = output_base / target_name / "users.txt"
    else:
        path = Path(path)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(get_users()))
        f.write("\n")
    return str(path)

# for future when we might want to clear state between scans without restarting the program
def clear():
    """Clear all recon state, users, and findings."""
    global _recon_state, _findings_index
    _recon_state = {
        "target": None,
        "open_ports": [],
        "services": [],
        "web_endpoints": [],
        "subdomains": [],
        "credentials": [],
        "findings": {
            "discoveries": [],
            "vulnerabilities": [],
            "misconfigurations": [],
            "credentials": [],
            "errors": [],
            "notes": []
        }
    }
    _findings_index = {}
    _users.clear()


def print_summary():
    state = get_recon_state()
    findings_data = get_findings()

    section("Summary")

    # FINDINGS
    for category, items in findings_data.items():
        if not items:
            continue

        print(f"[+] [{category.upper()}]")

        for f in items:
            if isinstance(f, dict):
                title = f.get("title", str(f))
                details = f.get("details", "")
                source = f.get("source", "")
            else:
                title = str(f)
                details = ""
                source = ""

            line = f"  - {title}"
            if source:
                line += f" ({source})"

            print(line)

            if details:
                print(f"    {details}")

        print()

    # WEB ENDPOINTS
    endpoints = state.get("web_endpoints", [])
    if endpoints:
        print("[+] WEB ENDPOINTS")
        for e in endpoints:
            print(f"    {e}")
        print()

    # SUBDOMAINS
    subdomains = state.get("subdomains", [])
    if subdomains:
        print("[+] SUBDOMAINS")
        for s in subdomains:
            print(f"    {s}")
        print()