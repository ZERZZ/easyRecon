import subprocess
import re

from utils.output import print

## this module is a mess


def _append_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return
    if not isinstance(values, list):
        values = [values]
    data_list = recon_data.setdefault(key, [])
    for value in values:
        if value and value not in data_list:
            data_list.append(value)


def _execute_mssql_query(target, username, password, query, timeout=10):
    """Execute a query against MSSQL with credentials."""
    try:
        cmd = [
            "impacket-mssqlclient",
            f"{username}:{password}@{target}",
            "-command",
            query,
            "exit"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        stdout = _clean_tool_output(result.stdout)
        stderr = _clean_tool_output(result.stderr)
        return stdout, stderr, result.returncode

    except subprocess.TimeoutExpired:
        return None, "Query timeout", -1
    except Exception as e:
        return None, str(e), -1


def _parse_mssql_version(output):
    """Extract MSSQL version from connection output."""
    if not output:
        return None
    
    patterns = [
        r"SQL Server [\d.]+",
        r"Microsoft SQL Server (\d+\.\d+)",
        r"Version ([\d.]+)"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(0)
    
    return None


def _clean_tool_output(output):
    """Strip known noisy tool output before parsing."""
    if not output:
        return ""

    cleaned = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if re.match(r"^(Impacket\b|Encryption required|ENVCHANGE|ACK:|SQL>|\[.*DEBUG.*\]|DEBUG:|WARNING:|INFO:|Error:)", line, re.IGNORECASE):
            continue

        if line.startswith("SQL>"):
            line = line[4:].strip()
            if not line:
                continue

        cleaned.append(line)

    return "\n".join(cleaned)


def run_mssql_rid_brute(target, username, password, verbose=False, recon_data=None):
    """Run MSSQL RID brute via nxc after valid MSSQL credentials are confirmed."""
    print("[*] Attempting MSSQL RID brute via nxc...")

    results = {
        "phase1_users": [],
        "phase1_error": None
    }

    try:
        cmd = [
            "nxc",
            "mssql",
            target,
            "-u",
            username,
            "-p",
            password,
            "--local-auth",
            "--rid-brute"
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        output = _clean_tool_output(proc.stdout + "\n" + proc.stderr)
        if verbose and output:
            print(output)

        users = []
        for line in output.splitlines():
            if not re.search(r"(?i)(user|username|account|found)", line):
                continue

            match = re.search(r"(?i)(?:found\s+(?:user|account)|user(?:name)?|account)[:=]?\s*([A-Za-z0-9_.-]+)", line)
            if match:
                candidate = match.group(1)
            else:
                tokens = re.findall(r"[A-Za-z0-9_.-]+", line)
                candidate = tokens[-1] if tokens else None

            if not candidate:
                continue

            user = candidate.strip()
            if not user or user.endswith("$"):
                continue

            if user not in users:
                users.append(user)

        if users:
            results["phase1_users"] = users
            print(f"[+] Discovered {len(users)} users via RID brute:")
            for u in users:
                print(f"    {u}")
            if recon_data is not None:
                for u in users:
                    _append_unique(recon_data, "users", u)
        else:
            print("[-] No MSSQL users discovered via RID brute.")
            if proc.returncode != 0:
                results["phase1_error"] = "RID brute failed or returned no users"

    except FileNotFoundError:
        results["phase1_error"] = "nxc not found"
        print("[-] nxc not found; skipping MSSQL RID brute.")
    except subprocess.TimeoutExpired:
        results["phase1_error"] = "nxc timeout"
        print("[-] MSSQL RID brute timed out.")
    except Exception as e:
        results["phase1_error"] = str(e)
        print(f"[!] MSSQL RID brute error: {e}")

    return results


def run_mssql_authenticated(target, username, password, recon_data=None, verbose=False):
    """Phase 2: Authenticated MSSQL enumeration."""
    print("[*] Performing authenticated MSSQL enumeration...")

    results = {
        "phase2_connection": False,
        "phase2_data": {},
        "phase2_error": None
    }

    try:
        stdout, stderr, returncode = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT 1"
        )
        if returncode != 0:
            results["phase2_error"] = "Authentication failed"
            print("[-] MSSQL authentication failed during enumeration.")
            return results
        results["phase2_connection"] = True
    except Exception as e:
        results["phase2_error"] = str(e)
        return results

    enum_data = {}

    def _limit(values, limit=5):
        return values[:limit] if isinstance(values, list) else values

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT @@version AS [SQL Server Version]"
        )
        if stdout:
            version_match = re.search(r"SQL Server [\d.]+", stdout)
            if version_match:
                enum_data["version"] = version_match.group(0)
                print(f"[+] Version: {enum_data['version']}")
    except Exception:
        pass

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT SYSTEM_USER"
        )
        if stdout:
            current_user = stdout.splitlines()[0].strip()
            if current_user:
                enum_data["current_user"] = current_user
                print(f"[+] Current User: {enum_data['current_user']}")
    except Exception:
        pass

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT 'sysadmin' AS role WHERE IS_SRVROLEMEMBER('sysadmin')=1 "
            "UNION SELECT 'serveradmin' WHERE IS_SRVROLEMEMBER('serveradmin')=1 "
            "UNION SELECT 'securityadmin' WHERE IS_SRVROLEMEMBER('securityadmin')=1 "
            "UNION SELECT 'processadmin' WHERE IS_SRVROLEMEMBER('processadmin')=1 "
            "UNION SELECT 'setupadmin' WHERE IS_SRVROLEMEMBER('setupadmin')=1 "
            "UNION SELECT 'diskadmin' WHERE IS_SRVROLEMEMBER('diskadmin')=1 "
            "UNION SELECT 'dbcreator' WHERE IS_SRVROLEMEMBER('dbcreator')=1"
        )
        if stdout:
            roles = [line.strip() for line in stdout.splitlines() if line.strip() and not line.lower().startswith('role')]
            roles = list(dict.fromkeys(roles))
            if roles:
                enum_data["server_roles"] = _limit(roles, 5)
                print(f"[+] Server Roles: {', '.join(enum_data['server_roles'])}")
    except Exception:
        pass

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT TOP 10 name FROM sys.databases WHERE database_id > 4 ORDER BY name"
        )
        if stdout:
            dbs = [line.strip() for line in stdout.splitlines() if line.strip() and not line.lower().startswith('name')]
            if dbs:
                enum_data["databases"] = _limit(dbs, 5)
                print(f"[+] Databases: {', '.join(enum_data['databases'])}" + (" (truncated)" if len(dbs) > 5 else ""))
    except Exception:
        pass

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT name FROM sys.servers WHERE is_linked = 1"
        )
        if stdout:
            linked = [line.strip() for line in stdout.splitlines() if line.strip() and not line.lower().startswith('name')]
            if linked:
                enum_data["linked_servers"] = _limit(linked, 5)
                print(f"[+] Linked Servers: {', '.join(enum_data['linked_servers'])}")
    except Exception:
        pass

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
        )
        if stdout:
            enabled = "1" in stdout
            enum_data["xp_cmdshell"] = "enabled" if enabled else "disabled"
            print(f"[+] xp_cmdshell: {enum_data['xp_cmdshell']}" + (" ⚠️" if enabled else ""))
    except Exception:
        pass

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\\CurrentControlSet\\Services\\MSSQLServer', 'ObjectName'"
        )
        if stdout:
            account_match = re.search(r"([\w\\.-]+)", stdout.strip())
            if account_match:
                enum_data["service_account"] = account_match.group(1)
                print(f"[+] Service Account: {enum_data['service_account']}")
    except Exception:
        pass

    try:
        stdout, stderr, code = _execute_mssql_query(
            target,
            username,
            password,
            "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND database_id > 4"
        )
        if stdout:
            trustworthy = [line.strip() for line in stdout.splitlines() if line.strip() and not line.lower().startswith('name')]
            if trustworthy:
                enum_data["trustworthy_databases"] = _limit(trustworthy, 5)
                print(f"[+] Trustworthy databases: {', '.join(enum_data['trustworthy_databases'])}")
    except Exception:
        pass

    results["phase2_data"] = enum_data
    if enum_data:
        print("[+] Authenticated enumeration completed.")
        if recon_data is not None:
            recon_data["mssql_enumeration"] = enum_data
    else:
        print("[-] No data retrieved during authenticated enumeration.")

    return results


def run_mssql_enum(target, ports, cred_string=None, verbose=False, recon_data=None):
    """Main MSSQL enumeration function."""
    
    port_list = [str(p.get("port")) for p in ports]
    
    # Check if MSSQL port is open
    if "1433" not in port_list:
        print("[*] MSSQL port 1433 not detected. Skipping MSSQL enumeration.")
        return None
    
    print(f"[*] Running MSSQL enumeration against {target}...")

    results = {
        "rid_brute": None,
        "authenticated": None,
        "users": []
    }

    if cred_string and ":" in cred_string and recon_data:
        username, password = cred_string.split(":", 1)
        authenticated_services = recon_data.get("authenticated_services", [])

        if "mssql" in authenticated_services:
            brute_results = run_mssql_rid_brute(target, username, password, verbose=verbose, recon_data=recon_data)
            results["rid_brute"] = brute_results
            if brute_results.get("phase1_users"):
                results["users"] = brute_results["phase1_users"]

            print("\n[*] Valid MSSQL credentials detected. Proceeding with authenticated enumeration...")
            auth_results = run_mssql_authenticated(target, username, password, recon_data=recon_data, verbose=verbose)
            results["authenticated"] = auth_results
        else:
            print("[-] MSSQL credentials were not confirmed by test-creds; skipping authenticated MSSQL enumeration.")
    else:
        print("[-] No MSSQL credentials provided or recon_data unavailable; skipping authenticated MSSQL enumeration.")

    return results
