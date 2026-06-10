import subprocess
import re

from utils.output import print
from utils.report import add_user
from utils.findings import add_discovery, add_vulnerability, add_misconfiguration


# better parsing to remove noise from impacket-mssqlclient
def _clean_mssql_output(output):
    if not output:
        return []

    cleaned = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        if (
            line.startswith("[*]") or
            line.startswith("INFO(") or
            line.startswith("ACK:") or
            line.startswith("ENVCHANGE") or
            line.startswith("Encryption required") or
            line.startswith("Changed database context") or
            line.startswith("Changed language") or
            line.startswith("SQL>") or
            line.startswith("DEBUG") or
            line.startswith("WARNING")
        ):
            continue

        cleaned.append(line)

    return cleaned


def _execute_mssql_query(target, username, password, query, timeout=10, verbose=False):
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


def _extract_sql_values(lines):
    clean = []
    for l in lines:
        l = l.strip()
        if not l:
            continue

        if re.match(r"^-+$", l):
            continue

        if l.lower() in ("name", "role", "sql server version"):
            continue

        clean.append(l)

    return clean



# RID BRUTE (WORKING EXCEPT PARSING)
def run_mssql_rid_brute(target, username, password, verbose=False):
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

        output = proc.stdout + "\n" + proc.stderr

        if verbose:
            print("\n[DEBUG RID RAW OUTPUT]\n" + proc.stdout)

        users = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.search(r"\d+:\s*([A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+)", line)
            if not match:
                continue

            full = match.group(1).strip()
            user = full.split("\\")[-1]

            if user.endswith("$"):
                continue

            looks_like_user = (
                "." in user or
                re.match(r"^[a-z]+[a-z0-9]*$", user) or
                re.match(r"^[a-z]+\\.[a-z]+$", user)
            )

            if not looks_like_user:
                continue

            if user.isalpha() and user[0].isupper() and len(user) < 6:
                continue

            users.append(user)

        if users:
            results["phase1_users"] = users
            print(f"[+] Discovered {len(users)} users via RID brute:")
            for u in users:
                print(f"    {u}")
                add_user(u, source="mssql_rid_brute")

        else:
            print("[-] No MSSQL users discovered via RID brute.")
            if proc.returncode != 0:
                results["phase1_error"] = "RID brute failed or returned no users"

    except Exception as e:
        results["phase1_error"] = str(e)
        print(f"[!] RID brute error: {e}")

    return results


# authenicated enumeration (this should be split into individual queries for debugging in future)
def run_mssql_authenticated(target, username, password, verbose=False):
    print("[*] Performing authenticated MSSQL enumeration...")

    results = {
        "phase2_connection": False,
        "phase2_data": {},
        "phase2_error": None
    }

    stdout, stderr, code = _execute_mssql_query(
        target, username, password, "SELECT 1",
        verbose=verbose
    )

    if code != 0:
        print("[-] MSSQL authentication failed during enumeration.")
        results["phase2_error"] = "Auth failed"
        return results

    results["phase2_connection"] = True
    enum_data = {}

    # find the version (still parses a bit messy)
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "SELECT @@version AS [SQL Server Version]",
        verbose=verbose
    )
    lines = _extract_sql_values(_clean_mssql_output(stdout))
    if lines:
        enum_data["version"] = " ".join(lines)
        print(f"[+] Version: {enum_data['version']}")

    # current user (futile)
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "SELECT SYSTEM_USER",
        verbose=verbose
    )
    lines = _extract_sql_values(_clean_mssql_output(stdout))
    if lines:
        enum_data["current_user"] = lines[-1]
        print(f"[+] Current User: {lines[-1]}")

    # find roles
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "SELECT 'sysadmin' AS role WHERE IS_SRVROLEMEMBER('sysadmin')=1 "
        "UNION SELECT 'serveradmin' WHERE IS_SRVROLEMEMBER('serveradmin')=1 "
        "UNION SELECT 'securityadmin' WHERE IS_SRVROLEMEMBER('securityadmin')=1 "
        "UNION SELECT 'processadmin' WHERE IS_SRVROLEMEMBER('processadmin')=1 "
        "UNION SELECT 'setupadmin' WHERE IS_SRVROLEMEMBER('setupadmin')=1 "
        "UNION SELECT 'diskadmin' WHERE IS_SRVROLEMEMBER('diskadmin')=1 "
        "UNION SELECT 'dbcreator' WHERE IS_SRVROLEMEMBER('dbcreator')=1",
        verbose=verbose
    )

    roles = _extract_sql_values(_clean_mssql_output(stdout))
    roles = list(dict.fromkeys([r for r in roles if r not in ("role", "")]))

    if roles:
        enum_data["server_roles"] = roles
        print(f"[+] Server Roles: {', '.join(roles)}")

    # enumerate databases
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name",
        verbose=verbose
    )

    dbs = _extract_sql_values(_clean_mssql_output(stdout))
    dbs = [d for d in dbs if d.lower() != "name"]

    if dbs:
        enum_data["databases"] = dbs
        print(f"[+] Databases: {', '.join(dbs)}")

        add_discovery(
            "Databases discovered",
            ", ".join(dbs),
            source="mssql"
        )

    # linked servers (needs verification this is functional and parsing is correct)
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "SELECT name FROM sys.servers WHERE is_linked = 1",
        verbose=verbose
    )

    linked = _extract_sql_values(_clean_mssql_output(stdout))
    linked = [l for l in linked if l.lower() != "name"]

    if linked:
        enum_data["linked_servers"] = linked
        print(f"[+] Linked Servers: {', '.join(linked)}")

    # xp_cmdshell check
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'",
        verbose=verbose
    )

    val = _extract_sql_values(_clean_mssql_output(stdout))
    enum_data["xp_cmdshell"] = "enabled" if "1" in val else "disabled"
    print(f"[+] xp_cmdshell: {enum_data['xp_cmdshell']}")

    if "1" in val:
        add_vulnerability(
            "xp_cmdshell enabled",
            "xp_cmdshell is enabled on the MSSQL server",
            source="mssql"
        )

    # enum_impersonate check
    try:
        cmd = [
            "impacket-mssqlclient",
            f"{username}:{password}@{target}"
        ]

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        out, _ = proc.communicate("enum_impersonate\nexit\n", timeout=20)

        imp = []

        for line in out.splitlines():
            line = line.strip()

            if not line:
                continue

            if "IMPERSONATE" in line.upper() or "GRANT" in line.upper():
                parts = re.split(r"\s+", line)
                candidate = parts[-1].strip() if parts else None

                if candidate and re.match(r"^[a-zA-Z0-9_.-]+$", candidate):
                    if candidate.lower() == "grantor":
                        continue
                    imp.append(candidate)

        imp = list(dict.fromkeys(imp))

        if imp:
            enum_data["impersonation"] = imp
            print(f"[+] Impersonation targets: {', '.join(imp)}")

            add_misconfiguration(
                "SQL impersonation targets found",
                ", ".join(imp),
                source="mssql"
            )

    except Exception:
        pass

    # check the service acc
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "EXEC xp_regread 'HKEY_LOCAL_MACHINE', "
        "'SYSTEM\\CurrentControlSet\\Services\\MSSQLServer', 'ObjectName'",
        verbose=verbose
    )

    for l in _extract_sql_values(_clean_mssql_output(stdout)):
        if "\\" in l:
            enum_data["service_account"] = l
            print(f"[+] Service Account: {l}")
            break

    # trustworthy dbs enum
    stdout, _, _ = _execute_mssql_query(
        target, username, password,
        "SELECT name FROM sys.databases WHERE is_trustworthy_on=1 AND database_id>4",
        verbose=verbose
    )

    trust = _extract_sql_values(_clean_mssql_output(stdout))
    trust = [t for t in trust if t.lower() != "name"]

    if trust:
        enum_data["trustworthy_databases"] = trust
        print(f"[+] Trustworthy databases: {', '.join(trust)}")

    results["phase2_data"] = enum_data

    print("[+] Authenticated enumeration completed.")
    return results


# main function
def run_mssql_enum(target, ports, cred_string=None, verbose=False):

    port_list = [str(p.get("port")) for p in ports]

    if "1433" not in port_list: # needs to use service check from main, what if irregular port ?
        print("[*] MSSQL port 1433 not detected. Skipping MSSQL enumeration.")
        return None

    print(f"[*] Running MSSQL enumeration against {target}...")

    results = {
        "rid_brute": None,
        "authenticated": None,
        "users": []
    }

    if cred_string and ":" in cred_string:

        username, password = cred_string.split(":", 1)

        if "mssql" in ["mssql"]: 

            brute_results = run_mssql_rid_brute(
                target, username, password,
                verbose=verbose
            )

            results["rid_brute"] = brute_results
            results["users"] = brute_results.get("phase1_users", [])

            print("\n[*] Valid MSSQL credentials detected. Proceeding with authenticated enumeration...")

            results["authenticated"] = run_mssql_authenticated(
                target, username, password,
                verbose=verbose
            )

    return results
