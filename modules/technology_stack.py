import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_tech_stack(target, hostname, open_ports):
    print("[*] Running technology stack detection...")

    tech = set()
    versions = {}

    http_ports = [
        p["port"] for p in open_ports
        if p["service"] in ["http", "https"] or p["port"] in ["80", "443"]
    ]

    if not http_ports:
        print("[*] No HTTP services detected.")
        return {}

    for port in http_ports:
        scheme = "https" if port == "443" else "http"

        if hostname:
            url = f"{scheme}://{target}" if port in ["80", "443"] else f"{scheme}://{target}:{port}"
            headers_override = {"Host": hostname}
        else:
            url = f"{scheme}://{target}" if port in ["80", "443"] else f"{scheme}://{target}:{port}"
            headers_override = {}

        try:
            resp = requests.get(
                url,
                headers=headers_override,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
        except requests.RequestException:
            continue

        headers = resp.headers
        body = resp.text.lower()

        server = headers.get("Server")
        powered = headers.get("X-Powered-By")

        if server:
            if "apache" in server.lower():
                tech.add("Apache")
            if "nginx" in server.lower():
                tech.add("Nginx")

            match = re.search(r'([A-Za-z\-]+)/([\d\.]+)', server)
            if match:
                versions[match.group(1)] = match.group(2)

        if powered:
            if "php" in powered.lower():
                tech.add("PHP")

            match = re.search(r'([A-Za-z\-]+)/([\d\.]+)', powered)
            if match:
                versions[match.group(1)] = match.group(2)

        #wordpress and other cms/frameworks detection in body 
        if (
            "wp-content" in body or
            "wp-includes" in body or
            "wp-json" in body or
            "xmlrpc.php" in body or
            "wp-login.php" in body
        ):
            tech.add("WordPress")

            wp_ver = re.search(r'wordpress\s*([\d\.]+)', body)
            if wp_ver:
                versions["WordPress"] = wp_ver.group(1)

        if "drupal.settings" in body:
            tech.add("Drupal")

        if "joomla" in body:
            tech.add("Joomla")

        if "laravel" in body:
            tech.add("Laravel")

        if "csrfmiddlewaretoken" in body:
            tech.add("Django")

        if "asp.net" in body or "x-aspnet-version" in headers:
            tech.add("ASP.NET")

        if "express" in body:
            tech.add("Express")

    if tech:
        print("[+] Technology detected:")
        for t in sorted(tech):
            if t in versions:
                print(f"    - {t} ({versions[t]})")
            else:
                print(f"    - {t}")
    else:
        print("[*] No identifiable technology detected.")

    return {
        "technologies": list(tech),
        "versions": versions
    }