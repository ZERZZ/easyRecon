import subprocess
import json
import os
import re
from datetime import datetime


def _parse_json_results(results):
    hits = []
    for result in results:
        hits.append({
            'url': result.get('url', ''),
            'status': result.get('status', 0),
            'lines': result.get('lines', ''),
            'words': result.get('words', '')
        })
    return hits


def _parse_text_results(content):
    hits = []
    line_re = re.compile(r"^\s*(\d{3})\s+\S+\s+(\d+l)\s+(\d+w)\s+\S+\s+(https?://\S+)", re.IGNORECASE)
    
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        match = line_re.match(line)
        if match:
            hits.append({
                'url': match.group(4),
                'status': int(match.group(1)),
                'lines': match.group(2),
                'words': match.group(3)
            })
        else:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    hits.append({
                        'url': parts[-1],
                        'status': int(parts[0]),
                        'lines': '',
                        'words': ''
                    })
                except ValueError:
                    continue
    
    return hits


def run_dirbuster(target, hostname=None, show_output=False):
    scan_target = target.rstrip("/")

    print(f"[*] Running feroxbuster against {scan_target}...")      
    
    timestamp = datetime.now().strftime("%s")
    output_file = f"/tmp/ferox_{timestamp}.json"
    
    valuable_statuses = {200, 204, 301, 302, 307, 308, 401, 403}
    
    skip_extensions = {
        '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff', '.woff2', 
        '.ttf', '.svg', '.ico', '.mp4', '.webp', '.eot', '.otf'
    }
    
    important_extensions = {
        '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.cgi', '.pl', 
        '.html', '.htm', '.xml', '.json', '.env', '.conf', '.config',
        '.txt', '.key', '.pem', '.bak'
    }

    try:
        stdout_opt = None if show_output else subprocess.DEVNULL
        stderr_opt = None if show_output else subprocess.DEVNULL

        command = [
            "feroxbuster",
            "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "-u", scan_target,
            "-o", output_file,
            "-f",
            "--depth", "1",
            "-t", "50"
        ]

        # add host header if hostname exists
        if hostname:
            command.extend(["-H", f"Host: {hostname}"])

        subprocess.run(
            command,
            check=True,
            stdout=stdout_opt,
            stderr=stderr_opt
        )

        print("[*] Directory scan completed. Parsing results...")
        
        valuable_hits = []
        all_hits = []
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                content = f.read().strip()
            
            try:
                data = json.loads(content)
                results = data if isinstance(data, list) else data.get('results', [])
                hits = _parse_json_results(results)
            except json.JSONDecodeError:
                hits = _parse_text_results(content)
            
            for hit in hits:
                all_hits.append(hit)
                status = hit['status']
                url = hit['url']
                
                if status not in valuable_statuses:
                    continue
                if any(url.lower().endswith(ext) for ext in skip_extensions):
                    continue
                
                is_dir = url.endswith('/')
                has_important_ext = any(url.lower().endswith(ext) for ext in important_extensions)
                is_auth = status in {401, 403}
                
                if has_important_ext or is_dir or is_auth:
                    valuable_hits.append(hit)
            
            print(f"\n[*] Total endpoints found: {len(all_hits)}")
            
            if valuable_hits:
                print(f"[+] Found {len(valuable_hits)} valuable endpoints:\n")
                for hit in valuable_hits:
                    marker = "[AUTH]" if hit['status'] in {401, 403} else "[OK]"
                    print(f"  {marker} [{hit['status']}] {hit['url']}")
            else:
                successful = [h for h in all_hits if 200 <= h['status'] < 400]
                if successful:
                    print(f"[+] Successful responses ({len(successful)}):\n")
                    for hit in successful[:30]:
                        print(f"  [{hit['status']}] {hit['url']}")
                    if len(successful) > 30:
                        print(f"  ... and {len(successful) - 30} more")
            
            os.remove(output_file)
            return valuable_hits
        else:
            print("[!] Output file not found.")
            return []

    except subprocess.CalledProcessError:
        print("[!] Directory scan failed.")
        return []
    except OSError as e:
        print(f"[!] Error: {e}")
        return []