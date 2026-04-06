import subprocess
import os

from utils.output import print


def run_nfsenum(target, show_output=False):

    print(f"[*] Running NFS enumeration against {target}...")

    results = {
        "exports": [],
        "mounted": []
    }

    discovered_uids = set()

    # get current user UID
    try:
        current_uid = str(os.getuid())
    except Exception:
        current_uid = None

    try:
        cmd = ["showmount", "-e", target]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        output = proc.stdout or ""

        if "Export list" not in output:
            print("[-] No NFS exports found.")
            return results

        exports = []

        for line in output.splitlines():
            if line.startswith("/"):
                share = line.split()[0]
                exports.append(share)

        if not exports:
            print("[-] No mountable exports discovered.")
            return results

        results["exports"] = exports

        print("[+] NFS exports discovered:")
        for e in exports:
            print(f"    {e}")

        if show_output:
            print(output)

    except FileNotFoundError:
        print("[!] showmount not found.")
        return results
    except Exception as e:
        print(f"[!] showmount error: {e}")
        return results
    
    # give option whether to mount or not 
    try:
        choice = input("[?] Mount discovered NFS shares to /tmp? (y/N): ").strip().lower()

        if choice != "y":
            return results

        for share in exports:

            safe_name = share.replace("/", "_").strip("_")
            mount_point = f"/tmp/{target}_{safe_name}"

            try:
                os.makedirs(mount_point, exist_ok=True)

                mount_cmd = [
                    "sudo",
                    "mount",
                    "-t",
                    "nfs",
                    f"{target}:{share}",
                    mount_point
                ]

                mount_proc = subprocess.run(
                    mount_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if mount_proc.returncode == 0:
                    results["mounted"].append(mount_point)
                    print(f"[+] Mounted {share} -> {mount_point}")

                    # get UID owner of mount
                    stat_proc = subprocess.run(
                        ["ls", "-ld", mount_point],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True
                    )

                    if stat_proc.stdout:
                        parts = stat_proc.stdout.split()
                        if len(parts) >= 4:
                            owner = parts[2]

                            try:
                                uid_proc = subprocess.run(
                                    ["id", "-u", owner],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    text=True
                                )

                                uid = uid_proc.stdout.strip()
                                if uid:
                                    discovered_uids.add((owner, uid))
                            except Exception:
                                pass

                    print("[*] Listing mounted files:")

                    ls_proc = subprocess.run(
                        ["ls", "-la", mount_point],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True
                    )

                    if ls_proc.stdout:
                        print(ls_proc.stdout)

                else:
                    print(f"[-] Failed to mount {share}")
                    if mount_proc.stderr:
                        print(f"[!] Mount error: {mount_proc.stderr.strip()}")

            except Exception as e:
                print(f"[!] Mount error for {share}: {e}")

    except KeyboardInterrupt:
        print("\n[!] Mounting cancelled by user.")

    # print hint once at end (skip if UID matches current user)
    filtered_uids = [(owner, uid) for owner, uid in discovered_uids if uid != current_uid]

    if filtered_uids:
        print("[*] Files appear owned by another user on the NFS server.")
        print("[*] You may be able to impersonate the UID locally:")

        for owner, uid in filtered_uids:
            print(f"\n    Discovered owner: {owner} (UID: {uid})\n")
            print("    sudo useradd james")
            print(f"    sudo usermod -u {uid} james")
            print(f"    sudo groupmod -g {uid} james")
            print("    sudo su james")

    return results