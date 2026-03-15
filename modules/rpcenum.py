import subprocess
import re

from utils.output import print


def run_rpcenum(target, show_output=False):
    print(f"[*] Running RPC enumeration against {target}...")

    results = {
        "null_bind": False,
        "enumdomusers_output": "",
        "users": []
    }

    stdout_opt = None if show_output else subprocess.PIPE
    stderr_opt = None if show_output else subprocess.DEVNULL

    # attempt rpc null bind
    try:
        rpc_cmd = [
            "rpcclient",
            "-U",
            "",
            "-N",
            target,
            "-c",
            "exit"
        ]

        rpc_proc = subprocess.run(
            rpc_cmd,
            stdout=stdout_opt,
            stderr=stderr_opt,
            text=True
        )

        if rpc_proc.returncode == 0:
            results["null_bind"] = True
            print("[+] RPC null bind successful.")
        else:
            print("[-] RPC null bind failed.")

    except FileNotFoundError:
        print("[!] rpcclient not found.")
        return results
    except Exception as e:
        print(f"[!] rpcclient error: {e}")
        return results

    # attempt enumdomusers if null bind worked
    if results["null_bind"]:
        try:
            enum_cmd = [
                "rpcclient",
                "-U",
                "",
                "-N",
                target,
                "-c",
                "enumdomusers"
            ]

            enum_proc = subprocess.run(
                enum_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            output = enum_proc.stdout or ""

            if output and "NT_STATUS_ACCESS_DENIED" not in output:
                results["enumdomusers_output"] = output

                if show_output:
                    print(output)

                users = []

                for line in output.splitlines():
                    match = re.search(r"user:\[(.*?)\]", line)
                    if match:
                        user = match.group(1)

                        if (
                            user.endswith("$")
                            or user.startswith("$")
                            or user.startswith("SM_")
                            or user.startswith("HealthMailbox")
                            or user.startswith("SystemMailbox")
                            or user.startswith("Migration.")
                            or user.startswith("DiscoverySearchMailbox")
                            or user.startswith("FederatedEmail")
                            or user.startswith("Exchange")
                            or user in ["Guest", "DefaultAccount"]
                        ):
                            continue

                        users.append(user)

                results["users"] = users

                if users:
                    print("[+] Discovered domain users:")
                    for u in users:
                        print(f"    {u}")

                print("[+] enumdomusers successful.")

            else:
                print("[-] enumdomusers not successful.")

        except Exception as e:
            print(f"[!] enumdomusers error: {e}")

    return results