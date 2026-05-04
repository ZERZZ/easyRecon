import subprocess
import re

from utils.output import print


def _append_unique(recon_data, key, values):
    if recon_data is None or values is None:
        return
    if not isinstance(values, list):
        values = [values]
    data_list = recon_data.setdefault(key, [])
    for value in values:
        if value and value not in data_list:
            data_list.append(value)

def run_rpcenum(target, show_output=False, recon_data=None):
    print(f"[*] Running RPC enumeration against {target}...")

    results = {
        "connection": False,
        "enumeration": False,
        "error": None,
        "enumdomusers_output": "",
        "users": []
    }

    ERROR_KEYWORDS = ["NT_STATUS_", "denied", "failed", "error", "Error", "access denied", "not successful"]

    stdout_opt = None if show_output else subprocess.PIPE
    stderr_opt = None if show_output else subprocess.DEVNULL

    # Step 1: attempt rpc null bind 
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
            results["connection"] = True
            print("[+] RPC null bind successful.")
        else:
            results["error"] = "RPC null bind failed"
            print("[-] RPC null bind failed.")
            return results

    except FileNotFoundError:
        print("[!] rpcclient not found.")
        results["error"] = "rpcclient not found"
        return results
    except Exception as e:
        print(f"[!] rpcclient error: {e}")
        results["error"] = str(e)
        return results

    # step 2.2: attempt enumdomusers if null bind worked
    if results["connection"]:
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

            # check for explicit errors FIRST
            if any(err in output for err in ERROR_KEYWORDS) or enum_proc.returncode != 0:
                results["error"] = f"Enumeration failed: {[err for err in ERROR_KEYWORDS if err in output]}"
                print("[-] RPC enumdomusers failed: access denied or error")
                return results

            if output:
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

                # only mark enumeration success if we actually parsed valid users
                if users:
                    results["enumeration"] = True
                    print("[+] RPC enumdomusers successful:")
                    for u in users:
                        print(f"    {u}")
                else:
                    results["error"] = "No valid users parsed"
                    print("[-] enumdomusers returned no valid users")

            else:
                results["error"] = "enumdomusers returned no output"
                print("[-] enumdomusers returned no output.")

        except FileNotFoundError:
            print("[!] rpcclient not found for enumdomusers.")
        except Exception as e:
            print(f"[!] enumdomusers error: {e}")
            results["error"] = str(e)

    return results
