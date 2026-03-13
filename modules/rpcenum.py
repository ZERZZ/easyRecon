import subprocess

from utils.output import print


def run_rpcenum(target, show_output=False):
    print(f"[*] Running RPC enumeration against {target}...")

    results = {
        "null_bind": False,
        "enumdomusers_output": ""
    }

    stdout_opt = None if show_output else subprocess.PIPE
    stderr_opt = None if show_output else subprocess.DEVNULL

    # attempt rpc null bind
    try:
        rpc_cmd = [
            "rpcclient",
            "-U",
            "",
            target,
            "-N",
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
    except Exception as e:
        print(f"[!] rpcclient error: {e}")

    # attempt enumdomusers if null bind worked
    if results["null_bind"]:
        try:
            enum_cmd = [
                "rpcclient",
                "-U",
                "",
                target,
                "-N",
                "-c",
                "enumdomusers"
            ]

            enum_proc = subprocess.run(
                enum_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            if enum_proc.stdout and "NT_STATUS_ACCESS_DENIED" not in enum_proc.stdout:
                results["enumdomusers_output"] = enum_proc.stdout
                print("[+] enumdomusers successful.")
            else:
                print("[-] enumdomusers not successful.")

        except Exception as e:
            print(f"[!] enumdomusers error: {e}")

    return results