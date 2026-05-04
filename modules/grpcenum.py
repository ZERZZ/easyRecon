import subprocess

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

def run_grpcenum(target, show_output=False, recon_data=None):
    print(f"[*] Running gRPC enumeration against {target}...")

    results = {
        "grpc_detected": False,
        "services": {},
    }

    stdout_opt = None if show_output else subprocess.PIPE
    stderr_opt = None if show_output else subprocess.DEVNULL

    # check grpcurl exists
    try:
        subprocess.run(
            ["which", "grpcurl"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
    except subprocess.CalledProcessError:
            _append_unique(recon_data, "interesting_findings", [f"gRPC service: {name}" for name in results["services"].keys()])

    if recon_data is not None:
        if results.get("grpc_detected") and results.get("services"):
            _append_unique(recon_data, "interesting_findings", [f"gRPC service: {name}" for name in results["services"].keys()])

        return results

    try:
        # get services
        cmd = [
            "grpcurl",
            "-plaintext",
            f"{target}:50051",
            "list"
        ]

        proc = subprocess.run(
            cmd,
            stdout=stdout_opt,
            stderr=stderr_opt,
            text=True
        )

        if proc.returncode != 0 or not proc.stdout:
            print("[*] No gRPC services detected.")
            return results

        services = [s.strip() for s in proc.stdout.splitlines() if s.strip()]

        if not services:
            print("[*] No gRPC services detected.")
            return results

        results["grpc_detected"] = True

        for service in services:

            if "reflection" in service.lower():
                continue

            print(f"[+] Found service: {service}")

            results["services"][service] = []

            # enumerate methods
            try:

                method_cmd = [
                    "grpcurl",
                    "-plaintext",
                    f"{target}:50051",
                    "list",
                    service
                ]

                method_proc = subprocess.run(
                    method_cmd,
                    stdout=stdout_opt,
                    stderr=stderr_opt,
                    text=True
                )

                if method_proc.stdout:

                    methods = [
                        m.strip()
                        for m in method_proc.stdout.splitlines()
                        if m.strip()
                    ]

                    for method in methods:
                        results["services"][service].append(method)

                        print(f"    └─ Method: {method}")

            except Exception:
                pass

            # show rpc definitions
            try:

                describe_cmd = [
                    "grpcurl",
                    "-plaintext",
                    f"{target}:50051",
                    "describe",
                    service
                ]

                describe_proc = subprocess.run(
                    describe_cmd,
                    stdout=stdout_opt,
                    stderr=stderr_opt,
                    text=True
                )

                if describe_proc.stdout:
                    print("    └─ RPC Definition:")
                    for line in describe_proc.stdout.splitlines():
                        print(f"       {line}")

            except Exception:
                pass

    except Exception:
        pass

    return results