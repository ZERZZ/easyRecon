import subprocess

from utils.output import print
from utils.findings import add_misconfiguration, add_note


def run_grpcenum(target, show_output=False):
    print(f"[*] Running gRPC enumeration against {target}...")

    results = {
        "grpc_detected": False,
        "services": {},
        "rpc_definitions": {}
    }

    # check grpcurl installed
    try:
        subprocess.run(
            ["which", "grpcurl"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
    except subprocess.CalledProcessError:
        print("[!] grpcurl not installed")
        add_note(
            "gRPC enumeration skipped - grpcurl not installed",
            source="grpcenum"
        )
        return results

    # run grpcurl list
    try:
        output = subprocess.getoutput(
            f"grpcurl -plaintext {target}:50051 list"
        )

        raw_lines = [
            l.strip()
            for l in output.splitlines()
            if l.strip()
        ]

        services = []

        for line in raw_lines:
            if "reflection" in line.lower():
                continue
            if "grpcurl" in line.lower():
                continue
            if line.startswith("grpc."):
                continue

            services.append(line)

        services = list(set(services))

        if not services:
            print("[*] No gRPC services detected.")
            return results

        # report it
        results["grpc_detected"] = True

        add_misconfiguration(
            "gRPC service exposed (plaintext endpoint discovered via grpcurl)",
            source="grpcenum"
        )

        print("[+] gRPC services detected:")
        for s in services:
            print(f"  - {s}")

        # enumerate services and methods
        for service in services:
            results["services"][service] = []

            add_note(
                f"gRPC service discovered: {service}",
                source="grpcenum"
            )


            method_output = subprocess.getoutput(
                f"grpcurl -plaintext {target}:50051 list {service}"
            )

            methods = [
                m.strip()
                for m in method_output.splitlines()
                if m.strip()
            ]

            for method in methods:
                results["services"][service].append(method)

                add_note(
                    f"gRPC method: {method}",
                    source="grpcenum"
                )

            desc_output = subprocess.getoutput(
                f"grpcurl -plaintext {target}:50051 describe {service}"
            )

            if desc_output.strip():
                results["rpc_definitions"][service] = desc_output.splitlines()

    except Exception:
        print("[!] gRPC enumeration failed")

    return results