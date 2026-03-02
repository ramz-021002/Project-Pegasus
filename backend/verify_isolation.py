import sys
import os
import time
from pathlib import Path

sys.path.append(os.path.join(os.getcwd(), "backend"))

from app.services.docker_manager import DockerManager


def verify_isolation():
    dm = DockerManager()
    print("Creating isolated network...")
    net_id = dm.create_isolated_network()

    try:
        # Create a dummy sample
        sample = Path("isolation_test.py")
        with open(sample, "w") as f:
            f.write(
                "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(5); s.connect(('8.8.8.8', 53)); print('CONNECTED')"
            )

        print("Running dynamic analysis (attempting to reach 8.8.8.8)...")

        success, results, container_id = dm.run_dynamic_analysis(
            sample, net_id, timeout=10, original_filename="isolation_test.py"
        )

        # Check results
        network_conns = results.get("network_connections", [])
        connected_to_google = False
        for nj in network_conns:
            if nj.get("dst_ip") == "8.8.8.8":
                connected_to_google = True

        if connected_to_google:
            print("ISOLATION FAILED: Connection to 8.8.8.8 established.")
        else:
            print("ISOLATION VERIFIED: No connection to 8.8.8.8 found in results.")

        syscalls = results.get("system_calls", [])

        print("\nanalysis results summary:")
        print(f"Network connections found: {len(network_conns)}")
        for c in network_conns:
            print(f" - {c}")

    finally:
        dm.remove_network(net_id)
        if os.path.exists("isolation_test.py"):
            os.remove("isolation_test.py")


if __name__ == "__main__":
    verify_isolation()
