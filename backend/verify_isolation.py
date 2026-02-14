import sys
import os
import time
from pathlib import Path

# Add backend to path to import services
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.services.docker_manager import DockerManager

def verify_isolation():
    dm = DockerManager()
    print("Creating isolated network...")
    net_id = dm.create_isolated_network()
    
    try:
        # Create a dummy sample
        sample = Path("isolation_test.py")
        with open(sample, "w") as f:
            f.write("import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(5); s.connect(('8.8.8.8', 53)); print('CONNECTED')")
            
        print("Running dynamic analysis (attempting to reach 8.8.8.8)...")
        # We expect this to FAIL (return False or timed out connection) if isolated
        # effectively, run_dynamic_analysis runs monitor.py.
        # But monitor.py executes the sample.
        # If the sample prints "CONNECTED", isolation failed.
        
        success, results, container_id = dm.run_dynamic_analysis(
            sample,
            net_id,
            timeout=10,
            original_filename="isolation_test.py"
        )
        
        # Check results
        network_conns = results.get("network_connections", [])
        connected_to_google = False
        for nj in network_conns:
            if nj.get("dst_ip") == "8.8.8.8":
                connected_to_google = True
                
        # Also check stdout for our print
        # (Though monitor.py structure doesn't easily expose stdout of the sample in the return dict unless we parse it.
        # But monitor.py captures network connections via strace/tcpdump/psutil)
        
        if connected_to_google:
             print("❌ ISOLATION FAILED: Connection to 8.8.8.8 established.")
        else:
             print("✅ ISOLATION VERIFIED: No connection to 8.8.8.8 found in results.")
             
        # Verification via syscalls
        syscalls = results.get("system_calls", [])
        # We might see 'connect' syscalls, but they should fail or timeout.
        # monitor.py parses successful connections from established state in psutil or strace?
        # monitor.py's parse_strace_network parses connect() syscalls.
        # If the syscall appears, it means it *tried* to connect.
        # We need to know if it SUCCEEDED.
        # psutil only reports ESTABLISHED.
        
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
