#!/usr/bin/env python3
import requests
import json
import time
import sys
import os

API_BASE = "http://localhost:8000"

def upload_and_check():
    if not os.path.exists("fake_malware.py"):
        print("fake_malware.py not found")
        return

    print("Uploading fake_malware.py...")
    try:
        with open("fake_malware.py", "rb") as f:
            files = {"file": ("fake_malware.py", f, "text/x-python")}
            response = requests.post(f"{API_BASE}/api/upload/", files=files)
            
        if response.status_code != 201:
            print(f"Upload failed: {response.text}")
            return

        sample_id = response.json()['sample_id']
        print(f"Sample ID: {sample_id}")

        # Wait for analysis
        print("Waiting for analysis...")
        for _ in range(60): # Wait up to 5 minutes
            res = requests.get(f"{API_BASE}/api/upload/{sample_id}")
            status = res.json()['status']
            print(f"Status: {status}")
            if status in ['completed', 'failed']:
                break
            time.sleep(5)
            
        # Get results
        print("Fetching results...")
        res = requests.get(f"{API_BASE}/api/analysis/{sample_id}")
        data = res.json()
        
        print("\n--- Analysis Results ---")
        if 'analysis_results' in data and 'dynamic' in data['analysis_results']:
            dynamic = data['analysis_results']['dynamic']
            print(json.dumps(dynamic, indent=2))
            
            # Check specific fields
            print("\n--- Verification ---")
            
            # Check Network
            net_conns = dynamic.get('network_connections', [])
            print(f"Network Connections: {len(net_conns)}")
            for conn in net_conns:
                print(f"  - {conn}")
            
            # Check DNS
            dns = dynamic.get('dns_queries', [])
            print(f"DNS Queries: {len(dns)}")
            for q in dns:
                print(f"  - {q}")
                
            # Check Files
            files = dynamic.get('files_accessed', [])
            files_created = dynamic.get('file_operations', [])
            print(f"Files Accessed: {len(files)}")
            print(f"File Operations (created): {len(files_created)}")
            found_dropped = any('dropped_file.txt' in str(f) for f in files_created)
            print(f"  - Found 'dropped_file.txt' creation: {found_dropped}")
            
            # Check Commands
            cmds = dynamic.get('commands_executed', [])
            print(f"Commands Executed: {len(cmds)}")
            ls_found = any('ls' in c.get('binary', '') or 'ls' in c.get('cmdline', '') for c in cmds)
            print(f"  - Found 'ls' command: {ls_found}")

            # Check Errors
            errors = dynamic.get('errors', [])
            if errors:
                print("\n--- Errors Reported ---")
                for err in errors:
                    print(f"  - {err}")

        else:
            print("No dynamic analysis results found.")

    except Exception as e:
        print(f"Test failed: {e}")

if __name__ == "__main__":
    upload_and_check()
