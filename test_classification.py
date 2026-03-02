#!/usr/bin/env python3
"""
Test script for the classification service.
"""

test_static_results = {
    "capa": {
        "attack": [
            {
                "id": "T1055",
                "technique": "Process Injection",
                "tactic": "Defense Evasion",
            },
            {
                "id": "T1027",
                "technique": "Obfuscated Files",
                "tactic": "Defense Evasion",
            },
        ],
        "mbc": [
            {
                "id": "B0009",
                "behavior": "Process Injection",
                "objective": "Defense Evasion",
            }
        ],
        "capabilities": [],
    },
    "yara_matches": [{"rule": "malware_family", "tags": ["trojan"]}],
    "indicators": [
        {
            "type": "suspicious_api",
            "value": "VirtualAlloc",
            "category": "memory_manipulation",
        },
        {"type": "ip", "value": "192.168.1.100"},
    ],
    "entropy": 7.8,
}

test_dynamic_results = {
    "behavior_summary": {
        "network_connections_count": 3,
        "dns_queries_count": 5,
        "commands_executed_count": 2,
        "processes_killed_count": 1,
        "suspicious_behaviors": [
            "network_activity",
            "dns_resolution",
            "executes_commands",
            "kills_processes",
        ],
    }
}


def test_classification():

    import sys
    import os

    sys.path.append("/home/rama/Project Pegasus/backend")

    from app.services.classification import classify_sample

    malicious_results = {
        "static": {"results": test_static_results},
        "dynamic": {"results": test_dynamic_results},
    }

    classification = classify_sample(malicious_results)
    print(f"Test 1 - Expected: malicious, Got: {classification}")

    clean_results = {
        "static": {
            "results": {
                "capa": {"attack": [], "mbc": [], "capabilities": []},
                "entropy": 3.2,
            }
        },
        "dynamic": {"results": {"behavior_summary": {"suspicious_behaviors": []}}},
    }

    classification = classify_sample(clean_results)
    print(f"Test 2 - Expected: clean, Got: {classification}")

    suspicious_results = {
        "static": {
            "results": {
                "capa": {
                    "attack": [],
                    "mbc": [],
                    "capabilities": ["file operations"] * 15,
                },
                "indicators": [{"type": "ip", "value": "1.2.3.4"}] * 12,
            }
        },
        "dynamic": {
            "results": {
                "behavior_summary": {
                    "network_connections_count": 2,
                    "files_created": 25,
                    "suspicious_behaviors": [
                        "network_activity",
                        "extensive_file_operations",
                    ],
                }
            }
        },
    }

    classification = classify_sample(suspicious_results)
    print(f"Test 3 - Expected: suspicious, Got: {classification}")


if __name__ == "__main__":
    test_classification()
