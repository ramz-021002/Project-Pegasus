"""
Classification service for determining sample threat level.
Analyzes static and dynamic analysis results to classify samples.
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def classify_sample(analysis_results: Dict[str, Any]) -> str:
    """
    Classify a sample as 'malicious', 'suspicious', or 'clean' based on analysis results.

    Args:
        analysis_results: Complete analysis results from all analysis types

    Returns:
        str: Classification - 'malicious', 'suspicious', or 'clean'
    """
    try:
        static_results = analysis_results.get("static", {}).get("results", {})
        dynamic_results = analysis_results.get("dynamic", {}).get("results", {})

        # Initialize scoring system
        malicious_score = 0
        suspicious_score = 0

        # Static analysis indicators
        malicious_score += _score_static_analysis(static_results)
        suspicious_score += _score_suspicious_static(static_results)

        # Dynamic analysis indicators
        malicious_score += _score_dynamic_analysis(dynamic_results)
        suspicious_score += _score_suspicious_dynamic(dynamic_results)

        # Classification thresholds
        if malicious_score >= 10:
            return "malicious"
        elif malicious_score >= 5 or suspicious_score >= 15:
            return "suspicious"
        elif suspicious_score >= 5:
            return "suspicious"
        else:
            return "clean"

    except Exception as e:
        logger.error(f"Classification error: {e}", exc_info=True)
        return "unknown"


def _score_static_analysis(static_results: Dict[str, Any]) -> int:
    """Score malicious indicators from static analysis."""
    score = 0

    # CAPA ATT&CK techniques (strong malicious indicator)
    capa = static_results.get("capa", {})
    attack_techniques = capa.get("attack", [])
    if len(attack_techniques) > 0:
        score += 8  # Strong indicator
        if len(attack_techniques) > 5:
            score += 5  # Multiple techniques = very suspicious

    # MBC (Malware Behavior Catalog) behaviors
    mbc_behaviors = capa.get("mbc", [])
    if len(mbc_behaviors) > 0:
        score += 6
        if len(mbc_behaviors) > 3:
            score += 4

    # YARA rule matches (depends on rules, but generally suspicious)
    yara_matches = static_results.get("yara_matches", [])
    if len(yara_matches) > 0:
        score += 7

    # Suspicious API imports
    indicators = static_results.get("indicators", [])
    suspicious_apis = [i for i in indicators if i.get("type") == "suspicious_api"]
    if len(suspicious_apis) > 0:
        score += 3
        if len(suspicious_apis) > 5:
            score += 3

    # High entropy (packed/encrypted files)
    entropy = static_results.get("entropy", 0)
    if entropy > 7.5:
        score += 2

    return score


def _score_suspicious_static(static_results: Dict[str, Any]) -> int:
    """Score suspicious (but not necessarily malicious) indicators from static analysis."""
    score = 0

    # Network IOCs (could be legitimate)
    indicators = static_results.get("indicators", [])
    network_iocs = [i for i in indicators if i.get("type") in ["ip", "domain", "url"]]
    if len(network_iocs) > 0:
        score += 2
        if len(network_iocs) > 10:
            score += 3

    # CAPA capabilities (not ATT&CK/MBC)
    capa = static_results.get("capa", {})
    capabilities = capa.get("capabilities", [])
    if len(capabilities) > 10:
        score += 3
        if len(capabilities) > 25:
            score += 2

    # Medium entropy
    entropy = static_results.get("entropy", 0)
    if 6.5 <= entropy <= 7.5:
        score += 1

    return score


def _score_dynamic_analysis(dynamic_results: Dict[str, Any]) -> int:
    """Score malicious indicators from dynamic analysis."""
    score = 0

    behavior_summary = dynamic_results.get("behavior_summary", {})
    suspicious_behaviors = behavior_summary.get("suspicious_behaviors", [])

    # Network activity (outbound connections)
    network_count = behavior_summary.get("network_connections_count", 0)
    dns_count = behavior_summary.get("dns_queries_count", 0)

    if network_count > 0:
        score += 3
        if network_count > 5:
            score += 2

    if dns_count > 0:
        score += 2
        if dns_count > 3:
            score += 2

    # Process manipulation
    if behavior_summary.get("processes_killed_count", 0) > 0:
        score += 5  # Killing processes is highly suspicious

    # Command execution
    commands_count = behavior_summary.get("commands_executed_count", 0)
    if commands_count > 0:
        score += 4
        if commands_count > 3:
            score += 3

    # Specific suspicious behaviors
    high_risk_behaviors = ["spawns_shell", "kills_processes", "executes_commands"]
    medium_risk_behaviors = ["network_activity", "dns_resolution", "multiple_processes"]

    for behavior in suspicious_behaviors:
        if behavior in high_risk_behaviors:
            score += 4
        elif behavior in medium_risk_behaviors:
            score += 2

    return score


def _score_suspicious_dynamic(dynamic_results: Dict[str, Any]) -> int:
    """Score suspicious (but not necessarily malicious) indicators from dynamic analysis."""
    score = 0

    behavior_summary = dynamic_results.get("behavior_summary", {})

    # File operations (could be legitimate)
    files_count = behavior_summary.get("files_created", 0) + behavior_summary.get(
        "files_accessed_count", 0
    )
    if files_count > 10:
        score += 2
        if files_count > 50:
            score += 3

    # Process creation (could be legitimate)
    process_count = behavior_summary.get("process_count", 0)
    if process_count > 3:
        score += 1
        if process_count > 8:
            score += 2

    # Extensive file operations
    suspicious_behaviors = behavior_summary.get("suspicious_behaviors", [])
    if "extensive_file_operations" in suspicious_behaviors:
        score += 2

    return score
