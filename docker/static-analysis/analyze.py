#!/usr/bin/env python3
"""
Static malware analysis script for Project Pegasus.
Performs comprehensive static analysis on malware samples.
"""
import json
import sys
import os
import re
import hashlib
import math
from pathlib import Path
from typing import Dict, List, Any

try:
    import pefile
    import magic
    import yara
except ImportError as e:
    print(json.dumps({"error": f"Missing dependency: {e}"}))
    sys.exit(1)


class StaticAnalyzer:
    """Static malware analysis engine."""

    def __init__(self, sample_path: str):
        """Initialize analyzer with sample path."""
        self.sample_path = Path(sample_path)
        self.results = {
            "file_info": {},
            "hashes": {},
            "strings": [],
            "pe_info": {},
            "indicators": [],
            "entropy": 0.0,
            "file_type": "unknown",
            "analysis_version": "1.0"
        }

    def analyze(self) -> Dict[str, Any]:
        """Run complete static analysis."""
        try:
            if not self.sample_path.exists():
                return {"error": "Sample file not found"}

            # Basic file information
            self.analyze_file_info()

            # Calculate hashes
            self.calculate_hashes()

            # Identify file type
            self.identify_file_type()

            # Extract strings
            self.extract_strings()

            # Calculate entropy
            self.calculate_entropy()

            # PE analysis if applicable
            if self.is_pe_file():
                self.analyze_pe()

            # Extract indicators
            self.extract_indicators()

            # YARA scanning (if rules exist)
            self.yara_scan()

            # CAPA capability analysis
            self.capa_analyze()

            return self.results

        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def analyze_file_info(self):
        """Analyze basic file information."""
        stat = self.sample_path.stat()
        self.results["file_info"] = {
            "size": stat.st_size,
            "permissions": oct(stat.st_mode),
        }

    def calculate_hashes(self):
        """Calculate file hashes."""
        with open(self.sample_path, "rb") as f:
            data = f.read()
            self.results["hashes"] = {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest()
            }

    def identify_file_type(self):
        """Identify file type using magic."""
        try:
            mime = magic.Magic(mime=True)
            self.results["file_type"] = mime.from_file(str(self.sample_path))
        except:
            self.results["file_type"] = "unknown"

    def is_pe_file(self) -> bool:
        """Check if file is a PE executable."""
        return self.results["file_type"] in [
            "application/x-dosexec",
            "application/x-executable",
            "application/x-msdownload"
        ]

    def extract_strings(self, min_length: int = 4, max_strings: int = 1000):
        """Extract ASCII and Unicode strings from file."""
        strings = []

        with open(self.sample_path, "rb") as f:
            data = f.read()

            # ASCII strings
            ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
            ascii_strings = re.findall(ascii_pattern, data)
            strings.extend([s.decode('ascii', errors='ignore') for s in ascii_strings])

            # Unicode strings (UTF-16LE common in Windows)
            unicode_pattern = rb'(?:[ -~]\x00){' + str(min_length).encode() + rb',}'
            unicode_strings = re.findall(unicode_pattern, data)
            strings.extend([s.decode('utf-16le', errors='ignore') for s in unicode_strings])

        # Categorize and rank strings
        self.results["strings"] = self.rank_strings(strings, max_strings)
        self.results["total_strings_found"] = len(strings)

    def rank_strings(self, strings: List[str], limit: int) -> List[str]:
        """Rank strings by 'interest' level (APIs, paths, reg keys, etc)."""
        scored_strings = []
        
        # Patterns for interesting strings
        interesting_patterns = {
            'api': re.compile(r'^[A-Z][a-zA-Z0-9]{3,}(?:Alloc|Protect|Write|Create|Open|Read|Set|Get|Load|Query)[a-zA-Z0-9]*$'),
            'path': re.compile(r'(?:[a-zA-Z]:\\(?:[\w.-]+\\)*[\w.-]+|/(?:[\w.-]+/)*[\w.-]+)'),
            'registry': re.compile(r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CLASSES_ROOT|CURRENT_CONFIG)'),
            'url': re.compile(r'https?://[^\s<>"]+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}'),
            'ip': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
            'domain': re.compile(r'[a-zA-Z0-9.-]+\.(?:com|net|org|edu|gov|io|biz|info)'),
            'ua': re.compile(r'Mozilla/|User-Agent:', re.I),
            'cmd': re.compile(r'cmd\.exe|powershell\.exe|/bin/sh|/bin/bash', re.I)
        }

        for s in set(strings):
            score = 0
            # Length bonus (moderate length is usually more interesting than very short/long)
            if 6 < len(s) < 100:
                score += 1
            
            # Pattern matches
            for category, pattern in interesting_patterns.items():
                if pattern.search(s):
                    score += 5
                    if category in ['api', 'url', 'ip', 'path']:
                        score += 5 # High priority categories
            
            # Entropy check for string (less random is usually more interesting)
            # (Simplified entropy-like check: ratio of unique characters)
            if len(s) > 0:
                unique_ratio = len(set(s)) / len(s)
                if 0.3 < unique_ratio < 0.7: # Balanced strings are often words/paths
                    score += 2
            
            scored_strings.append((score, s))
        
        # Sort by score (descending) then length (descending)
        scored_strings.sort(key=lambda x: (x[0], len(x[1])), reverse=True)
        
        return [s for score, s in scored_strings[:limit]]

    def calculate_entropy(self):
        """Calculate Shannon entropy of file."""
        with open(self.sample_path, "rb") as f:
            data = f.read()

        if len(data) == 0:
            self.results["entropy"] = 0.0
            return

        # Calculate byte frequency
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        self.results["entropy"] = round(entropy, 2)

        # Flag high entropy (possible packing/encryption)
        if entropy > 7.0:
            self.results["indicators"].append({
                "type": "suspicious",
                "value": "high_entropy",
                "description": f"High entropy ({entropy:.2f}) suggests packing or encryption"
            })

    def analyze_pe(self):
        """Analyze PE file structure."""
        try:
            pe = pefile.PE(str(self.sample_path))

            # Basic PE info
            self.results["pe_info"] = {
                "machine": hex(pe.FILE_HEADER.Machine),
                "sections": [],
                "imports": [],
                "exports": [],
                "compile_time": pe.FILE_HEADER.TimeDateStamp,
                "is_dll": pe.is_dll(),
                "is_exe": pe.is_exe(),
            }

            # Section information
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                self.results["pe_info"]["sections"].append({
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy()
                })

            # Import table
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imports = []
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(imp.name.decode('utf-8', errors='ignore'))
                        if len(imports) >= 50:  # Limit per DLL
                            break

                    self.results["pe_info"]["imports"].append({
                        "dll": dll_name,
                        "functions": imports
                    })

            # Export table
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        self.results["pe_info"]["exports"].append(
                            exp.name.decode('utf-8', errors='ignore')
                        )

            # Check for suspicious imports
            self.check_suspicious_imports()

            pe.close()

        except pefile.PEFormatError as e:
            self.results["pe_info"]["error"] = f"Invalid PE file: {str(e)}"
        except Exception as e:
            self.results["pe_info"]["error"] = str(e)

    def check_suspicious_imports(self):
        """Check for suspicious API imports."""
        suspicious_apis = {
            "VirtualAlloc": "memory_manipulation",
            "VirtualProtect": "memory_manipulation",
            "WriteProcessMemory": "process_injection",
            "CreateRemoteThread": "process_injection",
            "LoadLibrary": "dynamic_loading",
            "GetProcAddress": "dynamic_loading",
            "WinExec": "execution",
            "CreateProcess": "execution",
            "ShellExecute": "execution",
            "URLDownloadToFile": "network",
            "InternetOpen": "network",
            "InternetReadFile": "network",
            "RegSetValue": "registry",
            "RegCreateKey": "registry",
        }

        if "imports" not in self.results["pe_info"]:
            return

        for dll_import in self.results["pe_info"]["imports"]:
            for func in dll_import["functions"]:
                if func in suspicious_apis:
                    self.results["indicators"].append({
                        "type": "suspicious_api",
                        "value": func,
                        "category": suspicious_apis[func],
                        "dll": dll_import["dll"]
                    })

    def extract_indicators(self):
        """Extract IOCs from strings (IPs, URLs, domains, emails)."""
        all_strings = ' '.join(self.results["strings"])

        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, all_strings)
        for ip in set(ips):
            # Filter out common internal IPs
            if not ip.startswith(('127.', '0.0.', '255.255')):
                self.results["indicators"].append({
                    "type": "ip",
                    "value": ip
                })

        # Domain names - use stricter pattern with valid TLDs
        valid_tlds = (
            'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'uk', 'de', 'fr', 'ru', 'cn', 'jp', 'br',
            'in', 'au', 'ca', 'es', 'it', 'nl', 'se', 'no', 'fi', 'dk', 'pl', 'cz', 'at', 'ch', 'be', 'pt',
            'info', 'biz', 'us', 'me', 'tv', 'cc', 'ws', 'xyz', 'top', 'site', 'online', 'club', 'shop', 'app',
            'dev', 'cloud', 'tech', 'pro', 'live', 'download', 'link', 'click', 'work', 'space', 'fun', 'vip',
            'onion', 'bit', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'su', 'ua', 'kz', 'by', 'ir', 'pk', 'bd', 'vn'
        )
        tld_pattern = '|'.join(valid_tlds)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(' + tld_pattern + r')\b'
        domains = re.findall(domain_pattern, all_strings, re.IGNORECASE)
        # The regex returns just the TLD, so we need to find the full domain
        full_domain_pattern = r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*(?:' + tld_pattern + r'))\b'
        domains = re.findall(full_domain_pattern, all_strings, re.IGNORECASE)
        for domain in set(domains):
            # Filter out common extensions and false positives
            if not domain.lower().endswith(('.exe', '.dll', '.sys', '.txt')):
                self.results["indicators"].append({
                    "type": "domain",
                    "value": domain.lower()
                })

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, all_strings, re.IGNORECASE)
        for url in set(urls):
            self.results["indicators"].append({
                "type": "url",
                "value": url
            })

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, all_strings)
        for email in set(emails):
            self.results["indicators"].append({
                "type": "email",
                "value": email.lower()
            })

        # Limit indicators
        self.results["indicators"] = self.results["indicators"][:500]

    def yara_scan(self):
        """Scan with YARA rules if available."""
        yara_rules_path = Path("/analysis/rules.yar")

        if not yara_rules_path.exists():
            self.results["yara_matches"] = []
            return

        try:
            rules = yara.compile(filepath=str(yara_rules_path))
            matches = rules.match(str(self.sample_path))

            self.results["yara_matches"] = [
                {
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta
                }
                for match in matches
            ]

        except Exception as e:
            self.results["yara_matches"] = []
            self.results["yara_error"] = str(e)

    def capa_analyze(self):
        """Run CAPA capability analysis on the sample."""
        import subprocess
        
        self.results["capa"] = {
            "capabilities": [],
            "attack": [],
            "mbc": []
        }
        
        # CAPA works best on PE files and ELF files. 
        # Be more inclusive with white-listing to avoid missing results.
        file_type = self.results.get("file_type", "").lower()
        capa_eligible = any(t in file_type for t in [
            "executable", "x-dosexec", "x-msdownload", "portable-executable", 
            "vnd.microsoft", "msi", "x-elf", "octet-stream"
        ])
        
        if not capa_eligible:
            self.results["capa"]["note"] = f"Skipped: file type '{file_type}' might not be supported"
            return
        
        try:
            # Run capa with JSON output and rules directory
            capa_rules_path = "/analysis/capa-rules"
            result = subprocess.run(
                ["capa", "-r", capa_rules_path, "-j", str(self.sample_path)],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Robust JSON extraction: CAPA might output banners or warnings before the JSON
            raw_output = result.stdout
            capa_output = None
            
            if raw_output:
                # Find the last occurrence of { to the end, hoping it's the JSON block
                # A more robust way is to find the first '{' and last '}'
                try:
                    start_idx = raw_output.find('{')
                    end_idx = raw_output.rfind('}')
                    if start_idx != -1 and end_idx != -1:
                        json_str = raw_output[start_idx:end_idx+1]
                        capa_output = json.loads(json_str)
                except Exception as je:
                    # Assuming a logger is available, otherwise print or store
                    # print(f"WARNING: Failed to extract JSON from CAPA output: {je}")
                    self.results["capa"]["error"] = f"Failed to parse CAPA output: {str(je)[:100]}"

            if capa_output:
                # Extract capabilities
                rules = capa_output.get("rules", {})
                capabilities = []
                attack_techniques = []
                mbc_behaviors = []
                
                for rule_name, rule_data in rules.items():
                    meta = rule_data.get("meta", {})
                    
                    cap = {
                        "name": rule_name,
                        "namespace": meta.get("namespace", ""),
                        "scope": meta.get("scope", "function")
                    }
                    capabilities.append(cap)
                    
                    # Extract ATT&CK techniques
                    attack = meta.get("attack", [])
                    for att in attack:
                        if isinstance(att, dict):
                            attack_techniques.append({
                                "technique": att.get("technique", ""),
                                "id": att.get("id", ""),
                                "tactic": att.get("tactic", "")
                            })
                    
                    # Extract MBC behaviors
                    mbc = meta.get("mbc", [])
                    for m in mbc:
                        if isinstance(m, dict):
                            mbc_behaviors.append({
                                "behavior": m.get("behavior", ""),
                                "id": m.get("id", ""),
                                "objective": m.get("objective", "")
                            })
                
                self.results["capa"]["capabilities"] = capabilities[:100]  # Increase limit
                self.results["capa"]["attack"] = list({json.dumps(a): a for a in attack_techniques}.values())[:50]
                self.results["capa"]["mbc"] = list({json.dumps(m): m for m in mbc_behaviors}.values())[:50]
                
            elif result.stderr:
                # CAPA may output errors for unsupported files
                stderr_lower = result.stderr.lower()
                if "unsupported architecture" in stderr_lower or "aarch64" in stderr_lower or "arm" in stderr_lower:
                    self.results["capa"]["note"] = "CAPA only supports x86/x64 binaries (ARM64 not supported)"
                elif "unsupported" in stderr_lower or "not a supported" in stderr_lower:
                    self.results["capa"]["note"] = "File format not supported by CAPA (requires x86 PE/ELF)"
                else:
                    self.results["capa"]["error"] = result.stderr[:200]
            else:
                self.results["capa"]["note"] = "No capabilities detected"
                    
        except subprocess.TimeoutExpired:
            self.results["capa"]["error"] = "Analysis timed out"
        except FileNotFoundError:
            self.results["capa"]["error"] = "CAPA not installed"
        except Exception as e:
            self.results["capa"]["error"] = str(e)[:200]


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: analyze.py <sample_path>"}))
        sys.exit(1)

    sample_path = sys.argv[1]

    analyzer = StaticAnalyzer(sample_path)
    results = analyzer.analyze()

    # Output results as JSON
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
