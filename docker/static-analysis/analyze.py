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
import shutil

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
            "xor_analysis": {},
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
            
            # Extract text snippet for scripts/text files
            self.extract_text_snippet()
            
            # PE analysis if applicable
            if self.is_pe_file():
                self.analyze_pe()

            # Extract indicators
            self.extract_indicators()

            # YARA scanning (if rules exist)
            self.yara_scan()

            # CAPA capability analysis
            self.capa_analyze()
            
            # XOR analysis (xorsearch, brxor, bbcrack)
            self.analyze_xor()

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
            
            # Also get descriptive text for UI
            desc = magic.Magic()
            self.results["file_info"]["type_desc"] = desc.from_file(str(self.sample_path))
        except:
            self.results["file_type"] = "unknown"
            self.results["file_info"]["type_desc"] = "Unknown binary data"

    def extract_text_snippet(self, max_size: int = 4096):
        """Extract a snippet of text from the file if it appears to be text-based."""
        ft = self.results.get("file_type", "").lower()
        is_text = any(t in ft for t in ["text/", "javascript", "json", "xml", "shellscript"])
        
        try:
            with open(self.sample_path, "rb") as f:
                header = f.read(max_size)
                
            # If magic didn't catch it but it looks like text (high printable ratio)
            if not is_text:
                printable = sum(1 for b in header if 32 <= b <= 126 or b in [9, 10, 13])
                if len(header) > 0 and (printable / len(header)) > 0.8:
                    is_text = True
            
            if is_text:
                self.results["text_preview"] = header.decode('utf-8', errors='ignore')
        except:
            pass

    def is_pe_file(self) -> bool:
        """Check if file is a PE executable."""
        ft = self.results["file_type"].lower()
        return any(t in ft for t in [
            "x-dosexec", "x-executable", "msdownload", "application/x-msi"
        ])

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
            # Try both the rules root and the rules subdirectory if it exists
            capa_rules_path = "/analysis/capa-rules"
            capa_sigs_path = "/analysis/capa-signatures"
            if os.path.isdir(os.path.join(capa_rules_path, "rules")):
                capa_rules_path = os.path.join(capa_rules_path, "rules")
                
            result = subprocess.run(
                ["capa", "-r", capa_rules_path, "-s", capa_sigs_path, "-j", str(self.sample_path)],
                capture_output=True,
                text=True,
                timeout=180 # Increased timeout for larger files
            )
            
            raw_output = result.stdout
            capa_output = None
            
            if raw_output:
                try:
                    # Find the first '{' and last '}' to extract the JSON object
                    start_idx = raw_output.find('{')
                    end_idx = raw_output.rfind('}')
                    if start_idx != -1 and end_idx != -1:
                        json_str = raw_output[start_idx:end_idx+1]
                        capa_output = json.loads(json_str)
                except Exception as je:
                    self.results["capa"]["error"] = f"JSON parse error: {str(je)[:100]}"

            if capa_output:
                # Extract capabilities
                # Note: Newer versions of CAPA might have a different JSON structure
                # but we'll try to be compatible with common patterns.
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
                            attr_id = att.get("id", "")
                            # Format: {id: "T1234", technique: "...", tactic: "..."}
                            attack_techniques.append({
                                "technique": att.get("technique", ""),
                                "id": attr_id,
                                "tactic": att.get("tactic", "")
                            })
                        elif isinstance(att, list):
                            # Sometimes it's a list of [id, technique]
                            for item in att:
                                if isinstance(item, dict):
                                    attack_techniques.append({
                                        "technique": item.get("technique", ""),
                                        "id": item.get("id", ""),
                                        "tactic": item.get("tactic", "")
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
                
                self.results["capa"]["capabilities"] = capabilities[:100]
                self.results["capa"]["attack"] = list({json.dumps(a): a for a in attack_techniques}.values())[:50]
                self.results["capa"]["mbc"] = list({json.dumps(m): m for m in mbc_behaviors}.values())[:50]
                
            elif result.stderr:
                stderr_lower = result.stderr.lower()
                if "unsupported" in stderr_lower:
                    self.results["capa"]["note"] = "CAPA: Unsupported file format or architecture"
                else:
                    self.results["capa"]["error"] = f"CAPA error: {result.stderr[:200]}"
            else:
                self.results["capa"]["note"] = "No capabilities detected"
                     
        except subprocess.TimeoutExpired:
            self.results["capa"]["error"] = "CAPA analysis timed out (3 min)"
        except FileNotFoundError:
            self.results["capa"]["error"] = "CAPA tool not found in container"
        except Exception as e:
            self.results["capa"]["error"] = f"CAPA execution failed: {str(e)[:200]}"

    def analyze_xor(self):
        """Run XOR-related analysis tools (xorsearch, brxor, bbcrack)."""
        import subprocess
        
        self.results["xor_analysis"] = {
            "xorsearch_http": [],
            "brxor": [],
            "bbcrack": [],
            "performed": True
        }
        
        # 1. xorsearch for common patterns
        # Patterns to search for in encoded state
        patterns = ["http", "https", "This program", "KERNEL32", "CreateProcess", "ShellExecute"]
        found_lines = set()
        
        try:
            for pattern in patterns:
                # ASCII search (-i for case insensitive)
                # We don't use -p here as it's for PE-file detection only
                result = subprocess.run(
                    ["xorsearch", "-i", str(self.sample_path), pattern],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                if result.stdout:
                    for line in result.stdout.splitlines():
                        l = line.strip()
                        if l:
                            found_lines.add(l)

                # Unicode search (-u)
                result_u = subprocess.run(
                    ["xorsearch", "-i", "-u", str(self.sample_path), pattern],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                if result_u.stdout:
                    for line in result_u.stdout.splitlines():
                        l = line.strip()
                        if l:
                            # Mark as Unicode for clarity in UI
                            if not l.startswith("Unicode:"):
                                l = f"Unicode: {l}"
                            found_lines.add(l)
            
            # Also search for embedded PE files (correct use of -p)
            result_pe = subprocess.run(
                ["xorsearch", "-p", str(self.sample_path)],
                capture_output=True,
                text=True,
                timeout=20
            )
            if result_pe.stdout:
                for line in result_pe.stdout.splitlines():
                    l = line.strip()
                    if l and "found PE file" in l.lower():
                        found_lines.add(f"Potential Embedded PE: {l}")
            
            self.results["xor_analysis"]["xorsearch_http"] = sorted(list(found_lines))[:50]
        except Exception as e:
            self.results["xor_analysis"]["xorsearch_error"] = str(e)

        # 2. brxor.py (Didier Stevens)
        # Try finding the script in common locations
        brxor_cmd = None
        for cmd in ["brxor.py", "/usr/local/bin/brxor.py", "/opt/didier-suite/brxor.py"]:
            if shutil.which(cmd) or os.path.exists(cmd):
                brxor_cmd = cmd
                break
        
        if brxor_cmd:
            try:
                result = subprocess.run(
                    [sys.executable, brxor_cmd, str(self.sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.stdout:
                    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                    self.results["xor_analysis"]["brxor"] = lines[:20]
            except Exception:
                pass

        # 3. bbcrack.py (Didier Stevens)
        bbcrack_cmd = None
        for cmd in ["bbcrack.py", "/usr/local/bin/bbcrack.py", "/opt/didier-suite/bbcrack.py"]:
            if shutil.which(cmd) or os.path.exists(cmd):
                bbcrack_cmd = cmd
                break
                
        if bbcrack_cmd:
            try:
                result = subprocess.run(
                    [sys.executable, bbcrack_cmd, str(self.sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.stdout:
                    # bbcrack output can be long, take first 30 lines
                    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                    self.results["xor_analysis"]["bbcrack"] = lines[:30]
            except Exception:
                pass


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
