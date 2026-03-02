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
            "analysis_version": "1.0",
        }

    def analyze(self) -> Dict[str, Any]:
        """Run complete static analysis."""
        try:
            if not self.sample_path.exists():
                return {"error": "Sample file not found"}

            self.analyze_file_info()

            self.calculate_hashes()

            self.identify_file_type()

            self.extract_strings()

            self.calculate_entropy()

            self.extract_text_snippet()

            if self.is_pe_file():
                self.analyze_pe()

            self.extract_indicators()

            self.yara_scan()

            self.capa_analyze()

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
                "sha256": hashlib.sha256(data).hexdigest(),
            }

    def identify_file_type(self):
        """Identify file type using magic."""
        try:
            mime = magic.Magic(mime=True)
            self.results["file_type"] = mime.from_file(str(self.sample_path))

            desc = magic.Magic()
            self.results["file_info"]["type_desc"] = desc.from_file(
                str(self.sample_path)
            )
        except:
            self.results["file_type"] = "unknown"
            self.results["file_info"]["type_desc"] = "Unknown binary data"

    def extract_text_snippet(self, max_size: int = 4096):
        """Extract a snippet of text from the file if it appears to be text-based."""
        ft = self.results.get("file_type", "").lower()
        is_text = any(
            t in ft for t in ["text/", "javascript", "json", "xml", "shellscript"]
        )

        try:
            with open(self.sample_path, "rb") as f:
                header = f.read(max_size)

            if not is_text:
                printable = sum(1 for b in header if 32 <= b <= 126 or b in [9, 10, 13])
                if len(header) > 0 and (printable / len(header)) > 0.8:
                    is_text = True

            if is_text:
                self.results["text_preview"] = header.decode("utf-8", errors="ignore")
        except:
            pass

    def is_pe_file(self) -> bool:
        """Check if file is a PE executable."""
        ft = self.results["file_type"].lower()
        return any(
            t in ft
            for t in ["x-dosexec", "x-executable", "msdownload", "application/x-msi"]
        )

    def extract_strings(self, min_length: int = 4, max_strings: int = 1000):
        """Extract ASCII and Unicode strings from file."""
        strings = []

        with open(self.sample_path, "rb") as f:
            data = f.read()

            ascii_pattern = rb"[ -~]{" + str(min_length).encode() + rb",}"
            ascii_strings = re.findall(ascii_pattern, data)
            strings.extend([s.decode("ascii", errors="ignore") for s in ascii_strings])

            unicode_pattern = rb"(?:[ -~]\x00){" + str(min_length).encode() + rb",}"
            unicode_strings = re.findall(unicode_pattern, data)
            strings.extend(
                [s.decode("utf-16le", errors="ignore") for s in unicode_strings]
            )

        self.results["strings"] = self.rank_strings(strings, max_strings)
        self.results["total_strings_found"] = len(strings)

    def rank_strings(self, strings: List[str], limit: int) -> List[str]:
        """Rank strings by 'interest' level (APIs, paths, reg keys, etc)."""
        scored_strings = []

        interesting_patterns = {
            "api": re.compile(
                r"^[A-Z][a-zA-Z0-9]{3,}(?:Alloc|Protect|Write|Create|Open|Read|Set|Get|Load|Query)[a-zA-Z0-9]*$"
            ),
            "path": re.compile(
                r"(?:[a-zA-Z]:\\(?:[\w.-]+\\)*[\w.-]+|/(?:[\w.-]+/)*[\w.-]+)"
            ),
            "registry": re.compile(
                r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CLASSES_ROOT|CURRENT_CONFIG)"
            ),
            "url": re.compile(r'https?://[^\s<>"]+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}'),
            "ip": re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
            "domain": re.compile(
                r"[a-zA-Z0-9.-]+\.(?:com|net|org|edu|gov|io|biz|info)"
            ),
            "ua": re.compile(r"Mozilla/|User-Agent:", re.I),
            "cmd": re.compile(r"cmd\.exe|powershell\.exe|/bin/sh|/bin/bash", re.I),
        }

        for s in set(strings):
            score = 0

            if 6 < len(s) < 100:
                score += 1

            for category, pattern in interesting_patterns.items():
                if pattern.search(s):
                    score += 5
                    if category in ["api", "url", "ip", "path"]:
                        score += 5

            if len(s) > 0:
                unique_ratio = len(set(s)) / len(s)
                if 0.3 < unique_ratio < 0.7:
                    score += 2

            scored_strings.append((score, s))

        scored_strings.sort(key=lambda x: (x[0], len(x[1])), reverse=True)

        return [s for score, s in scored_strings[:limit]]

    def calculate_entropy(self):
        """Calculate Shannon entropy of file."""
        with open(self.sample_path, "rb") as f:
            data = f.read()

        if len(data) == 0:
            self.results["entropy"] = 0.0
            return

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        self.results["entropy"] = round(entropy, 2)

        if entropy > 7.0:
            self.results["indicators"].append(
                {
                    "type": "suspicious",
                    "value": "high_entropy",
                    "description": f"High entropy ({entropy:.2f}) suggests packing or encryption",
                }
            )

    def analyze_pe(self):
        """Analyze PE file structure."""
        try:
            pe = pefile.PE(str(self.sample_path))

            self.results["pe_info"] = {
                "machine": hex(pe.FILE_HEADER.Machine),
                "sections": [],
                "imports": [],
                "exports": [],
                "compile_time": pe.FILE_HEADER.TimeDateStamp,
                "is_dll": pe.is_dll(),
                "is_exe": pe.is_exe(),
            }

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").strip(
                    "\x00"
                )
                self.results["pe_info"]["sections"].append(
                    {
                        "name": section_name,
                        "virtual_address": hex(section.VirtualAddress),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": section.get_entropy(),
                    }
                )

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    imports = []
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(imp.name.decode("utf-8", errors="ignore"))
                        if len(imports) >= 50:
                            break

                    self.results["pe_info"]["imports"].append(
                        {"dll": dll_name, "functions": imports}
                    )

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        self.results["pe_info"]["exports"].append(
                            exp.name.decode("utf-8", errors="ignore")
                        )

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
                    self.results["indicators"].append(
                        {
                            "type": "suspicious_api",
                            "value": func,
                            "category": suspicious_apis[func],
                            "dll": dll_import["dll"],
                        }
                    )

    def extract_indicators(self):
        """Extract IOCs from strings (IPs, URLs, domains, emails)."""
        all_strings = " ".join(self.results["strings"])

        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ips = re.findall(ip_pattern, all_strings)
        for ip in set(ips):

            if not ip.startswith(("127.", "0.0.", "255.255")):
                self.results["indicators"].append({"type": "ip", "value": ip})

        valid_tlds = (
            "com",
            "net",
            "org",
            "edu",
            "gov",
            "mil",
            "int",
            "io",
            "co",
            "uk",
            "de",
            "fr",
            "ru",
            "cn",
            "jp",
            "br",
            "in",
            "au",
            "ca",
            "es",
            "it",
            "nl",
            "se",
            "no",
            "fi",
            "dk",
            "pl",
            "cz",
            "at",
            "ch",
            "be",
            "pt",
            "info",
            "biz",
            "us",
            "me",
            "tv",
            "cc",
            "ws",
            "xyz",
            "top",
            "site",
            "online",
            "club",
            "shop",
            "app",
            "dev",
            "cloud",
            "tech",
            "pro",
            "live",
            "download",
            "link",
            "click",
            "work",
            "space",
            "fun",
            "vip",
            "onion",
            "bit",
            "pw",
            "tk",
            "ml",
            "ga",
            "cf",
            "gq",
            "su",
            "ua",
            "kz",
            "by",
            "ir",
            "pk",
            "bd",
            "vn",
        )
        tld_pattern = "|".join(valid_tlds)
        domain_pattern = (
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+("
            + tld_pattern
            + r")\b"
        )
        domains = re.findall(domain_pattern, all_strings, re.IGNORECASE)

        full_domain_pattern = (
            r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*(?:"
            + tld_pattern
            + r"))\b"
        )
        domains = re.findall(full_domain_pattern, all_strings, re.IGNORECASE)
        for domain in set(domains):

            if not domain.lower().endswith((".exe", ".dll", ".sys", ".txt")):
                self.results["indicators"].append(
                    {"type": "domain", "value": domain.lower()}
                )

        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, all_strings, re.IGNORECASE)
        for url in set(urls):
            self.results["indicators"].append({"type": "url", "value": url})

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        emails = re.findall(email_pattern, all_strings)
        for email in set(emails):
            self.results["indicators"].append({"type": "email", "value": email.lower()})

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
                {"rule": match.rule, "tags": match.tags, "meta": match.meta}
                for match in matches
            ]

        except Exception as e:
            self.results["yara_matches"] = []
            self.results["yara_error"] = str(e)

    def capa_analyze(self):
        """Run CAPA capability analysis on the sample."""
        import subprocess

        self.results["capa"] = {"capabilities": [], "attack": [], "mbc": []}

        file_type = self.results.get("file_type", "").lower()
        capa_eligible = any(
            t in file_type
            for t in [
                "executable",
                "x-dosexec",
                "x-msdownload",
                "portable-executable",
                "vnd.microsoft",
                "msi",
                "x-elf",
                "octet-stream",
            ]
        )

        if not capa_eligible:
            self.results["capa"][
                "note"
            ] = f"Skipped: file type '{file_type}' might not be supported"
            return

        try:

            capa_rules_path = "/analysis/capa-rules"
            capa_sigs_path = "/analysis/capa-signatures"
            if os.path.isdir(os.path.join(capa_rules_path, "rules")):
                capa_rules_path = os.path.join(capa_rules_path, "rules")

            result = subprocess.run(
                [
                    "capa",
                    "-r",
                    capa_rules_path,
                    "-s",
                    capa_sigs_path,
                    "-j",
                    str(self.sample_path),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )

            raw_output = result.stdout
            capa_output = None

            if raw_output:
                try:

                    start_idx = raw_output.find("{")
                    end_idx = raw_output.rfind("}")
                    if start_idx != -1 and end_idx != -1:
                        json_str = raw_output[start_idx : end_idx + 1]
                        capa_output = json.loads(json_str)
                except Exception as je:
                    self.results["capa"]["error"] = f"JSON parse error: {str(je)[:100]}"

            if capa_output:

                rules = capa_output.get("rules", {})
                capabilities = []
                attack_techniques = []
                mbc_behaviors = []

                for rule_name, rule_data in rules.items():
                    meta = rule_data.get("meta", {})

                    cap = {
                        "name": rule_name,
                        "namespace": meta.get("namespace", ""),
                        "scope": meta.get("scope", "function"),
                    }
                    capabilities.append(cap)

                    attack = meta.get("attack", [])
                    for att in attack:
                        if isinstance(att, dict):
                            attr_id = att.get("id", "")

                            attack_techniques.append(
                                {
                                    "technique": att.get("technique", ""),
                                    "id": attr_id,
                                    "tactic": att.get("tactic", ""),
                                }
                            )
                        elif isinstance(att, list):

                            for item in att:
                                if isinstance(item, dict):
                                    attack_techniques.append(
                                        {
                                            "technique": item.get("technique", ""),
                                            "id": item.get("id", ""),
                                            "tactic": item.get("tactic", ""),
                                        }
                                    )

                    mbc = meta.get("mbc", [])
                    for m in mbc:
                        if isinstance(m, dict):
                            mbc_behaviors.append(
                                {
                                    "behavior": m.get("behavior", ""),
                                    "id": m.get("id", ""),
                                    "objective": m.get("objective", ""),
                                }
                            )

                self.results["capa"]["capabilities"] = capabilities[:100]
                self.results["capa"]["attack"] = list(
                    {json.dumps(a): a for a in attack_techniques}.values()
                )[:50]
                self.results["capa"]["mbc"] = list(
                    {json.dumps(m): m for m in mbc_behaviors}.values()
                )[:50]

            elif result.stderr:
                stderr_lower = result.stderr.lower()
                if "unsupported" in stderr_lower:
                    self.results["capa"][
                        "note"
                    ] = "CAPA: Unsupported file format or architecture"
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

    def _is_meaningful_xor_string(self, s: str, min_length: int = 6) -> bool:
        """
        Aggressively filter out garbage XOR results.
        Returns True ONLY if the string contains recognizable meaningful content.
        """
        if not s or len(s) < min_length:
            return False

        s_clean = s.strip()
        if len(s_clean) < min_length:
            return False

        # === WHITELIST CHECK: Known malware indicators pass immediately ===
        meaningful_patterns = [
            "http://",
            "https://",
            "ftp://",
            ".exe",
            ".dll",
            ".bat",
            ".cmd",
            ".ps1",
            ".com",
            ".net",
            ".org",
            ".ru",
            ".cn",
            ".onion",
            "C:\\",
            "C:/",
            "Windows",
            "System32",
            "Program Files",
            "AppData",
            "Temp",
            "/bin/",
            "/etc/",
            "/tmp/",
            "/var/",
            "/usr/",
            "CreateProcess",
            "VirtualAlloc",
            "WriteProcessMemory",
            "LoadLibrary",
            "GetProcAddress",
            "ShellExecute",
            "WinExec",
            "RegOpenKey",
            "cmd.exe",
            "powershell",
            "KERNEL32",
            "ntdll",
            "USER32",
            "ADVAPI32",
            "password",
            "admin",
            "root",
            "login",
            "user",
            "secret",
            "Mozilla",
            "User-Agent",
            "GET ",
            "POST ",
            "Host:",
            "HKEY_",
            "SOFTWARE\\",
            "CurrentVersion",
            "Run",
        ]
        s_lower = s_clean.lower()
        for pattern in meaningful_patterns:
            if pattern.lower() in s_lower:
                return True

        # === AGGRESSIVE GARBAGE DETECTION ===

        # Count character frequencies
        char_counts = {}
        for c in s_clean:
            char_counts[c] = char_counts.get(c, 0) + 1

        # Reject if any single character appears more than 35% of the time
        most_common_count = max(char_counts.values())
        if most_common_count / len(s_clean) > 0.35:
            return False

        # Reject low unique character ratio (repetitive garbage)
        unique_ratio = len(char_counts) / len(s_clean)
        if unique_ratio < 0.25:
            return False

        # Reject if too many special characters (>40%)
        special_count = sum(1 for c in s_clean if not c.isalnum() and c not in " ._-/")
        if special_count / len(s_clean) > 0.40:
            return False

        # Detect alternating patterns like "AxBxCxDx" or "AaAaAa"
        if len(s_clean) >= 6:
            # Check for alternating single char pattern
            odd_chars = s_clean[::2]
            even_chars = s_clean[1::2]

            odd_unique = len(set(odd_chars))
            even_unique = len(set(even_chars))

            # If one position is nearly constant while other varies - it's garbage
            if len(odd_chars) >= 3 and odd_unique <= 2 and even_unique >= 3:
                return False
            if len(even_chars) >= 3 and even_unique <= 2 and odd_unique >= 3:
                return False

        # Detect near-repetition: patterns that repeat with minor variations
        for pattern_len in range(2, min(8, len(s_clean) // 2 + 1)):
            chunks = [
                s_clean[i : i + pattern_len]
                for i in range(0, len(s_clean) - pattern_len + 1, pattern_len)
            ]
            if len(chunks) >= 3:
                # Count how many chunks are similar to the first
                first_chunk = chunks[0]
                similar_count = sum(
                    1
                    for chunk in chunks
                    if sum(a == b for a, b in zip(chunk, first_chunk))
                    >= pattern_len * 0.6
                )
                if similar_count >= len(chunks) * 0.6:
                    return False

        # Require minimum letter content for longer strings (not just numbers/symbols)
        letter_count = sum(1 for c in s_clean if c.isalpha())
        if len(s_clean) > 10 and letter_count / len(s_clean) < 0.4:
            return False

        # Check for actual readable words (at least one 3+ letter sequence)
        import re

        words = re.findall(r"[a-zA-Z]{3,}", s_clean)
        if len(s_clean) > 12 and not words:
            return False

        # For strings with words, check they look somewhat meaningful
        # (have vowels, not random consonants)
        if words:
            vowels = set("aeiouAEIOU")
            valid_words = 0
            for word in words:
                has_vowel = any(c in vowels for c in word)
                # Check consonant clusters aren't too extreme
                consonant_runs = re.findall(
                    r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{4,}", word
                )
                reasonable_consonants = len(consonant_runs) == 0 or all(
                    len(run) <= 4 for run in consonant_runs
                )
                if has_vowel and reasonable_consonants:
                    valid_words += 1

            if len(s_clean) > 15 and valid_words == 0:
                return False

        # Final entropy-like check: truly random data has more uniform distribution
        # Real text/code has characteristic distributions
        variance = sum(
            (count - len(s_clean) / len(char_counts)) ** 2
            for count in char_counts.values()
        ) / len(char_counts)
        avg_count = len(s_clean) / len(char_counts)
        if avg_count > 1 and variance / avg_count < 0.3 and len(s_clean) > 15:
            # Very uniform distribution suggests random XOR garbage
            return False

        return True

    def analyze_xor(self):
        """Run XOR-related analysis tools using XORStrings (Didier Stevens tool)."""
        import subprocess
        import re

        self.results["xor_analysis"] = {
            "decoded_strings": [],  # All XOR/ROL/SHIFT-decoded strings found
            "plaintext_urls": [],  # Plain-text HTTP/HTTPS URLs (not obfuscated)
            "performed": True,
        }
        
        # First, check for plain-text HTTP/HTTPS URLs in already-extracted strings
        plaintext_http_urls = []
        for s in self.results.get("strings", []):
            if any(pattern in s for pattern in ["http://", "https://"]):
                url_match = re.search(r'https?://[^\s\'"]+', s)
                if url_match:
                    url = url_match.group(0)
                    if url not in plaintext_http_urls:
                        plaintext_http_urls.append(url)
                        if len(plaintext_http_urls) >= 20:
                            break
        
        self.results["xor_analysis"]["plaintext_urls"] = plaintext_http_urls

        try:
            # Test if xorstrings/xorsearch is available
            test_result = subprocess.run(
                ["xorsearch"], capture_output=True, text=True, timeout=5
            )

            usage_indicators = ["Usage:", "XORStrings", "Didier Stevens"]
            has_usage = any(
                indicator in (test_result.stdout + test_result.stderr)
                for indicator in usage_indicators
            )

            if not has_usage:
                self.results["xor_analysis"][
                    "error"
                ] = f"XORStrings not working - exit code: {test_result.returncode}"
                return

            # XORStrings usage: xorsearch [-l min_length] [-d] file
            # Extract all XOR/ROL/SHIFT encoded strings with -d (dump longest)
            try:
                result = subprocess.run(
                    ["xorsearch", "-l", "10", "-d", str(self.sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                if result.stdout:
                    decoded_strings = []
                    seen_strings = set()
                    
                    # Parse XORStrings output:
                    # Opr   Key  Count Avg   Max
                    #   XOR 0x42     1  40.0    40 http://hidden-domain.com
                    
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if not line or line.startswith("Opr"):
                            continue
                        
                        # Look for lines with decoded strings: "  XOR 0xKEY ... decoded_string"
                        if ("XOR" in line or "ROL" in line or "SHIFT" in line) and "0x" in line:
                            # Extract the decoded string part (after the numbers)
                            parts = line.split(maxsplit=5)
                            if len(parts) >= 6:
                                decoded = parts[5].strip()
                                
                                # Filter meaningful strings
                                if (len(decoded) >= 10 and 
                                    decoded not in seen_strings and
                                    self._is_meaningful_xor_string(decoded, min_length=10)):
                                    
                                    # Extract operation and key
                                    operation = parts[0]  # XOR/ROL/SHIFT
                                    key = parts[1]  # 0xXX
                                    
                                    # Check if contains interesting patterns
                                    interesting_patterns = [
                                        "http://", "https://", "ftp://",
                                        ".exe", ".dll", ".bat", ".ps1", ".sh", ".com",
                                        "cmd", "powershell", "bash", "wget", "curl",
                                        "C:\\", "/bin/", "/etc/", "/tmp/",
                                        "VirtualAlloc", "CreateProcess", "LoadLibrary",
                                        "GET ", "POST ", "User-Agent", "Cookie",
                                        "password", "admin", "token", "api",
                                        "download", "upload", "execute"
                                    ]
                                    
                                    has_interesting = any(
                                        p.lower() in decoded.lower() for p in interesting_patterns
                                    )
                                    
                                    # Include if interesting or reasonably long
                                    if has_interesting or len(decoded) >= 15:
                                        finding = f"{operation} {key}: {decoded}"
                                        decoded_strings.append(finding)
                                        seen_strings.add(decoded)
                                        
                                        if len(decoded_strings) >= 30:  # Limit results
                                            break
                    
                    self.results["xor_analysis"]["decoded_strings"] = decoded_strings
                    
            except subprocess.TimeoutExpired:
                self.results["xor_analysis"]["warning"] = "XORStrings analysis timed out (>30s)"
            except Exception as e:
                self.results["xor_analysis"]["warning"] = f"XORStrings error: {str(e)}"

            # Generate summary
            decoded_count = len(self.results["xor_analysis"]["decoded_strings"])
            plain_count = len(self.results["xor_analysis"]["plaintext_urls"])
            
            summary_parts = []
            if decoded_count > 0:
                summary_parts.append(f"{decoded_count} XOR/ROL/SHIFT-decoded string(s)")
            if plain_count > 0:
                summary_parts.append(f"{plain_count} plain-text URL(s)")
            
            if not summary_parts:
                self.results["xor_analysis"]["summary"] = "No obfuscated content detected"
            else:
                self.results["xor_analysis"]["summary"] = "Found: " + ", ".join(summary_parts)

        except FileNotFoundError:
            # Check which XOR tools are available
            available_tools = []
            for tool in ["xorsearch", "python3"]:
                if shutil.which(tool):
                    available_tools.append(tool)

            self.results["xor_analysis"][
                "xorsearch_error"
            ] = "xorsearch command not found in PATH"
            self.results["xor_analysis"]["available_tools"] = available_tools
            self.results["xor_analysis"]["path_debug"] = os.environ.get(
                "PATH", "no PATH env var"
            )
        except Exception as e:
            self.results["xor_analysis"][
                "xorsearch_error"
            ] = f"xorsearch execution failed: {str(e)}"


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: analyze.py <sample_path>"}))
        sys.exit(1)

    sample_path = sys.argv[1]

    analyzer = StaticAnalyzer(sample_path)
    results = analyzer.analyze()

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
