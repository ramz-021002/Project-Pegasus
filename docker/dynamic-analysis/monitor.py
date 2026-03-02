#!/usr/bin/env python3
"""
Dynamic malware analysis monitor for Project Pegasus.
Executes malware in controlled environment and monitors behavior.
"""

import json
import sys
import os
import subprocess
import shutil
import time
import signal
from pathlib import Path
from typing import Dict, List, Any, Tuple
import threading
import queue

try:
    import psutil
except ImportError:
    print(json.dumps({"error": "psutil not installed"}))
    sys.exit(1)


class DynamicAnalyzer:
    """Dynamic malware analysis engine."""

    def __init__(self, sample_path: str, timeout: int = 30):
        """Initialize analyzer."""
        self.sample_path = Path(sample_path)
        self.timeout = int(os.getenv("EXECUTION_TIMEOUT", timeout))
        self.workspace = Path("/analysis/workspace")
        self.results = {
            "executed": False,
            "processes": [],
            "network_connections": [],
            "dns_queries": [],
            "urls_found": [],
            "file_operations": [],
            "system_calls": [],
            "commands_executed": [],
            "processes_killed": [],
            "files_accessed": [],
            "behavior_summary": {},
            "errors": [],
            "trace_debug": [],
        }
        self.process = None
        self.start_time = None
        self.tcpdump_proc = None
        self.pcap_file = "/tmp/capture.pcap"

        self.original_filename = os.getenv("ORIGINAL_FILENAME", str(sample_path))

    def analyze(self) -> Dict[str, Any]:
        """Run dynamic analysis."""
        try:
            if not self.sample_path.exists():

                try:
                    print(f"DEBUG: Workspace contents ({self.workspace}):")
                    for item in self.workspace.iterdir():
                        print(
                            f" - {item} ({oct(item.stat().st_mode)[-3:]}) uid={item.stat().st_uid} gid={item.stat().st_gid}"
                        )
                except Exception as e:
                    print(f"DEBUG: Failed to list workspace: {e}")
                return {"error": "Sample file not found"}

            self.results["urls_found"] = self.extract_urls_from_sample()

            is_windows = self.is_windows_executable()
            interpreter, is_script = self.get_script_interpreter()
            qemu_cmd = None
            if not is_windows and not is_script:
                qemu_cmd = self.get_qemu_for_elf()

            try:
                file_desc = subprocess.run(
                    ["file", "-b", str(self.sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout.strip()
            except Exception as e:
                file_desc = f"file_cmd_failed:{e}"

            self.results.setdefault("debug", {})
            self.results["debug"]["file_desc"] = file_desc
            self.results["debug"]["is_windows"] = bool(is_windows)
            self.results["debug"]["is_script"] = bool(is_script)
            self.results["debug"]["pre_qemu_cmd"] = qemu_cmd

            exec_dir = Path("/tmp")
            exec_path = exec_dir / f"sample_exec_{os.getpid()}"
            try:
                if not self.sample_path.exists():
                    raise FileNotFoundError(str(self.sample_path))
                shutil.copy2(self.sample_path, exec_path)
                self.sample_path = exec_path
            except Exception as e:
                self.results.setdefault("debug", {})["copy_error"] = str(e)

            try:
                os.chmod(self.sample_path, 0o755)
            except Exception as e:
                self.results.setdefault("debug", {})["chmod_error"] = str(e)

            try:
                upx_unpacked = self.attempt_upx_unpack()
                self.results.setdefault("debug", {})["upx_unpacked"] = bool(
                    upx_unpacked
                )
            except Exception as e:
                self.results.setdefault("debug", {})["upx_unpack_error"] = str(e)

            if is_windows:
                return self.execute_with_wine()

            if is_script:
                return self.execute_script(interpreter)

            if qemu_cmd:
                return self.execute_with_qemu(qemu_cmd)

            fallback_qemu = self._check_native_compat()
            if fallback_qemu:
                return self.execute_with_qemu(fallback_qemu)

            try:
                return self.execute_native()
            except OSError as e:
                if hasattr(e, "errno") and e.errno == 8:
                    qemu_fallback = (
                        self.get_qemu_for_elf() or self._check_native_compat()
                    )
                    if qemu_fallback:
                        self.results.setdefault("debug", {})
                        self.results["debug"]["fallback_reason"] = "ENOEXEC"
                        self.results["debug"]["qemu_fallback"] = qemu_fallback
                        return self.execute_with_qemu(qemu_fallback)

                    if str(self.sample_path).endswith(".js"):
                        self.results["errors"].append(
                            "Exec format error: This is a JavaScript file. Try running with Node.js (node <file.js>)."
                        )
                    else:
                        self.results["errors"].append(
                            "Exec format error: Not a native Linux executable or missing interpreter."
                        )
                else:
                    self.results["errors"].append(f"Execution error: {e}")
                return self.results

        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def _check_native_compat(self) -> str:
        """
        Last-resort check: if the binary is an ELF for a different architecture
        that get_qemu_for_elf() didn't catch (e.g. unknown machine type or
        reading error), use `file` command as a fallback detector.
        Returns a QEMU binary name if emulation is needed, else None.
        """
        try:
            import platform

            host = platform.machine()

            result = subprocess.run(
                ["file", "-b", str(self.sample_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            desc = result.stdout.lower()

            arch_map = [
                ("x86-64", "x86_64", "qemu-x86_64-static"),
                ("intel 80386", "i386", "qemu-i386-static"),
                ("aarch64", "aarch64", "qemu-aarch64-static"),
                ("arm,", "arm", "qemu-arm-static"),
                ("mips", "mips", "qemu-mips-static"),
                ("powerpc", "ppc", "qemu-ppc-static"),
                ("sparc", "sparc", "qemu-sparc-static"),
                ("s390", "s390x", "qemu-s390x-static"),
                ("risc-v", "riscv64", "qemu-riscv64-static"),
            ]

            native_aliases = {
                "x86_64": ["x86-64", "intel 80386"],
                "aarch64": ["aarch64", "arm,"],
                "i686": ["intel 80386"],
                "armv7l": ["arm,"],
            }
            host_native = native_aliases.get(host, [host.lower()])

            for keyword, _arch_name, qemu_bin in arch_map:
                if keyword in desc:

                    if keyword in host_native:
                        return None

                    base = qemu_bin
                    if base.endswith("-static"):
                        base_no_static = base.replace("-static", "")
                    else:
                        base_no_static = base + "-static"

                    candidates = []

                    if os.path.isfile(f"/usr/bin/{base}"):
                        candidates.append(base)
                    if os.path.isfile(f"/usr/bin/{base_no_static}"):
                        candidates.append(base_no_static)
                    if candidates:
                        return candidates
                    return None

        except Exception as e:
            self.results["errors"].append(f"Compat check error: {e}")
        return None

    def get_qemu_for_elf(self) -> str:
        try:
            import platform

            host_arch = platform.machine()

            with open(self.sample_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return None

                elf_class = f.read(1)[0]

                f.read(1)

                f.read(1)

                f.read(1)

                f.read(8)

                f.read(2)

                machine_bytes = f.read(2)
                machine = int.from_bytes(machine_bytes, "little")

                elf_machines = {
                    0x03: ("i386", "qemu-i386"),
                    0x3E: ("x86_64", "qemu-x86_64"),
                    0x28: ("arm", "qemu-arm"),
                    0xB7: ("aarch64", "qemu-aarch64"),
                    0x08: ("mips", "qemu-mips"),
                    0x14: ("ppc", "qemu-ppc"),
                    0x15: ("ppc64", "qemu-ppc64"),
                    0x02: ("sparc", "qemu-sparc"),
                    0x2B: ("sparc64", "qemu-sparc64"),
                    0x16: ("s390", "qemu-s390x"),
                    0xF3: ("riscv", "qemu-riscv64"),
                    0x32: ("sh4", "qemu-sh4"),
                    0x5C: ("m68k", "qemu-m68k"),
                }

                if machine not in elf_machines:
                    return None

                elf_arch, qemu_bin = elf_machines[machine]

                native_matches = {
                    "x86_64": ["x86_64", "i386"],
                    "aarch64": ["aarch64", "arm"],
                    "i686": ["i386"],
                    "armv7l": ["arm"],
                }

                host_native = native_matches.get(host_arch, [host_arch])

                if elf_arch in host_native:
                    return None

                candidates = []
                for variant in [f"{qemu_bin}-static", qemu_bin]:
                    if os.path.exists(f"/usr/bin/{variant}"):
                        candidates.append(variant)

                return candidates if candidates else None

        except Exception as e:
            self.results["errors"].append(f"ELF detection error: {str(e)}")
            return None

    def is_windows_executable(self) -> bool:
        """Check if sample is Windows PE."""
        try:
            with open(self.sample_path, "rb") as f:
                header = f.read(2)
                return header == b"MZ"
        except:
            return False

    def extract_urls_from_sample(self) -> List[Dict]:
        """Extract URLs and hostnames from sample file."""
        import re

        urls_found = []
        seen = set()

        try:

            try:
                with open(
                    self.sample_path, "r", encoding="utf-8", errors="ignore"
                ) as f:
                    content = f.read(1024 * 100)
            except:
                with open(self.sample_path, "rb") as f:
                    content = f.read(1024 * 100).decode("utf-8", errors="ignore")

            url_pattern = re.compile(
                r'https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\'"<>]*)?',
                re.IGNORECASE,
            )

            for match in url_pattern.finditer(content):
                url = match.group(0)
                if url not in seen:
                    seen.add(url)

                    host_match = re.search(r"https?://([^/:]+)", url)
                    hostname = host_match.group(1) if host_match else url
                    urls_found.append(
                        {"url": url[:200], "hostname": hostname, "type": "url"}
                    )

            host_patterns = [
                r'["\']([a-zA-Z0-9][-a-zA-Z0-9.]*\.(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk))["\']',
                r'\.get\(["\']([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})',
                r'\.request\(["\']([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})',
            ]

            for pattern in host_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    hostname = match.group(1)
                    if hostname not in seen and not hostname.startswith("."):
                        seen.add(hostname)
                        urls_found.append(
                            {"url": hostname, "hostname": hostname, "type": "hostname"}
                        )

        except Exception as e:
            self.results["errors"].append(f"URL extraction error: {str(e)}")

        return urls_found[:20]

    def get_script_interpreter(self) -> tuple:
        """
        Detect script type and return appropriate interpreter.
        Returns (interpreter_cmd, is_script) tuple.
        """

        filename = self.original_filename.lower()

        script_interpreters = {
            ".js": ["node"],
            ".mjs": ["node"],
            ".py": ["python3"],
            ".pyw": ["python3"],
            ".sh": ["bash"],
            ".bash": ["bash"],
            ".pl": ["perl"],
            ".pm": ["perl"],
            ".rb": ["ruby"],
            ".php": ["php"],
            ".lua": ["lua"],
            ".vbs": ["cscript", "//Nologo"],
            ".ps1": ["powershell", "-ExecutionPolicy", "Bypass", "-File"],
            ".bat": ["cmd.exe", "/c"],
            ".cmd": ["cmd.exe", "/c"],
        }

        for ext, interpreter in script_interpreters.items():
            if filename.endswith(ext):
                return interpreter, True

        try:
            with open(self.sample_path, "rb") as f:
                first_line = f.readline(256)
                if first_line.startswith(b"#!"):
                    shebang = first_line.decode("utf-8", errors="ignore").strip()
                    if "python" in shebang:
                        return ["python3"], True
                    elif "node" in shebang or "nodejs" in shebang:
                        return ["node"], True
                    elif "bash" in shebang or "/sh" in shebang:
                        return ["bash"], True
                    elif "perl" in shebang:
                        return ["perl"], True
                    elif "ruby" in shebang:
                        return ["ruby"], True
                    elif "php" in shebang:
                        return ["php"], True
        except:
            pass

        try:
            with open(self.sample_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(2048)

                js_keywords = [
                    "var ",
                    "let ",
                    "const ",
                    "function ",
                    "=>",
                    "require(",
                    "module.exports",
                    "console.log",
                ]
                if any(kw in content for kw in js_keywords):
                    return ["node"], True
        except Exception as e:
            pass

        return None, False

    def attempt_upx_unpack(self) -> bool:
        """
        Attempt to unpack UPX-packed executables in-place using the `upx` tool.
        Returns True if unpack succeeded, False otherwise.
        """
        try:
            upx_path = shutil.which("upx")
            dbg = self.results.setdefault("debug", {})
            if not upx_path:
                dbg["upx_available"] = False
                return False

            dbg["upx_available"] = True

            backup_path = Path(str(self.sample_path) + ".upxbak")
            try:
                shutil.copy2(self.sample_path, backup_path)
                dbg["upx_backup"] = str(backup_path)
            except Exception:
                dbg["upx_backup"] = "backup_failed"

            proc = subprocess.run(
                [upx_path, "-d", str(self.sample_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            dbg["upx_returncode"] = proc.returncode
            dbg["upx_stdout"] = (proc.stdout or "")[:2000]
            dbg["upx_stderr"] = (proc.stderr or "")[:2000]

            return proc.returncode == 0
        except Exception as e:
            self.results.setdefault("debug", {})["upx_exception"] = str(e)
            return False

    def start_tcpdump(self):
        """Start tcpdump to capture all network traffic."""
        try:
            self.tcpdump_proc = subprocess.Popen(
                ["tcpdump", "-i", "any", "-n", "-w", self.pcap_file],
                stdout=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )

            time.sleep(0.5)

            try:
                self.results["urls_found"] = self.extract_urls_from_sample()
            except Exception:
                pass

            try:
                interpreter, is_script = self.get_script_interpreter()
                if is_script and interpreter and interpreter[0] == "node":
                    deob = getattr(self, "deobfuscate_javascript", lambda: None)()
                    if deob:
                        self.results["js_deobfuscated"] = deob
            except Exception:
                pass
        except Exception as e:
            self.results["errors"].append(f"tcpdump start failed: {str(e)}")

    def stop_tcpdump(self):
        """Stop tcpdump and parse captured traffic."""
        if self.tcpdump_proc:
            try:
                os.killpg(os.getpgid(self.tcpdump_proc.pid), signal.SIGTERM)
                self.tcpdump_proc.wait(timeout=5)
            except:
                pass

            self.parse_pcap()

    def parse_pcap(self):
        """Parse pcap file for network connections and DNS queries."""
        if not os.path.exists(self.pcap_file):
            self.results["errors"].append("PCAP file not found - tcpdump may have failed to capture")
            return

        try:
            # Parse with more verbose output to get protocol info
            result = subprocess.run(
                ["tcpdump", "-n", "-r", self.pcap_file, "-tt"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            seen_connections = set()
            for line in result.stdout.split("\n"):
                # Skip empty lines
                if not line.strip():
                    continue

                # Detect protocol
                protocol = "unknown"
                if " tcp " in line.lower():
                    protocol = "tcp"
                elif " udp " in line.lower():
                    protocol = "udp"
                elif " icmp " in line.lower():
                    protocol = "icmp"

                # Look for IP traffic with port info
                if " > " in line and ("IP" in line or "IP6" in line):
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == ">" and i > 0 and i < len(parts) - 1:
                            src = parts[i - 1]
                            dst = parts[i + 1].rstrip(":")

                            # Parse source
                            src_ip = None
                            src_port = None
                            if "." in src:
                                src_parts = src.rsplit(".", 1)
                                if len(src_parts) == 2:
                                    try:
                                        src_ip = src_parts[0]
                                        src_port = int(src_parts[1])
                                    except ValueError:
                                        src_ip = src

                            # Parse destination
                            if "." in dst:
                                dst_parts = dst.rsplit(".", 1)
                                if len(dst_parts) == 2:
                                    try:
                                        dst_ip = dst_parts[0]
                                        dst_port = int(dst_parts[1])

                                        # Skip mDNS and multicast
                                        if dst_port in [5353]:
                                            continue
                                        if dst_ip in ["224.0.0.251", "ff02::fb"]:
                                            continue

                                        conn_key = (dst_ip, dst_port)
                                        if conn_key not in seen_connections:
                                            seen_connections.add(conn_key)
                                            conn_info = {
                                                "dst_ip": dst_ip,
                                                "dst_port": dst_port,
                                                "protocol": protocol,
                                            }
                                            if src_ip:
                                                conn_info["local_addr"] = f"{src_ip}:{src_port}" if src_port else src_ip
                                            self.results["network_connections"].append(conn_info)
                                    except ValueError:
                                        pass

            dns_result = subprocess.run(
                ["tcpdump", "-n", "-r", self.pcap_file, "port 53", "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            import re

            dns_patterns = [
                r"A\? ([a-zA-Z0-9\.\-]+)\.",
                r"AAAA\? ([a-zA-Z0-9\.\-\:]+)\.",
            ]
            for pattern in dns_patterns:
                for match in re.findall(pattern, dns_result.stdout):
                    if match not in [
                        q.get("domain") for q in self.results.get("dns_queries", [])
                    ]:
                        self.results["dns_queries"].append(
                            {
                                "domain": match,
                                "type": "A" if "AAAA" not in pattern else "AAAA",
                            }
                        )

        except Exception as e:
            self.results["errors"].append(f"pcap parse error: {str(e)}")

    def execute_native(self) -> Dict[str, Any]:
        """Execute native Linux malware with monitoring."""
        try:
            self.results["execution_method"] = "native"

            self.start_tcpdump()

            cmd = [str(self.sample_path)]

            results_queue = queue.Queue()

            self.start_time = time.time()

            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            strace_thread = threading.Thread(
                target=self.monitor_with_strace, args=(cmd, results_queue)
            )
            strace_thread.start()

            strace_thread.join(timeout=self.timeout + 5)

            try:
                while True:
                    result = results_queue.get_nowait()
                    if "system_calls" in result:
                        self.results["system_calls"] = result["system_calls"]
                    if "network_connections" in result:
                        self.results["network_connections"].extend(
                            result["network_connections"]
                        )
                    if "dns_queries" in result:
                        self.results["dns_queries"].extend(result["dns_queries"])
                    if "commands_executed" in result:

                        for cmd_obj in result["commands_executed"]:
                            cmd_str = cmd_obj.get("cmdline", cmd_obj.get("binary"))
                            if (
                                cmd_str
                                and cmd_str not in self.results["commands_executed"]
                            ):
                                self.results["commands_executed"].append(cmd_str)
                    if "processes" in result:

                        for p_obj in result["processes"]:
                            p_cmd = p_obj.get("cmdline") or p_obj.get("name")
                            if p_cmd and p_cmd not in self.results["commands_executed"]:
                                self.results["commands_executed"].append(p_cmd)
                    if "processes_killed" in result:
                        self.results["processes_killed"].extend(
                            result["processes_killed"]
                        )
                    if "files_accessed" in result:
                        self.results["files_accessed"].extend(result["files_accessed"])
            except queue.Empty:
                pass

            try:
                syscalls = self.results.get("system_calls", []) or []
                enoexec_seen = any(
                    "ENOEXEC" in sc or "Exec format error" in sc for sc in syscalls
                )
                if enoexec_seen:
                    qemu_bin = self.get_qemu_for_elf() or self._check_native_compat()
                    if qemu_bin:
                        self.results.setdefault("debug", {})
                        self.results["debug"][
                            "fallback_reason"
                        ] = "ENOEXEC-detected-in-strace"
                        self.results["debug"]["qemu_fallback"] = qemu_bin

                        try:
                            self.stop_tcpdump()
                        except Exception:
                            pass
                        return self.execute_with_qemu(qemu_bin)
            except Exception:

                pass

            time.sleep(2)

            self.stop_tcpdump()

            self.results["executed"] = True
            self.summarize_behavior()

            return self.results

        except Exception as e:
            self.stop_tcpdump()
            self.results["errors"].append(str(e))
            return self.results

    def execute_with_qemu(self, qemu_bin: str) -> Dict[str, Any]:
        """Execute foreign-architecture ELF with QEMU user-mode emulation."""
        try:

            candidates = qemu_bin if isinstance(qemu_bin, (list, tuple)) else [qemu_bin]
            self.results["execution_method"] = f"qemu ({', '.join(candidates)})"

            self.start_tcpdump()

            qemu_attempts = []
            for candidate in candidates:
                if not candidate:
                    continue
                path = f"/usr/bin/{candidate}"
                if not os.path.exists(path):
                    qemu_attempts.append({"candidate": candidate, "error": "not_found"})
                    continue

                cmd = [path, str(self.sample_path)]

                self.results.setdefault("debug", {})
                self.results["debug"].setdefault("qemu_attempts", [])
                self.results["debug"]["pre_qemu_cmd"] = cmd

                results_queue = queue.Queue()
                self.start_time = time.time()

                process_thread = threading.Thread(target=self.monitor_processes)
                process_thread.daemon = True
                process_thread.start()

                network_thread = threading.Thread(target=self.monitor_network)
                network_thread.daemon = True
                network_thread.start()

                strace_thread = threading.Thread(
                    target=self.monitor_with_strace, args=(cmd, results_queue)
                )
                strace_thread.start()
                strace_thread.join(timeout=self.timeout + 5)

                try:
                    while True:
                        result = results_queue.get_nowait()
                        if "system_calls" in result:
                            self.results["system_calls"] = result["system_calls"]
                        if "network_connections" in result:
                            self.results["network_connections"].extend(
                                result["network_connections"]
                            )
                        if "dns_queries" in result:
                            self.results["dns_queries"].extend(result["dns_queries"])
                        if "commands_executed" in result:
                            self.results["commands_executed"].extend(
                                result["commands_executed"]
                            )
                        if "processes_killed" in result:
                            self.results["processes_killed"].extend(
                                result["processes_killed"]
                            )
                        if "files_accessed" in result:
                            self.results["files_accessed"].extend(
                                result["files_accessed"]
                            )
                except queue.Empty:
                    pass

                syscalls = self.results.get("system_calls", []) or []
                enoexec_seen = any(
                    "ENOEXEC" in sc or "Exec format error" in sc for sc in syscalls
                )
                perm_denied = any(
                    "EACCES" in sc or "Permission denied" in sc for sc in syscalls
                )

                qemu_attempts.append(
                    {
                        "candidate": candidate,
                        "syscalls_sample": syscalls[:8],
                    }
                )

                if syscalls and not (enoexec_seen or perm_denied):
                    self.results.setdefault("debug", {})["qemu_chosen"] = candidate
                    self.results.setdefault("debug", {})[
                        "qemu_attempts"
                    ] = qemu_attempts

                    try:
                        self.stop_tcpdump()
                    except Exception:
                        pass
                    self.results["executed"] = True
                    self.summarize_behavior()
                    return self.results

                time.sleep(0.5)

            self.results.setdefault("debug", {})["qemu_attempts"] = qemu_attempts
            self.results["errors"].append(
                "QEMU attempts failed or produced no observable syscalls"
            )
            self.stop_tcpdump()
            return self.results

            results_queue = queue.Queue()

            self.start_time = time.time()

            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            strace_thread = threading.Thread(
                target=self.monitor_with_strace, args=(cmd, results_queue)
            )
            strace_thread.start()

            strace_thread.join(timeout=self.timeout + 5)

            try:
                while True:
                    result = results_queue.get_nowait()
                    if "system_calls" in result:
                        self.results["system_calls"] = result["system_calls"]
                    if "network_connections" in result:
                        self.results["network_connections"].extend(
                            result["network_connections"]
                        )
                    if "dns_queries" in result:
                        self.results["dns_queries"].extend(result["dns_queries"])
                    if "commands_executed" in result:

                        for cmd_obj in result["commands_executed"]:
                            cmd_str = cmd_obj.get("cmdline", cmd_obj.get("binary"))
                            if (
                                cmd_str
                                and cmd_str not in self.results["commands_executed"]
                            ):
                                self.results["commands_executed"].append(cmd_str)
                    if "processes" in result:

                        for p_obj in result["processes"]:
                            p_cmd = p_obj.get("cmdline") or p_obj.get("name")
                            if p_cmd and p_cmd not in self.results["commands_executed"]:
                                self.results["commands_executed"].append(p_cmd)
                    if "processes_killed" in result:
                        self.results["processes_killed"].extend(
                            result["processes_killed"]
                        )
                    if "files_accessed" in result:
                        self.results["files_accessed"].extend(result["files_accessed"])
            except queue.Empty:
                pass

            time.sleep(2)

            self.stop_tcpdump()

            self.results["executed"] = True
            self.summarize_behavior()

            return self.results

        except Exception as e:
            self.stop_tcpdump()
            self.results["errors"].append(str(e))
            return self.results

    def execute_script(self, interpreter: List[str]) -> Dict[str, Any]:
        """Execute script file with appropriate interpreter."""
        try:
            self.results["execution_method"] = f"script ({interpreter[0]})"

            self.start_tcpdump()

            cmd = interpreter + [str(self.sample_path)]

            results_queue = queue.Queue()

            self.start_time = time.time()

            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            strace_thread = threading.Thread(
                target=self.monitor_with_strace, args=(cmd, results_queue)
            )
            strace_thread.start()

            strace_thread.join(timeout=self.timeout + 5)

            try:
                while True:
                    result = results_queue.get_nowait()
                    if "error" in result:
                        self.results["errors"].append(
                            f"Monitor thread error: {result['error']}"
                        )
                    if "system_calls" in result:
                        self.results["system_calls"] = result["system_calls"]
                    if "network_connections" in result:
                        self.results["network_connections"].extend(
                            result["network_connections"]
                        )
                    if "dns_queries" in result:
                        self.results["dns_queries"].extend(result["dns_queries"])
                    if "commands_executed" in result:

                        for cmd_obj in result["commands_executed"]:
                            cmd_str = cmd_obj.get("cmdline", cmd_obj.get("binary"))
                            if (
                                cmd_str
                                and cmd_str not in self.results["commands_executed"]
                            ):
                                self.results["commands_executed"].append(cmd_str)
                    if "processes" in result:

                        for p_obj in result["processes"]:
                            p_cmd = p_obj.get("cmdline") or p_obj.get("name")
                            if p_cmd and p_cmd not in self.results["commands_executed"]:
                                self.results["commands_executed"].append(p_cmd)
                    if "processes_killed" in result:
                        self.results["processes_killed"].extend(
                            result["processes_killed"]
                        )
                    if "files_accessed" in result:
                        self.results["files_accessed"].extend(result["files_accessed"])
            except queue.Empty:
                pass

            time.sleep(2)

            self.stop_tcpdump()

            self.results["executed"] = True
            self.summarize_behavior()

            return self.results

        except Exception as e:
            self.stop_tcpdump()
            self.results["errors"].append(str(e))
            return self.results

    def _find_wine(self) -> str:
        """Locate a working wine binary. Returns path or None."""
        for candidate in ["wine", "wine64", "/usr/bin/wine", "/usr/local/bin/wine"]:
            if os.path.isfile(candidate) or shutil.which(candidate):
                return shutil.which(candidate) or candidate
        return None

    def _get_pe_arch(self) -> str:
        """
        Read the PE COFF header to determine the target architecture.
        Returns a QEMU binary name suitable for emulating this PE,
        or None if native / unrecognisable.
        """
        try:
            import struct, platform

            host = platform.machine()
            with open(self.sample_path, "rb") as f:
                if f.read(2) != b"MZ":
                    return None
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset)
                if f.read(4) != b"PE\x00\x00":
                    return None
                machine = struct.unpack("<H", f.read(2))[0]

            pe_machines = {
                0x14C: ("i386", "qemu-i386-static"),
                0x8664: ("x86_64", "qemu-x86_64-static"),
                0x1C0: ("arm", "qemu-arm-static"),
                0xAA64: ("aarch64", "qemu-aarch64-static"),
            }
            if machine not in pe_machines:
                return None
            pe_arch, qemu_bin = pe_machines[machine]

            native = {
                "x86_64": ["x86_64", "i386"],
                "aarch64": ["aarch64", "arm"],
                "i686": ["i386"],
                "armv7l": ["arm"],
            }
            if pe_arch in native.get(host, [host]):
                return None
            for v in [qemu_bin, qemu_bin.replace("-static", "")]:
                if os.path.isfile(f"/usr/bin/{v}"):
                    return v
        except Exception:
            pass
        return None

    def execute_with_wine(self) -> Dict[str, Any]:
        """Execute Windows PE with Wine and monitoring.
        Uses strace to capture commands executed, files accessed, and network
        activity — matching the approach used by execute_native/execute_with_qemu.
        Falls back to QEMU user-mode + strace when Wine is unavailable
        (e.g. ARM64 hosts running x86 PE malware)."""

        wine_bin = self._find_wine()

        if wine_bin is None:
            qemu_bin = self._get_pe_arch()
            if qemu_bin:
                self.results["execution_method"] = f"qemu-pe ({qemu_bin})"
                self.results["errors"].append(
                    "Wine not available; executing PE under QEMU user-mode "
                    "(syscall-level emulation, no Windows API layer)"
                )
                return self.execute_with_qemu(qemu_bin)

            self.results["execution_method"] = "skipped (no wine, no qemu)"
            self.results["executed"] = False
            self.results["errors"].append(
                "Windows PE dynamic analysis unavailable: "
                "Wine is not installed and no suitable QEMU emulator found. "
                "Static analysis results are still available."
            )
            self.summarize_behavior()
            return self.results

        try:
            self.results["execution_method"] = "wine"

            self.start_tcpdump()

            workspace_sample = self.sample_path

            env = os.environ.copy()
            env["WINEDEBUG"] = "-all"
            env["WINEPREFIX"] = "/tmp/.wine"

            cmd = [wine_bin, str(workspace_sample)]

            results_queue = queue.Queue()

            self.start_time = time.time()

            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            strace_thread = threading.Thread(
                target=self.monitor_with_strace, args=(cmd, results_queue)
            )
            strace_thread.start()

            strace_thread.join(timeout=self.timeout + 5)

            try:
                while True:
                    result = results_queue.get_nowait()
                    if "system_calls" in result:
                        self.results["system_calls"] = result["system_calls"]
                    if "network_connections" in result:
                        self.results["network_connections"].extend(
                            result["network_connections"]
                        )
                    if "dns_queries" in result:
                        self.results["dns_queries"].extend(result["dns_queries"])
                    if "commands_executed" in result:

                        for cmd_obj in result["commands_executed"]:
                            cmd_str = cmd_obj.get("cmdline", cmd_obj.get("binary"))
                            if (
                                cmd_str
                                and cmd_str not in self.results["commands_executed"]
                            ):
                                self.results["commands_executed"].append(cmd_str)
                    if "processes" in result:

                        for p_obj in result["processes"]:
                            p_cmd = p_obj.get("cmdline") or p_obj.get("name")
                            if p_cmd and p_cmd not in self.results["commands_executed"]:
                                self.results["commands_executed"].append(p_cmd)
                    if "processes_killed" in result:
                        self.results["processes_killed"].extend(
                            result["processes_killed"]
                        )
                    if "files_accessed" in result:
                        self.results["files_accessed"].extend(result["files_accessed"])
            except queue.Empty:
                pass

            time.sleep(2)

            self.stop_tcpdump()

            self.check_file_operations()

            self.results["executed"] = True
            self.summarize_behavior()

            return self.results

        except Exception as e:
            self.stop_tcpdump()
            self.results["errors"].append(str(e))
            return self.results

    def log_debug(self, msg):

        if "trace_debug" not in self.results:
            self.results["trace_debug"] = []
        self.results["trace_debug"].append(msg)

    def monitor_with_strace(self, cmd: List[str], results_queue: queue.Queue):
        """Monitor system calls with strace."""
        self.log_debug(f"Starting monitor_with_strace for cmd: {cmd}")
        try:
            # Test if strace is available first
            try:
                strace_test = subprocess.run(
                    ["strace", "--version"], capture_output=True, timeout=5
                )
                self.log_debug(
                    f"strace test: returncode={strace_test.returncode}, stdout={strace_test.stdout[:100]}"
                )
            except Exception as e:
                self.results["errors"].append(f"strace not available: {e}")
                results_queue.put({"error": f"strace not available: {e}"})
                return

            # Create strace log file in /tmp (writable by non-root user)
            strace_log = Path(f"/tmp/strace_{os.getpid()}.log")
            strace_cmd = [
                "strace",
                "-f",
                "-tt",
                "-s",
                "2048",
                "-e",
                "trace=network,connect,socket,bind,listen,accept",
                "-o",
                str(strace_log),
            ] + cmd
            self.log_debug(f"Strace command: {strace_cmd}")

            # Set environment
            env = os.environ.copy()
            env["WINEDEBUG"] = "-all"
            env["WINEPREFIX"] = "/tmp/.wine"

            process = subprocess.Popen(
                strace_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=os.setsid,
            )

            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                self.log_debug(
                    f"Strace process completed: returncode={process.returncode}"
                )

                # Debug strace execution
                if stderr:
                    self.results["errors"].append(
                        f"strace stderr: {stderr.decode('utf-8', errors='ignore')[:500]}"
                    )

                # Try to read strace log
                if strace_log.exists():
                    try:
                        file_size = strace_log.stat().st_size
                        self.log_debug(f"strace log exists, size: {file_size} bytes")

                        with open(strace_log, "r", errors="ignore") as f:
                            strace_output = f.read()

                        self.log_debug(
                            f"Read {len(strace_output)} characters from strace log"
                        )
                    except Exception as e:
                        strace_output = ""
                        self.results["errors"].append(f"Failed to read strace log: {e}")
                else:
                    strace_output = ""
                    # Check if file exists in different location
                    alt_locations = [
                        self.workspace / f"strace_{os.getpid()}.log",
                        Path("/tmp/strace.log"),
                        Path("/analysis/strace.log"),
                    ]
                    found_alt = None
                    for alt_path in alt_locations:
                        if alt_path.exists():
                            found_alt = alt_path
                            try:
                                with open(alt_path, "r", errors="ignore") as f:
                                    strace_output = f.read()
                                break
                            except Exception:
                                pass

                    if found_alt:
                        self.results["errors"].append(
                            f"strace log found at alternate location: {found_alt}"
                        )
                    else:
                        self.results["errors"].append(
                            f"strace log not found at {strace_log}, checked alternatives"
                        )

                # Show sample of strace output for debugging
                if strace_output:
                    lines = strace_output.split("\n")
                    sample_lines = [line for line in lines[:50] if line.strip()][:10]
                    self.results["trace_debug"].append(
                        f"strace sample ({len(lines)} total lines): {sample_lines}"
                    )
                else:
                    self.results["trace_debug"].append("No strace output captured")

                syscalls = self.parse_strace_output(strace_output)
                self.log_debug(f"Parsed {len(syscalls)} syscalls")

                connections, dns = self.parse_strace_network(strace_output)

                behaviors = self.parse_strace_behaviors(strace_output)

                results_queue.put(
                    {
                        "system_calls": syscalls[:100],
                        "network_connections": connections,
                        "dns_queries": dns,
                        "commands_executed": behaviors["commands_executed"],
                        "processes_killed": behaviors["processes_killed"],
                        "files_accessed": behaviors["files_accessed"],
                    }
                )

            except subprocess.TimeoutExpired:
                self.log_debug("Strace TimeoutExpired")
                results_queue.put({"error": "DEBUG: strace timed out"})
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(1)
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)

        except Exception as e:
            self.log_debug(f"Exception in monitor_with_strace: {e}")
            results_queue.put({"error": str(e)})

    def parse_strace_output(self, output: str) -> List[str]:
        """Parse strace output for interesting syscalls."""
        syscalls = []

        for line in output.split("\n")[:200]:
            line = line.strip()
            if not line or line.startswith("+"):
                continue

            if any(
                call in line
                for call in ["open", "socket", "connect", "execve", "write", "read"]
            ):
                syscalls.append(line)

        return syscalls

    def parse_strace_network(self, output: str) -> Tuple[List[Dict], List[Dict]]:
        """Extract network connections and DNS queries from strace output."""
        import re

        connections = []
        dns_queries = []
        seen_connections = set()

        # Enhanced patterns for network connections
        patterns = {
            "connect_ipv4": re.compile(
                r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)\}'
            ),
            "connect_ipv6": re.compile(
                r'connect\(\d+,\s*\{sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),\s*sin6_addr=inet_pton\(AF_INET6,\s*"([^"]+)"\)'
            ),
            "socket_inet": re.compile(
                r"socket\(AF_INET,\s*SOCK_STREAM,\s*IPPROTO_TCP\)"
            ),
            "getaddrinfo": re.compile(r'getaddrinfo\("([^"]+)"'),
            "gethostbyname": re.compile(r'gethostbyname\("([^"]+)"'),
        }

        matches_found = {pattern_name: 0 for pattern_name in patterns}

        for line_num, line in enumerate(output.split("\n"), 1):
            line = line.strip()
            if not line:
                continue

            # IPv4 connections
            match = patterns["connect_ipv4"].search(line)
            if match:
                matches_found["connect_ipv4"] += 1
                port = int(match.group(1))
                ip = match.group(2)
                self._record_connection(
                    ip, port, connections, dns_queries, seen_connections
                )
                continue

            # IPv6 connections
            match = patterns["connect_ipv6"].search(line)
            if match:
                matches_found["connect_ipv6"] += 1
                port = int(match.group(1))
                ip = match.group(2)
                self._record_connection(
                    ip, port, connections, dns_queries, seen_connections
                )
                continue

            # DNS lookups
            for dns_pattern in ["getaddrinfo", "gethostbyname"]:
                match = patterns[dns_pattern].search(line)
                if match:
                    matches_found[dns_pattern] += 1
                    domain = match.group(1)
                    if domain not in [d.get("domain") for d in dns_queries]:
                        dns_queries.append(
                            {
                                "domain": domain,
                                "query_type": dns_pattern,
                                "line_num": line_num,
                            }
                        )

        # Add debugging info
        if hasattr(self, "results"):
            self.results.setdefault("trace_debug", []).append(
                f"Network pattern matches: {matches_found}"
            )
            if connections:
                self.results["trace_debug"].append(
                    f"Found {len(connections)} network connections"
                )
            if dns_queries:
                self.results["trace_debug"].append(
                    f"Found {len(dns_queries)} DNS queries"
                )

        return connections, dns_queries

    def _record_connection(self, ip, port, connections, dns_queries, seen_connections):
        """Helper to record a connection if not duplicate and not noise."""

        if (
            ip.startswith("127.")
            or ip.startswith("169.254.")
            or ip == "::1"
            or ip.startswith("fe80:")
        ):
            return

        if port == 5353:
            return

        conn_key = (ip, port)
        if conn_key not in seen_connections:
            seen_connections.add(conn_key)

            if port == 53:
                dns_queries.append({"server": ip, "port": port, "type": "DNS"})
            else:
                connections.append(
                    {
                        "protocol": "tcp",
                        "dst_ip": ip,
                        "dst_port": port,
                        "local_addr": "0.0.0.0:0",
                    }
                )

    def parse_strace_behaviors(self, output: str) -> Dict[str, List]:
        """Extract behavioral information from strace output."""
        import re

        behaviors = {
            "commands_executed": [],
            "processes_killed": [],
            "files_accessed": [],
            "files_created": [],
            "files_deleted": [],
        }
        seen_commands = set()
        seen_files = set()

        for line in output.split("\n"):

            execve_match = re.search(r'execve\("([^"]+)",\s*\[([^\]]*)\]', line)
            if execve_match:
                binary = execve_match.group(1)
                args_str = execve_match.group(2)

                wine_internal = [
                    "wineserver",
                    "wineboot",
                    "winedevice",
                    "plugplay",
                    "services.exe",
                    "explorer.exe",
                    "rpcss.exe",
                ]
                if (
                    not any(skip == binary.split("/")[-1] for skip in wine_internal)
                    and binary not in seen_commands
                ):
                    seen_commands.add(binary)

                    args = re.findall(r'"([^"]*)"', args_str)
                    cmd_line = " ".join(args) if args else binary

                    behaviors["commands_executed"].append(
                        {"binary": binary, "cmdline": cmd_line[:200], "type": "execve"}
                    )

            kill_match = re.search(r"kill\((\d+),\s*(\w+)\)\s*=\s*(\d+)", line)
            if kill_match:
                pid = kill_match.group(1)
                signal = kill_match.group(2)
                behaviors["processes_killed"].append(
                    {"pid": int(pid), "signal": signal}
                )

            openat_match = re.search(
                r'openat\([^,]+,\s*"([^"]+)",\s*([^)]+)\)\s*=\s*(\d+)', line
            )
            if openat_match:
                filepath = openat_match.group(1)
                flags = openat_match.group(2)

                if not any(
                    skip in filepath
                    for skip in [
                        "/lib/",
                        "/usr/lib/",
                        "/etc/ld",
                        "/proc/",
                        "/dev/",
                        "/sys/",
                        "/.wine/",
                        "/windows/",
                        "/dosdevices/",
                    ]
                ):
                    if filepath not in seen_files:
                        seen_files.add(filepath)

                        file_info = {"path": filepath[:200], "operation": "read"}

                        if (
                            "O_CREAT" in flags
                            or "O_WRONLY" in flags
                            or "O_RDWR" in flags
                        ):
                            file_info["operation"] = "write"
                            behaviors["files_created"].append(file_info)

                        behaviors["files_accessed"].append(file_info)

            unlink_match = re.search(r'unlink(?:at)?\([^,]*"([^"]+)"', line)
            if unlink_match:
                filepath = unlink_match.group(1)
                if not any(skip in filepath for skip in ["/tmp/", "/proc/"]):
                    behaviors["files_deleted"].append(
                        {"path": filepath[:200], "operation": "delete"}
                    )

            rename_match = re.search(r'rename\("([^"]+)",\s*"([^"]+)"\)', line)
            if rename_match:
                src = rename_match.group(1)
                dst = rename_match.group(2)
                behaviors["files_accessed"].append(
                    {"path": f"{src} -> {dst}"[:200], "operation": "rename"}
                )

        for key in behaviors:
            behaviors[key] = behaviors[key][:30]

        return behaviors

    def monitor_processes(self):
        """Monitor spawned processes."""
        seen_pids = set()
        start_time = time.time()

        while time.time() - start_time < self.timeout + 2:
            try:
                for proc in psutil.process_iter(
                    ["pid", "name", "cmdline", "create_time"]
                ):
                    try:
                        pid = proc.info["pid"]
                        if (
                            pid not in seen_pids
                            and proc.info["create_time"] > self.start_time
                        ):
                            seen_pids.add(pid)
                            self.results["processes"].append(
                                {
                                    "pid": pid,
                                    "name": proc.info["name"],
                                    "cmdline": (
                                        " ".join(proc.info["cmdline"])
                                        if proc.info["cmdline"]
                                        else ""
                                    ),
                                }
                            )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                time.sleep(0.5)
            except Exception:
                break

    def monitor_network(self):
        """Monitor network connections."""
        seen_connections = set()
        start_time = time.time()
        use_psutil = True
        psutil_failed = False

        while time.time() - start_time < self.timeout + 2:
            try:
                if use_psutil:
                    try:
                        # Try using psutil (requires elevated privileges)
                        for conn in psutil.net_connections(kind="all"):
                            if conn.status == "ESTABLISHED":
                                conn_tuple = (conn.laddr, conn.raddr)
                                if conn_tuple not in seen_connections:
                                    seen_connections.add(conn_tuple)

                                    if conn.raddr:
                                        dst_ip = conn.raddr.ip
                                        dst_port = conn.raddr.port

                                        if dst_port == 5353:
                                            continue

                                        self.results["network_connections"].append(
                                            {
                                                "protocol": "tcp" if conn.type == 1 else "udp",
                                                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                                                "dst_ip": dst_ip,
                                                "dst_port": dst_port,
                                            }
                                        )
                    except (PermissionError, psutil.AccessDenied) as e:
                        # psutil requires root - fallback to /proc parsing
                        if not psutil_failed:
                            self.results["errors"].append(
                                f"psutil network monitoring failed (non-root), using /proc fallback: {type(e).__name__}"
                            )
                            psutil_failed = True
                        use_psutil = False

                if not use_psutil:
                    # Fallback: Read /proc/net/tcp and /proc/net/tcp6 directly
                    self._monitor_network_from_proc(seen_connections)

                time.sleep(0.5)
            except Exception as e:
                self.results["errors"].append(f"Network monitoring error: {str(e)}")
                break

    def _monitor_network_from_proc(self, seen_connections: set):
        """
        Read network connections from /proc/net/tcp and /proc/net/tcp6.
        This works for non-root users.
        """
        import socket
        import struct

        def parse_address(hex_addr, hex_port):
            """Parse hex address and port from /proc/net/tcp."""
            try:
                # Convert hex string to IP address
                addr_int = int(hex_addr, 16)
                # Handle endianness - /proc/net/tcp uses little-endian for IPv4
                ip_bytes = struct.pack('<I' if len(hex_addr) == 8 else '>IIII', addr_int)
                if len(hex_addr) == 8:  # IPv4
                    ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
                else:  # IPv6
                    ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
                port = int(hex_port, 16)
                return ip, port
            except Exception:
                return None, None

        # Read TCP connections (IPv4)
        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    
                    # parts[1] is local_address, parts[2] is rem_address, parts[3] is st (state)
                    local_addr, rem_addr, state = parts[1], parts[2], parts[3]
                    
                    # 01 = ESTABLISHED
                    if state == "01":
                        local_ip, local_port = local_addr.split(":")
                        rem_ip, rem_port = rem_addr.split(":")
                        
                        dst_ip, dst_port = parse_address(rem_ip, rem_port)
                        src_ip, src_port = parse_address(local_ip, local_port)
                        
                        if dst_ip and dst_port and dst_ip != "0.0.0.0":
                            conn_key = (dst_ip, dst_port)
                            if conn_key not in seen_connections:
                                seen_connections.add(conn_key)
                                
                                # Skip mDNS
                                if dst_port == 5353:
                                    continue
                                
                                self.results["network_connections"].append(
                                    {
                                        "protocol": "tcp",
                                        "local_addr": f"{src_ip}:{src_port}" if src_ip else "unknown",
                                        "dst_ip": dst_ip,
                                        "dst_port": dst_port,
                                    }
                                )
        except Exception as e:
            self.results["errors"].append(f"Failed to read /proc/net/tcp: {str(e)}")

        # Read TCP6 connections (IPv6)
        try:
            with open("/proc/net/tcp6", "r") as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    
                    local_addr, rem_addr, state = parts[1], parts[2], parts[3]
                    
                    if state == "01":  # ESTABLISHED
                        local_ip, local_port = local_addr.split(":")
                        rem_ip, rem_port = rem_addr.split(":")
                        
                        # Parse IPv6 address
                        try:
                            rem_ip_bytes = bytes.fromhex(rem_ip)
                            dst_ip = socket.inet_ntop(socket.AF_INET6, rem_ip_bytes)
                            dst_port = int(rem_port, 16)
                            
                            if dst_ip != "::" and dst_port != 0:
                                conn_key = (dst_ip, dst_port)
                                if conn_key not in seen_connections:
                                    seen_connections.add(conn_key)
                                    
                                    if dst_port == 5353:
                                        continue
                                    
                                    local_ip_bytes = bytes.fromhex(local_ip)
                                    src_ip = socket.inet_ntop(socket.AF_INET6, local_ip_bytes)
                                    src_port = int(local_port, 16)
                                    
                                    self.results["network_connections"].append(
                                        {
                                            "protocol": "tcp6",
                                            "local_addr": f"[{src_ip}]:{src_port}",
                                            "dst_ip": dst_ip,
                                            "dst_port": dst_port,
                                        }
                                    )
                        except Exception:
                            pass
        except Exception as e:
            self.results["errors"].append(f"Failed to read /proc/net/tcp6: {str(e)}")

    def check_file_operations(self):
        """Check for created/modified files in workspace."""
        try:
            for item in self.workspace.rglob("*"):
                if item.is_file() and item != self.sample_path:
                    try:
                        stat = item.stat()
                        self.results["file_operations"].append(
                            {
                                "path": str(item.relative_to(self.workspace)),
                                "size": stat.st_size,
                                "type": "created",
                            }
                        )
                    except:
                        pass
        except Exception as e:
            self.results["errors"].append(f"File check error: {str(e)}")

    def summarize_behavior(self):
        """Summarize observed behavior."""
        summary = {
            "process_count": len(self.results["processes"]),
            "network_connections_count": len(self.results["network_connections"]),
            "dns_queries_count": len(self.results.get("dns_queries", [])),
            "files_created": len(self.results["file_operations"]),
            "commands_executed_count": len(self.results.get("commands_executed", [])),
            "processes_killed_count": len(self.results.get("processes_killed", [])),
            "files_accessed_count": len(self.results.get("files_accessed", [])),
            "suspicious_behaviors": [],
        }

        if len(self.results["network_connections"]) > 0:
            summary["suspicious_behaviors"].append("network_activity")

        if len(self.results.get("dns_queries", [])) > 0:
            summary["suspicious_behaviors"].append("dns_resolution")

        if len(self.results["processes"]) > 5:
            summary["suspicious_behaviors"].append("multiple_processes")

        if len(self.results["file_operations"]) > 10:
            summary["suspicious_behaviors"].append("extensive_file_operations")

        if len(self.results.get("commands_executed", [])) > 0:
            summary["suspicious_behaviors"].append("executes_commands")

        if len(self.results.get("processes_killed", [])) > 0:
            summary["suspicious_behaviors"].append("kills_processes")

        for cmd in self.results.get("commands_executed", []):
            binary = cmd.get("binary", "")
            if any(
                sh in binary
                for sh in ["/bin/sh", "/bin/bash", "/bin/zsh", "cmd.exe", "powershell"]
            ):
                if "spawns_shell" not in summary["suspicious_behaviors"]:
                    summary["suspicious_behaviors"].append("spawns_shell")

        self.results["behavior_summary"] = summary


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: monitor.py <sample_path>"}))
        sys.exit(1)

    sample_path = sys.argv[1]
    timeout = int(os.getenv("EXECUTION_TIMEOUT", 30))

    analyzer = DynamicAnalyzer(sample_path, timeout)
    results = analyzer.analyze()

    try:
        out_dir = Path("/analysis/workspace")
        out_path = out_dir / f"monitor_results_{os.getpid()}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(results, indent=2))
    except Exception:

        pass

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
