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
        self.timeout = int(os.getenv('EXECUTION_TIMEOUT', timeout))
        self.workspace = Path('/analysis/workspace')
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
            "trace_debug": []
        }
        self.process = None
        self.start_time = None
        self.tcpdump_proc = None
        self.pcap_file = '/tmp/capture.pcap'
        # Get original filename from environment (passed by docker_manager)
        self.original_filename = os.getenv('ORIGINAL_FILENAME', str(sample_path))

    def analyze(self) -> Dict[str, Any]:
        """Run dynamic analysis."""
        try:
            if not self.sample_path.exists():
                # Debug: list workspace contents
                try:
                    print(f"DEBUG: Workspace contents ({self.workspace}):")
                    for item in self.workspace.iterdir():
                        print(f" - {item} ({oct(item.stat().st_mode)[-3:]}) uid={item.stat().st_uid} gid={item.stat().st_gid}")
                except Exception as e:
                    print(f"DEBUG: Failed to list workspace: {e}")
                return {"error": "Sample file not found"}

            # Extract URLs/hostnames from the sample BEFORE copying
            self.results["urls_found"] = self.extract_urls_from_sample()

            # Determine execution method BEFORE copying (to preserve extension info)
            is_windows = self.is_windows_executable()
            interpreter, is_script = self.get_script_interpreter()
            qemu_cmd = None
            if not is_windows and not is_script:
                qemu_cmd = self.get_qemu_for_elf()

            # Debug: record file(1) description and interpreter decision to help diagnose ENOEXEC
            try:
                file_desc = subprocess.run(['file', '-b', str(self.sample_path)], capture_output=True, text=True, timeout=5).stdout.strip()
            except Exception as e:
                file_desc = f'file_cmd_failed:{e}'

            self.results.setdefault('debug', {})
            self.results['debug']['file_desc'] = file_desc
            self.results['debug']['is_windows'] = bool(is_windows)
            self.results['debug']['is_script'] = bool(is_script)
            self.results['debug']['pre_qemu_cmd'] = qemu_cmd

            # Copy sample to a container-local tmp path for execution (writable and executable).
            # Some mounts may be read-only (bind mounts), so avoid relying on the source path
            # being writable. Use a per-run name so concurrent analyses don't clash.
            exec_dir = Path('/tmp')
            exec_path = exec_dir / f'sample_exec_{os.getpid()}'
            try:
                if not self.sample_path.exists():
                    raise FileNotFoundError(str(self.sample_path))
                shutil.copy2(self.sample_path, exec_path)
                self.sample_path = exec_path
            except Exception as e:
                # If copy fails (e.g., permission), record debug info and fall back to
                # attempting to run the original file in-place.
                self.results.setdefault('debug', {})['copy_error'] = str(e)

            # Make sample executable (best-effort; may fail for bind-mounted files)
            try:
                os.chmod(self.sample_path, 0o755)
            except Exception as e:
                # Non-fatal: record and continue; container may still execute via QEMU or interpreter
                self.results.setdefault('debug', {})['chmod_error'] = str(e)

            # If the sample appears UPX-packed, try to unpack it in-place
            try:
                upx_unpacked = self.attempt_upx_unpack()
                self.results.setdefault('debug', {})['upx_unpacked'] = bool(upx_unpacked)
            except Exception as e:
                self.results.setdefault('debug', {})['upx_unpack_error'] = str(e)

            # Execute based on pre-determined method
            if is_windows:
                return self.execute_with_wine()

            if is_script:
                return self.execute_script(interpreter)

            # Use pre-computed QEMU command if needed
            if qemu_cmd:
                return self.execute_with_qemu(qemu_cmd)

            # Before attempting native execution, verify the binary can actually
            # run on this architecture.  On ARM hosts an x86 ELF (or any foreign
            # ELF) will fail with ENOEXEC unless binfmt_misc is configured on the
            # host kernel.  Detect the mismatch early and fall back to QEMU.
            fallback_qemu = self._check_native_compat()
            if fallback_qemu:
                return self.execute_with_qemu(fallback_qemu)

            # Default: try to run as native executable
            try:
                return self.execute_native()
            except OSError as e:
                # ENOEXEC -> exec format error; try QEMU fallback if available
                if hasattr(e, 'errno') and e.errno == 8:  # ENOEXEC
                    # Try ELF-based QEMU detection first
                    qemu_fallback = self.get_qemu_for_elf() or self._check_native_compat()
                    if qemu_fallback:
                        # Record debug info and attempt QEMU execution
                        self.results.setdefault('debug', {})
                        self.results['debug']['fallback_reason'] = 'ENOEXEC'
                        self.results['debug']['qemu_fallback'] = qemu_fallback
                        return self.execute_with_qemu(qemu_fallback)

                    # If no QEMU available, provide helpful hints
                    if str(self.sample_path).endswith('.js'):
                        self.results['errors'].append('Exec format error: This is a JavaScript file. Try running with Node.js (node <file.js>).')
                    else:
                        self.results['errors'].append('Exec format error: Not a native Linux executable or missing interpreter.')
                else:
                    self.results['errors'].append(f'Execution error: {e}')
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
            host = platform.machine()  # e.g. 'aarch64', 'x86_64'

            result = subprocess.run(
                ['file', '-b', str(self.sample_path)],
                capture_output=True, text=True, timeout=5
            )
            desc = result.stdout.lower()

            # Map file(1) descriptions to QEMU binaries
            arch_map = [
                ('x86-64',        'x86_64',  'qemu-x86_64-static'),
                ('intel 80386',   'i386',    'qemu-i386-static'),
                ('aarch64',       'aarch64', 'qemu-aarch64-static'),
                ('arm,',          'arm',     'qemu-arm-static'),
                ('mips',          'mips',    'qemu-mips-static'),
                ('powerpc',       'ppc',     'qemu-ppc-static'),
                ('sparc',         'sparc',   'qemu-sparc-static'),
                ('s390',          's390x',   'qemu-s390x-static'),
                ('risc-v',        'riscv64', 'qemu-riscv64-static'),
            ]

            native_aliases = {
                'x86_64':  ['x86-64', 'intel 80386'],
                'aarch64': ['aarch64', 'arm,'],
                'i686':    ['intel 80386'],
                'armv7l':  ['arm,'],
            }
            host_native = native_aliases.get(host, [host.lower()])

            for keyword, _arch_name, qemu_bin in arch_map:
                if keyword in desc:
                    # Is it native?
                    if keyword in host_native:
                        return None
                    # Normalize qemu_bin (some mappings include '-static' already)
                    base = qemu_bin
                    if base.endswith('-static'):
                        base_no_static = base.replace('-static', '')
                    else:
                        base_no_static = base + '-static'

                    candidates = []
                    # Prefer the -static variant then the plain variant (if present)
                    if os.path.isfile(f'/usr/bin/{base}'):
                        candidates.append(base)
                    if os.path.isfile(f'/usr/bin/{base_no_static}'):
                        candidates.append(base_no_static)
                    if candidates:
                        return candidates
                    return None

        except Exception as e:
            self.results['errors'].append(f'Compat check error: {e}')
        return None

    def get_qemu_for_elf(self) -> str:
        """
        Check if ELF binary needs QEMU emulation.
        Returns QEMU command if needed, None if native execution is possible.
        """
        try:
            import platform
            host_arch = platform.machine()
            
            # Read ELF header to determine architecture
            with open(self.sample_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'\x7fELF':
                    return None  # Not an ELF file
                
                # Read ELF class (32 or 64 bit) at offset 4
                elf_class = f.read(1)[0]
                
                # Read ELF data encoding at offset 5
                f.read(1)  # Skip
                
                # Read ELF version at offset 6
                f.read(1)  # Skip
                
                # Read OS/ABI at offset 7
                f.read(1)  # Skip
                
                # Skip padding (8 bytes)
                f.read(8)
                
                # Read type (2 bytes) at offset 16
                f.read(2)  # Skip
                
                # Read machine at offset 18 (2 bytes, little-endian)
                machine_bytes = f.read(2)
                machine = int.from_bytes(machine_bytes, 'little')
                
                # ELF machine types (e_machine field)
                elf_machines = {
                    0x03: ('i386', 'qemu-i386'),
                    0x3E: ('x86_64', 'qemu-x86_64'),
                    0x28: ('arm', 'qemu-arm'),
                    0xB7: ('aarch64', 'qemu-aarch64'),
                    0x08: ('mips', 'qemu-mips'),
                    0x14: ('ppc', 'qemu-ppc'),
                    0x15: ('ppc64', 'qemu-ppc64'),
                    0x02: ('sparc', 'qemu-sparc'),
                    0x2B: ('sparc64', 'qemu-sparc64'),
                    0x16: ('s390', 'qemu-s390x'),
                    0xF3: ('riscv', 'qemu-riscv64'),
                    0x32: ('sh4', 'qemu-sh4'),
                    0x5C: ('m68k', 'qemu-m68k'),
                }
                
                if machine not in elf_machines:
                    return None

                elf_arch, qemu_bin = elf_machines[machine]
                
                # Check if we need emulation
                native_matches = {
                    'x86_64': ['x86_64', 'i386'],
                    'aarch64': ['aarch64', 'arm'],
                    'i686': ['i386'],
                    'armv7l': ['arm'],
                }
                
                host_native = native_matches.get(host_arch, [host_arch])
                
                if elf_arch in host_native:
                    return None  # Can run natively

                # Build candidate list of qemu variants
                candidates = []
                for variant in [f'{qemu_bin}-static', qemu_bin]:
                    if os.path.exists(f'/usr/bin/{variant}'):
                        candidates.append(variant)

                return candidates if candidates else None
                
        except Exception as e:
            self.results["errors"].append(f"ELF detection error: {str(e)}")
            return None

    def is_windows_executable(self) -> bool:
        """Check if sample is Windows PE."""
        try:
            with open(self.sample_path, 'rb') as f:
                header = f.read(2)
                return header == b'MZ'
        except:
            return False

    def extract_urls_from_sample(self) -> List[Dict]:
        """Extract URLs and hostnames from sample file."""
        import re
        urls_found = []
        seen = set()
        
        try:
            # Read file content (text files and scripts)
            try:
                with open(self.sample_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024 * 100)  # First 100KB
            except:
                with open(self.sample_path, 'rb') as f:
                    content = f.read(1024 * 100).decode('utf-8', errors='ignore')
            
            # URL patterns
            url_pattern = re.compile(
                r'https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\'"<>]*)?',
                re.IGNORECASE
            )
            
            # Find full URLs
            for match in url_pattern.finditer(content):
                url = match.group(0)
                if url not in seen:
                    seen.add(url)
                    # Extract hostname from URL
                    host_match = re.search(r'https?://([^/:]+)', url)
                    hostname = host_match.group(1) if host_match else url
                    urls_found.append({
                        "url": url[:200],  # Truncate long URLs
                        "hostname": hostname,
                        "type": "url"
                    })
            
            # Also look for standalone hostnames in common patterns
            host_patterns = [
                r'["\']([a-zA-Z0-9][-a-zA-Z0-9.]*\.(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk))["\']',
                r'\.get\(["\']([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})',
                r'\.request\(["\']([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})',
            ]
            
            for pattern in host_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    hostname = match.group(1)
                    if hostname not in seen and not hostname.startswith('.'):
                        seen.add(hostname)
                        urls_found.append({
                            "url": hostname,
                            "hostname": hostname,
                            "type": "hostname"
                        })
            
        except Exception as e:
            self.results["errors"].append(f"URL extraction error: {str(e)}")
        
        return urls_found[:20]  # Limit to 20

    def get_script_interpreter(self) -> tuple:
        """
        Detect script type and return appropriate interpreter.
        Returns (interpreter_cmd, is_script) tuple.
        """
        # Use original filename for extension detection
        filename = self.original_filename.lower()
        
        # Check by extension
        script_interpreters = {
            '.js': ['node'],
            '.mjs': ['node'],
            '.py': ['python3'],
            '.pyw': ['python3'],
            '.sh': ['bash'],
            '.bash': ['bash'],
            '.pl': ['perl'],
            '.pm': ['perl'],
            '.rb': ['ruby'],
            '.php': ['php'],
            '.lua': ['lua'],
            '.vbs': ['cscript', '//Nologo'],
            '.ps1': ['powershell', '-ExecutionPolicy', 'Bypass', '-File'],
            '.bat': ['cmd.exe', '/c'],
            '.cmd': ['cmd.exe', '/c'],
        }
        
        for ext, interpreter in script_interpreters.items():
            if filename.endswith(ext):
                return interpreter, True

        # Check shebang for extensionless files
        try:
            with open(self.sample_path, 'rb') as f:
                first_line = f.readline(256)
                if first_line.startswith(b'#!'):
                    shebang = first_line.decode('utf-8', errors='ignore').strip()
                    if 'python' in shebang:
                        return ['python3'], True
                    elif 'node' in shebang or 'nodejs' in shebang:
                        return ['node'], True
                    elif 'bash' in shebang or '/sh' in shebang:
                        return ['bash'], True
                    elif 'perl' in shebang:
                        return ['perl'], True
                    elif 'ruby' in shebang:
                        return ['ruby'], True
                    elif 'php' in shebang:
                        return ['php'], True
        except:
            pass

        # Content-based detection for JavaScript (if extension/shebang missing)
        try:
            with open(self.sample_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2048)
                # Heuristic: look for JS keywords/constructs
                js_keywords = ['var ', 'let ', 'const ', 'function ', '=>', 'require(', 'module.exports', 'console.log']
                if any(kw in content for kw in js_keywords):
                    return ['node'], True
        except Exception as e:
            pass

        return None, False

    def attempt_upx_unpack(self) -> bool:
        """
        Attempt to unpack UPX-packed executables in-place using the `upx` tool.
        Returns True if unpack succeeded, False otherwise.
        """
        try:
            upx_path = shutil.which('upx')
            dbg = self.results.setdefault('debug', {})
            if not upx_path:
                dbg['upx_available'] = False
                return False

            dbg['upx_available'] = True
            # Back up original sample just in case
            backup_path = Path(str(self.sample_path) + '.upxbak')
            try:
                shutil.copy2(self.sample_path, backup_path)
                dbg['upx_backup'] = str(backup_path)
            except Exception:
                dbg['upx_backup'] = 'backup_failed'

            # Run `upx -d <file>` to attempt decompression. This modifies file in-place.
            proc = subprocess.run([upx_path, '-d', str(self.sample_path)], capture_output=True, text=True, timeout=30)
            dbg['upx_returncode'] = proc.returncode
            dbg['upx_stdout'] = (proc.stdout or '')[:2000]
            dbg['upx_stderr'] = (proc.stderr or '')[:2000]

            return proc.returncode == 0
        except Exception as e:
            self.results.setdefault('debug', {})['upx_exception'] = str(e)
            return False

    def start_tcpdump(self):
        """Start tcpdump to capture all network traffic."""
        try:
            self.tcpdump_proc = subprocess.Popen(
                ['tcpdump', '-i', 'any', '-n', '-w', self.pcap_file],
                stdout=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            # Give tcpdump time to start
            time.sleep(0.5)

            # Populate URLs found (re-scan now copy is in-place)
            try:
                self.results["urls_found"] = self.extract_urls_from_sample()
            except Exception:
                pass

            # If JS, attempt deobfuscation/beautification
            try:
                interpreter, is_script = self.get_script_interpreter()
                if is_script and interpreter and interpreter[0] == 'node':
                    deob = getattr(self, 'deobfuscate_javascript', lambda: None)()
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
            
            # Parse pcap file for connections
            self.parse_pcap()

    def parse_pcap(self):
        """Parse pcap file for network connections and DNS queries."""
        if not os.path.exists(self.pcap_file):
            return
            
        try:
            # Read pcap with tcpdump in text mode
            result = subprocess.run(
                ['tcpdump', '-n', '-r', self.pcap_file, '-q'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            seen_connections = set()
            for line in result.stdout.split('\n'):
                # Handle both IP (IPv4) and IP6 (IPv6)
                if ' > ' in line and ('IP' in line or 'IP6' in line):
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == '>' and i > 0 and i < len(parts) - 1:
                            src = parts[i-1]
                            dst = parts[i+1].rstrip(':')
                            
                            # Parse address and port
                            # IPv4 format: 1.2.3.4.12345
                            # IPv6 format: 2001:db8::1.12345 or [2001:db8::1].12345
                            if '.' in dst:
                                # Try to extract port (last dot-separated part)
                                dst_parts = dst.rsplit('.', 1)
                                if len(dst_parts) == 2:
                                    try:
                                        dst_ip = dst_parts[0]
                                        dst_port = int(dst_parts[1])
                                        
                                        # Filter out mDNS and other common noise
                                        if dst_port in [5353]:
                                            continue
                                        if dst_ip in ['224.0.0.251', 'ff02::fb']:
                                            continue

                                        conn_key = (dst_ip, dst_port)
                                        if conn_key not in seen_connections:
                                            seen_connections.add(conn_key)
                                            self.results["network_connections"].append({
                                                "dst_ip": dst_ip,
                                                "dst_port": dst_port,
                                                "protocol": "unknown"
                                            })
                                    except ValueError:
                                        pass
            
            # Also parse DNS queries
            dns_result = subprocess.run(
                ['tcpdump', '-n', '-r', self.pcap_file, 'port 53', '-v'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            import re
            # Match both A (IPv4) and AAAA (IPv6) queries
            dns_patterns = [
                r'A\? ([a-zA-Z0-9\.\-]+)\.',
                r'AAAA\? ([a-zA-Z0-9\.\-\:]+)\.'
            ]
            for pattern in dns_patterns:
                for match in re.findall(pattern, dns_result.stdout):
                    if match not in [q.get('domain') for q in self.results.get("dns_queries", [])]:
                        self.results["dns_queries"].append({
                            "domain": match, 
                            "type": "A" if "AAAA" not in pattern else "AAAA"
                        })
                    
        except Exception as e:
            self.results["errors"].append(f"pcap parse error: {str(e)}")

    def execute_native(self) -> Dict[str, Any]:
        """Execute native Linux malware with monitoring."""
        try:
            self.results["execution_method"] = "native"

            # Start tcpdump before anything else
            self.start_tcpdump()

            # Prepare execution
            cmd = [str(self.sample_path)]

            # Start monitoring threads
            results_queue = queue.Queue()

            # Set start_time BEFORE launching monitor threads
            self.start_time = time.time()

            # Start process monitoring
            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            # Start network monitoring (psutil-based, as backup)
            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            # Start strace monitoring (runs the actual sample)
            strace_thread = threading.Thread(
                target=self.monitor_with_strace,
                args=(cmd, results_queue)
            )
            strace_thread.start()

            # Wait for strace to complete (it runs the sample)
            strace_thread.join(timeout=self.timeout + 5)

            # Get results from queue
            try:
                while True:
                    result = results_queue.get_nowait()
                    if 'system_calls' in result:
                        self.results['system_calls'] = result['system_calls']
                    if 'network_connections' in result:
                        self.results['network_connections'].extend(result['network_connections'])
                    if 'dns_queries' in result:
                        self.results['dns_queries'].extend(result['dns_queries'])
                    if 'commands_executed' in result:
                        # commands_executed from strace are objects with binary/cmdline
                        for cmd_obj in result['commands_executed']:
                            cmd_str = cmd_obj.get('cmdline', cmd_obj.get('binary'))
                            if cmd_str and cmd_str not in self.results['commands_executed']:
                                self.results['commands_executed'].append(cmd_str)
                    if 'processes' in result:
                        # processes from psutil are objects with pid/name/cmdline
                        for p_obj in result['processes']:
                            p_cmd = p_obj.get('cmdline') or p_obj.get('name')
                            if p_cmd and p_cmd not in self.results['commands_executed']:
                                self.results['commands_executed'].append(p_cmd)
                    if 'processes_killed' in result:
                        self.results['processes_killed'].extend(result['processes_killed'])
                    if 'files_accessed' in result:
                        self.results['files_accessed'].extend(result['files_accessed'])
            except queue.Empty:
                pass

            # If strace captured an ENOEXEC (exec format error), attempt a
            # single QEMU retry if an appropriate emulator is available.
            try:
                syscalls = self.results.get('system_calls', []) or []
                enoexec_seen = any('ENOEXEC' in sc or 'Exec format error' in sc for sc in syscalls)
                if enoexec_seen:
                    qemu_bin = self.get_qemu_for_elf() or self._check_native_compat()
                    if qemu_bin:
                        self.results.setdefault('debug', {})
                        self.results['debug']['fallback_reason'] = 'ENOEXEC-detected-in-strace'
                        self.results['debug']['qemu_fallback'] = qemu_bin
                        # Stop tcpdump before retrying under QEMU
                        try:
                            self.stop_tcpdump()
                        except Exception:
                            pass
                        return self.execute_with_qemu(qemu_bin)
            except Exception:
                # Don't let fallback logic break analysis; continue normally
                pass

            # Wait a bit for monitoring threads to capture data
            time.sleep(2)

            # Stop tcpdump and parse captured traffic
            self.stop_tcpdump()

            self.results["executed"] = True
            self.summarize_behavior()

            return self.results

        except Exception as e:
            self.stop_tcpdump()  # Ensure tcpdump is stopped on error
            self.results["errors"].append(str(e))
            return self.results

    def execute_with_qemu(self, qemu_bin: str) -> Dict[str, Any]:
        """Execute foreign-architecture ELF with QEMU user-mode emulation."""
        try:
            # qemu_bin may be a single string or a list of candidate binaries
            candidates = qemu_bin if isinstance(qemu_bin, (list, tuple)) else [qemu_bin]
            self.results["execution_method"] = f"qemu ({', '.join(candidates)})"

            # Start tcpdump before anything else
            self.start_tcpdump()

            # Prepare execution and try each candidate until one yields useful traces
            qemu_attempts = []
            for candidate in candidates:
                if not candidate:
                    continue
                path = f'/usr/bin/{candidate}'
                if not os.path.exists(path):
                    qemu_attempts.append({"candidate": candidate, "error": "not_found"})
                    continue

                # Try plain invocation first
                cmd = [path, str(self.sample_path)]

                # Record attempt and command
                self.results.setdefault('debug', {})
                self.results['debug'].setdefault('qemu_attempts', [])
                self.results['debug']['pre_qemu_cmd'] = cmd

                # Run under strace monitor to capture syscalls (worker threads expect this behavior)
                results_queue = queue.Queue()
                self.start_time = time.time()

                process_thread = threading.Thread(target=self.monitor_processes)
                process_thread.daemon = True
                process_thread.start()

                network_thread = threading.Thread(target=self.monitor_network)
                network_thread.daemon = True
                network_thread.start()

                strace_thread = threading.Thread(
                    target=self.monitor_with_strace,
                    args=(cmd, results_queue)
                )
                strace_thread.start()
                strace_thread.join(timeout=self.timeout + 5)

                # Collect results from the attempt
                try:
                    while True:
                        result = results_queue.get_nowait()
                        if 'system_calls' in result:
                            self.results['system_calls'] = result['system_calls']
                        if 'network_connections' in result:
                            self.results['network_connections'].extend(result['network_connections'])
                        if 'dns_queries' in result:
                            self.results['dns_queries'].extend(result['dns_queries'])
                        if 'commands_executed' in result:
                            self.results['commands_executed'].extend(result['commands_executed'])
                        if 'processes_killed' in result:
                            self.results['processes_killed'].extend(result['processes_killed'])
                        if 'files_accessed' in result:
                            self.results['files_accessed'].extend(result['files_accessed'])
                except queue.Empty:
                    pass

                # Inspect whether the attempt produced a non-ENOEXEC/Permission error
                syscalls = self.results.get('system_calls', []) or []
                enoexec_seen = any('ENOEXEC' in sc or 'Exec format error' in sc for sc in syscalls)
                perm_denied = any('EACCES' in sc or 'Permission denied' in sc for sc in syscalls)

                qemu_attempts.append({
                    "candidate": candidate,
                    "syscalls_sample": syscalls[:8],
                })

                # If we observed meaningful syscalls (not just ENOEXEC/EACCES), accept this attempt
                if syscalls and not (enoexec_seen or perm_denied):
                    self.results.setdefault('debug', {})['qemu_chosen'] = candidate
                    self.results.setdefault('debug', {})['qemu_attempts'] = qemu_attempts
                    # Stop tcpdump and finalize
                    try:
                        self.stop_tcpdump()
                    except Exception:
                        pass
                    self.results["executed"] = True
                    self.summarize_behavior()
                    return self.results

                # Otherwise, continue to next candidate
                # Small pause between attempts
                time.sleep(0.5)

            # If none of the candidates produced behavior, record attempts and return
            self.results.setdefault('debug', {})['qemu_attempts'] = qemu_attempts
            self.results['errors'].append('QEMU attempts failed or produced no observable syscalls')
            self.stop_tcpdump()
            return self.results

            # Start monitoring threads
            results_queue = queue.Queue()

            # Set start_time BEFORE launching monitor threads
            self.start_time = time.time()

            # Start process monitoring
            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            # Start network monitoring (psutil-based, as backup)
            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            # Start strace monitoring (runs the sample via QEMU)
            strace_thread = threading.Thread(
                target=self.monitor_with_strace,
                args=(cmd, results_queue)
            )
            strace_thread.start()

            # Wait for strace to complete
            strace_thread.join(timeout=self.timeout + 5)

            # Get results from queue
            try:
                while True:
                    result = results_queue.get_nowait()
                    if 'system_calls' in result:
                        self.results['system_calls'] = result['system_calls']
                    if 'network_connections' in result:
                        self.results['network_connections'].extend(result['network_connections'])
                    if 'dns_queries' in result:
                        self.results['dns_queries'].extend(result['dns_queries'])
                    if 'commands_executed' in result:
                        # commands_executed from strace are objects with binary/cmdline
                        for cmd_obj in result['commands_executed']:
                            cmd_str = cmd_obj.get('cmdline', cmd_obj.get('binary'))
                            if cmd_str and cmd_str not in self.results['commands_executed']:
                                self.results['commands_executed'].append(cmd_str)
                    if 'processes' in result:
                        # processes from psutil are objects with pid/name/cmdline
                        for p_obj in result['processes']:
                            p_cmd = p_obj.get('cmdline') or p_obj.get('name')
                            if p_cmd and p_cmd not in self.results['commands_executed']:
                                self.results['commands_executed'].append(p_cmd)
                    if 'processes_killed' in result:
                        self.results['processes_killed'].extend(result['processes_killed'])
                    if 'files_accessed' in result:
                        self.results['files_accessed'].extend(result['files_accessed'])
            except queue.Empty:
                pass

            # Wait a bit for monitoring threads to capture data
            time.sleep(2)

            # Stop tcpdump and parse captured traffic
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

            # Start tcpdump before anything else
            self.start_tcpdump()

            # Prepare execution command: interpreter + script path
            cmd = interpreter + [str(self.sample_path)]

            # Start monitoring threads
            results_queue = queue.Queue()

            # Set start_time BEFORE launching monitor threads
            self.start_time = time.time()

            # Start process monitoring
            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            # Start network monitoring (psutil-based, as backup)
            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            # Start strace monitoring (runs the script with interpreter)
            strace_thread = threading.Thread(
                target=self.monitor_with_strace,
                args=(cmd, results_queue)
            )
            strace_thread.start()

            # Wait for strace to complete
            strace_thread.join(timeout=self.timeout + 5)

            # Get results from queue
            try:
                while True:
                    result = results_queue.get_nowait()
                    if 'error' in result:
                        self.results['errors'].append(f"Monitor thread error: {result['error']}")
                    if 'system_calls' in result:
                        self.results['system_calls'] = result['system_calls']
                    if 'network_connections' in result:
                        self.results['network_connections'].extend(result['network_connections'])
                    if 'dns_queries' in result:
                        self.results['dns_queries'].extend(result['dns_queries'])
                    if 'commands_executed' in result:
                        # commands_executed from strace are objects with binary/cmdline
                        for cmd_obj in result['commands_executed']:
                            cmd_str = cmd_obj.get('cmdline', cmd_obj.get('binary'))
                            if cmd_str and cmd_str not in self.results['commands_executed']:
                                self.results['commands_executed'].append(cmd_str)
                    if 'processes' in result:
                        # processes from psutil are objects with pid/name/cmdline
                        for p_obj in result['processes']:
                            p_cmd = p_obj.get('cmdline') or p_obj.get('name')
                            if p_cmd and p_cmd not in self.results['commands_executed']:
                                self.results['commands_executed'].append(p_cmd)
                    if 'processes_killed' in result:
                        self.results['processes_killed'].extend(result['processes_killed'])
                    if 'files_accessed' in result:
                        self.results['files_accessed'].extend(result['files_accessed'])
            except queue.Empty:
                pass

            # Wait a bit for monitoring threads to capture data
            time.sleep(2)

            # Stop tcpdump and parse captured traffic
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
        for candidate in ['wine', 'wine64', '/usr/bin/wine', '/usr/local/bin/wine']:
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
            with open(self.sample_path, 'rb') as f:
                if f.read(2) != b'MZ':
                    return None
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset)
                if f.read(4) != b'PE\x00\x00':
                    return None
                machine = struct.unpack('<H', f.read(2))[0]

            pe_machines = {
                0x14c:  ('i386',    'qemu-i386-static'),    # IMAGE_FILE_MACHINE_I386
                0x8664: ('x86_64',  'qemu-x86_64-static'),  # IMAGE_FILE_MACHINE_AMD64
                0x1c0:  ('arm',     'qemu-arm-static'),     # IMAGE_FILE_MACHINE_ARM
                0xaa64: ('aarch64', 'qemu-aarch64-static'), # IMAGE_FILE_MACHINE_ARM64
            }
            if machine not in pe_machines:
                return None
            pe_arch, qemu_bin = pe_machines[machine]

            native = {'x86_64': ['x86_64','i386'], 'aarch64': ['aarch64','arm'],
                      'i686': ['i386'], 'armv7l': ['arm']}
            if pe_arch in native.get(host, [host]):
                return None            # Wine can run it natively
            for v in [qemu_bin, qemu_bin.replace('-static', '')]:
                if os.path.isfile(f'/usr/bin/{v}'):
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

        # ---- Fallback: no Wine available (ARM64 host) ---------
        if wine_bin is None:
            qemu_bin = self._get_pe_arch()
            if qemu_bin:
                self.results['execution_method'] = f'qemu-pe ({qemu_bin})'
                self.results['errors'].append(
                    'Wine not available; executing PE under QEMU user-mode '
                    '(syscall-level emulation, no Windows API layer)'
                )
                return self.execute_with_qemu(qemu_bin)

            # Cannot emulate at all — return static-only result
            self.results['execution_method'] = 'skipped (no wine, no qemu)'
            self.results['executed'] = False
            self.results['errors'].append(
                'Windows PE dynamic analysis unavailable: '
                'Wine is not installed and no suitable QEMU emulator found. '
                'Static analysis results are still available.'
            )
            self.summarize_behavior()
            return self.results

        # ---- Normal Wine path ---------------------------------
        try:
            self.results["execution_method"] = "wine"

            # Start tcpdump before anything else
            self.start_tcpdump()

            # Use sample already copied to /tmp from analyze()
            workspace_sample = self.sample_path  # Already in /tmp/sample_exec

            # Prepare Wine environment
            env = os.environ.copy()
            env['WINEDEBUG'] = '-all'
            env['WINEPREFIX'] = '/tmp/.wine'

            # Build Wine command for strace
            cmd = [wine_bin, str(workspace_sample)]

            # Start monitoring threads
            results_queue = queue.Queue()

            # Set start_time BEFORE launching monitor threads so they
            # can filter processes by creation time without a race condition
            self.start_time = time.time()

            # Start process monitoring
            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()

            # Start network monitoring (psutil-based, as backup)
            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()

            # Start strace monitoring (runs the actual Wine + sample)
            strace_thread = threading.Thread(
                target=self.monitor_with_strace,
                args=(cmd, results_queue)
            )
            strace_thread.start()

            # Wait for strace to complete (it runs the sample)
            strace_thread.join(timeout=self.timeout + 5)

            # Get results from queue
            try:
                while True:
                    result = results_queue.get_nowait()
                    if 'system_calls' in result:
                        self.results['system_calls'] = result['system_calls']
                    if 'network_connections' in result:
                        self.results['network_connections'].extend(result['network_connections'])
                    if 'dns_queries' in result:
                        self.results['dns_queries'].extend(result['dns_queries'])
                    if 'commands_executed' in result:
                        # commands_executed from strace are objects with binary/cmdline
                        for cmd_obj in result['commands_executed']:
                            cmd_str = cmd_obj.get('cmdline', cmd_obj.get('binary'))
                            if cmd_str and cmd_str not in self.results['commands_executed']:
                                self.results['commands_executed'].append(cmd_str)
                    if 'processes' in result:
                        # processes from psutil are objects with pid/name/cmdline
                        for p_obj in result['processes']:
                            p_cmd = p_obj.get('cmdline') or p_obj.get('name')
                            if p_cmd and p_cmd not in self.results['commands_executed']:
                                self.results['commands_executed'].append(p_cmd)
                    if 'processes_killed' in result:
                        self.results['processes_killed'].extend(result['processes_killed'])
                    if 'files_accessed' in result:
                        self.results['files_accessed'].extend(result['files_accessed'])
            except queue.Empty:
                pass

            # Wait a bit for monitoring threads to capture data
            time.sleep(2)

            # Stop tcpdump and parse captured traffic
            self.stop_tcpdump()

            # Check for created/modified files in workspace
            self.check_file_operations()

            self.results["executed"] = True
            self.summarize_behavior()

            return self.results

        except Exception as e:
            self.stop_tcpdump()  # Ensure tcpdump is stopped on error
            self.results["errors"].append(str(e))
            return self.results

    def log_debug(self, msg):
        # sys.stderr.write(f"MONITOR_DEBUG: {msg}\n")
        if 'trace_debug' not in self.results:
            self.results['trace_debug'] = []
        self.results['trace_debug'].append(msg)

    def monitor_with_strace(self, cmd: List[str], results_queue: queue.Queue):
        """Monitor system calls with strace."""
        self.log_debug(f"Starting monitor_with_strace for cmd: {cmd}")
        try:
            # output to file instead of stderr pipe to avoid buffering/pipe issues
            strace_log = self.workspace / 'strace.log'
            strace_cmd = ['strace', '-f', '-tt', '-s', '2048', '-o', str(strace_log)] + cmd
            self.log_debug(f"Strace command: {strace_cmd}")

            # Build environment — include WINEDEBUG/WINEPREFIX for Wine
            env = os.environ.copy()
            env['WINEDEBUG'] = '-all'
            env['WINEPREFIX'] = '/tmp/.wine'

            process = subprocess.Popen(
                strace_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,  # strace writes to file now, but capture stderr just in case
                env=env,
                preexec_fn=os.setsid
            )

            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                self.log_debug("Strace process commuicate returned")

                # Read strace output from file
                if strace_log.exists():
                    try:
                        with open(strace_log, 'r', errors='ignore') as f:
                            strace_output = f.read()
                    except Exception as e:
                        strace_output = ""
                        self.results['errors'].append(f"Failed to read strace log: {e}")
                else:
                    strace_output = ""
                    self.results['errors'].append("strace log file not found")

                # Parse strace output
                # Debug: Log first 20 lines of strace output to errors list to see format
                head = '\n'.join(strace_output.split('\n')[:20])
                self.results['errors'].append(f"DEBUG: strace header: {head}")

                syscalls = self.parse_strace_output(strace_output)
                self.log_debug(f"Parsed {len(syscalls)} syscalls")
                
                # Extract network connections from strace
                connections, dns = self.parse_strace_network(strace_output)
                
                # Extract behavioral information
                behaviors = self.parse_strace_behaviors(strace_output)

                results_queue.put({
                    'system_calls': syscalls[:100],
                    'network_connections': connections,
                    'dns_queries': dns,
                    'commands_executed': behaviors['commands_executed'],
                    'processes_killed': behaviors['processes_killed'],
                    'files_accessed': behaviors['files_accessed']
                })

            except subprocess.TimeoutExpired:
                self.log_debug("Strace TimeoutExpired")
                results_queue.put({'error': "DEBUG: strace timed out"})
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(1)
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)

        except Exception as e:
            self.log_debug(f"Exception in monitor_with_strace: {e}")
            results_queue.put({'error': str(e)})

    def parse_strace_output(self, output: str) -> List[str]:
        """Parse strace output for interesting syscalls."""
        syscalls = []

        for line in output.split('\n')[:200]:  # Limit lines
            line = line.strip()
            if not line or line.startswith('+'):
                continue

            # Look for interesting syscalls
            if any(call in line for call in ['open', 'socket', 'connect', 'execve', 'write', 'read']):
                syscalls.append(line)

        return syscalls

    def parse_strace_network(self, output: str) -> Tuple[List[Dict], List[Dict]]:
        """Extract network connections and DNS queries from strace output."""
        import re
        connections = []
        dns_queries = []
        seen_connections = set()
        
        # Patterns for connect() syscalls
        # IPv4: connect(18, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("104.18.26.120")}, 16)
        # IPv6: connect(18, {sa_family=AF_INET6, sin6_port=htons(80), sin6_addr=inet_pton(AF_INET6, "2606:4700::6812:1a78"), ...}, 28)
        ipv4_pattern = re.compile(
            r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)\}'
        )
        ipv6_pattern = re.compile(
            r'connect\(\d+,\s*\{sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),\s*sin6_addr=inet_pton\(AF_INET6,\s*"([^"]+)"\)'
        )
        
        for line in output.split('\n'):
            # Check IPv4
            match4 = ipv4_pattern.search(line)
            if match4:
                port = int(match4.group(1))
                ip = match4.group(2)
                self._record_connection(ip, port, connections, dns_queries, seen_connections)
                continue
            
            # Check IPv6
            match6 = ipv6_pattern.search(line)
            if match6:
                port = int(match6.group(1))
                ip = match6.group(2)
                self._record_connection(ip, port, connections, dns_queries, seen_connections)

        return connections, dns_queries

    def _record_connection(self, ip, port, connections, dns_queries, seen_connections):
        """Helper to record a connection if not duplicate and not noise."""
        # Skip localhost and link-local
        if ip.startswith('127.') or ip.startswith('169.254.') or ip == '::1' or ip.startswith('fe80:'):
            return
        
        # Filter out mDNS
        if port == 5353:
            return

        conn_key = (ip, port)
        if conn_key not in seen_connections:
            seen_connections.add(conn_key)
            
            if port == 53:
                dns_queries.append({
                    "server": ip,
                    "port": port,
                    "type": "DNS"
                })
            else:
                connections.append({
                    "protocol": "tcp",
                    "dst_ip": ip,
                    "dst_port": port,
                    "local_addr": "0.0.0.0:0"
                })

    def parse_strace_behaviors(self, output: str) -> Dict[str, List]:
        """Extract behavioral information from strace output."""
        import re
        
        behaviors = {
            "commands_executed": [],
            "processes_killed": [],
            "files_accessed": [],
            "files_created": [],
            "files_deleted": []
        }
        seen_commands = set()
        seen_files = set()
        
        for line in output.split('\n'):
            # Extract execve() calls - commands executed
            # e.g., [pid 1234] 12:34:56 execve("/bin/sh", ["sh", "-c", "whoami"], ...) = 0
            # Matches: anything before execve( then capture the binary and args
            execve_match = re.search(r'execve\("([^"]+)",\s*\[([^\]]*)\]', line)
            if execve_match:
                binary = execve_match.group(1)
                args_str = execve_match.group(2)
                
                # Skip internal Wine noise, but keep cmd.exe, powershell.exe, etc.
                wine_internal = ['wineserver', 'wineboot', 'winedevice', 'plugplay', 'services.exe', 'explorer.exe', 'rpcss.exe']
                if not any(skip == binary.split('/')[-1] for skip in wine_internal) and binary not in seen_commands:
                    seen_commands.add(binary)
                    
                    # Parse arguments
                    args = re.findall(r'"([^"]*)"', args_str)
                    cmd_line = ' '.join(args) if args else binary
                    
                    behaviors["commands_executed"].append({
                        "binary": binary,
                        "cmdline": cmd_line[:200],
                        "type": "execve"
                    })
            
            # Extract kill() calls - processes being killed
            # e.g., kill(1234, SIGKILL) = 0  or  kill(1234, 9) = 0
            kill_match = re.search(r'kill\((\d+),\s*(\w+)\)\s*=\s*(\d+)', line)
            if kill_match:
                pid = kill_match.group(1)
                signal = kill_match.group(2)
                behaviors["processes_killed"].append({
                    "pid": int(pid),
                    "signal": signal
                })
            
            # Extract file operations
            # openat() with write flags
            openat_match = re.search(r'openat\([^,]+,\s*"([^"]+)",\s*([^)]+)\)\s*=\s*(\d+)', line)
            if openat_match:
                filepath = openat_match.group(1)
                flags = openat_match.group(2)
                
                # Skip system files, libraries, and Wine internals
                if not any(skip in filepath for skip in ['/lib/', '/usr/lib/', '/etc/ld', '/proc/', '/dev/', '/sys/', '/.wine/', '/windows/', '/dosdevices/']):
                    if filepath not in seen_files:
                        seen_files.add(filepath)
                        
                        file_info = {
                            "path": filepath[:200],
                            "operation": "read"
                        }
                        # Check if creating/writing
                        if 'O_CREAT' in flags or 'O_WRONLY' in flags or 'O_RDWR' in flags:
                            file_info["operation"] = "write"
                            behaviors["files_created"].append(file_info)
                        
                        behaviors["files_accessed"].append(file_info)
            
            # unlink/unlinkat - file deletion
            unlink_match = re.search(r'unlink(?:at)?\([^,]*"([^"]+)"', line)
            if unlink_match:
                filepath = unlink_match.group(1)
                if not any(skip in filepath for skip in ['/tmp/', '/proc/']):
                    behaviors["files_deleted"].append({
                        "path": filepath[:200],
                        "operation": "delete"
                    })
            
            # rename - file operations
            rename_match = re.search(r'rename\("([^"]+)",\s*"([^"]+)"\)', line)
            if rename_match:
                src = rename_match.group(1)
                dst = rename_match.group(2)
                behaviors["files_accessed"].append({
                    "path": f"{src} -> {dst}"[:200],
                    "operation": "rename"
                })
        
        # Limit results
        for key in behaviors:
            behaviors[key] = behaviors[key][:30]
        
        return behaviors

    def monitor_processes(self):
        """Monitor spawned processes."""
        seen_pids = set()
        start_time = time.time()

        while time.time() - start_time < self.timeout + 2:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        if pid not in seen_pids and proc.info['create_time'] > self.start_time:
                            seen_pids.add(pid)
                            self.results["processes"].append({
                                "pid": pid,
                                "name": proc.info['name'],
                                "cmdline": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                time.sleep(0.5)
            except Exception:
                break

    def monitor_network(self):
        """Monitor network connections."""
        seen_connections = set()
        start_time = time.time()

        while time.time() - start_time < self.timeout + 2:
            try:
                # kind='all' includes both IPv4 and IPv6
                for conn in psutil.net_connections(kind='all'):
                    if conn.status == 'ESTABLISHED':
                        conn_tuple = (conn.laddr, conn.raddr)
                        if conn_tuple not in seen_connections:
                            seen_connections.add(conn_tuple)

                            if conn.raddr:
                                dst_ip = conn.raddr.ip
                                dst_port = conn.raddr.port
                                
                                # Filter out mDNS
                                if dst_port == 5353:
                                    continue

                                self.results["network_connections"].append({
                                    "protocol": "tcp" if conn.type == 1 else "udp",
                                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                                    "dst_ip": dst_ip,
                                    "dst_port": dst_port
                                })

                time.sleep(0.5)
            except Exception:
                break

    def check_file_operations(self):
        """Check for created/modified files in workspace."""
        try:
            for item in self.workspace.rglob('*'):
                if item.is_file() and item != self.sample_path:
                    try:
                        stat = item.stat()
                        self.results["file_operations"].append({
                            "path": str(item.relative_to(self.workspace)),
                            "size": stat.st_size,
                            "type": "created"
                        })
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
            "suspicious_behaviors": []
        }

        # Check for suspicious behaviors
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
            
        # Check for shell spawning
        for cmd in self.results.get("commands_executed", []):
            binary = cmd.get("binary", "")
            if any(sh in binary for sh in ["/bin/sh", "/bin/bash", "/bin/zsh", "cmd.exe", "powershell"]):
                if "spawns_shell" not in summary["suspicious_behaviors"]:
                    summary["suspicious_behaviors"].append("spawns_shell")

        self.results["behavior_summary"] = summary


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: monitor.py <sample_path>"}))
        sys.exit(1)

    sample_path = sys.argv[1]
    timeout = int(os.getenv('EXECUTION_TIMEOUT', 30))

    analyzer = DynamicAnalyzer(sample_path, timeout)
    results = analyzer.analyze()
    # Persist results to a file inside the workspace so the caller can
    # reliably read them even if container stdout/stderr are interleaved
    # with other diagnostic output (tcpdump/INetSim). Use PID to avoid
    # races when multiple analyses run concurrently.
    try:
        out_dir = Path('/analysis/workspace')
        out_path = out_dir / f'monitor_results_{os.getpid()}.json'
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(results, indent=2))
    except Exception:
        # Non-fatal: continue to emit results to stdout
        pass

    # Output results as JSON
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
