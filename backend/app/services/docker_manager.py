"""
Docker container management service.
Handles creation, execution, and cleanup of isolated analysis containers.
"""
import logging
import docker
import uuid
import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Optional, Tuple
import time

from app.config import settings

logger = logging.getLogger(__name__)


class DockerManager:
    """Manages Docker containers for malware analysis."""

    def __init__(self):
        """Initialize Docker client."""
        try:
            self.client = docker.DockerClient(base_url=settings.docker_socket)
            self.client.ping()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            raise

    def create_isolated_network(self, network_name: Optional[str] = None) -> str:
        """
        Create an isolated Docker network for analysis.

        Args:
            network_name: Optional network name (auto-generated if not provided)

        Returns:
            Network ID
        """
        if not network_name:
            network_name = f"{settings.docker_network_prefix}_{uuid.uuid4().hex[:8]}"

        try:
            network = self.client.networks.create(
                network_name,
                driver="bridge",
                internal=True,  # No external network access
                check_duplicate=True
            )
            logger.info(f"Created isolated network: {network_name}")
            return network.id
        except Exception as e:
            logger.error(f"Failed to create network: {e}")
            raise

    def remove_network(self, network_id: str) -> None:
        """
        Remove a Docker network.

        Args:
            network_id: Network ID to remove
        """
        try:
            network = self.client.networks.get(network_id)
            network.remove()
            logger.info(f"Removed network: {network_id}")
        except Exception as e:
            logger.warning(f"Failed to remove network {network_id}: {e}")

    def run_static_analysis(
        self,
        sample_path: Path,
        timeout: int = 300
    ) -> Tuple[bool, Dict, str]:
        """
        Run static analysis container.

        Args:
            sample_path: Path to the malware sample
            timeout: Analysis timeout in seconds

        Returns:
            Tuple of (success, results_dict, container_id)
        """
        container_id = None
        work_dir = None
        try:
            # Verify source file exists
            if not sample_path.exists():
                return False, {"error": f"Sample file not found: {sample_path}"}, "none"
            
            # Create a workspace directory inside quarantine for sample
            analysis_temp_dir = settings.upload_dir / '_analysis_temp'
            analysis_temp_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(analysis_temp_dir, 0o755)
            
            work_dir = tempfile.mkdtemp(prefix='static_', dir=str(analysis_temp_dir))
            os.chmod(work_dir, 0o755)  # Allow non-root user in container to access
            sample_dest = Path(work_dir) / 'sample.bin'
            shutil.copy2(sample_path, sample_dest)
            os.chmod(sample_dest, 0o644)  # World-readable
            
            # Calculate host path for Docker mount
            # Container path: /app/quarantine/_analysis_temp/static_XXX
            # Host path: {HOST_QUARANTINE_PATH}/_analysis_temp/static_XXX
            relative_path = Path(work_dir).relative_to(settings.upload_dir)
            if settings.host_quarantine_path:
                host_work_dir = str(Path(settings.host_quarantine_path) / relative_path)
            else:
                # Fallback: assume the container path matches host path
                host_work_dir = work_dir
            
            logger.info(f"Work dir: container={work_dir}, host={host_work_dir}")
            
            # Container configuration
            container_config = {
                'image': settings.static_analysis_image,
                'detach': True,
                'network_mode': 'none',  # No network access for static analysis
                'mem_limit': '2g',
                'cpu_quota': 100000,  # 1 CPU core
                'read_only': False,  # Need write access to workspace
                'security_opt': ['no-new-privileges:true'],
                'cap_drop': ['ALL'],
                'tmpfs': {'/tmp': 'size=100M,mode=1777'},
                'volumes': {
                    host_work_dir: {'bind': '/analysis/workspace', 'mode': 'rw'}
                },
                'environment': {
                    'ANALYSIS_TIMEOUT': str(timeout)
                },
                'command': ['python3', '/analysis/analyze.py', '/analysis/workspace/sample.bin']
            }

            # Run container
            logger.info(f"Starting static analysis container for {sample_path}")
            container = self.client.containers.run(**container_config)
            container_id = container.id

            # Wait for container to complete
            result = container.wait(timeout=timeout)

            # Get logs (contains JSON results). Logs may include diagnostic
            # lines before/after the JSON (e.g. tcpdump or INetSim messages).
            logs = container.logs().decode('utf-8')

            # Parse results robustly: try to parse whole output first, then
            # search for a JSON object substring (try from last '{' backwards)
            import json, re
            results = None
            logger.info(f"Container raw logs: {logs}")
            try:
                results = json.loads(logs)
                success = result['StatusCode'] == 0
            except json.JSONDecodeError:
                # Try to locate a JSON object within the logs by searching for
                # opening braces and attempting to parse from the last ones.
                try:
                    positions = [m.start() for m in re.finditer(r"\{", logs)]
                    for pos in reversed(positions):
                        try:
                            candidate = logs[pos:]
                            results = json.loads(candidate)
                            break
                        except Exception:
                            continue
                except Exception:
                    results = None

                # As a fallback, try to extract any {...} balanced blocks via regex
                if results is None:
                    try:
                        matches = re.findall(r"(\{.*\})", logs, re.DOTALL)
                        for m in reversed(matches):
                            try:
                                results = json.loads(m)
                                break
                            except Exception:
                                continue
                    except Exception:
                        results = None

                if results is None:
                    logger.error(f"Failed to parse container output: {logs}")
                    results = {"error": "Failed to parse analysis results", "raw_logs": logs}
                    success = False
                else:
                    success = result['StatusCode'] == 0

            logger.info(f"Static analysis completed: {container_id}")
            return success, results, container_id

        except docker.errors.ContainerError as e:
            logger.error(f"Container error: {e}")
            return False, {"error": str(e)}, container_id or "unknown"

        except docker.errors.ImageNotFound:
            logger.error(f"Image not found: {settings.static_analysis_image}")
            return False, {"error": f"Analysis image not found: {settings.static_analysis_image}"}, "none"

        except Exception as e:
            logger.error(f"Static analysis failed: {e}", exc_info=True)
            return False, {"error": str(e)}, container_id or "unknown"

        finally:
            # Clean up container
            if container_id:
                self.cleanup_container(container_id)
            # Clean up work directory
            if work_dir and os.path.exists(work_dir):
                shutil.rmtree(work_dir, ignore_errors=True)

    def run_dynamic_analysis(
        self,
        sample_path: Path,
        network_id: str,
        timeout: int = 60,
        original_filename: str = 'sample.bin'
    ) -> Tuple[bool, Dict, str]:
        """
        Run dynamic analysis container with network monitoring.

        Args:
            sample_path: Path to the malware sample
            network_id: Network ID for isolated network
            timeout: Analysis timeout in seconds
            original_filename: Original filename for script detection

        Returns:
            Tuple of (success, results_dict, container_id)
        """
        container_id = None
        work_dir = None
        try:
            # Verify sample exists
            if not os.path.isfile(sample_path):
                raise FileNotFoundError(f"Sample not found: {sample_path}")

            # Create workspace directory inside quarantine for sample
            analysis_temp_dir = settings.upload_dir / '_analysis_temp'
            analysis_temp_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(analysis_temp_dir, 0o755)
            
            work_dir = tempfile.mkdtemp(prefix='dynamic_', dir=str(analysis_temp_dir))
            os.chmod(work_dir, 0o755)  # Allow non-root user in container to access
            sample_dest = os.path.join(work_dir, 'sample.bin')
            shutil.copy2(str(sample_path), sample_dest)
            os.chmod(sample_dest, 0o644)  # World-readable

            # Calculate host path for Docker mount
            relative_path = Path(work_dir).relative_to(settings.upload_dir)
            if settings.host_quarantine_path:
                host_work_dir = str(Path(settings.host_quarantine_path) / relative_path)
            else:
                host_work_dir = work_dir
            
            logger.error(f"DEBUG: Dynamic work dir: container={work_dir}, host={host_work_dir}")

            # Retrieve Gateway IP to use as DNS
            gateway_ip = None
            try:
                # Find the gateway container on this network
                containers = self.client.containers.list(filters={'network': network_id})
                for c in containers:
                    if settings.network_gateway_image in c.image.tags or 'network-gateway' in c.name:
                        # Refresh to get latest networking info
                        c.reload()
                        net_info = c.attrs.get('NetworkSettings', {}).get('Networks', {}).get(network_id, {})
                        if not net_info:
                            # Try by network name if network_id is not the key
                            for name, info in c.attrs.get('NetworkSettings', {}).get('Networks', {}).items():
                                if info.get('NetworkID') == network_id:
                                    net_info = info
                                    break
                        
                        gateway_ip = net_info.get('IPAddress')
                        if gateway_ip:
                            break
            except Exception as e:
                logger.warning(f"Failed to retrieve gateway IP for DNS: {e}")

            # Container configuration
            container_config = {
                'image': settings.dynamic_analysis_image,
                'detach': True,
                'network': network_id,  # Attach to isolated analysis network (connects to gateway)
                'mem_limit': '2g',
                'cpu_quota': 100000,
                # 'security_opt': ['no-new-privileges:true'],
                'cap_drop': ['ALL'],
                'cap_add': ['SYS_PTRACE', 'NET_RAW', 'NET_ADMIN'],  # Needed for strace, tcpdump and iptables
                'tmpfs': {
                    '/tmp': 'size=100M,mode=1777,exec'
                },
                'volumes': {
                    host_work_dir: {'bind': '/analysis/workspace', 'mode': 'rw'}
                },
                'environment': {
                    'ANALYSIS_TIMEOUT': str(timeout),
                    'EXECUTION_TIMEOUT': str(settings.dynamic_execution_timeout),
                    'ORIGINAL_FILENAME': original_filename,
                    'GATEWAY_IP': gateway_ip or ""
                },
                'dns': [gateway_ip] if gateway_ip else None,
                'command': ['python3', '/analysis/monitor.py', '/analysis/workspace/sample.bin']
            }

            # Run container
            logger.info(f"Starting dynamic analysis container for {sample_path}")
            container = self.client.containers.run(**container_config)
            container_id = container.id

            # Wait for container to complete
            result = container.wait(timeout=timeout + 30)

            # Get logs (contains JSON results)
            logs = container.logs().decode('utf-8')

            # Parse results robustly: try to parse whole output first, then
            # search for a JSON object substring (try from last '{' backwards).
            # If that fails, look for a results file written to the mounted
            # workspace by the monitor (monitor_results_<pid>.json).
            import json, re, glob
            results = None
            try:
                results = json.loads(logs)
                success = result['StatusCode'] == 0
            except json.JSONDecodeError:
                # Try to locate a JSON object within the logs by searching for
                # opening braces and attempting to parse from the last ones.
                try:
                    positions = [m.start() for m in re.finditer(r"\{", logs)]
                    for pos in reversed(positions):
                        try:
                            candidate = logs[pos:]
                            results = json.loads(candidate)
                            break
                        except Exception:
                            continue
                except Exception:
                    results = None

                # As a fallback, try to extract any {...} balanced blocks via regex
                if results is None:
                    try:
                        matches = re.findall(r"(\{.*\})", logs, re.DOTALL)
                        for m in reversed(matches):
                            try:
                                results = json.loads(m)
                                break
                            except Exception:
                                continue
                    except Exception:
                        results = None

                # If still not found, check for output files in the host workspace
                if results is None:
                    try:
                        # host_work_dir is the path mounted into the container
                        pattern = os.path.join(host_work_dir, 'monitor_results_*.json')
                        files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
                        for fp in files:
                            try:
                                with open(fp, 'r', encoding='utf-8') as fh:
                                    results = json.load(fh)
                                    logger.debug(f"Loaded results from file: {fp}")
                                    break
                            except Exception:
                                continue
                    except Exception:
                        results = None

                if results is None:
                    logger.error(f"Failed to parse container output: {logs}")
                    results = {"error": "Failed to parse analysis results", "raw_logs": logs}
                    success = False
                else:
                    success = result['StatusCode'] == 0

            logger.info(f"Dynamic analysis completed: {container_id}")
            return success, results, container_id

        except docker.errors.ContainerError as e:
            logger.error(f"Container error: {e}")
            return False, {"error": str(e)}, container_id or "unknown"

        except docker.errors.ImageNotFound:
            logger.error(f"Image not found: {settings.dynamic_analysis_image}")
            return False, {"error": f"Analysis image not found: {settings.dynamic_analysis_image}"}, "none"

        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}", exc_info=True)
            return False, {"error": str(e)}, container_id or "unknown"

        finally:
            # Clean up container
            if container_id:
                self.cleanup_container(container_id)
            # Clean up work directory
            if work_dir and os.path.exists(work_dir):
                logger.error(f"DEBUG: Preserving work dir for debugging: {work_dir}")
                # shutil.rmtree(work_dir, ignore_errors=True)

    def run_network_gateway(
        self,
        network_id: str,
        duration: int = 60
    ) -> Tuple[bool, str]:
        """
        Run network gateway container with INetSim.

        Args:
            network_id: Network ID to attach to
            duration: How long to run gateway (seconds)

        Returns:
            Tuple of (success, container_id)
        """
        container_id = None
        try:
            # Container configuration
            container_config = {
                'image': settings.network_gateway_image,
                'detach': True,
                'privileged': True,
                'network': network_id,
                'mem_limit': '1g',
                'cpu_quota': 50000,
                # 'security_opt': ['no-new-privileges:true'],
                # 'cap_drop': ['ALL'],
                'cap_add': ['NET_ADMIN', 'NET_RAW'],  # Needed for networking
                'tmpfs': {'/tmp': 'size=100M,mode=1777'},
                'command': ['/start_gateway.sh']
            }

            # Run container
            logger.info(f"Starting network gateway container on network {network_id}")
            container = self.client.containers.run(**container_config)
            container_id = container.id

            # Wait a moment for gateway to initialize
            time.sleep(2)

            logger.info(f"Network gateway started: {container_id}")
            return True, container_id

        except docker.errors.ImageNotFound:
            logger.error(f"Image not found: {settings.network_gateway_image}")
            return False, "none"

        except Exception as e:
            logger.error(f"Failed to start network gateway: {e}", exc_info=True)
            return False, container_id or "unknown"

    def stop_container(self, container_id: str, timeout: int = 10) -> None:
        """
        Stop a running container.

        Args:
            container_id: Container ID to stop
            timeout: Timeout for graceful shutdown
        """
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=timeout)
            logger.info(f"Stopped container: {container_id}")
        except docker.errors.NotFound:
            logger.warning(f"Container not found: {container_id}")
        except Exception as e:
            logger.error(f"Failed to stop container {container_id}: {e}")

    def cleanup_container(self, container_id: str) -> None:
        """
        Remove a container and clean up resources.

        Args:
            container_id: Container ID to remove
        """
        try:
            container = self.client.containers.get(container_id)
            container.remove(force=True)
            logger.info(f"Removed container: {container_id}")
        except docker.errors.NotFound:
            logger.debug(f"Container already removed: {container_id}")
        except Exception as e:
            logger.error(f"Failed to remove container {container_id}: {e}")

    def get_container_logs(self, container_id: str) -> str:
        """
        Get logs from a container.

        Args:
            container_id: Container ID

        Returns:
            Container logs as string
        """
        try:
            container = self.client.containers.get(container_id)
            return container.logs().decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to get logs for {container_id}: {e}")
            return ""

    def cleanup_orphaned_containers(self) -> int:
        """
        Clean up any orphaned analysis containers.

        Returns:
            Number of containers cleaned up
        """
        cleaned = 0
        try:
            # Find containers with our prefix
            containers = self.client.containers.list(
                all=True,
                filters={'name': 'pegasus-'}
            )

            for container in containers:
                try:
                    container.remove(force=True)
                    cleaned += 1
                    logger.info(f"Cleaned up orphaned container: {container.id}")
                except Exception as e:
                    logger.warning(f"Failed to clean up {container.id}: {e}")

        except Exception as e:
            logger.error(f"Failed to cleanup orphaned containers: {e}")

        return cleaned

    def cleanup_orphaned_networks(self) -> int:
        """
        Clean up any orphaned analysis networks.

        Returns:
            Number of networks cleaned up
        """
        cleaned = 0
        try:
            # Find networks with our prefix
            networks = self.client.networks.list(
                filters={'name': settings.docker_network_prefix}
            )

            for network in networks:
                try:
                    network.remove()
                    cleaned += 1
                    logger.info(f"Cleaned up orphaned network: {network.id}")
                except Exception as e:
                    logger.warning(f"Failed to clean up network {network.id}: {e}")

        except Exception as e:
            logger.error(f"Failed to cleanup orphaned networks: {e}")

        return cleaned


# Singleton instance
docker_manager = DockerManager()
