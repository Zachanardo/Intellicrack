"""Network Analysis Plugin Template
Specialized template for network traffic analysis.
"""

import logging
import shlex
import shutil
import sys

logger = logging.getLogger(__name__)


class NetworkAnalysisPlugin:
    """Plugin for network traffic analysis and monitoring capabilities for security research."""

    def __init__(self):
        """Initialize the network analysis plugin with traffic monitoring capabilities."""
        self.name = "Network Analysis Plugin"
        self.version = "1.0.0"
        self.description = "Template for network traffic analysis"
        self.protocols = ["HTTP", "HTTPS", "TCP", "UDP"]

    def analyze(self, binary_path):
        """Analyze binary for network-related functionality."""
        results = []
        results.append(f"Analyzing network capabilities of: {binary_path}")

        # Check for network-related strings
        network_indicators = [
            b"http://",
            b"https://",
            b"ftp://",
            b"socket",
            b"connect",
            b"bind",
            b"listen",
            b"send",
            b"recv",
            b"WSAStartup",
        ]

        try:
            with open(binary_path, "rb") as f:
                data = f.read()

                found_indicators = []
                for indicator in network_indicators:
                    if indicator in data:
                        found_indicators.append(indicator.decode("utf-8", errors="ignore"))

                if found_indicators:
                    results.append("Network indicators found:")
                    for indicator in found_indicators:
                        results.append(f"  - {indicator}")
                else:
                    results.append("No obvious network indicators found")

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            results.append(f"Analysis error: {e}")

        return results

    def monitor_traffic(self, target_process=None):
        """Monitor network traffic for a process or system-wide."""
        results = []

        try:
            # Windows implementation using WinPcap/Npcap if available
            if sys.platform == "win32":
                results.extend(self._monitor_windows_traffic(target_process))
            else:
                # Linux/Unix implementation
                results.extend(self._monitor_unix_traffic(target_process))

        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
            results.append(f"Error: {str(e)}")
            results.append("Fallback: Using netstat-based monitoring")
            results.extend(self._fallback_network_monitor(target_process))

        return results

    def _monitor_windows_traffic(self, target_process=None):
        """Monitor network traffic on Windows."""
        results = []

        try:
            # Try to use pypcap or scapy if available
            try:
                from scapy.all import IP, TCP, UDP, sniff

                results.append("Using Scapy for packet capture")

                # Get process connections first
                if target_process:
                    pid = self._get_process_pid(target_process)
                    if pid:
                        results.append(f"Monitoring traffic for PID: {pid}")
                        connections = self._get_process_connections(pid)
                        results.extend(connections)

                # Capture packets (limited to prevent blocking)
                def packet_callback(packet):
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                        if TCP in packet:
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport
                            results.append(f"TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                        elif UDP in packet:
                            src_port = packet[UDP].sport
                            dst_port = packet[UDP].dport
                            results.append(f"UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

                # Capture 10 packets as example
                packets = sniff(count=10, prn=packet_callback, timeout=5)
                results.append(f"Captured {len(packets)} packets")

            except ImportError:
                # Fallback to WMI for connection monitoring
                results.append("Using WMI for connection monitoring")
                results.extend(self._monitor_wmi_connections(target_process))

        except Exception as e:
            results.append(f"Windows monitoring error: {e}")

        return results

    def _monitor_unix_traffic(self, target_process=None):
        """Monitor network traffic on Unix/Linux."""
        results = []

        try:
            # Check if we have permissions
            import os

            if os.geteuid() != 0:
                results.append("Warning: Root privileges required for packet capture")

            # Try to use tcpdump or similar
            import subprocess

            if target_process:
                pid = self._get_process_pid(target_process)
                if pid:
                    # Get connections for specific process
                    cmd = f"lsof -i -n -P -p {pid}"
                    try:
                        output = subprocess.check_output(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                            shlex.split(cmd), text=True
                        )
                        results.append(f"Network connections for PID {pid}:")
                        results.extend(output.strip().split("\n")[1:])  # Skip header
                    except subprocess.CalledProcessError as e:
                        results.append(f"Failed to get network connections for PID {pid}: {e}")
                    except (OSError, FileNotFoundError):
                        results.append("lsof command not available on this system")

            # Try to capture some traffic
            try:
                cmd = "tcpdump -c 10 -n -i any"
                output = subprocess.check_output(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    shlex.split(cmd), text=True, timeout=5
                )
                results.append("Captured traffic:")
                results.extend(output.strip().split("\n"))
            except subprocess.TimeoutExpired:
                results.append("Packet capture timed out")
            except Exception:
                # Fallback to netstat
                results.extend(self._get_netstat_connections(target_process))

        except Exception as e:
            results.append(f"Unix monitoring error: {e}")

        return results

    def _fallback_network_monitor(self, target_process=None):
        """Fallback network monitoring using netstat/ss."""
        results = []

        try:
            import subprocess

            if sys.platform == "win32":
                cmd = ["netstat", "-ano"]
                output = subprocess.check_output(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    cmd, text=True
                )
            else:
                # Try ss first, then netstat as fallback
                try:
                    ss_path = shutil.which("ss")
                    if ss_path:
                        output = subprocess.check_output(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                            [ss_path, "-tunap"], text=True, stderr=subprocess.DEVNULL
                        )
                    else:
                        raise FileNotFoundError("ss command not found")
                except (subprocess.CalledProcessError, FileNotFoundError):
                    netstat_path = shutil.which("netstat")
                    if netstat_path:
                        output = subprocess.check_output(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                            [netstat_path, "-tunap"], text=True, stderr=subprocess.DEVNULL
                        )
                    else:
                        output = ""
            lines = output.strip().split("\n")

            if target_process:
                pid = self._get_process_pid(target_process)
                if pid:
                    results.append(f"Connections for PID {pid}:")
                    for line in lines:
                        if str(pid) in line:
                            results.append(line.strip())
            else:
                results.append("Active network connections:")
                # Show first 20 connections
                for line in lines[1:21]:  # Skip header, limit output
                    results.append(line.strip())

        except Exception as e:
            results.append(f"Fallback monitoring error: {e}")

        return results

    def _get_process_pid(self, process_name):
        """Get PID from process name."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            for proc in psutil.process_iter(["pid", "name"]):
                if process_name.lower() in proc.info["name"].lower():
                    return proc.info["pid"]
        except Exception:
            # Fallback method
            try:
                import subprocess

                if sys.platform == "win32":
                    cmd = ["wmic", "process", "where", f"name like '%{process_name}%'", "get", "processid"]
                    output = subprocess.check_output(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        cmd, text=True
                    )
                    lines = output.strip().split("\n")
                    if len(lines) > 1:
                        return int(lines[1].strip())
                else:
                    cmd = ["pgrep", "-f", process_name]
                    output = subprocess.check_output(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        cmd, text=True
                    )
                    return int(output.strip().split("\n")[0])
            except (subprocess.CalledProcessError, ValueError, IndexError) as e:
                logger.debug(f"Failed to get PID for process '{process_name}': {e}")
            except (OSError, FileNotFoundError):
                logger.debug("Process enumeration command not available on this system")
        return None

    def _get_process_connections(self, pid):
        """Get network connections for a specific PID."""
        results = []

        try:
            from intellicrack.handlers.psutil_handler import psutil

            process = psutil.Process(pid)
            connections = process.connections(kind="inet")

            results.append(f"Process {pid} has {len(connections)} connections:")
            for conn in connections:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                status = conn.status if hasattr(conn, "status") else "N/A"
                results.append(f"  {conn.type.name} {laddr} -> {raddr} [{status}]")

        except Exception as e:
            results.append(f"Error getting connections: {e}")

        return results

    def _monitor_wmi_connections(self, target_process=None):
        """Monitor connections using WMI on Windows."""
        results = []

        try:
            import wmi

            c = wmi.WMI()

            # Get network connections
            for conn in c.Win32_PerfRawData_Tcpip_TCPv4():
                results.append(f"TCP Connections: {conn.ConnectionsActive}")
                results.append(f"Connection Failures: {conn.ConnectionFailures}")
                break  # Just show summary

            # Get process-specific info if requested
            if target_process:
                for process in c.Win32_Process(Name=target_process):
                    results.append(f"Process {process.Name} (PID: {process.ProcessId})")
                    # Note: Direct connection mapping requires additional APIs

        except Exception as e:
            results.append(f"WMI error: {e}")

        return results

    def _get_netstat_connections(self, target_process=None):
        """Get connections using netstat."""
        results = []

        try:
            import subprocess

            # Get netstat output, then filter for tcp/udp
            netstat_path = shutil.which("netstat")
            if netstat_path:
                netstat_proc = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    [netstat_path, "-tunap"], capture_output=True, text=True, stderr=subprocess.DEVNULL, shell=False
                )
            else:
                netstat_proc = type("obj", (object,), {"returncode": 1, "stdout": ""})()
            if netstat_proc.returncode == 0:
                grep_path = shutil.which("grep")
                if grep_path:
                    grep_proc = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        [grep_path, "-E", "tcp|udp"], input=netstat_proc.stdout, capture_output=True, text=True, shell=False
                    )
                else:
                    grep_proc = type("obj", (object,), {"returncode": 1, "stdout": ""})()
                output = grep_proc.stdout if grep_proc.returncode == 0 else ""
            else:
                output = ""

            lines = output.strip().split("\n")
            results.append("Active connections:")

            for line in lines[:20]:  # Limit output
                results.append(line.strip())

        except Exception as e:
            results.append(f"Netstat error: {e}")

        return results


def register():
    """Register and return an instance of the network analysis plugin for the plugin system."""
    return NetworkAnalysisPlugin()
