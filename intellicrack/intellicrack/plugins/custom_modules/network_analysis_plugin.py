"""Network Analysis Plugin Template.

Specialized template for network traffic analysis.
"""

import logging
import sys

from intellicrack.utils.subprocess_security import secure_run


class NetworkAnalysisPlugin:
    """Analyze binary network capabilities and monitor network traffic."""

    def __init__(self):
        """Initialize the network analysis plugin."""
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
            b'http://', b'https://', b'ftp://',
            b'socket', b'connect', b'bind', b'listen',
            b'send', b'recv', b'WSAStartup'
        ]

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

                found_indicators = []
                for indicator in network_indicators:
                    if indicator in data:
                        found_indicators.append(indicator.decode('utf-8', errors='ignore'))

                if found_indicators:
                    results.append("Network indicators found:")
                    for indicator in found_indicators:
                        results.append(f"  - {indicator}")
                else:
                    results.append("No obvious network indicators found")

        except Exception as e:
            logging.getLogger(__name__).error("Exception in plugin_system: %s", e)
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
            logging.getLogger(__name__).error(f"Network monitoring error: {e}")
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
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                results.append("Warning: Root privileges required for packet capture")

            # Try to use tcpdump or similar
            import subprocess

            if target_process:
                pid = self._get_process_pid(target_process)
                if pid:
                    # Get connections for specific process
                    cmd = ["lsof", "-i", "-n", "-P", "-p", str(pid)]
                    try:
                        output = secure_run(cmd, capture_output=True, text=True).stdout
                        results.append(f"Network connections for PID {pid}:")
                        results.extend(output.strip().split('\n')[1:])  # Skip header
                    except subprocess.CalledProcessError as e:
                        results.append(f"Failed to get network connections for PID {pid}: {e}")
                    except (OSError, FileNotFoundError):
                        results.append("lsof command not available on this system")

            # Try to capture some traffic
            try:
                cmd = ["tcpdump", "-c", "10", "-n", "-i", "any"]
                output = secure_run(cmd, capture_output=True, text=True, timeout=5).stdout
                results.append("Captured traffic:")
                results.extend(output.strip().split('\n'))
            except subprocess.TimeoutExpired:
                results.append("Packet capture timed out")
            except (subprocess.CalledProcessError, OSError, FileNotFoundError) as e:
                # Fallback to netstat
                logging.getLogger(__name__).debug(f"Packet capture failed: {e}")
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
                output = secure_run(cmd, capture_output=True, text=True).stdout
            else:
                # Try ss first, then fall back to netstat
                try:
                    cmd = ["ss", "-tunap"]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
                except (subprocess.CalledProcessError, FileNotFoundError):
                    cmd = ["netstat", "-tunap"]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
            lines = output.strip().split('\n')

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
            for proc in psutil.process_iter(['pid', 'name']):
                if process_name.lower() in (proc.info.get('name') or "").lower():
                    return proc.info['pid']
        except Exception:
            # Fallback method
            try:
                import subprocess
                if sys.platform == "win32":
                    cmd = ["wmic", "process", "where", f"name like '%{process_name}%'", "get", "processid"]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        return int(lines[1].strip())
                else:
                    cmd = ["pgrep", "-f", process_name]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
                    return int(output.strip().split('\n')[0])
            except (subprocess.CalledProcessError, ValueError, IndexError) as e:
                logging.getLogger(__name__).debug(f"Failed to get PID for process '{process_name}': {e}")
            except (OSError, FileNotFoundError):
                logging.getLogger(__name__).debug("Process enumeration command not available on this system")
        return None

    def _get_process_connections(self, pid):
        """Get network connections for a specific PID."""
        results = []

        try:
            from intellicrack.handlers.psutil_handler import psutil
            process = psutil.Process(pid)
            connections = process.connections(kind='inet')

            results.append(f"Process {pid} has {len(connections)} connections:")
            for conn in connections:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                status = conn.status if hasattr(conn, 'status') else "N/A"
                prot = getattr(conn, "type", None)
                proto_name = prot.name if hasattr(prot, "name") else str(prot)
                results.append(f"  {proto_name} {laddr} -> {raddr} [{status}]")

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

            # Run netstat and then filter for tcp/udp lines
            netstat_cmd = ["netstat", "-tunap"]
            netstat_result = secure_run(netstat_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)

            # Filter output for tcp/udp lines
            lines = netstat_result.stdout.strip().split('\n')
            filtered_lines = [line for line in lines if any(proto in line.lower() for proto in ['tcp', 'udp'])]
            output = '\n'.join(filtered_lines)

            lines = output.strip().split('\n')
            results.append("Active connections:")

            for line in lines[:20]:  # Limit output
                results.append(line.strip())

        except Exception as e:
            results.append(f"Netstat error: {e}")

        return results

def register():
    """Register and instantiate the network analysis plugin."""
    return NetworkAnalysisPlugin()
