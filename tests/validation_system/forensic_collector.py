#!/usr/bin/env python3
"""
Forensic Evidence Collection Infrastructure for Intellicrack Validation System.

This module provides production-ready forensic evidence collection capabilities
including memory dumps, API call monitoring, network traffic capture, registry
monitoring, file system tracking, and screen recording with proper chain-of-custody.
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import threading
import queue
import struct
import ctypes
import ctypes.wintypes
import winreg
import socket
import datetime
import tempfile
import zipfile
import gnupg
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import win32api
import win32con
import win32process
import win32security
import win32file
import win32event
import win32evtlog
import win32evtlogutil
import wmi
import pymem
import pymem.process
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import cv2
import numpy as np
from PIL import ImageGrab
import pygetwindow as gw
import mss


@dataclass
class ForensicEvidence:
    """Container for forensic evidence with metadata."""
    
    evidence_type: str
    timestamp: float
    data_path: str
    sha256_hash: str
    size_bytes: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)


class MemoryDumper:
    """Handles process memory dumping with integrity verification."""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.psapi = ctypes.windll.psapi
        self.advapi32 = ctypes.windll.advapi32
        
    def dump_process_memory(self, pid: int, output_path: str) -> bool:
        """
        Dump complete process memory to file.
        
        Args:
            pid: Process ID to dump
            output_path: Path to save memory dump
            
        Returns:
            True if successful, False otherwise
        """
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        
        try:
            # Open process with required permissions
            process_handle = self.kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            if not process_handle:
                return False
                
            # Get process memory information
            mem_info = pymem.Pymem()
            mem_info.open_process_from_id(pid)
            
            with open(output_path, 'wb') as dump_file:
                # Iterate through memory regions
                address = 0
                while address < 0x7FFFFFFF0000:
                    try:
                        mbi = pymem.memory.virtual_query(mem_info.process_handle, address)
                        
                        # Check if memory is committed (0x1000 = MEM_COMMIT)
                        if mbi.State == 0x1000:
                            try:
                                # Read memory region
                                buffer = mem_info.read_bytes(mbi.BaseAddress, mbi.RegionSize)
                                
                                # Write to dump file with header
                                header = struct.pack('<QQ', mbi.BaseAddress, len(buffer))
                                dump_file.write(header)
                                dump_file.write(buffer)
                            except:
                                pass
                        
                        address = mbi.BaseAddress + mbi.RegionSize
                    except:
                        # Move to next page if query fails
                        address += 0x1000
            
            self.kernel32.CloseHandle(process_handle)
            return True
            
        except Exception as e:
            print(f"Memory dump failed: {e}")
            return False
    
    def capture_system_memory_snapshot(self, output_dir: str) -> List[str]:
        """
        Capture memory snapshots of all critical system processes.
        
        Args:
            output_dir: Directory to save memory dumps
            
        Returns:
            List of created dump file paths
        """
        dumps = []
        critical_processes = ['lsass.exe', 'csrss.exe', 'services.exe', 'svchost.exe']
        
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() in critical_processes:
                dump_path = os.path.join(output_dir, f"{proc.info['name']}_{proc.info['pid']}.dmp")
                if self.dump_process_memory(proc.info['pid'], dump_path):
                    dumps.append(dump_path)
        
        return dumps


class APIMonitor:
    """Monitors and logs Windows API calls using inline hooks."""
    
    def __init__(self):
        self.hooked_apis = {}
        self.api_log = []
        self.hook_lock = threading.Lock()
        
    def install_inline_hook(self, module: str, function: str, callback) -> bool:
        """
        Install inline hook on specified API function.
        
        Args:
            module: Module name containing the function
            function: Function name to hook
            callback: Callback function to execute on API call
            
        Returns:
            True if hook installed successfully
        """
        try:
            # Get module handle
            module_handle = ctypes.windll.kernel32.GetModuleHandleW(module)
            if not module_handle:
                module_handle = ctypes.windll.kernel32.LoadLibraryW(module)
            
            # Get function address
            func_addr = ctypes.windll.kernel32.GetProcAddress(module_handle, function.encode())
            if not func_addr:
                return False
            
            # Create inline hook (x64 assembly)
            hook_code = bytes([
                0x48, 0xB8,  # mov rax, imm64
            ]) + struct.pack('<Q', ctypes.cast(callback, ctypes.c_void_p).value) + bytes([
                0xFF, 0xE0   # jmp rax
            ])
            
            # Make memory writable
            old_protect = ctypes.wintypes.DWORD()
            ctypes.windll.kernel32.VirtualProtect(
                func_addr, len(hook_code), 0x40, ctypes.byref(old_protect)
            )
            
            # Save original bytes
            original_bytes = ctypes.string_at(func_addr, len(hook_code))
            
            # Write hook
            ctypes.memmove(func_addr, hook_code, len(hook_code))
            
            # Restore protection
            ctypes.windll.kernel32.VirtualProtect(
                func_addr, len(hook_code), old_protect.value, ctypes.byref(old_protect)
            )
            
            with self.hook_lock:
                self.hooked_apis[f"{module}::{function}"] = original_bytes
            
            return True
            
        except Exception as e:
            print(f"Failed to hook {module}::{function}: {e}")
            return False
    
    def log_api_call(self, api_name: str, args: tuple, return_value: Any):
        """Log API call with arguments and return value."""
        with self.hook_lock:
            self.api_log.append({
                'timestamp': time.time(),
                'api': api_name,
                'arguments': str(args),
                'return_value': str(return_value),
                'thread_id': threading.get_ident(),
                'process_id': os.getpid()
            })
    
    def export_api_log(self, output_path: str):
        """Export API call log to JSON file."""
        with self.hook_lock:
            with open(output_path, 'w') as f:
                json.dump(self.api_log, f, indent=2)


class NetworkMonitor:
    """Captures and analyzes network traffic using raw sockets."""
    
    def __init__(self):
        self.capture_thread = None
        self.stop_capture_event = threading.Event()
        self.packets = []
        self.packet_lock = threading.Lock()
        
    def start_capture(self, interface: str = None):
        """
        Start capturing network packets.
        
        Args:
            interface: Network interface to capture on (None for all)
        """
        self.stop_capture_event.clear()
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface,)
        )
        self.capture_thread.start()
    
    def _capture_packets(self, interface: str):
        """Internal packet capture loop."""
        try:
            # Create raw socket for packet capture
            if os.name == 'nt':
                # Windows raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Unix raw socket
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            while not self.stop_capture_event.is_set():
                # Receive packet
                raw_data, addr = sock.recvfrom(65536)
                
                # Parse packet with scapy
                packet = IP(raw_data)
                
                # Store packet data
                with self.packet_lock:
                    self.packets.append({
                        'timestamp': time.time(),
                        'src_ip': packet.src if hasattr(packet, 'src') else None,
                        'dst_ip': packet.dst if hasattr(packet, 'dst') else None,
                        'protocol': packet.proto if hasattr(packet, 'proto') else None,
                        'size': len(raw_data),
                        'raw_hex': raw_data.hex()
                    })
            
            if os.name == 'nt':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def stop_capture(self):
        """Stop packet capture."""
        self.stop_capture_event.set()
        if self.capture_thread:
            self.capture_thread.join()
    
    def export_pcap(self, output_path: str):
        """Export captured packets to PCAP file."""
        with self.packet_lock:
            packets_scapy = []
            for pkt_data in self.packets:
                try:
                    raw_bytes = bytes.fromhex(pkt_data['raw_hex'])
                    packet = IP(raw_bytes)
                    packets_scapy.append(packet)
                except:
                    pass
            
            scapy.wrpcap(output_path, packets_scapy)


class RegistryMonitor:
    """Monitors Windows registry changes in real-time."""
    
    def __init__(self):
        self.monitored_keys = []
        self.registry_changes = []
        self.monitor_threads = []
        self.stop_monitoring_event = threading.Event()
        
    def add_monitored_key(self, hive: int, subkey: str):
        """
        Add registry key to monitoring list.
        
        Args:
            hive: Registry hive constant (e.g., winreg.HKEY_LOCAL_MACHINE)
            subkey: Subkey path to monitor
        """
        self.monitored_keys.append((hive, subkey))
    
    def start_monitoring(self):
        """Start monitoring all configured registry keys."""
        self.stop_monitoring_event.clear()
        
        for hive, subkey in self.monitored_keys:
            thread = threading.Thread(
                target=self._monitor_key,
                args=(hive, subkey)
            )
            thread.start()
            self.monitor_threads.append(thread)
    
    def _monitor_key(self, hive: int, subkey: str):
        """Internal registry monitoring loop."""
        try:
            # Take initial snapshot
            initial_snapshot = self._capture_key_snapshot(hive, subkey)
            
            while not self.stop_monitoring_event.is_set():
                time.sleep(0.5)
                
                # Take current snapshot
                current_snapshot = self._capture_key_snapshot(hive, subkey)
                
                # Compare snapshots
                changes = self._compare_snapshots(initial_snapshot, current_snapshot)
                
                if changes:
                    self.registry_changes.extend(changes)
                    initial_snapshot = current_snapshot
                    
        except Exception as e:
            print(f"Registry monitoring error: {e}")
    
    def _capture_key_snapshot(self, hive: int, subkey: str) -> Dict:
        """Capture current state of registry key."""
        snapshot = {
            'values': {},
            'subkeys': []
        }
        
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            
            # Enumerate values
            idx = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, idx)
                    snapshot['values'][name] = (value, value_type)
                    idx += 1
                except WindowsError:
                    break
            
            # Enumerate subkeys
            idx = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, idx)
                    snapshot['subkeys'].append(subkey_name)
                    idx += 1
                except WindowsError:
                    break
            
            winreg.CloseKey(key)
            
        except Exception:
            pass
        
        return snapshot
    
    def _compare_snapshots(self, old: Dict, new: Dict) -> List[Dict]:
        """Compare two registry snapshots and return changes."""
        changes = []
        
        # Check for value changes
        for name, (value, vtype) in new['values'].items():
            if name not in old['values']:
                changes.append({
                    'timestamp': time.time(),
                    'type': 'value_added',
                    'name': name,
                    'value': value,
                    'value_type': vtype
                })
            elif old['values'][name] != (value, vtype):
                changes.append({
                    'timestamp': time.time(),
                    'type': 'value_modified',
                    'name': name,
                    'old_value': old['values'][name][0],
                    'new_value': value
                })
        
        # Check for deleted values
        for name in old['values']:
            if name not in new['values']:
                changes.append({
                    'timestamp': time.time(),
                    'type': 'value_deleted',
                    'name': name
                })
        
        # Check for subkey changes
        added_keys = set(new['subkeys']) - set(old['subkeys'])
        deleted_keys = set(old['subkeys']) - set(new['subkeys'])
        
        for key in added_keys:
            changes.append({
                'timestamp': time.time(),
                'type': 'subkey_added',
                'name': key
            })
        
        for key in deleted_keys:
            changes.append({
                'timestamp': time.time(),
                'type': 'subkey_deleted',
                'name': key
            })
        
        return changes
    
    def stop_monitoring(self):
        """Stop all registry monitoring threads."""
        self.stop_monitoring_event.set()
        for thread in self.monitor_threads:
            thread.join()
    
    def export_changes(self, output_path: str):
        """Export registry changes to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.registry_changes, f, indent=2)


class FileSystemMonitor:
    """Monitors file system changes using Windows API."""
    
    def __init__(self):
        self.monitored_paths = []
        self.file_changes = []
        self.monitor_threads = []
        self.stop_monitoring_event = threading.Event()
        
    def add_monitored_path(self, path: str, recursive: bool = True):
        """
        Add path to file system monitoring.
        
        Args:
            path: Directory path to monitor
            recursive: Monitor subdirectories recursively
        """
        self.monitored_paths.append((path, recursive))
    
    def start_monitoring(self):
        """Start monitoring all configured paths."""
        self.stop_monitoring_event.clear()
        
        for path, recursive in self.monitored_paths:
            thread = threading.Thread(
                target=self._monitor_path,
                args=(path, recursive)
            )
            thread.start()
            self.monitor_threads.append(thread)
    
    def _monitor_path(self, path: str, recursive: bool):
        """Internal file system monitoring loop."""
        try:
            # File change notification flags
            FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
            FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
            FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
            FILE_NOTIFY_CHANGE_SIZE = 0x00000008
            FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
            FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
            
            change_handle = win32file.FindFirstChangeNotification(
                path,
                recursive,
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_ATTRIBUTES |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SECURITY
            )
            
            while not self.stop_monitoring_event.is_set():
                result = win32event.WaitForSingleObject(change_handle, 500)
                
                if result == win32con.WAIT_OBJECT_0:
                    # Change detected
                    self.file_changes.append({
                        'timestamp': time.time(),
                        'path': path,
                        'type': 'change_detected'
                    })
                    
                    # Get detailed change information
                    self._get_change_details(path)
                    
                    # Reset notification
                    win32file.FindNextChangeNotification(change_handle)
            
            win32file.FindCloseChangeNotification(change_handle)
            
        except Exception as e:
            print(f"File system monitoring error: {e}")
    
    def _get_change_details(self, path: str):
        """Get detailed information about file system changes."""
        try:
            # Use WMI to get more detailed change information
            c = wmi.WMI()
            
            # Query recent file operations
            query = f"SELECT * FROM CIM_DataFile WHERE Drive='{path[0]}:'"
            for file in c.query(query):
                if file.LastModified:
                    # Check if recently modified
                    mod_time = datetime.datetime.strptime(
                        file.LastModified.split('.')[0], '%Y%m%d%H%M%S'
                    )
                    if (datetime.datetime.now() - mod_time).seconds < 5:
                        self.file_changes.append({
                            'timestamp': time.time(),
                            'path': file.Name,
                            'type': 'modified',
                            'size': file.FileSize,
                            'last_modified': str(mod_time)
                        })
        except:
            pass
    
    def stop_monitoring(self):
        """Stop all file system monitoring threads."""
        self.stop_monitoring_event.set()
        for thread in self.monitor_threads:
            thread.join()
    
    def export_changes(self, output_path: str):
        """Export file system changes to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.file_changes, f, indent=2)


class ScreenRecorder:
    """Records screen activity with timestamp overlay."""
    
    def __init__(self, fps: int = 10):
        self.fps = fps
        self.recording = False
        self.record_thread = None
        self.frames = []
        self.frame_lock = threading.Lock()
        
    def start_recording(self):
        """Start screen recording."""
        self.recording = True
        self.record_thread = threading.Thread(target=self._record_screen)
        self.record_thread.start()
    
    def _record_screen(self):
        """Internal screen recording loop."""
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # Primary monitor
            
            while self.recording:
                # Capture screenshot
                screenshot = sct.grab(monitor)
                
                # Convert to numpy array
                frame = np.array(screenshot)
                
                # Add timestamp overlay
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                font = cv2.FONT_HERSHEY_SIMPLEX
                cv2.putText(frame, timestamp, (10, 30), font, 1, (0, 255, 0), 2)
                
                # Store frame
                with self.frame_lock:
                    self.frames.append(frame)
                
                # Control frame rate
                time.sleep(1.0 / self.fps)
    
    def stop_recording(self):
        """Stop screen recording."""
        self.recording = False
        if self.record_thread:
            self.record_thread.join()
    
    def save_video(self, output_path: str):
        """Save recorded frames as video file."""
        if not self.frames:
            return
        
        with self.frame_lock:
            # Get frame dimensions
            height, width = self.frames[0].shape[:2]
            
            # Create video writer
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(output_path, fourcc, self.fps, (width, height))
            
            # Write frames
            for frame in self.frames:
                # Convert BGRA to BGR
                frame_bgr = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
                out.write(frame_bgr)
            
            out.release()


class ForensicCollector:
    """Main forensic evidence collection orchestrator."""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.memory_dumper = MemoryDumper()
        self.api_monitor = APIMonitor()
        self.network_monitor = NetworkMonitor()
        self.registry_monitor = RegistryMonitor()
        self.filesystem_monitor = FileSystemMonitor()
        self.screen_recorder = ScreenRecorder()
        
        self.evidence_list = []
        self.gpg = gnupg.GPG()
        
        # Setup monitoring for critical areas
        self._setup_default_monitoring()
    
    def _setup_default_monitoring(self):
        """Configure default monitoring targets."""
        # Registry keys commonly used by protection systems
        self.registry_monitor.add_monitored_key(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Classes\Licenses"
        )
        self.registry_monitor.add_monitored_key(
            winreg.HKEY_CURRENT_USER,
            r"Software\Classes\Licenses"
        )
        self.registry_monitor.add_monitored_key(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\FLEXlm License Manager"
        )
        
        # File system paths
        self.filesystem_monitor.add_monitored_path(
            os.environ.get('PROGRAMDATA', r'C:\ProgramData'),
            recursive=True
        )
        self.filesystem_monitor.add_monitored_path(
            os.environ.get('APPDATA', r'C:\Users\Default\AppData\Roaming'),
            recursive=True
        )
        
        # API hooks for license checking
        self.api_monitor.install_inline_hook("kernel32.dll", "CreateFileW", self._api_callback)
        self.api_monitor.install_inline_hook("advapi32.dll", "RegQueryValueExW", self._api_callback)
        self.api_monitor.install_inline_hook("ws2_32.dll", "connect", self._api_callback)
    
    def _api_callback(self, *args):
        """Callback for API hooks."""
        # Log API call
        import inspect
        caller = inspect.stack()[1]
        self.api_monitor.log_api_call(caller.function, args, None)
    
    def start_collection(self):
        """Start all forensic evidence collection."""
        print("[+] Starting forensic evidence collection...")
        
        # Start monitors
        self.network_monitor.start_capture()
        self.registry_monitor.start_monitoring()
        self.filesystem_monitor.start_monitoring()
        self.screen_recorder.start_recording()
        
        # Capture initial memory state
        self._capture_memory_snapshot("before")
        
        print("[+] All forensic collectors active")
    
    def stop_collection(self):
        """Stop all forensic evidence collection and package results."""
        print("[+] Stopping forensic evidence collection...")
        
        # Stop monitors
        self.network_monitor.stop_capture()
        self.registry_monitor.stop_monitoring()
        self.filesystem_monitor.stop_monitoring()
        self.screen_recorder.stop_recording()
        
        # Capture final memory state
        self._capture_memory_snapshot("after")
        
        # Export all collected data
        self._export_all_evidence()
        
        # Create evidence package
        package_path = self._create_evidence_package()
        
        print(f"[+] Evidence package created: {package_path}")
        return package_path
    
    def _capture_memory_snapshot(self, phase: str):
        """Capture memory snapshot for specified phase."""
        snapshot_dir = self.output_dir / f"memory_{phase}"
        snapshot_dir.mkdir(exist_ok=True)
        
        # Dump current process memory
        current_pid = os.getpid()
        dump_path = snapshot_dir / f"process_{current_pid}.dmp"
        self.memory_dumper.dump_process_memory(current_pid, str(dump_path))
        
        # Add to evidence list
        self._add_evidence(
            ForensicEvidence(
                evidence_type="memory_dump",
                timestamp=time.time(),
                data_path=str(dump_path),
                sha256_hash=self._calculate_file_hash(dump_path),
                size_bytes=dump_path.stat().st_size,
                metadata={'phase': phase, 'pid': current_pid}
            )
        )
    
    def _export_all_evidence(self):
        """Export all collected evidence to files."""
        # Export API calls
        api_log_path = self.output_dir / "api_calls.json"
        self.api_monitor.export_api_log(str(api_log_path))
        self._add_evidence(
            ForensicEvidence(
                evidence_type="api_calls",
                timestamp=time.time(),
                data_path=str(api_log_path),
                sha256_hash=self._calculate_file_hash(api_log_path),
                size_bytes=api_log_path.stat().st_size
            )
        )
        
        # Export network traffic
        pcap_path = self.output_dir / "network_traffic.pcap"
        self.network_monitor.export_pcap(str(pcap_path))
        self._add_evidence(
            ForensicEvidence(
                evidence_type="network_traffic",
                timestamp=time.time(),
                data_path=str(pcap_path),
                sha256_hash=self._calculate_file_hash(pcap_path),
                size_bytes=pcap_path.stat().st_size
            )
        )
        
        # Export registry changes
        registry_path = self.output_dir / "registry_changes.json"
        self.registry_monitor.export_changes(str(registry_path))
        self._add_evidence(
            ForensicEvidence(
                evidence_type="registry_changes",
                timestamp=time.time(),
                data_path=str(registry_path),
                sha256_hash=self._calculate_file_hash(registry_path),
                size_bytes=registry_path.stat().st_size
            )
        )
        
        # Export file system changes
        fs_path = self.output_dir / "filesystem_changes.json"
        self.filesystem_monitor.export_changes(str(fs_path))
        self._add_evidence(
            ForensicEvidence(
                evidence_type="filesystem_changes",
                timestamp=time.time(),
                data_path=str(fs_path),
                sha256_hash=self._calculate_file_hash(fs_path),
                size_bytes=fs_path.stat().st_size
            )
        )
        
        # Save screen recording
        video_path = self.output_dir / "screen_recording.mp4"
        self.screen_recorder.save_video(str(video_path))
        self._add_evidence(
            ForensicEvidence(
                evidence_type="screen_recording",
                timestamp=time.time(),
                data_path=str(video_path),
                sha256_hash=self._calculate_file_hash(video_path),
                size_bytes=video_path.stat().st_size
            )
        )
    
    def _create_evidence_package(self) -> str:
        """Create compressed and signed evidence package."""
        # Create package directory
        package_dir = self.output_dir / f"evidence_package_{int(time.time())}"
        package_dir.mkdir(exist_ok=True)
        
        # Copy all evidence files
        for evidence in self.evidence_list:
            src = Path(evidence.data_path)
            if src.exists():
                dst = package_dir / src.name
                import shutil
                shutil.copy2(src, dst)
        
        # Create chain of custody document
        chain_of_custody = {
            'created': datetime.datetime.now().isoformat(),
            'collector_version': '1.0.0',
            'system_info': {
                'platform': sys.platform,
                'hostname': socket.gethostname(),
                'username': os.environ.get('USERNAME', 'unknown')
            },
            'evidence_items': [asdict(e) for e in self.evidence_list]
        }
        
        custody_path = package_dir / "chain_of_custody.json"
        with open(custody_path, 'w') as f:
            json.dump(chain_of_custody, f, indent=2)
        
        # Create ZIP archive
        zip_path = self.output_dir / f"evidence_{int(time.time())}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(package_dir):
                for file in files:
                    file_path = Path(root) / file
                    arc_name = file_path.relative_to(package_dir)
                    zf.write(file_path, arc_name)
        
        # Calculate package hash
        package_hash = self._calculate_file_hash(zip_path)
        
        # Sign package (if GPG key available)
        signature_path = self._sign_package(zip_path)
        
        # Create final manifest
        manifest = {
            'package_path': str(zip_path),
            'package_hash': package_hash,
            'signature_path': str(signature_path) if signature_path else None,
            'created': datetime.datetime.now().isoformat()
        }
        
        manifest_path = self.output_dir / "manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return str(zip_path)
    
    def _sign_package(self, package_path: Path) -> Optional[Path]:
        """Sign evidence package with GPG."""
        try:
            # Check if GPG key is available
            keys = self.gpg.list_keys(True)
            if not keys:
                print("[!] No GPG key available for signing")
                return None
            
            # Sign the package
            sig_path = package_path.with_suffix('.sig')
            with open(package_path, 'rb') as f:
                signed_data = self.gpg.sign_file(f, detach=True, output=str(sig_path))
            
            if signed_data:
                return sig_path
            else:
                print("[!] Failed to sign package")
                return None
                
        except Exception as e:
            print(f"[!] GPG signing error: {e}")
            return None
    
    def _add_evidence(self, evidence: ForensicEvidence):
        """Add evidence item to collection."""
        # Add to chain of custody
        evidence.chain_of_custody.append({
            'timestamp': time.time(),
            'action': 'collected',
            'collector': self.__class__.__name__
        })
        
        self.evidence_list.append(evidence)
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return "error_calculating_hash"
    
    def capture_during_bypass(self, target_process: str, bypass_function):
        """
        Capture forensic evidence during bypass execution.
        
        Args:
            target_process: Name of process being bypassed
            bypass_function: Function that performs the bypass
        """
        # Start collection
        self.start_collection()
        
        # Wait for stabilization
        time.sleep(2)
        
        # Capture "during" memory state
        self._capture_memory_snapshot("during")
        
        # Execute bypass
        print(f"[+] Executing bypass on {target_process}...")
        try:
            result = bypass_function()
            print(f"[+] Bypass result: {result}")
        except Exception as e:
            print(f"[!] Bypass failed: {e}")
        
        # Wait for bypass to take effect
        time.sleep(5)
        
        # Stop collection and package
        return self.stop_collection()


def run_forensic_test():
    """Test forensic evidence collection capabilities."""
    print("=== Forensic Evidence Collection Test ===")
    
    # Create collector
    collector = ForensicCollector(r"C:\Intellicrack\tests\validation_system\forensic_evidence")
    
    # Start collection
    collector.start_collection()
    
    # Simulate some activity
    print("[*] Simulating system activity...")
    
    # Create a test file
    test_file = Path(os.environ['TEMP']) / "forensic_test.txt"
    with open(test_file, 'w') as f:
        f.write("Forensic test data")
    
    # Modify registry (safe test key)
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\IntellicrackForensicTest")
        winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "TestData")
        winreg.CloseKey(key)
    except:
        pass
    
    # Network activity
    try:
        socket.gethostbyname("example.com")
    except:
        pass
    
    # Wait for collection
    time.sleep(5)
    
    # Stop collection
    package = collector.stop_collection()
    
    print(f"\n[+] Test complete. Evidence package: {package}")
    
    # Cleanup
    if test_file.exists():
        test_file.unlink()
    
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\IntellicrackForensicTest")
    except:
        pass


if __name__ == "__main__":
    run_forensic_test()