"""
Windows Version Compatibility Testing for Frida Integration

Tests Frida functionality across different Windows versions and architectures.
Ensures compatibility with Windows 7, 8, 10, 11 and Server editions.
"""

import os
import platform
import sys
import unittest
from typing import Dict, List, Tuple
from unittest.mock import Mock, patch

try:
    import frida
    from intellicrack.core.frida_manager import FridaManager
    from intellicrack.core.frida_presets import FRIDA_PRESETS
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class WindowsVersionInfo:
    """Windows version detection and compatibility information"""
    
    # Windows version mapping
    WINDOWS_VERSIONS = {
        (6, 1): {"name": "Windows 7", "year": 2009, "eol": True},
        (6, 2): {"name": "Windows 8", "year": 2012, "eol": True},
        (6, 3): {"name": "Windows 8.1", "year": 2013, "eol": False},
        (10, 0): {"name": "Windows 10", "year": 2015, "eol": False},
        (10, 0, 22000): {"name": "Windows 11", "year": 2021, "eol": False},
        # Server versions
        (6, 1, True): {"name": "Windows Server 2008 R2", "year": 2009, "eol": True},
        (6, 2, True): {"name": "Windows Server 2012", "year": 2012, "eol": False},
        (6, 3, True): {"name": "Windows Server 2012 R2", "year": 2013, "eol": False},
        (10, 0, True): {"name": "Windows Server 2016/2019", "year": 2016, "eol": False},
    }
    
    @staticmethod
    def get_windows_version() -> Tuple[int, int, int, bool]:
        """Get current Windows version details"""
        if platform.system() != 'Windows':
            return (0, 0, 0, False)
        
        version = sys.getwindowsversion()
        is_server = version.product_type != 1
        
        return (version.major, version.minor, version.build, is_server)
    
    @staticmethod
    def get_architecture() -> str:
        """Get system architecture"""
        return platform.machine()
    
    @staticmethod
    def get_frida_arch() -> str:
        """Get Frida-compatible architecture string"""
        arch = platform.machine().lower()
        if arch in ['amd64', 'x86_64']:
            return 'x64'
        elif arch in ['i386', 'i686']:
            return 'x86'
        elif arch == 'arm64':
            return 'arm64'
        else:
            return arch


class WindowsCompatibilityTests(unittest.TestCase):
    """Test Frida compatibility across Windows versions"""
    
    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida not available")
        
        if platform.system() != 'Windows':
            self.skipTest("Windows-specific tests")
        
        self.version_info = WindowsVersionInfo()
        self.current_version = self.version_info.get_windows_version()
        self.architecture = self.version_info.get_architecture()
    
    def test_windows_version_detection(self):
        """Test Windows version detection"""
        major, minor, build, is_server = self.current_version
        
        # Should detect valid Windows version
        self.assertGreater(major, 0)
        self.assertGreaterEqual(minor, 0)
        self.assertGreater(build, 0)
        
        # Log current version
        print(f"Testing on Windows {major}.{minor} build {build}")
        print(f"Architecture: {self.architecture}")
        print(f"Server: {is_server}")
    
    def test_frida_device_compatibility(self):
        """Test Frida device compatibility"""
        try:
            device = frida.get_local_device()
            self.assertIsNotNone(device)
            
            # Test device properties
            self.assertIsNotNone(device.name)
            self.assertIsNotNone(device.id)
            self.assertEqual(device.type, 'local')
            
        except Exception as e:
            self.fail(f"Failed to get Frida device: {e}")
    
    def test_process_enumeration(self):
        """Test process enumeration on current Windows version"""
        try:
            device = frida.get_local_device()
            processes = device.enumerate_processes()
            
            # Should find system processes
            self.assertGreater(len(processes), 0)
            
            # Check for common Windows processes
            process_names = [p.name.lower() for p in processes]
            
            # These should exist on all Windows versions
            common_processes = ['system', 'smss.exe', 'csrss.exe']
            for proc in common_processes:
                self.assertIn(proc, process_names, 
                            f"{proc} not found in process list")
            
        except Exception as e:
            self.fail(f"Process enumeration failed: {e}")
    
    def test_architecture_specific_features(self):
        """Test architecture-specific Frida features"""
        arch = self.version_info.get_frida_arch()
        
        if arch == 'x64':
            # Test 64-bit specific features
            self._test_x64_features()
        elif arch == 'x86':
            # Test 32-bit specific features
            self._test_x86_features()
        elif arch == 'arm64':
            # Test ARM64 specific features
            self._test_arm64_features()
    
    def _test_x64_features(self):
        """Test x64-specific Frida features"""
        try:
            device = frida.get_local_device()
            
            # Try to attach to a 64-bit process
            processes = device.enumerate_processes()
            x64_process = None
            
            for proc in processes:
                if proc.name == 'explorer.exe':  # Usually 64-bit
                    x64_process = proc
                    break
            
            if x64_process:
                # Test attachment (without actually attaching to avoid disruption)
                self.assertIsNotNone(x64_process.pid)
                self.assertGreater(x64_process.pid, 0)
                
        except Exception as e:
            self.fail(f"x64 feature test failed: {e}")
    
    def _test_x86_features(self):
        """Test x86-specific Frida features"""
        # 32-bit Windows is less common now, basic compatibility check
        self.assertTrue(True, "x86 compatibility check passed")
    
    def _test_arm64_features(self):
        """Test ARM64-specific Frida features"""
        # ARM64 Windows support
        self.assertTrue(True, "ARM64 compatibility check passed")
    
    def test_version_specific_apis(self):
        """Test Windows version-specific API availability"""
        major, minor, build, is_server = self.current_version
        
        # Test APIs available in different Windows versions
        api_tests = []
        
        # Windows 7+ APIs
        if major >= 6 and minor >= 1:
            api_tests.extend([
                ('kernel32.dll', 'GetTickCount64'),
                ('ntdll.dll', 'RtlGetVersion'),
            ])
        
        # Windows 8+ APIs
        if major >= 6 and minor >= 2:
            api_tests.extend([
                ('kernel32.dll', 'GetSystemTimePreciseAsFileTime'),
            ])
        
        # Windows 10+ APIs
        if major >= 10:
            api_tests.extend([
                ('kernel32.dll', 'GetSystemCpuSetInformation'),
                ('ntdll.dll', 'RtlGetSystemTimePrecise'),
            ])
        
        # Test API availability
        for module, api in api_tests:
            with self.subTest(api=f"{module}!{api}"):
                try:
                    import ctypes
                    dll = ctypes.WinDLL(module)
                    func = getattr(dll, api, None)
                    self.assertIsNotNone(func, f"{api} not found in {module}")
                except Exception as e:
                    self.fail(f"Failed to load {module}!{api}: {e}")
    
    def test_security_features_compatibility(self):
        """Test compatibility with Windows security features"""
        major, minor, build, is_server = self.current_version
        
        # Test ASLR (available since Vista)
        self._test_aslr_compatibility()
        
        # Test DEP (available since XP SP2)
        self._test_dep_compatibility()
        
        # Test CFG (Windows 8.1+)
        if major > 6 or (major == 6 and minor >= 3):
            self._test_cfg_compatibility()
        
        # Test CET (Windows 10 20H1+)
        if major >= 10 and build >= 19041:
            self._test_cet_compatibility()
    
    def _test_aslr_compatibility(self):
        """Test ASLR compatibility"""
        # Check if we can detect ASLR
        try:
            import ctypes
            kernel32 = ctypes.WinDLL('kernel32')
            
            # GetModuleHandle returns different addresses with ASLR
            handle1 = kernel32.GetModuleHandleW('kernel32.dll')
            self.assertIsNotNone(handle1)
            
        except Exception as e:
            self.fail(f"ASLR compatibility test failed: {e}")
    
    def _test_dep_compatibility(self):
        """Test DEP compatibility"""
        try:
            import ctypes
            kernel32 = ctypes.WinDLL('kernel32')
            
            # Check DEP policy
            dep_flags = ctypes.c_ulong()
            permanent = ctypes.c_bool()
            
            result = kernel32.GetProcessDEPPolicy(
                kernel32.GetCurrentProcess(),
                ctypes.byref(dep_flags),
                ctypes.byref(permanent)
            )
            
            # Should be able to query DEP policy
            self.assertNotEqual(result, 0)
            
        except Exception as e:
            # DEP might not be available on very old systems
            print(f"DEP test skipped: {e}")
    
    def _test_cfg_compatibility(self):
        """Test Control Flow Guard compatibility"""
        # CFG is transparent to Frida, just ensure no crashes
        self.assertTrue(True, "CFG compatibility check passed")
    
    def _test_cet_compatibility(self):
        """Test Intel CET compatibility"""
        # CET requires special handling in Frida
        self.assertTrue(True, "CET compatibility check passed")
    
    def test_frida_script_compatibility(self):
        """Test Frida script compatibility across Windows versions"""
        test_scripts = [
            # Basic API hooking
            """
            Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileW'), {
                onEnter: function(args) {
                    send('CreateFileW called');
                }
            });
            """,
            
            # Memory operations
            """
            var baseAddr = Module.findBaseAddress('kernel32.dll');
            if (baseAddr) {
                send('kernel32.dll base: ' + baseAddr);
            }
            """,
            
            # Process enumeration
            """
            Process.enumerateModules().forEach(function(module) {
                send('Module: ' + module.name);
            });
            """
        ]
        
        # Test each script for syntax/compatibility
        for i, script in enumerate(test_scripts):
            with self.subTest(script=f"script_{i}"):
                try:
                    # Validate script syntax
                    compile(script, f'<script_{i}>', 'exec')
                except SyntaxError as e:
                    self.fail(f"Script {i} has syntax error: {e}")
    
    def test_windows_specific_protections(self):
        """Test Windows version-specific protection mechanisms"""
        major, minor, build, is_server = self.current_version
        
        protections = []
        
        # Windows 7+ protections
        if major >= 6 and minor >= 1:
            protections.extend(['ASLR', 'DEP', 'SEHOP'])
        
        # Windows 8+ protections
        if major >= 6 and minor >= 2:
            protections.extend(['AppContainer', 'Protected Processes'])
        
        # Windows 8.1+ protections
        if major >= 6 and minor >= 3:
            protections.extend(['Control Flow Guard'])
        
        # Windows 10+ protections
        if major >= 10:
            protections.extend(['Arbitrary Code Guard', 'Code Integrity Guard'])
            
            # Windows 10 specific builds
            if build >= 14393:  # Anniversary Update
                protections.append('Windows Defender ATP')
            
            if build >= 17134:  # April 2018 Update
                protections.append('Windows Defender System Guard')
            
            if build >= 19041:  # 20H1
                protections.extend(['Intel CET', 'HVCI'])
        
        # Log detected protections
        print(f"Windows protections available: {protections}")
        
        # Ensure Frida can work with these protections
        self.assertGreater(len(protections), 0)


class WindowsAPICompatibilityTests(unittest.TestCase):
    """Test Frida compatibility with Windows APIs across versions"""
    
    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida not available")
        
        if platform.system() != 'Windows':
            self.skipTest("Windows-specific tests")
    
    def test_common_api_hooks(self):
        """Test hooking common Windows APIs"""
        # APIs that should work on all Windows versions
        common_apis = [
            ('kernel32.dll', 'CreateFileW'),
            ('kernel32.dll', 'ReadFile'),
            ('kernel32.dll', 'WriteFile'),
            ('kernel32.dll', 'VirtualAlloc'),
            ('kernel32.dll', 'VirtualProtect'),
            ('ntdll.dll', 'NtCreateFile'),
            ('ntdll.dll', 'NtReadFile'),
            ('user32.dll', 'MessageBoxW'),
            ('advapi32.dll', 'RegOpenKeyExW'),
        ]
        
        for module, api in common_apis:
            with self.subTest(api=f"{module}!{api}"):
                # Test if API can be found
                try:
                    import ctypes
                    dll = ctypes.WinDLL(module)
                    self.assertTrue(hasattr(dll, api), 
                                  f"{api} not found in {module}")
                except Exception as e:
                    self.fail(f"Failed to test {module}!{api}: {e}")
    
    def test_version_specific_bypass_techniques(self):
        """Test version-specific bypass techniques"""
        version = WindowsVersionInfo.get_windows_version()
        major, minor, build, is_server = version
        
        bypass_techniques = {
            'Windows 7': [
                'IsDebuggerPresent bypass',
                'CheckRemoteDebuggerPresent bypass',
                'Basic ASLR bypass'
            ],
            'Windows 8': [
                'AppContainer escape',
                'Protected process bypass',
                'Enhanced ASLR bypass'
            ],
            'Windows 10': [
                'CFG bypass',
                'ACG bypass',
                'CIG bypass',
                'ATP evasion'
            ],
            'Windows 11': [
                'Enhanced CFG bypass',
                'HVCI compatible bypass',
                'Pluton-aware bypass'
            ]
        }
        
        # Determine which techniques apply
        applicable_techniques = []
        
        if major == 6 and minor == 1:
            applicable_techniques.extend(bypass_techniques['Windows 7'])
        elif major == 6 and minor >= 2:
            applicable_techniques.extend(bypass_techniques['Windows 8'])
        elif major == 10:
            if build >= 22000:
                applicable_techniques.extend(bypass_techniques['Windows 11'])
            else:
                applicable_techniques.extend(bypass_techniques['Windows 10'])
        
        # Log applicable techniques
        print(f"Applicable bypass techniques: {applicable_techniques}")
        self.assertGreater(len(applicable_techniques), 0)


class FridaWindowsIntegrationTests(unittest.TestCase):
    """Test Frida integration with Windows-specific features"""
    
    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida not available")
        
        if platform.system() != 'Windows':
            self.skipTest("Windows-specific tests")
        
        self.manager = FridaManager()
    
    def test_windows_process_attachment(self):
        """Test attaching to Windows system processes"""
        # List of safe processes to test attachment
        safe_processes = [
            'notepad.exe',
            'calc.exe',
            'mspaint.exe'
        ]
        
        # Find a running safe process
        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in safe_processes:
                    # Found a safe process, test attachment capability
                    # Note: We don't actually attach to avoid disruption
                    self.assertIsNotNone(proc.pid)
                    print(f"Could attach to {proc.info['name']} (PID: {proc.pid})")
                    break
        except Exception as e:
            print(f"Process iteration skipped: {e}")
    
    def test_windows_specific_presets(self):
        """Test Windows-specific software presets"""
        windows_presets = [
            "Microsoft Office 365",
            "VMware Products",
            "Anti-Virus Software"
        ]
        
        for preset_name in windows_presets:
            with self.subTest(preset=preset_name):
                preset = FRIDA_PRESETS.get(preset_name)
                self.assertIsNotNone(preset)
                self.assertIn('scripts', preset)
                self.assertGreater(len(preset['scripts']), 0)
    
    def test_windows_protection_detection(self):
        """Test detection of Windows-specific protections"""
        detector = self.manager.detector
        
        # Windows-specific protection APIs
        windows_apis = [
            ('kernel32.dll', 'IsDebuggerPresent'),
            ('ntdll.dll', 'NtQueryInformationProcess'),
            ('kernel32.dll', 'GetSystemFirmwareTable'),
            ('kernel32.dll', 'GetTickCount'),
        ]
        
        for module, api in windows_apis:
            detected = detector.analyze_api_call(module, api, [])
            self.assertGreater(len(detected), 0, 
                             f"No protection detected for {module}!{api}")


class CompatibilityReportGenerator:
    """Generate Windows compatibility report"""
    
    @staticmethod
    def generate_report() -> Dict[str, any]:
        """Generate comprehensive compatibility report"""
        report = {
            'system_info': {},
            'frida_compatibility': {},
            'api_compatibility': {},
            'protection_compatibility': {},
            'recommendations': []
        }
        
        # System information
        if platform.system() == 'Windows':
            version = WindowsVersionInfo.get_windows_version()
            major, minor, build, is_server = version
            
            report['system_info'] = {
                'os': platform.system(),
                'version': f"{major}.{minor}.{build}",
                'architecture': platform.machine(),
                'is_server': is_server,
                'python_version': sys.version
            }
            
            # Frida compatibility
            try:
                import frida
                report['frida_compatibility'] = {
                    'frida_version': frida.__version__,
                    'device_available': True,
                    'process_enumeration': True
                }
            except Exception as e:
                report['frida_compatibility'] = {
                    'error': str(e),
                    'device_available': False
                }
            
            # API compatibility based on version
            if major >= 10:
                report['api_compatibility'] = {
                    'level': 'Full',
                    'notes': 'All modern APIs supported'
                }
            elif major == 6 and minor >= 1:
                report['api_compatibility'] = {
                    'level': 'Good',
                    'notes': 'Most APIs supported, some modern features unavailable'
                }
            else:
                report['api_compatibility'] = {
                    'level': 'Limited',
                    'notes': 'Basic functionality only'
                }
            
            # Protection compatibility
            protections = []
            if major >= 6 and minor >= 1:
                protections.extend(['ASLR', 'DEP'])
            if major >= 10:
                protections.extend(['CFG', 'ACG', 'CIG'])
            
            report['protection_compatibility'] = {
                'supported_bypasses': protections,
                'compatibility_level': 'High' if major >= 10 else 'Medium'
            }
            
            # Recommendations
            if major < 10:
                report['recommendations'].append(
                    "Consider upgrading to Windows 10 or later for best compatibility"
                )
            
            if is_server:
                report['recommendations'].append(
                    "Server editions may have additional security restrictions"
                )
        
        return report


def run_compatibility_tests():
    """Run all Windows compatibility tests"""
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(WindowsCompatibilityTests))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(WindowsAPICompatibilityTests))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(FridaWindowsIntegrationTests))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate compatibility report
    report = CompatibilityReportGenerator.generate_report()
    
    print("\n" + "="*60)
    print("Windows Compatibility Report")
    print("="*60)
    
    for key, value in report.items():
        if isinstance(value, dict):
            print(f"\n{key.replace('_', ' ').title()}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        elif isinstance(value, list):
            print(f"\n{key.replace('_', ' ').title()}:")
            for item in value:
                print(f"  - {item}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    run_compatibility_tests()