"""
Anti-Analysis Technique Detector

Detects various anti-debugging, anti-VM, and anti-analysis techniques
commonly used by protected software and malware.

@author Intellicrack Team
@category Protection Analysis
@version 1.0
@tags anti-debug,anti-vm,protection,evasion
"""

from ghidra.app.script import GhidraScript


class AntiAnalysisDetector(GhidraScript):

    # Anti-debugging APIs
    ANTI_DEBUG_APIS = [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "NtSetInformationThread",
        "DebugActiveProcess",
        "FindWindowA",
        "FindWindowW",
        "GetTickCount",
        "QueryPerformanceCounter",
        "NtQuerySystemInformation",
        "NtQueryObject"
    ]

    # Anti-VM artifacts to check
    VM_ARTIFACTS = [
        # VMware
        "VMware", "vmware", "VBOX", "VirtualBox",
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",

        # VirtualBox
        "VBoxService.exe", "VBoxTray.exe", "VBoxMouse",
        "VBoxGuest", "VBoxSF", "VBoxVideo",

        # Generic VM
        "vmsrvc", "vmusrvc", "xenservice", "qemu-ga",

        # Registry keys
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0",
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
    ]

    # CPU instructions for detection
    DETECTION_INSTRUCTIONS = [
        "cpuid",      # CPU identification
        "rdtsc",      # Read timestamp counter
        "int 3",      # Breakpoint interrupt
        "int 2d",     # Windows debug interrupt
        "in al, dx",  # Port I/O (VM detection)
        "sidt",       # Store IDT register
        "sgdt",       # Store GDT register
        "sldt",       # Store LDT register
        "str"         # Store task register
    ]

    def run(self):
        print("=== Anti-Analysis Technique Detector ===\n")

        findings = {
            'anti_debug': [],
            'anti_vm': [],
            'timing_checks': [],
            'cpu_detection': [],
            'exception_tricks': []
        }

        # Check for anti-debugging APIs
        print("Checking for anti-debugging APIs...")
        self.find_anti_debug_apis(findings)

        # Check for VM detection strings
        print("\nChecking for VM detection artifacts...")
        self.find_vm_artifacts(findings)

        # Check for detection instructions
        print("\nChecking for detection instructions...")
        self.find_detection_instructions(findings)

        # Check for timing-based detection
        print("\nChecking for timing-based detection...")
        self.find_timing_checks(findings)

        # Check for exception-based tricks
        print("\nChecking for exception-based anti-analysis...")
        self.find_exception_tricks(findings)

        # Generate report
        self.generate_report(findings)

    def find_anti_debug_apis(self, findings):
        """Find references to anti-debugging APIs"""
        symbol_table = currentProgram.getSymbolTable()

        for api in self.ANTI_DEBUG_APIS:
            symbols = symbol_table.getSymbols(api)

            for symbol in symbols:
                refs = getReferencesTo(symbol.getAddress())
                if refs:
                    for ref in refs:
                        if ref.getReferenceType().isCall():
                            findings['anti_debug'].append({
                                'type': 'API Call',
                                'name': api,
                                'address': ref.getFromAddress(),
                                'description': self.get_api_description(api)
                            })
                            print(f"  [+] Found {api} at {ref.getFromAddress()}")
                            createBookmark(ref.getFromAddress(), "AntiDebug", f"{api} call")

    def find_vm_artifacts(self, findings):
        """Search for VM-related strings and artifacts"""
        memory = currentProgram.getMemory()

        for artifact in self.VM_ARTIFACTS:
            # Search for string
            addresses = findBytes(None, artifact.encode(), 50)

            for addr in addresses:
                if addr:
                    findings['anti_vm'].append({
                        'type': 'VM Artifact',
                        'name': artifact,
                        'address': addr,
                        'description': 'Potential VM detection string'
                    })
                    print(f"  [+] Found VM artifact '{artifact}' at {addr}")
                    createBookmark(addr, "AntiVM", f"VM artifact: {artifact}")

    def find_detection_instructions(self, findings):
        """Find CPU instructions used for detection"""
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(True)

        while instructions.hasNext():
            instr = instructions.next()
            mnemonic = instr.getMnemonicString().lower()

            if mnemonic in self.DETECTION_INSTRUCTIONS:
                findings['cpu_detection'].append({
                    'type': 'CPU Instruction',
                    'instruction': mnemonic,
                    'address': instr.getAddress(),
                    'description': self.get_instruction_description(mnemonic)
                })
                print(f"  [+] Found {mnemonic} instruction at {instr.getAddress()}")
                createBookmark(instr.getAddress(), "Detection", f"{mnemonic} instruction")

    def find_timing_checks(self, findings):
        """Find potential timing-based anti-analysis"""
        # Look for GetTickCount patterns
        tick_refs = self.find_api_refs("GetTickCount")
        perf_refs = self.find_api_refs("QueryPerformanceCounter")
        rdtsc_addrs = self.find_instruction("rdtsc")

        # Look for paired timing calls (common pattern)
        all_timing = tick_refs + perf_refs + rdtsc_addrs
        all_timing.sort(key=lambda x: x.getOffset())

        for i in range(len(all_timing) - 1):
            addr1 = all_timing[i]
            addr2 = all_timing[i + 1]

            # If two timing calls are close together, likely a timing check
            distance = addr2.getOffset() - addr1.getOffset()
            if distance < 0x100:  # Within 256 bytes
                findings['timing_checks'].append({
                    'type': 'Timing Check',
                    'start': addr1,
                    'end': addr2,
                    'description': 'Potential timing-based anti-debugging check'
                })
                print(f"  [+] Found timing check between {addr1} and {addr2}")
                createBookmark(addr1, "Timing", "Timing check start")

    def find_exception_tricks(self, findings):
        """Find exception-based anti-analysis tricks"""
        # Look for SetUnhandledExceptionFilter
        seh_refs = self.find_api_refs("SetUnhandledExceptionFilter")
        for ref in seh_refs:
            findings['exception_tricks'].append({
                'type': 'Exception Handler',
                'api': 'SetUnhandledExceptionFilter',
                'address': ref,
                'description': 'Custom exception handler (possible anti-debug)'
            })
            createBookmark(ref, "Exception", "SEH manipulation")

        # Look for int3 instructions (breakpoints)
        int3_addrs = self.find_instruction("int3")
        for addr in int3_addrs:
            findings['exception_tricks'].append({
                'type': 'INT3 Breakpoint',
                'address': addr,
                'description': 'Hardcoded breakpoint (possible anti-debug trap)'
            })
            createBookmark(addr, "Exception", "INT3 trap")

    def find_api_refs(self, api_name):
        """Helper to find all references to an API"""
        refs = []
        symbol_table = currentProgram.getSymbolTable()

        for symbol in symbol_table.getSymbols(api_name):
            for ref in getReferencesTo(symbol.getAddress()):
                if ref.getReferenceType().isCall():
                    refs.append(ref.getFromAddress())

        return refs

    def find_instruction(self, mnemonic):
        """Helper to find all instances of an instruction"""
        addrs = []
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(True)

        while instructions.hasNext():
            instr = instructions.next()
            if instr.getMnemonicString().lower() == mnemonic:
                addrs.append(instr.getAddress())

        return addrs

    def get_api_description(self, api):
        """Get description for known anti-debug APIs"""
        descriptions = {
            "IsDebuggerPresent": "Direct debugger detection",
            "CheckRemoteDebuggerPresent": "Remote debugger detection",
            "NtQueryInformationProcess": "Process information query (ProcessDebugPort)",
            "OutputDebugStringA": "Debug string output detection",
            "NtSetInformationThread": "Thread hiding from debugger",
            "FindWindowA": "Debugger window detection",
            "GetTickCount": "Timing-based debugger detection",
            "QueryPerformanceCounter": "High-precision timing check"
        }
        return descriptions.get(api, "Anti-debugging API")

    def get_instruction_description(self, instr):
        """Get description for detection instructions"""
        descriptions = {
            "cpuid": "CPU identification - VM detection",
            "rdtsc": "Read timestamp counter - timing detection",
            "int 3": "Software breakpoint - debugger detection",
            "int 2d": "Windows debug service - debugger detection",
            "sidt": "Store IDT - VM/debugger detection",
            "sgdt": "Store GDT - VM/debugger detection"
        }
        return descriptions.get(instr, "Detection instruction")

    def generate_report(self, findings):
        """Generate analysis report"""
        print("\n=== Anti-Analysis Technique Report ===")

        total = sum(len(v) for v in findings.values())
        print(f"\nTotal anti-analysis techniques found: {total}")

        if findings['anti_debug']:
            print(f"\nAnti-Debugging ({len(findings['anti_debug'])} found):")
            for item in findings['anti_debug'][:5]:
                print(f"  - {item['name']} at {item['address']}")

        if findings['anti_vm']:
            print(f"\nAnti-VM ({len(findings['anti_vm'])} found):")
            for item in findings['anti_vm'][:5]:
                print(f"  - '{item['name']}' at {item['address']}")

        if findings['timing_checks']:
            print(f"\nTiming Checks ({len(findings['timing_checks'])} found):")
            for item in findings['timing_checks'][:5]:
                print(f"  - Check between {item['start']} and {item['end']}")

        if findings['cpu_detection']:
            print(f"\nCPU Detection ({len(findings['cpu_detection'])} found):")
            for item in findings['cpu_detection'][:5]:
                print(f"  - {item['instruction']} at {item['address']}")

        # Protection level assessment
        protection_level = self.assess_protection_level(findings)
        print(f"\n[*] Protection Level: {protection_level}")
        print("[*] Check bookmarks for all findings")

    def assess_protection_level(self, findings):
        """Assess overall protection level"""
        score = 0

        score += len(findings['anti_debug']) * 2
        score += len(findings['anti_vm']) * 1
        score += len(findings['timing_checks']) * 3
        score += len(findings['cpu_detection']) * 2
        score += len(findings['exception_tricks']) * 3

        if score == 0:
            return "None - No anti-analysis detected"
        elif score < 10:
            return "Low - Basic anti-analysis techniques"
        elif score < 25:
            return "Medium - Multiple anti-analysis techniques"
        elif score < 50:
            return "High - Advanced anti-analysis protection"
        else:
            return "Very High - Heavily protected/obfuscated"

# Run the script
if __name__ == "__main__":
    detector = AntiAnalysisDetector()
    detector.run()
