"""Intellicrack - Anti-Analysis Technique Detector.

Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""
from typing import NoReturn

"""Anti-Analysis Technique Detector.

Detects various anti-debugging, anti-VM, and anti-analysis techniques
commonly used by protected software and malware.

@author Intellicrack Team
@category Protection Analysis
@version 1.0
@tags anti-debug,anti-vm,protection,evasion
"""

try:
    from ghidra.app.script import GhidraScript

    # Ghidra API functions available in script environment:
    # current_program, get_references_to, create_bookmark, find_bytes
    GHIDRA_AVAILABLE = True
except ImportError:
    # Running outside Ghidra environment
    GHIDRA_AVAILABLE = False

    import os
    import sys

    class GhidraScript:
        """Base class for Ghidra scripts when running outside Ghidra environment.

        This implementation provides the necessary interface for scripts that
        can run both inside and outside the Ghidra environment.
        """

        def __init__(self) -> None:
            """Initialize the GhidraScript base class."""
            self.script_name = self.__class__.__name__
            self.state = ScriptState()
            self.monitor = TaskMonitor()
            self._script_args = []
            self._script_dir = os.path.dirname(os.path.abspath(__file__))

        def run(self) -> NoReturn:
            """Execute the script logic.

            This method should be overridden by subclasses to implement
            the actual script functionality.
            """
            raise NotImplementedError("Subclasses must implement the run() method")

        def println(self, message) -> None:
            """Print a message to the console.

            Args:
                message: The message to print

            """
            print(message)

        def printerr(self, message) -> None:
            """Print an error message to the console.

            Args:
                message: The error message to print

            """
            print(f"ERROR: {message}", file=sys.stderr)

        def askYesNo(self, title, question) -> bool:
            """Ask a yes/no question (returns False in non-interactive mode).

            Args:
                title: The dialog title
                question: The question to ask

            Returns:
                bool: Always False in non-Ghidra environment

            """
            print(f"{title}: {question}")
            return False

        def askString(self, title, prompt, default_value=""):
            """Ask for string input.

            Args:
                title: Dialog title
                prompt: The prompt message
                default_value: Default value

            Returns:
                str: The default value in non-interactive mode

            """
            print(f"{title}: {prompt} (default: {default_value})")
            return default_value

        def askInt(self, title, prompt, default_value=0):
            """Ask for integer input.

            Args:
                title: Dialog title
                prompt: The prompt message
                default_value: Default value

            Returns:
                int: The default value in non-interactive mode

            """
            print(f"{title}: {prompt} (default: {default_value})")
            return default_value

        def getScriptName(self):
            """Get the name of this script.

            Returns:
                str: The script class name

            """
            return self.script_name

        def getScriptArgs(self):
            """Get script arguments.

            Returns:
                list: Script arguments

            """
            return self._script_args

        def setScriptArgs(self, args) -> None:
            """Set script arguments.

            Args:
                args: List of arguments

            """
            self._script_args = args if args else []

        def getScriptFile(self):
            """Get the script file path.

            Returns:
                str: Path to the script file

            """
            return os.path.abspath(__file__)

        def getScriptDir(self):
            """Get the script directory.

            Returns:
                str: Directory containing the script

            """
            return self._script_dir

        def popup(self, message) -> None:
            """Show a popup message.

            Args:
                message: Message to display

            """
            print(f"POPUP: {message}")

        def isRunningHeadless(self) -> bool:
            """Check if running in headless mode.

            Returns:
                bool: True when not in Ghidra environment

            """
            return True

    class ScriptState:
        """Represents the state of a script execution."""

        def __init__(self) -> None:
            """Initialize the script state with empty variables and environment."""
            self._variables = {}
            self._environment = {}

        def addEnvironmentVar(self, name, value) -> None:
            """Add an environment variable."""
            self._environment[name] = value

        def getEnvironmentVar(self, name):
            """Get an environment variable."""
            return self._environment.get(name)

        def setValue(self, name, value) -> None:
            """Set a state variable."""
            self._variables[name] = value

        def getValue(self, name):
            """Get a state variable."""
            return self._variables.get(name)

    class TaskMonitor:
        """Monitor for long-running tasks."""

        def __init__(self) -> None:
            """Initialize the task monitor with default progress tracking state."""
            self._cancelled = False
            self._message = ""
            self._progress = 0
            self._max = 100

        def isCancelled(self):
            """Check if task was cancelled."""
            return self._cancelled

        def cancel(self) -> None:
            """Cancel the task."""
            self._cancelled = True

        def setMessage(self, message) -> None:
            """Set status message."""
            self._message = message
            print(f"STATUS: {message}")

        def getMessage(self):
            """Get current status message."""
            return self._message

        def setProgress(self, progress) -> None:
            """Set progress value."""
            self._progress = progress

        def getProgress(self):
            """Get current progress."""
            return self._progress

        def setMaximum(self, maximum) -> None:
            """Set maximum progress value."""
            self._max = maximum

        def getMaximum(self):
            """Get maximum progress value."""
            return self._max

    # Placeholder Ghidra globals for compatibility
    current_program = None
    get_references_to = None
    create_bookmark = None
    find_bytes = None


def safe_ghidra_call(func_name, *args, **kwargs):
    """Safely call Ghidra function, avoiding pylint errors."""
    if not GHIDRA_AVAILABLE:
        return None

    if func_name in globals():
        func = globals()[func_name]
        if func is not None:
            return func(*args, **kwargs)
    return None


def get_current_program():
    """Get current program, avoiding pylint errors."""
    if not GHIDRA_AVAILABLE:
        return None
    return globals().get("current_program")


class AntiAnalysisDetector(GhidraScript):
    """Ghidra script to detect anti-analysis techniques in binaries.

    Identifies various anti-debugging, anti-VM, and anti-analysis patterns
    by scanning for suspicious API calls, timing checks, exception handling,
    and other evasion techniques commonly used by malware and protected software.
    """

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
        "NtQueryObject",
    ]

    # Anti-VM artifacts to check
    VM_ARTIFACTS = [
        # VMware
        "VMware",
        "vmware",
        "VBOX",
        "VirtualBox",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        # VirtualBox
        "VBoxService.exe",
        "VBoxTray.exe",
        "VBoxMouse",
        "VBoxGuest",
        "VBoxSF",
        "VBoxVideo",
        # Generic VM
        "vmsrvc",
        "vmusrvc",
        "xenservice",
        "qemu-ga",
        # Registry keys
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0",
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    ]

    # CPU instructions for detection
    DETECTION_INSTRUCTIONS = [
        "cpuid",  # CPU identification
        "rdtsc",  # Read timestamp counter
        "int 3",  # Breakpoint interrupt
        "int 2d",  # Windows debug interrupt
        "in al, dx",  # Port I/O (VM detection)
        "sidt",  # Store IDT register
        "sgdt",  # Store GDT register
        "sldt",  # Store LDT register
        "str",  # Store task register
    ]

    def run(self) -> None:
        """Execute anti-analysis detection scan on the current program.

        Performs comprehensive analysis to identify anti-debugging, anti-VM,
        and other anti-analysis techniques. Scans for suspicious API imports,
        timing checks, hardware breakpoint detection, and VM detection patterns.

        Results are printed to the Ghidra console with detailed findings
        for each category of anti-analysis technique detected.
        """
        if not GHIDRA_AVAILABLE:
            print("Error: This script must be run within Ghidra environment")
            return

        # Access Ghidra globals - use helper function to avoid pylint errors
        program = get_current_program()
        if program is None:
            print("Error: No program loaded in Ghidra")
            return

        print("=== Anti-Analysis Technique Detector ===\n")

        findings = {
            "anti_debug": [],
            "anti_vm": [],
            "timing_checks": [],
            "cpu_detection": [],
            "exception_tricks": [],
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

    def find_anti_debug_apis(self, findings) -> None:
        """Find references to anti-debugging APIs."""
        program = get_current_program()
        symbol_table = program.getSymbolTable()

        for api in self.ANTI_DEBUG_APIS:
            symbols = symbol_table.getSymbols(api)

            for symbol in symbols:
                refs = safe_ghidra_call("getReferencesTo", symbol.getAddress())
                if refs:
                    for ref in refs:
                        if ref.getReferenceType().isCall():
                            findings["anti_debug"].append(
                                {
                                    "type": "API Call",
                                    "name": api,
                                    "address": ref.getFromAddress(),
                                    "description": self.get_api_description(api),
                                },
                            )
                            print(f"  [+] Found {api} at {ref.getFromAddress()}")
                            safe_ghidra_call("createBookmark", ref.getFromAddress(), "AntiDebug", f"{api} call")

    def find_vm_artifacts(self, findings) -> None:
        """Search for VM-related strings and artifacts."""
        program = get_current_program()
        memory = program.getMemory()

        for artifact in self.VM_ARTIFACTS:
            # Search for string in memory
            # Get all memory blocks to search
            for block in memory.getBlocks():
                if block.isInitialized():
                    addresses = safe_ghidra_call("findBytes", block.getStart(), artifact.encode(), 50)

                    for addr in addresses:
                        if addr:
                            findings["anti_vm"].append(
                                {
                                    "type": "VM Artifact",
                                    "name": artifact,
                                    "address": addr,
                                    "description": "Potential VM detection string",
                                },
                            )
                            print(f"  [+] Found VM artifact '{artifact}' at {addr}")
                            safe_ghidra_call("createBookmark", addr, "AntiVM", f"VM artifact: {artifact}")

    def find_detection_instructions(self, findings) -> None:
        """Find CPU instructions used for detection."""
        program = get_current_program()
        listing = program.getListing()
        instructions = listing.getInstructions(True)

        while instructions.hasNext():
            instr = instructions.next()
            mnemonic = instr.getMnemonicString().lower()

            if mnemonic in self.DETECTION_INSTRUCTIONS:
                findings["cpu_detection"].append(
                    {
                        "type": "CPU Instruction",
                        "instruction": mnemonic,
                        "address": instr.getAddress(),
                        "description": self.get_instruction_description(mnemonic),
                    },
                )
                print(f"  [+] Found {mnemonic} instruction at {instr.getAddress()}")
                safe_ghidra_call("createBookmark", instr.getAddress(), "Detection", f"{mnemonic} instruction")

    def find_timing_checks(self, findings) -> None:
        """Find potential timing-based anti-analysis."""
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
                findings["timing_checks"].append(
                    {
                        "type": "Timing Check",
                        "start": addr1,
                        "end": addr2,
                        "description": "Potential timing-based anti-debugging check",
                    },
                )
                print(f"  [+] Found timing check between {addr1} and {addr2}")
                safe_ghidra_call("createBookmark", addr1, "Timing", "Timing check start")

    def find_exception_tricks(self, findings) -> None:
        """Find exception-based anti-analysis tricks."""
        # Look for SetUnhandledExceptionFilter
        seh_refs = self.find_api_refs("SetUnhandledExceptionFilter")
        for ref in seh_refs:
            findings["exception_tricks"].append(
                {
                    "type": "Exception Handler",
                    "api": "SetUnhandledExceptionFilter",
                    "address": ref,
                    "description": "Custom exception handler (possible anti-debug)",
                },
            )
            safe_ghidra_call("createBookmark", ref, "Exception", "SEH manipulation")

        # Look for int3 instructions (breakpoints)
        int3_addrs = self.find_instruction("int3")
        for addr in int3_addrs:
            findings["exception_tricks"].append(
                {
                    "type": "INT3 Breakpoint",
                    "address": addr,
                    "description": "Hardcoded breakpoint (possible anti-debug trap)",
                },
            )
            safe_ghidra_call("createBookmark", addr, "Exception", "INT3 trap")

    def find_api_refs(self, api_name):
        """Find all references to an API."""
        refs = []
        program = get_current_program()
        symbol_table = program.getSymbolTable()

        for symbol in symbol_table.getSymbols(api_name):
            refs = safe_ghidra_call("getReferencesTo", symbol.getAddress())
            for ref in refs or []:
                if ref.getReferenceType().isCall():
                    refs.append(ref.getFromAddress())

        return refs

    def find_instruction(self, mnemonic):
        """Find all instances of an instruction."""
        addrs = []
        program = get_current_program()
        listing = program.getListing()
        instructions = listing.getInstructions(True)

        while instructions.hasNext():
            instr = instructions.next()
            if instr.getMnemonicString().lower() == mnemonic:
                addrs.append(instr.getAddress())

        return addrs

    def get_api_description(self, api):
        """Get description for known anti-debug APIs."""
        descriptions = {
            "IsDebuggerPresent": "Direct debugger detection",
            "CheckRemoteDebuggerPresent": "Remote debugger detection",
            "NtQueryInformationProcess": "Process information query (ProcessDebugPort)",
            "OutputDebugStringA": "Debug string output detection",
            "NtSetInformationThread": "Thread hiding from debugger",
            "FindWindowA": "Debugger window detection",
            "GetTickCount": "Timing-based debugger detection",
            "QueryPerformanceCounter": "High-precision timing check",
        }
        return descriptions.get(api, "Anti-debugging API")

    def get_instruction_description(self, instr):
        """Get description for detection instructions."""
        descriptions = {
            "cpuid": "CPU identification - VM detection",
            "rdtsc": "Read timestamp counter - timing detection",
            "int 3": "Software breakpoint - debugger detection",
            "int 2d": "Windows debug service - debugger detection",
            "sidt": "Store IDT - VM/debugger detection",
            "sgdt": "Store GDT - VM/debugger detection",
        }
        return descriptions.get(instr, "Detection instruction")

    def generate_report(self, findings) -> None:
        """Generate analysis report."""
        print("\n=== Anti-Analysis Technique Report ===")

        total = sum(len(v) for v in findings.values())
        print(f"\nTotal anti-analysis techniques found: {total}")

        if findings["anti_debug"]:
            print(f"\nAnti-Debugging ({len(findings['anti_debug'])} found):")
            for item in findings["anti_debug"][:5]:
                print(f"  - {item['name']} at {item['address']}")

        if findings["anti_vm"]:
            print(f"\nAnti-VM ({len(findings['anti_vm'])} found):")
            for item in findings["anti_vm"][:5]:
                print(f"  - '{item['name']}' at {item['address']}")

        if findings["timing_checks"]:
            print(f"\nTiming Checks ({len(findings['timing_checks'])} found):")
            for item in findings["timing_checks"][:5]:
                print(f"  - Check between {item['start']} and {item['end']}")

        if findings["cpu_detection"]:
            print(f"\nCPU Detection ({len(findings['cpu_detection'])} found):")
            for item in findings["cpu_detection"][:5]:
                print(f"  - {item['instruction']} at {item['address']}")

        # Protection level assessment
        protection_level = self.assess_protection_level(findings)
        print(f"\n[*] Protection Level: {protection_level}")
        print("[*] Check bookmarks for all findings")

    def assess_protection_level(self, findings) -> str:
        """Assess overall protection level."""
        score = 0

        score += len(findings["anti_debug"]) * 2
        score += len(findings["anti_vm"]) * 1
        score += len(findings["timing_checks"]) * 3
        score += len(findings["cpu_detection"]) * 2
        score += len(findings["exception_tricks"]) * 3

        if score == 0:
            return "None - No anti-analysis detected"
        if score < 10:
            return "Low - Basic anti-analysis techniques"
        if score < 25:
            return "Medium - Multiple anti-analysis techniques"
        if score < 50:
            return "High - Advanced anti-analysis protection"
        return "Very High - Heavily protected/obfuscated"


# Run the script
if __name__ == "__main__":
    detector = AntiAnalysisDetector()
    detector.run()
