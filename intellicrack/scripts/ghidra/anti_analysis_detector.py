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

import logging
from typing import Any


logger = logging.getLogger(__name__)


"""Anti-Analysis Technique Detector.

Detects various anti-debugging, anti-VM, and anti-analysis techniques
commonly used by protected software and malware.

@author Intellicrack Team
@category Protection Analysis
@version 1.0
@tags anti-debug,anti-vm,protection,evasion
"""

import os
import sys

try:
    from ghidra.app.script import GhidraScript as GhidraScriptBase

    # Ghidra API functions available in script environment:
    # current_program, get_references_to, create_bookmark, find_bytes
    GHIDRA_AVAILABLE = True
except ImportError:
    # Running outside Ghidra environment
    GHIDRA_AVAILABLE = False

    class GhidraScriptBase:  # type: ignore[no-redef]
        """Base class for Ghidra scripts when running outside Ghidra environment.

        This implementation provides the necessary interface for scripts that
        can run both inside and outside the Ghidra environment.
        """

        def __init__(self) -> None:
            """Initialize the GhidraScript base class."""
            self.script_name = self.__class__.__name__
            self.state = ScriptState()
            self.monitor = TaskMonitor()
            self._script_args: list[str] = []
            self._script_dir = os.path.dirname(os.path.abspath(__file__))

        def run(self) -> None:
            """Execute the script logic.

            This method is designed to be overridden by subclasses to implement
            the actual script functionality. The base implementation provides
            graceful handling when no subclass override is available by logging
            a diagnostic message.
            """
            script_name = getattr(self, "script_name", self.__class__.__name__)
            message = f"Script execution initiated for {script_name} (base implementation)"
            if hasattr(self, "println"):
                self.println(message)
            else:
                logger.info("%s", message)

        def println(self, message: str) -> None:
            """Print a message to the console.

            Args:
                message: The message to print

            """
            logger.info("%s", message)

        def printerr(self, message: str) -> None:
            """Print an error message to the console.

            Args:
                message: The error message to print

            """
            logger.exception("ERROR: %s", message)

        def askYesNo(self, title: str, question: str) -> bool:
            """Ask a yes/no question (returns False in non-interactive mode).

            Args:
                title: The dialog title
                question: The question to ask

            Returns:
                bool: Always False in non-Ghidra environment

            """
            logger.info("%s: %s", title, question)
            return False

        def askString(self, title: str, prompt: str, default_value: str = "") -> str:
            """Ask for string input.

            Args:
                title: Dialog title
                prompt: The prompt message
                default_value: Default value

            Returns:
                str: The default value in non-interactive mode

            """
            logger.info("%s: %s (default: %s)", title, prompt, default_value)
            return default_value

        def askInt(self, title: str, prompt: str, default_value: int = 0) -> int:
            """Ask for integer input.

            Args:
                title: Dialog title
                prompt: The prompt message
                default_value: Default value

            Returns:
                int: The default value in non-interactive mode

            """
            logger.info("%s: %s (default: %s)", title, prompt, default_value)
            return default_value

        def getScriptName(self) -> str:
            """Get the name of this script.

            Returns:
                str: The script class name

            """
            return self.script_name

        def getScriptArgs(self) -> list[str]:
            """Get script arguments.

            Returns:
                list[str]: Script arguments

            """
            return self._script_args

        def setScriptArgs(self, args: list[str] | None) -> None:
            """Set script arguments.

            Args:
                args: List of arguments

            """
            self._script_args = args or []

        def getScriptFile(self) -> str:
            """Get the script file path.

            Returns:
                str: Path to the script file

            """
            return os.path.abspath(__file__)

        def getScriptDir(self) -> str:
            """Get the script directory.

            Returns:
                str: Directory containing the script

            """
            return self._script_dir

        def popup(self, message: str) -> None:
            """Show a popup message.

            Args:
                message: Message to display

            """
            logger.info("POPUP: %s", message)

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
            self._variables: dict[str, object] = {}
            self._environment: dict[str, object] = {}

        def addEnvironmentVar(self, name: str, value: object) -> None:
            """Add an environment variable.

            Args:
                name: The variable name.
                value: The variable value.

            """
            self._environment[name] = value

        def getEnvironmentVar(self, name: str) -> object:
            """Get an environment variable.

            Args:
                name: The variable name.

            Returns:
                object: The variable value, or None if not found.

            """
            return self._environment.get(name)

        def setValue(self, name: str, value: object) -> None:
            """Set a state variable.

            Args:
                name: The variable name.
                value: The variable value.

            """
            self._variables[name] = value

        def getValue(self, name: str) -> object:
            """Get a state variable.

            Args:
                name: The variable name.

            Returns:
                object: The variable value, or None if not found.

            """
            return self._variables.get(name)

    class TaskMonitor:
        """Monitor for long-running tasks."""

        def __init__(self) -> None:
            """Initialize the task monitor with default progress tracking state."""
            self._cancelled: bool = False
            self._message: str = ""
            self._progress: int = 0
            self._max: int = 100

        def isCancelled(self) -> bool:
            """Check if task was cancelled.

            Returns:
                bool: True if task was cancelled, False otherwise.

            """
            return self._cancelled

        def cancel(self) -> None:
            """Cancel the task."""
            self._cancelled = True

        def setMessage(self, message: str) -> None:
            """Set status message.

            Args:
                message: The status message to display.

            """
            self._message = message
            logger.info("STATUS: %s", message)

        def getMessage(self) -> str:
            """Get current status message.

            Returns:
                str: The current status message.

            """
            return self._message

        def setProgress(self, progress: int) -> None:
            """Set progress value.

            Args:
                progress: The progress value.

            """
            self._progress = progress

        def getProgress(self) -> int:
            """Get current progress.

            Returns:
                int: The current progress value.

            """
            return self._progress

        def setMaximum(self, maximum: int) -> None:
            """Set maximum progress value.

            Args:
                maximum: The maximum progress value.

            """
            self._max = maximum

        def getMaximum(self) -> int:
            """Get maximum progress value.

            Returns:
                int: The maximum progress value.

            """
            return self._max


current_program: Any = None
"""The current Ghidra program object when running in Ghidra environment."""

get_references_to: Any = None
"""Function to get all references to a given address in Ghidra."""

create_bookmark: Any = None
"""Function to create bookmarks at specific addresses in Ghidra."""

find_bytes: Any = None
"""Function to search for byte patterns within program memory in Ghidra."""


def safe_ghidra_call(func_name: str, *args: object, **kwargs: object) -> object:
    """Safely call Ghidra function, avoiding pylint errors.

    Args:
        func_name: Name of the Ghidra function to call.
        *args: Positional arguments to pass to the function.
        **kwargs: Keyword arguments to pass to the function.

    Returns:
        The result of the Ghidra function call, or None if unavailable.

    """
    if not GHIDRA_AVAILABLE:
        return None

    if func_name in globals():
        func = globals()[func_name]
        if func is not None:
            return func(*args, **kwargs)
    return None


def get_current_program() -> Any:
    """Get current program, avoiding pylint errors.

    Returns:
        The current Ghidra program object, or None if unavailable.

    """
    return globals().get("current_program") if GHIDRA_AVAILABLE else None


class AntiAnalysisDetector(GhidraScriptBase):  # type: ignore[misc]
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
            logger.error("This script must be run within Ghidra environment")
            return

        # Access Ghidra globals - use helper function to avoid pylint errors
        program = get_current_program()
        if program is None:
            logger.error("No program loaded in Ghidra")
            return

        logger.info("=== Anti-Analysis Technique Detector ===")

        findings: dict[str, list[dict[str, Any]]] = {
            "anti_debug": [],
            "anti_vm": [],
            "timing_checks": [],
            "cpu_detection": [],
            "exception_tricks": [],
        }

        # Check for anti-debugging APIs
        logger.info("Checking for anti-debugging APIs...")
        self.find_anti_debug_apis(findings)

        # Check for VM detection strings
        logger.info("Checking for VM detection artifacts...")
        self.find_vm_artifacts(findings)

        # Check for detection instructions
        logger.info("Checking for detection instructions...")
        self.find_detection_instructions(findings)

        # Check for timing-based detection
        logger.info("Checking for timing-based detection...")
        self.find_timing_checks(findings)

        # Check for exception-based tricks
        logger.info("Checking for exception-based anti-analysis...")
        self.find_exception_tricks(findings)

        # Generate report
        self.generate_report(findings)

    def find_anti_debug_apis(self, findings: dict[str, list[dict[str, Any]]]) -> None:
        """Find references to anti-debugging APIs.

        Args:
            findings: Dictionary to accumulate findings by category.

        """
        program: Any = get_current_program()
        symbol_table: Any = program.getSymbolTable()

        for api in self.ANTI_DEBUG_APIS:
            symbols: Any = symbol_table.getSymbols(api)

            for symbol in symbols:
                refs_result: Any = safe_ghidra_call("getReferencesTo", symbol.getAddress())
                if refs_result:
                    for ref in refs_result:
                        if ref.getReferenceType().isCall():
                            findings["anti_debug"].append(
                                {
                                    "type": "API Call",
                                    "name": api,
                                    "address": ref.getFromAddress(),
                                    "description": self.get_api_description(api),
                                },
                            )
                            logger.info("  [+] Found %s at %s", api, ref.getFromAddress())
                            safe_ghidra_call("createBookmark", ref.getFromAddress(), "AntiDebug", f"{api} call")

    def find_vm_artifacts(self, findings: dict[str, list[dict[str, Any]]]) -> None:
        """Search for VM-related strings and artifacts.

        Args:
            findings: Dictionary to accumulate findings by category.

        """
        program: Any = get_current_program()
        memory: Any = program.getMemory()

        for artifact in self.VM_ARTIFACTS:
            # Search for string in memory
            # Get all memory blocks to search
            blocks: Any = memory.getBlocks()
            for block in blocks:
                if block.isInitialized():
                    addresses: Any = safe_ghidra_call("findBytes", block.getStart(), artifact.encode(), 50)

                    if addresses:
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
                                logger.info("  [+] Found VM artifact '%s' at %s", artifact, addr)
                                safe_ghidra_call("createBookmark", addr, "AntiVM", f"VM artifact: {artifact}")

    def find_detection_instructions(self, findings: dict[str, list[dict[str, Any]]]) -> None:
        """Find CPU instructions used for detection.

        Args:
            findings: Dictionary to accumulate findings by category.

        """
        program: Any = get_current_program()
        listing: Any = program.getListing()
        instructions: Any = listing.getInstructions(True)

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
                logger.info("  [+] Found %s instruction at %s", mnemonic, instr.getAddress())
                safe_ghidra_call("createBookmark", instr.getAddress(), "Detection", f"{mnemonic} instruction")

    def find_timing_checks(self, findings: dict[str, list[dict[str, Any]]]) -> None:
        """Find potential timing-based anti-analysis.

        Args:
            findings: Dictionary to accumulate findings by category.

        """
        # Look for GetTickCount patterns
        tick_refs = self.find_api_refs("GetTickCount")
        perf_refs = self.find_api_refs("QueryPerformanceCounter")
        rdtsc_addrs = self.find_instruction("rdtsc")

        # Look for paired timing calls (common pattern)
        all_timing: list[Any] = tick_refs + perf_refs + rdtsc_addrs
        all_timing.sort(key=lambda x: x.getOffset())

        for i in range(len(all_timing) - 1):
            addr1: Any = all_timing[i]
            addr2: Any = all_timing[i + 1]

            # If two timing calls are close together, likely a timing check
            distance: int = addr2.getOffset() - addr1.getOffset()
            if distance < 0x100:  # Within 256 bytes
                findings["timing_checks"].append(
                    {
                        "type": "Timing Check",
                        "start": addr1,
                        "end": addr2,
                        "description": "Potential timing-based anti-debugging check",
                    },
                )
                logger.info("  [+] Found timing check between %s and %s", addr1, addr2)
                safe_ghidra_call("createBookmark", addr1, "Timing", "Timing check start")

    def find_exception_tricks(self, findings: dict[str, list[dict[str, Any]]]) -> None:
        """Find exception-based anti-analysis tricks.

        Args:
            findings: Dictionary to accumulate findings by category.

        """
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

    def find_api_refs(self, api_name: str) -> list[Any]:
        """Find all references to an API.

        Args:
            api_name: The API name to search for.

        Returns:
            list[Any]: List of addresses where the API is referenced.

        """
        refs: list[Any] = []
        program: Any = get_current_program()
        symbol_table: Any = program.getSymbolTable()

        symbols: Any = symbol_table.getSymbols(api_name)
        for symbol in symbols:
            refs_result: Any = safe_ghidra_call("getReferencesTo", symbol.getAddress())
            for ref in refs_result or []:
                if ref.getReferenceType().isCall():
                    refs.append(ref.getFromAddress())

        return refs

    def find_instruction(self, mnemonic: str) -> list[Any]:
        """Find all instances of an instruction.

        Args:
            mnemonic: The instruction mnemonic to search for.

        Returns:
            list[Any]: List of addresses where the instruction is found.

        """
        addrs: list[Any] = []
        program: Any = get_current_program()
        listing: Any = program.getListing()
        instructions: Any = listing.getInstructions(True)

        while instructions.hasNext():
            instr = instructions.next()
            if instr.getMnemonicString().lower() == mnemonic:
                addrs.append(instr.getAddress())

        return addrs

    def get_api_description(self, api: str) -> str:
        """Get description for known anti-debug APIs.

        Args:
            api: The API name to describe.

        Returns:
            str: A description of the API's anti-debugging purpose.

        """
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

    def get_instruction_description(self, instr: str) -> str:
        """Get description for detection instructions.

        Args:
            instr: The instruction mnemonic to describe.

        Returns:
            str: A description of the instruction's detection purpose.

        """
        descriptions = {
            "cpuid": "CPU identification - VM detection",
            "rdtsc": "Read timestamp counter - timing detection",
            "int 3": "Software breakpoint - debugger detection",
            "int 2d": "Windows debug service - debugger detection",
            "sidt": "Store IDT - VM/debugger detection",
            "sgdt": "Store GDT - VM/debugger detection",
        }
        return descriptions.get(instr, "Detection instruction")

    def generate_report(self, findings: dict[str, list[dict[str, Any]]]) -> None:
        """Generate analysis report.

        Args:
            findings: Dictionary containing findings organized by category.

        """
        logger.info("=== Anti-Analysis Technique Report ===")

        total = sum(len(v) for v in findings.values())
        logger.info("Total anti-analysis techniques found: %s", total)

        if findings["anti_debug"]:
            logger.info("Anti-Debugging (%s found):", len(findings["anti_debug"]))
            for item in findings["anti_debug"][:5]:
                logger.info("  - %s at %s", item["name"], item["address"])

        if findings["anti_vm"]:
            logger.info("Anti-VM (%s found):", len(findings["anti_vm"]))
            for item in findings["anti_vm"][:5]:
                logger.info("  - '%s' at %s", item["name"], item["address"])

        if findings["timing_checks"]:
            logger.info("Timing Checks (%s found):", len(findings["timing_checks"]))
            for item in findings["timing_checks"][:5]:
                logger.info("  - Check between %s and %s", item["start"], item["end"])

        if findings["cpu_detection"]:
            logger.info("CPU Detection (%s found):", len(findings["cpu_detection"]))
            for item in findings["cpu_detection"][:5]:
                logger.info("  - %s at %s", item["instruction"], item["address"])

        # Protection level assessment
        protection_level = self.assess_protection_level(findings)
        logger.info("[*] Protection Level: %s", protection_level)
        logger.info("[*] Check bookmarks for all findings")

    def assess_protection_level(self, findings: dict[str, list[dict[str, Any]]]) -> str:
        """Assess overall protection level.

        Args:
            findings: Dictionary containing findings organized by category.

        Returns:
            str: A description of the protection level detected.

        """
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
