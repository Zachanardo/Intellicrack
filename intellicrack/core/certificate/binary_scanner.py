"""Binary scanner for detecting certificate validation APIs and references in executable files.

CAPABILITIES:
- Import table analysis for PE, ELF, and Mach-O binaries (via LIEF)
- TLS/SSL library detection (WinHTTP, Schannel, OpenSSL, NSS, etc.)
- String extraction using ASCII and UTF-16LE pattern matching
- Certificate-related string identification (keywords, hashes, paths)
- API call location finding using radare2 disassembly
- Cross-reference analysis for API usage patterns
- Context extraction (surrounding code, function names)
- Confidence scoring for detected certificate validation
- Support for Windows PE, Linux ELF, and macOS Mach-O formats

LIMITATIONS:
- Requires LIEF library for import table parsing
- Requires radare2/r2pipe for call location analysis
- Cannot detect obfuscated or encrypted strings
- May miss dynamically loaded libraries (LoadLibrary, dlopen)
- Limited accuracy on packed or protected binaries
- String extraction is pattern-based, may have false positives
- Radare2 analysis can be slow on large binaries (>50MB)
- No support for virtualized or emulated code sections

USAGE EXAMPLES:
    # Basic import scanning
    from intellicrack.core.certificate.binary_scanner import BinaryScanner

    scanner = BinaryScanner("target.exe")
    imports = scanner.scan_imports()
    print(f"Imports: {imports}")

    # Detect TLS libraries
    tls_libs = scanner.detect_tls_libraries()
    print(f"TLS libraries: {tls_libs}")

    # Find certificate-related strings
    cert_strings = scanner.find_certificate_references()
    for s in cert_strings[:10]:
        print(f"Found: {s}")

    # Find specific API calls
    api_calls = scanner.find_api_calls("WinHttpSetOption")
    print(f"Found {len(api_calls)} calls at: {[hex(addr) for addr in api_calls]}")

    # Analyze call context
    if api_calls:
        context = scanner.analyze_call_context(api_calls[0])
        print(f"Function: {context.function_name}")
        print(f"Surrounding code: {context.surrounding_code}")

    # Calculate confidence score
    confidence = scanner.calculate_confidence(context)
    print(f"Confidence: {confidence:.2f}")

RELATED MODULES:
- api_signatures.py: Provides API signatures for detection
- validation_detector.py: Uses this scanner for comprehensive detection
- detection_report.py: Stores results from binary scanning
- cert_patcher.py: Uses scan results to locate patch targets
- pinning_detector.py: Uses string scanning to find hardcoded certificates

PERFORMANCE NOTES:
- Import scanning: Fast (<1s for most binaries)
- String extraction: Moderate (1-5s depending on size)
- radare2 analysis: Slow (10-60s for full analysis)
- Consider using caching for repeated analyses
- Disable radare2 analysis for quick scans (imports/strings only)
"""

import logging
import re
from pathlib import Path


logger = logging.getLogger(__name__)


try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False


class ContextInfo:
    """Information about the context surrounding an API call."""

    def __init__(
        self,
        address: int,
        function_name: str = "",
        surrounding_code: str = "",
        cross_references: list[int] | None = None,
    ) -> None:
        """Initialize context information.

        Args:
            address: Memory address of the API call
            function_name: Name of the function containing the call
            surrounding_code: Disassembly around the call site
            cross_references: List of addresses that reference this location

        """
        self.address = address
        self.function_name = function_name
        self.surrounding_code = surrounding_code
        self.cross_references = cross_references or []


class BinaryScanner:
    """Scans binaries for certificate validation API usage."""

    def __init__(self, binary_path: str) -> None:
        """Initialize binary scanner.

        Args:
            binary_path: Path to the binary to scan

        """
        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary: lief.PE.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary | None = None
        self.r2_handle: r2pipe.open_base.open | None = None

        if LIEF_AVAILABLE:
            try:
                self.binary = lief.parse(str(self.binary_path))
            except Exception as e:
                raise RuntimeError(f"Failed to parse binary with LIEF: {e}") from e

    def scan_imports(self) -> list[str]:
        """Scan binary imports and return imported DLL/library names.

        Returns:
            List of imported library names

        """
        if not self.binary:
            return []

        imports: set[str] = set()

        if isinstance(self.binary, lief.PE.Binary):
            for lib in self.binary.imports:
                lib_name = lib.name
                if isinstance(lib_name, str):
                    imports.add(lib_name.lower())
                elif isinstance(lib_name, bytes):
                    imports.add(lib_name.decode("utf-8", errors="ignore").lower())
        elif isinstance(self.binary, lief.ELF.Binary):
            for lib_name in self.binary.libraries:
                if isinstance(lib_name, str):
                    imports.add(lib_name.lower())
                elif isinstance(lib_name, bytes):
                    imports.add(lib_name.decode("utf-8", errors="ignore").lower())
        elif isinstance(self.binary, lief.MachO.Binary):
            for dylib_cmd in self.binary.libraries:
                lib_path = dylib_cmd.name
                imports.add(Path(lib_path).name.lower())

        return list(imports)

    def detect_tls_libraries(self, imports: list[str] | None = None) -> list[str]:
        """Identify SSL/TLS libraries from imports.

        Args:
            imports: List of imported libraries (if None, will scan imports)

        Returns:
            List of detected TLS library names

        """
        if imports is None:
            imports = self.scan_imports()

        tls_keywords = [
            "ssl",
            "tls",
            "crypt",
            "winhttp",
            "schannel",
            "sspicli",
            "nss",
            "security",
            "cfnetwork",
        ]

        tls_libs = []
        for imp in imports:
            imp_lower = imp.lower()
            if any(keyword in imp_lower for keyword in tls_keywords):
                tls_libs.append(imp)

        return tls_libs

    def scan_strings(self) -> list[str]:
        """Extract all strings from binary.

        Returns:
            List of strings found in binary

        """
        strings = []

        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()

            ascii_pattern = rb"[ -~]{4,}"
            matches = re.findall(ascii_pattern, data)
            strings.extend([m.decode("ascii", errors="ignore") for m in matches])

            unicode_pattern = rb"(?:[ -~]\x00){4,}"
            matches = re.findall(unicode_pattern, data)
            strings.extend([m.decode("utf-16le", errors="ignore").rstrip("\x00") for m in matches])

        except Exception as e:
            logger.debug("Failed to extract strings: %s", e, exc_info=True)

        return list(set(strings))

    def find_certificate_references(self, strings: list[str] | None = None) -> list[str]:
        """Find certificate-related strings in binary.

        Args:
            strings: List of strings to search (if None, will scan strings)

        Returns:
            List of certificate-related strings

        """
        if strings is None:
            strings = self.scan_strings()

        cert_keywords = [
            "certificate",
            "cert",
            "ssl",
            "tls",
            "x509",
            "pem",
            "der",
            "ca_bundle",
            "trusted",
            "verify",
            "pinning",
            "sha256",
            "sha1",
        ]

        cert_strings = []
        for s in strings:
            s_lower = s.lower()
            if any(keyword in s_lower for keyword in cert_keywords):
                cert_strings.append(s)

        return cert_strings

    def _init_radare2(self) -> bool:
        """Initialize radare2 connection.

        Returns:
            True if successful, False otherwise

        """
        if not R2PIPE_AVAILABLE:
            return False

        if self.r2_handle is None:
            try:
                self.r2_handle = r2pipe.open(str(self.binary_path))
                if self.r2_handle is not None:
                    self.r2_handle.cmd("aaa")
            except Exception as e:
                logger.debug("Failed to initialize radare2: %s", e, exc_info=True)
                return False

        return self.r2_handle is not None

    def find_api_calls(self, api_name: str) -> list[int]:
        """Find all calls to a specific API using radare2.

        Args:
            api_name: Name of the API to search for

        Returns:
            List of addresses where the API is called

        """
        if not self._init_radare2() or self.r2_handle is None:
            return self._find_api_calls_lief(api_name)

        try:
            result = self.r2_handle.cmd(f"axt @ sym.imp.{api_name}")
            addresses: list[int] = []

            for line in result.splitlines():
                if match := re.search(r"0x([0-9a-fA-F]+)", line):
                    addresses.append(int(match[1], 16))

            return addresses

        except Exception as e:
            logger.debug("Radare2 API call search failed, falling back to LIEF: %s", e, exc_info=True)
            return self._find_api_calls_lief(api_name)

    def _find_api_calls_lief(self, api_name: str) -> list[int]:
        """Fallback method to find API calls using LIEF.

        Args:
            api_name: Name of the API to search for

        Returns:
            List of addresses (may be import table addresses)

        """
        if not self.binary:
            return []

        addresses: list[int] = []

        if isinstance(self.binary, lief.PE.Binary):
            for imp in self.binary.imports:
                addresses.extend(entry.iat_address for entry in imp.entries if entry.name and api_name in entry.name)
        return addresses

    def analyze_call_context(self, address: int) -> ContextInfo:
        """Analyze the context surrounding a code address.

        Args:
            address: Address to analyze

        Returns:
            ContextInfo object with context information

        """
        if not self._init_radare2() or self.r2_handle is None:
            return ContextInfo(address)

        try:
            self.r2_handle.cmd(f"s {hex(address)}")

            func_name = self.r2_handle.cmd("afi~name[1]").strip()

            disasm = self.r2_handle.cmd("pdf @ $$ 20")

            xrefs_output = self.r2_handle.cmd(f"axt @ {hex(address)}")
            xrefs: list[int] = []
            for line in xrefs_output.splitlines():
                if match := re.search(r"0x([0-9a-fA-F]+)", line):
                    xrefs.append(int(match[1], 16))

            return ContextInfo(
                address=address,
                function_name=func_name,
                surrounding_code=disasm,
                cross_references=xrefs,
            )

        except Exception as e:
            logger.debug("Failed to analyze call context at %s: %s", hex(address), e, exc_info=True)
            return ContextInfo(address)

    def calculate_confidence(self, context: ContextInfo) -> float:
        """Calculate confidence score for certificate validation detection.

        Args:
            context: Context information for the API call

        Returns:
            Confidence score between 0.0 and 1.0

        """
        confidence = 0.0

        if context.function_name:
            confidence += 0.2

            func_lower = context.function_name.lower()
            high_confidence_keywords = ["license", "activate", "auth", "verify", "check"]
            if any(kw in func_lower for kw in high_confidence_keywords):
                confidence += 0.3

        if context.surrounding_code:
            code_lower = context.surrounding_code.lower()

            if "https" in code_lower or "ssl" in code_lower:
                confidence += 0.2

            if "license" in code_lower or "activation" in code_lower:
                confidence += 0.2

        if context.cross_references:
            if len(context.cross_references) == 1:
                confidence += 0.1
            elif len(context.cross_references) <= 5:
                confidence += 0.05

        return min(confidence, 1.0)

    def close(self) -> None:
        """Clean up resources."""
        if self.r2_handle:
            try:
                self.r2_handle.quit()
                self.r2_handle = None
            except Exception as e:
                logger.debug("Failed to close radare2: %s", e, exc_info=True)
                self.r2_handle = None

    def __enter__(self) -> "BinaryScanner":
        """Enter context manager.

        Returns:
            BinaryScanner: This instance for use in a with statement

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit context manager.

        Args:
            exc_type: Exception type if an error occurred
            exc_val: Exception value if an error occurred
            exc_tb: Exception traceback if an error occurred

        """
        self.close()
