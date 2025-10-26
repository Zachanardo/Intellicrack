"""Binary scanner for detecting certificate validation APIs and references."""

import re
from pathlib import Path
from typing import List, Optional

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
        cross_references: Optional[List[int]] = None
    ):
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

    def __init__(self, binary_path: str):
        """Initialize binary scanner.

        Args:
            binary_path: Path to the binary to scan

        """
        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary: Optional[lief.Binary] = None
        self.r2_handle = None

        if LIEF_AVAILABLE:
            try:
                self.binary = lief.parse(str(self.binary_path))
            except Exception as e:
                raise RuntimeError(f"Failed to parse binary with LIEF: {e}") from e

    def scan_imports(self) -> List[str]:
        """Scan binary imports and return imported DLL/library names.

        Returns:
            List of imported library names

        """
        if not self.binary:
            return []

        imports = set()

        if isinstance(self.binary, lief.PE.Binary):
            for lib in self.binary.imports:
                imports.add(lib.name.lower())
        elif isinstance(self.binary, lief.ELF.Binary):
            for lib in self.binary.libraries:
                imports.add(lib.lower())
        elif isinstance(self.binary, lief.MachO.Binary):
            for lib in self.binary.libraries:
                imports.add(Path(lib).name.lower())

        return list(imports)

    def detect_tls_libraries(self, imports: Optional[List[str]] = None) -> List[str]:
        """Identify SSL/TLS libraries from imports.

        Args:
            imports: List of imported libraries (if None, will scan imports)

        Returns:
            List of detected TLS library names

        """
        if imports is None:
            imports = self.scan_imports()

        tls_keywords = [
            "ssl", "tls", "crypt", "winhttp", "schannel", "sspicli",
            "nss", "security", "cfnetwork"
        ]

        tls_libs = []
        for imp in imports:
            imp_lower = imp.lower()
            if any(keyword in imp_lower for keyword in tls_keywords):
                tls_libs.append(imp)

        return tls_libs

    def scan_strings(self) -> List[str]:
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
            strings.extend([
                m.decode("utf-16le", errors="ignore").rstrip("\x00")
                for m in matches
            ])

        except Exception as e:
            import logging
            logging.getLogger(__name__).debug(f"Failed to extract strings: {e}")

        return list(set(strings))

    def find_certificate_references(self, strings: Optional[List[str]] = None) -> List[str]:
        """Find certificate-related strings in binary.

        Args:
            strings: List of strings to search (if None, will scan strings)

        Returns:
            List of certificate-related strings

        """
        if strings is None:
            strings = self.scan_strings()

        cert_keywords = [
            "certificate", "cert", "ssl", "tls", "x509", "pem", "der",
            "ca_bundle", "trusted", "verify", "pinning", "sha256", "sha1"
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
                self.r2_handle.cmd("aaa")
            except Exception:
                return False

        return True

    def find_api_calls(self, api_name: str) -> List[int]:
        """Find all calls to a specific API using radare2.

        Args:
            api_name: Name of the API to search for

        Returns:
            List of addresses where the API is called

        """
        if not self._init_radare2():
            return self._find_api_calls_lief(api_name)

        try:
            result = self.r2_handle.cmd(f"axt @ sym.imp.{api_name}")
            addresses = []

            for line in result.splitlines():
                match = re.search(r"0x([0-9a-fA-F]+)", line)
                if match:
                    addresses.append(int(match.group(1), 16))

            return addresses

        except Exception:
            return self._find_api_calls_lief(api_name)

    def _find_api_calls_lief(self, api_name: str) -> List[int]:
        """Fallback method to find API calls using LIEF.

        Args:
            api_name: Name of the API to search for

        Returns:
            List of addresses (may be import table addresses)

        """
        if not self.binary:
            return []

        addresses = []

        if isinstance(self.binary, lief.PE.Binary):
            for imp in self.binary.imports:
                for entry in imp.entries:
                    if entry.name and api_name in entry.name:
                        addresses.append(entry.iat_address)

        return addresses

    def analyze_call_context(self, address: int) -> ContextInfo:
        """Analyze the context surrounding a code address.

        Args:
            address: Address to analyze

        Returns:
            ContextInfo object with context information

        """
        if not self._init_radare2():
            return ContextInfo(address)

        try:
            self.r2_handle.cmd(f"s {hex(address)}")

            func_name = self.r2_handle.cmd("afi~name[1]").strip()

            disasm = self.r2_handle.cmd("pdf @ $$ 20")

            xrefs_output = self.r2_handle.cmd(f"axt @ {hex(address)}")
            xrefs = []
            for line in xrefs_output.splitlines():
                match = re.search(r"0x([0-9a-fA-F]+)", line)
                if match:
                    xrefs.append(int(match.group(1), 16))

            return ContextInfo(
                address=address,
                function_name=func_name,
                surrounding_code=disasm,
                cross_references=xrefs
            )

        except Exception:
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

    def close(self):
        """Clean up resources."""
        if self.r2_handle:
            try:
                self.r2_handle.quit()
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to close radare2: {e}")
            self.r2_handle = None

    def __enter__(self):
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self.close()
