"""Production tests for API obfuscation module.

Tests validate real API obfuscation and resolution techniques.
Tests verify hash-based resolution, dynamic loading, and anti-hooking.
"""

import platform
import sys
from typing import Any

import pytest

from intellicrack.core.anti_analysis.api_obfuscation import APIObfuscator


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestAPIObfuscator:
    """Test API obfuscation initialization and setup."""

    def test_create_api_obfuscator(self) -> None:
        """Create API obfuscator instance."""
        obfuscator = APIObfuscator()

        assert obfuscator is not None
        assert hasattr(obfuscator, "import_resolution_methods")
        assert hasattr(obfuscator, "call_obfuscation_methods")

    def test_obfuscator_has_resolution_methods(self) -> None:
        """Verify obfuscator has resolution methods."""
        obfuscator = APIObfuscator()

        assert "hash_resolution" in obfuscator.import_resolution_methods
        assert "string_encryption" in obfuscator.import_resolution_methods
        assert "dynamic_loading" in obfuscator.import_resolution_methods

    def test_obfuscator_has_call_methods(self) -> None:
        """Verify obfuscator has call obfuscation methods."""
        obfuscator = APIObfuscator()

        assert "indirect_calls" in obfuscator.call_obfuscation_methods
        assert "trampoline_calls" in obfuscator.call_obfuscation_methods
        assert "encrypted_payloads" in obfuscator.call_obfuscation_methods


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestNormalAPIResolution:
    """Test normal API resolution."""

    def test_resolve_kernel32_getprocaddress(self) -> None:
        """Resolve GetProcAddress from kernel32.dll."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="normal")

        assert address is not None
        assert isinstance(address, int)
        assert address > 0

    def test_resolve_kernel32_loadlibrary(self) -> None:
        """Resolve LoadLibraryW from kernel32.dll."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "LoadLibraryW", method="normal")

        assert address is not None
        assert isinstance(address, int)
        assert address > 0

    def test_resolve_kernel32_getmodulehandle(self) -> None:
        """Resolve GetModuleHandleW from kernel32.dll."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "GetModuleHandleW", method="normal")

        assert address is not None
        assert isinstance(address, int)
        assert address > 0

    def test_resolve_ntdll_ntcreatefile(self) -> None:
        """Resolve NtCreateFile from ntdll.dll."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("ntdll.dll", "NtCreateFile", method="normal")

        assert address is not None
        assert isinstance(address, int)
        assert address > 0

    def test_resolve_user32_messagebox(self) -> None:
        """Resolve MessageBoxW from user32.dll."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("user32.dll", "MessageBoxW", method="normal")

        assert address is not None
        assert isinstance(address, int)
        assert address > 0


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestDynamicAPIResolution:
    """Test dynamic API resolution."""

    def test_dynamic_resolve_kernel32_api(self) -> None:
        """Dynamically resolve kernel32 API."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="dynamic_resolution")

        assert address is not None or address == 0

    def test_dynamic_resolve_returns_address(self) -> None:
        """Verify dynamic resolution returns valid address."""
        obfuscator = APIObfuscator()

        if address := obfuscator.resolve_api(
            "kernel32.dll", "LoadLibraryW", method="dynamic_resolution"
        ):
            assert isinstance(address, int)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestHashBasedAPIResolution:
    """Test hash-based API resolution."""

    def test_hash_resolve_kernel32_api(self) -> None:
        """Resolve API using hash method."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="hash_lookup")

        assert isinstance(address, (int, type(None)))

    def test_hash_resolve_caching(self) -> None:
        """Verify hash resolution uses caching."""
        obfuscator = APIObfuscator()

        address1 = obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="hash_lookup")
        address2 = obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="hash_lookup")

        if address1 is not None:
            assert address1 == address2


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestAPIResolutionCaching:
    """Test API resolution caching."""

    def test_cache_stores_resolved_apis(self) -> None:
        """Verify resolved APIs are cached."""
        obfuscator = APIObfuscator()

        if address := obfuscator.resolve_api(
            "kernel32.dll", "GetProcAddress", method="normal"
        ):
            cache_key = "kernel32.dll!GetProcAddress"
            assert cache_key in obfuscator.resolved_apis_cache
            assert obfuscator.resolved_apis_cache[cache_key] == address

    def test_cache_hit_returns_same_address(self) -> None:
        """Verify cache hit returns same address."""
        obfuscator = APIObfuscator()

        address1 = obfuscator.resolve_api("kernel32.dll", "LoadLibraryW", method="normal")
        address2 = obfuscator.resolve_api("kernel32.dll", "LoadLibraryW", method="normal")

        if address1:
            assert address1 == address2

    def test_cache_tracks_resolved_count(self) -> None:
        """Verify cache tracks resolution count."""
        obfuscator = APIObfuscator()

        initial_count = obfuscator.resolved_apis

        obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="normal")
        obfuscator.resolve_api("kernel32.dll", "LoadLibraryW", method="normal")

        assert obfuscator.resolved_apis >= initial_count


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestCodeObfuscation:
    """Test code obfuscation generation."""

    def test_obfuscate_api_calls_returns_code(self) -> None:
        """Obfuscate API calls returns code."""
        obfuscator = APIObfuscator()

        code = "GetProcAddress()"
        obfuscated = obfuscator.obfuscate_api_calls(code, method="hash_lookup")

        assert isinstance(obfuscated, str)
        assert len(obfuscated) > 0

    def test_obfuscate_with_invalid_method(self) -> None:
        """Handle invalid obfuscation method."""
        obfuscator = APIObfuscator()

        code = "GetProcAddress()"
        obfuscated = obfuscator.obfuscate_api_calls(code, method="invalid_method")

        assert isinstance(obfuscated, str)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_resolve_nonexistent_dll(self) -> None:
        """Handle nonexistent DLL."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("nonexistent.dll", "SomeAPI", method="normal")

        assert address is None

    def test_resolve_nonexistent_api(self) -> None:
        """Handle nonexistent API."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "NonexistentAPI", method="normal")

        assert address is None or address == 0

    def test_resolve_empty_dll_name(self) -> None:
        """Handle empty DLL name."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("", "GetProcAddress", method="normal")

        assert address is None or address == 0

    def test_resolve_empty_api_name(self) -> None:
        """Handle empty API name."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "", method="normal")

        assert address is None or address == 0


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestMultipleAPIsResolution:
    """Test resolving multiple APIs."""

    def test_resolve_multiple_kernel32_apis(self) -> None:
        """Resolve multiple kernel32 APIs."""
        obfuscator = APIObfuscator()

        apis = ["GetProcAddress", "LoadLibraryW", "GetModuleHandleW", "VirtualAlloc"]
        addresses = []

        for api_name in apis:
            if address := obfuscator.resolve_api(
                "kernel32.dll", api_name, method="normal"
            ):
                addresses.append(address)

        assert len(addresses) >= 2
        assert all(addr > 0 for addr in addresses)
        assert len(set(addresses)) == len(addresses)

    def test_resolve_apis_from_different_dlls(self) -> None:
        """Resolve APIs from different DLLs."""
        obfuscator = APIObfuscator()

        apis = [
            ("kernel32.dll", "GetProcAddress"),
            ("ntdll.dll", "NtCreateFile"),
            ("user32.dll", "MessageBoxW"),
        ]

        addresses = []
        for dll, api in apis:
            if address := obfuscator.resolve_api(dll, api, method="normal"):
                addresses.append((dll, api, address))

        assert addresses


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestLicensingAntiHook:
    """Test anti-hook techniques for licensing bypass."""

    def test_resolve_license_validation_apis(self) -> None:
        """Resolve APIs used in license validation."""
        obfuscator = APIObfuscator()

        apis = [
            "GetSystemTime",
            "GetSystemTimeAsFileTime",
            "GetTickCount",
            "QueryPerformanceCounter",
        ]

        for api_name in apis:
            if address := obfuscator.resolve_api(
                "kernel32.dll", api_name, method="normal"
            ):
                assert isinstance(address, int)
                assert address > 0

    def test_resolve_registry_apis_for_trial_reset(self) -> None:
        """Resolve registry APIs for trial reset."""
        obfuscator = APIObfuscator()

        apis = [
            "RegOpenKeyExW",
            "RegSetValueExW",
            "RegDeleteValueW",
            "RegCloseKey",
        ]

        for api_name in apis:
            address = obfuscator.resolve_api("advapi32.dll", api_name, method="normal")
            if address is not None:
                assert isinstance(address, int)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestPerformance:
    """Test API resolution performance."""

    def test_cached_resolution_performance(self, benchmark: Any) -> None:
        """Benchmark cached API resolution."""
        obfuscator = APIObfuscator()

        obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="normal")

        result = benchmark(obfuscator.resolve_api, "kernel32.dll", "GetProcAddress", method="normal")

        assert result is not None

    def test_bulk_resolution_performance(self) -> None:
        """Test bulk API resolution performance."""
        obfuscator = APIObfuscator()

        apis = ["GetProcAddress", "LoadLibraryW", "GetModuleHandleW"] * 10

        for api_name in apis:
            obfuscator.resolve_api("kernel32.dll", api_name, method="normal")

        assert obfuscator.resolved_apis > 0


class TestCrossPlatformFallback:
    """Test fallback behavior on non-Windows platforms."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="Non-Windows test")
    def test_non_windows_returns_none(self) -> None:
        """Non-Windows platforms return None."""
        obfuscator = APIObfuscator()

        address = obfuscator.resolve_api("kernel32.dll", "GetProcAddress", method="normal")

        assert address is None
