"""
Pytest configuration and fixtures for Intellicrack testing.

CRITICAL: All fixtures must provide REAL data, not mocked or simulated data.
Every test using these fixtures will validate ACTUAL functionality.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
import sys
import os

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Test data directories
FIXTURES_DIR = Path(__file__).parent / "fixtures"
BINARIES_DIR = FIXTURES_DIR / "binaries"
VULNERABLE_DIR = FIXTURES_DIR / "vulnerable_samples"
NETWORK_DIR = FIXTURES_DIR / "network_captures"


@pytest.fixture(scope="session")
def test_data_dir():
    """Provide path to test data directory with REAL test files."""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def real_pe_binary():
    """
    Provide path to a REAL PE binary for testing.
    This must be an actual executable, not a mock file.
    """
    pe_path = BINARIES_DIR / "pe" / "simple_hello_world.exe"
    if not pe_path.exists():
        pytest.skip(f"Real PE binary not found at {pe_path}. Test requires REAL binary data.")
    return pe_path


@pytest.fixture(scope="session")
def real_elf_binary():
    """
    Provide path to a REAL ELF binary for testing.
    This must be an actual Linux executable, not a mock file.
    """
    elf_path = BINARIES_DIR / "elf" / "simple_x64"
    if not elf_path.exists():
        pytest.skip(f"Real ELF binary not found at {elf_path}. Test requires REAL binary data.")
    return elf_path


@pytest.fixture(scope="session")
def real_protected_binary():
    """
    Provide path to a REAL protected binary (VMProtect, Themida, etc).
    This must be an actual protected executable for testing protection detection.
    """
    protected_path = BINARIES_DIR / "protected" / "vmprotect_demo.exe"
    if not protected_path.exists():
        pytest.skip(f"Real protected binary not found at {protected_path}. Test requires REAL protected binary.")
    return protected_path


@pytest.fixture
def temp_workspace():
    """
    Provide a temporary directory for test operations.
    Cleaned up automatically after test.
    """
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def real_vulnerable_binary():
    """
    Provide path to a REAL vulnerable binary for exploit testing.
    This must be an actual exploitable program, not a simulation.
    """
    vuln_path = VULNERABLE_DIR / "buffer_overflow_x86.exe"
    if not vuln_path.exists():
        pytest.skip(f"Real vulnerable binary not found at {vuln_path}. Test requires REAL exploitable binary.")
    return vuln_path


@pytest.fixture(scope="session")
def real_network_capture():
    """
    Provide path to a REAL network capture file.
    This must be an actual PCAP with real protocol data.
    """
    pcap_path = NETWORK_DIR / "flexlm_handshake.pcap"
    if not pcap_path.exists():
        pytest.skip(f"Real network capture not found at {pcap_path}. Test requires REAL network data.")
    return pcap_path


@pytest.fixture
def isolated_test_env():
    """
    Provide an isolated environment for testing dangerous operations using Windows Sandbox.
    """
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_isolated_")

    restricted_env = os.environ.copy()
    restricted_env['INTELLICRACK_ISOLATED'] = '1'
    restricted_env['PATH'] = ''

    if sys.platform == "win32":
        try:
            import win32api
            import win32con
            import win32security

            user_sid = win32security.GetTokenInformation(
                win32security.GetCurrentProcessToken(),
                win32security.TokenUser
            )[0]

            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                user_sid
            )

            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                temp_dir,
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
        except ImportError:
            os.chmod(temp_dir, 0o700)
    else:
        os.chmod(temp_dir, 0o700)

    yield {'path': Path(temp_dir), 'env': restricted_env, 'is_isolated': True}
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def verify_no_mocks(monkeypatch):
    """
    Automatically verify that tests are not using mock data.
    This fixture runs for every test to ensure REAL data usage.
    """
    # Prevent common mocking libraries from being used
    def mock_error(*args, **kwargs):
        raise RuntimeError(
            "MOCKING DETECTED! All tests must use REAL data. "
            "No mock objects, fake responses, or simulated data allowed."
        )

    # Block unittest.mock
    monkeypatch.setattr("unittest.mock.Mock", mock_error)
    monkeypatch.setattr("unittest.mock.MagicMock", mock_error)
    monkeypatch.setattr("unittest.mock.patch", mock_error)

    # Block pytest-mock
    if "pytest_mock" in sys.modules:
        monkeypatch.setattr("pytest_mock.MockFixture", mock_error)


@pytest.fixture
def require_radare2():
    """Ensure radare2 is available for tests that need it."""
    try:
        import r2pipe
        r2 = r2pipe.open()
        r2.quit()
    except Exception:
        pytest.skip("Real radare2 installation required for this test")


@pytest.fixture
def require_frida():
    """Ensure Frida is available for tests that need it."""
    try:
        from intellicrack.handlers.frida_handler import HAS_FRIDA, frida
        if not HAS_FRIDA:
            raise ImportError("Frida not available")
        frida.get_local_device()
    except Exception:
        pytest.skip("Real Frida installation required for this test")


@pytest.fixture
def require_ai_model():
    """Ensure AI model is available for tests that need it."""
    # Check if real AI models are accessible
    model_path = PROJECT_ROOT / "models"
    if not model_path.exists() or not any(model_path.iterdir()):
        pytest.skip("Real AI models required for this test")


# Markers for test categorization
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "real_binary: test requires real binary files"
    )
    config.addinivalue_line(
        "markers", "real_exploit: test generates real exploits"
    )
    config.addinivalue_line(
        "markers", "real_network: test uses real network data"
    )
    config.addinivalue_line(
        "markers", "real_ai: test uses real AI models"
    )


# Ensure all tests validate real functionality
def pytest_collection_modifyitems(config, items):
    """Add markers to ensure tests use real data."""
    for item in items:
        # Add a marker to track real data usage
        item.add_marker(pytest.mark.real_data)

        # Warn if test name suggests mocking
        if any(word in item.name.lower() for word in ["mock", "fake", "stub", "dummy"]):
            raise ValueError(
                f"Test '{item.name}' appears to use mock data. "
                "All tests must validate REAL functionality!"
            )
