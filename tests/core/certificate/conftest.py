"""Pytest configuration for certificate module tests.

This conftest sets up the test environment to avoid problematic dependencies
like GPU handlers, PyTorch, and other heavy imports that aren't needed for
unit testing the certificate validation modules.
"""

import os
import sys
from unittest.mock import MagicMock

# Disable GPU and heavy dependencies for testing
os.environ["INTELLICRACK_DISABLE_GPU"] = "1"
os.environ["INTELLICRACK_TEST_MODE"] = "1"
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
os.environ["DISABLE_TORCH_XPU"] = "1"
os.environ["INTELLICRACK_MINIMAL_IMPORTS"] = "1"

# Mock problematic modules before they get imported
sys.modules["torch.xpu"] = MagicMock()

# Mock heavy Intellicrack modules that aren't needed for certificate tests
sys.modules["angr"] = MagicMock()
sys.modules["angr.state_plugins"] = MagicMock()
sys.modules["angr.state_plugins.unicorn_engine"] = MagicMock()

# Don't mock PyQt6 - let pytest-qt handle it and we'll disable the plugin via pytest.ini

# Mock analysis modules that load slowly
sys.modules["intellicrack.core.analysis"] = MagicMock()
sys.modules["intellicrack.core.analysis.concolic_executor"] = MagicMock()
sys.modules["intellicrack.core.analysis.radare2_error_handler"] = MagicMock()
sys.modules["intellicrack.core.analysis.firmware_analyzer"] = MagicMock()

# Mock config manager that does heavy initialization
sys.modules["intellicrack.core.config_manager"] = MagicMock()

# Mock utils modules that load heavy dependencies
sys.modules["intellicrack.utils.core"] = MagicMock()
sys.modules["intellicrack.utils.core.core_utilities"] = MagicMock()
sys.modules["intellicrack.utils.dependency_fallbacks"] = MagicMock()
sys.modules["intellicrack.utils.patching"] = MagicMock()
sys.modules["intellicrack.utils.patching.patch_utils"] = MagicMock()

# Mock matplotlib
sys.modules["matplotlib"] = MagicMock()
sys.modules["matplotlib.pyplot"] = MagicMock()

# Mock frida with proper exception classes
frida_mock = MagicMock()
frida_mock.__version__ = "16.0.0"
frida_mock.ProcessNotFoundError = type("ProcessNotFoundError", (Exception,), {})
frida_mock.PermissionDeniedError = type("PermissionDeniedError", (Exception,), {})
frida_mock.InvalidArgumentError = type("InvalidArgumentError", (Exception,), {})
frida_mock.InvalidOperationError = type("InvalidOperationError", (Exception,), {})
frida_mock.ServerNotRunningError = type("ServerNotRunningError", (Exception,), {})
sys.modules["frida"] = frida_mock

# Mock psutil with proper exception classes
psutil_mock = MagicMock()
psutil_mock.__version__ = "5.9.0"
psutil_mock.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
psutil_mock.AccessDenied = type("AccessDenied", (Exception,), {})
psutil_mock.TimeoutExpired = type("TimeoutExpired", (Exception,), {})
sys.modules["psutil"] = psutil_mock
