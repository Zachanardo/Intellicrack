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
sys.modules["intel_extension_for_pytorch"] = MagicMock()
sys.modules["ipex"] = MagicMock()
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
