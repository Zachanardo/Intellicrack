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

# Mock problematic modules before they get imported
sys.modules["intel_extension_for_pytorch"] = MagicMock()
sys.modules["ipex"] = MagicMock()
sys.modules["torch.xpu"] = MagicMock()
