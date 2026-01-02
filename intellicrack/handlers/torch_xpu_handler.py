"""PyTorch XPU Import Handler.

This module provides a centralized handler for importing PyTorch with XPU support.
Replaces the legacy Intel Extension for PyTorch (IPEX) handler.

The module automatically detects XPU device availability and initializes the XPU
runtime if available. It respects environment variables to skip initialization in
testing, CI, or when explicitly disabled.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0

Attributes:
    HAS_XPU: Boolean flag indicating whether PyTorch XPU devices are available.
        Automatically initialized during module import.
"""

import os
import warnings

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)

HAS_XPU = False


if skip_xpu_env_vars := (
    os.environ.get("PYTEST_CURRENT_TEST")
    or os.environ.get("CI")
    or os.environ.get("INTELLICRACK_TEST_MODE")
    or os.environ.get("INTELLICRACK_DISABLE_GPU")
    or os.environ.get("INTELLICRACK_SKIP_INTEL_XPU")
):
    logger.debug("Skipping XPU initialization in test/CI/disabled environment")
    HAS_XPU = False
else:
    try:
        old_cpp_min_log_level = os.environ.get("TORCH_CPP_LOG_LEVEL")
        os.environ["TORCH_CPP_LOG_LEVEL"] = "3"

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", category=FutureWarning)

            import torch

            if hasattr(torch, "xpu") and callable(getattr(torch.xpu, "is_available", None)):
                if torch.xpu.is_available():
                    HAS_XPU = True
                    device_count = torch.xpu.device_count()
                    logger.info("PyTorch XPU available with %d device(s)", device_count)
                    logger.info("PyTorch version: %s", torch.__version__)
                    for i in range(device_count):
                        device_name = torch.xpu.get_device_name(i)
                        logger.info("  XPU Device %d: %s", i, device_name)
                else:
                    logger.debug("PyTorch loaded but no XPU devices detected")
            else:
                logger.debug("PyTorch XPU backend not available")

        if old_cpp_min_log_level is not None:
            os.environ["TORCH_CPP_LOG_LEVEL"] = old_cpp_min_log_level
        else:
            os.environ.pop("TORCH_CPP_LOG_LEVEL", None)

    except (ImportError, RuntimeError, OSError) as e:
        error_msg = str(e)
        logger.info("PyTorch XPU not available: %s", error_msg)
        HAS_XPU = False


__all__ = ["HAS_XPU"]
