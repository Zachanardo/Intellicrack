"""Intel Extension for PyTorch Import Handler with DLL Path Resolution.

This module provides a centralized handler for importing Intel Extension for PyTorch
(IPEX) with proper DLL path setup to ensure esimd_kernels.dll and other required
DLLs can be found on Windows.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import sys
import warnings
from pathlib import Path

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

HAS_IPEX = False
ipex = None


def _preload_critical_dlls(dll_dirs) -> bool | None:
    """Pre-load critical DLLs in the correct dependency order.

    This is required for esimd_kernels.dll and unified runtime adapters to load successfully.
    """
    if os.environ.get("INTELLICRACK_TEST_MODE") or os.environ.get("INTELLICRACK_DISABLE_GPU"):
        logger.debug("Skipping DLL preload in test/disabled mode")
        return False

    try:
        import ctypes
        import ctypes.util

        dll_load_order = [
            "libiomp5md.dll",
            "svml_dispmd.dll",
            "libmmd.dll",
            "common_clang64.dll",
            "tbb12.dll",
            "ze_loader.dll",
            "ze_intel_gpu64.dll",
            "igc64.dll",
            "igdgmm64.dll",
            "mkl_core.2.dll",
            "mkl_sycl_blas.5.dll",
            "sycl8.dll",
            "c10.dll",
            "torch_cpu.dll",
        ]

        for dll_name in dll_load_order:
            for dll_dir in dll_dirs:
                dll_path = Path(dll_dir) / dll_name
                if dll_path.exists():
                    try:
                        ctypes.CDLL(str(dll_path), winmode=0)
                        logger.debug("Pre-loaded %s", dll_name)
                        break
                    except OSError as os_err:
                        error_code = getattr(os_err, 'winerror', None)
                        if error_code == 0xc0000139:
                            logger.debug("DLL %s missing entry point (0xc0000139) - skipping", dll_name)
                        else:
                            logger.debug("Could not pre-load %s: %s", dll_name, os_err)
                    except Exception as e:
                        logger.debug("Could not pre-load %s: %s", dll_name, e)

        return True
    except (OSError, Exception) as e:
        logger.debug("Could not pre-load critical DLLs: %s", e)
        return False


def _setup_ipex_dll_paths() -> bool | None:
    """Add Intel Extension for PyTorch and Intel oneAPI DLL directories.

    This ensures all IPEX DLLs, unified runtime adapters, and Intel runtime DLLs can be found.
    """
    try:
        site_packages_dir = Path(sys.prefix) / "Lib" / "site-packages"
        ipex_bin_dir = site_packages_dir / "intel_extension_for_pytorch" / "bin"

        if not ipex_bin_dir.exists():
            logger.debug("Intel Extension for PyTorch bin directory not found")
            return False

        dll_dirs = []

        dll_dirs.append(ipex_bin_dir)

        torch_lib = site_packages_dir / "torch" / "lib"
        if torch_lib.exists():
            dll_dirs.append(torch_lib)

        torch_bin = site_packages_dir / "torch" / "bin"
        if torch_bin.exists():
            dll_dirs.append(torch_bin)

        for dll_dir in dll_dirs:
            dll_dir_str = str(dll_dir)
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(dll_dir_str)
                logger.debug("Added to DLL search path: %s", dll_dir_str)
            else:
                if dll_dir_str not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = dll_dir_str + os.pathsep + os.environ.get("PATH", "")
                logger.debug("Added to PATH (fallback): %s", dll_dir_str)

        _preload_critical_dlls(dll_dirs)

        esimd_kernels = ipex_bin_dir / "esimd_kernels.dll"
        if esimd_kernels.exists():
            logger.debug("Found esimd_kernels.dll at: %s", esimd_kernels)
            return True
        logger.warning("esimd_kernels.dll not found in: %s", ipex_bin_dir)
        return False

    except Exception as e:
        logger.debug("Could not set up IPEX DLL paths (non-critical): %s", e)
        return False


if (os.environ.get("PYTEST_CURRENT_TEST") or
    os.environ.get("CI") or
    os.environ.get("INTELLICRACK_TEST_MODE") or
    os.environ.get("INTELLICRACK_DISABLE_GPU")):
    logger.debug("Skipping IPEX initialization in test/CI/disabled environment")
    dll_paths_configured = False
else:
    dll_paths_configured = _setup_ipex_dll_paths()

skip_cache_file = Path(sys.prefix) / ".ipex_skip_cache"
if skip_cache_file.exists():
    logger.debug("Intel XPU previously failed to load - skipping (remove %s to retry)", skip_cache_file)
    HAS_IPEX = False
    ipex = None
elif dll_paths_configured and not os.environ.get("INTELLICRACK_SKIP_INTEL_XPU"):
    try:
        old_cpp_min_log_level = os.environ.get("TORCH_CPP_LOG_LEVEL")
        os.environ["TORCH_CPP_LOG_LEVEL"] = "3"

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", category=FutureWarning)

            import intel_extension_for_pytorch as _ipex

            ipex = _ipex
            HAS_IPEX = True

            logger.info("Intel Extension for PyTorch loaded successfully (version %s)", getattr(ipex, "__version__", "unknown"))

            try:
                import torch

                if hasattr(torch, "xpu") and callable(getattr(torch.xpu, "is_available", None)):
                    if torch.xpu.is_available():
                        device_count = torch.xpu.device_count()
                        logger.info("Intel XPU available with %d device(s)", device_count)
                        for i in range(device_count):
                            device_name = torch.xpu.get_device_name(i)
                            logger.info("  XPU Device %d: %s", i, device_name)
                    else:
                        logger.info("Intel Extension for PyTorch loaded but no XPU devices detected")
                else:
                    logger.info("Intel Extension for PyTorch loaded (XPU detection not available)")
            except Exception as device_check_error:
                logger.debug("Could not check XPU device availability: %s", device_check_error)

        if old_cpp_min_log_level is not None:
            os.environ["TORCH_CPP_LOG_LEVEL"] = old_cpp_min_log_level
        else:
            os.environ.pop("TORCH_CPP_LOG_LEVEL", None)

    except (ImportError, RuntimeError, OSError, FileNotFoundError) as e:
        error_msg = str(e)

        try:
            skip_cache_file.write_text(f"IPEX import failed: {error_msg}")
            logger.warning("Created skip cache at %s (delete to retry IPEX loading)", skip_cache_file)
        except Exception as e:
            logger.debug(f"Failed to create skip cache: {e}")

        if "No module named" in error_msg:
            logger.debug("Intel Extension for PyTorch not installed")
        elif "dll" in error_msg.lower():
            logger.warning("Intel Extension for PyTorch DLL error: %s", error_msg)
        else:
            logger.info("Intel Extension for PyTorch not available: %s", error_msg)

        HAS_IPEX = False
        ipex = None
else:
    logger.debug("Intel Extension for PyTorch disabled (DLLs not configured or explicitly skipped)")


__all__ = ["HAS_IPEX", "ipex"]
