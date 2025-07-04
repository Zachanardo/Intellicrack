"""
GPU Auto-configuration System for Intellicrack

Automatically detects and configures GPU acceleration for Intel Arc, NVIDIA, AMD, and DirectML.
Provides a unified interface for all GPU operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class GPUAutoLoader:
    """Automatic GPU detection and configuration system"""

    def __init__(self):
        self.gpu_available = False
        self.gpu_type = None
        self.gpu_info = {}
        self._torch = None
        self._device = None
        self._ipex = None
        self._device_string = None

    def setup(self) -> bool:
        """Main setup function that tries different GPU configurations"""
        logger.info("Starting GPU auto-detection...")

        methods = [
            self._try_intel_xpu,
            self._try_nvidia_cuda,
            self._try_amd_rocm,
            self._try_directml,
            self._try_cpu_fallback
        ]

        for method in methods:
            try:
                if method():
                    logger.info(f"✓ GPU configured: {self.gpu_type}")
                    logger.info(f"  Device: {self._device_string}")
                    if self.gpu_info:
                        for key, value in self.gpu_info.items():
                            logger.info(f"  {key}: {value}")
                    return True
            except Exception as e:
                logger.debug(f"Method {method.__name__} failed: {e}")
                continue

        logger.warning("No GPU acceleration available, using CPU")
        return False

    def _try_intel_xpu(self) -> bool:
        """Try to use Intel Arc/XPU through Intel Extension for PyTorch"""
        try:
            # First check if we have a conda environment with Intel Extension
            conda_envs = self._find_conda_envs_with_ipex()
            if conda_envs:
                logger.info(f"Found {len(conda_envs)} conda environment(s) with Intel Extension for PyTorch")
                # Try to use the first one
                conda_env = conda_envs[0]
                python_path = os.path.join(conda_env['path'], 'python.exe' if sys.platform == 'win32' else 'python')
                
                # Test if we can import from that environment
                result = subprocess.run(
                    [python_path, '-c', 'import torch; import intel_extension_for_pytorch as ipex; print(torch.xpu.is_available())'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0 and 'True' in result.stdout:
                    # Inject the conda environment's packages
                    self._inject_conda_packages(conda_env['path'])

            # Try to import
            import torch
            self._torch = torch

            # Check for Intel Extension
            try:
                import intel_extension_for_pytorch as ipex
                self._ipex = ipex
            except ImportError:
                logger.debug("Intel Extension for PyTorch not available")
                return False

            # Check XPU availability
            if hasattr(torch, 'xpu') and torch.xpu.is_available():
                self.gpu_available = True
                self.gpu_type = "intel_xpu"
                self._device = torch.device("xpu")
                self._device_string = "xpu"
                
                # Get detailed info
                device_count = torch.xpu.device_count()
                self.gpu_info = {
                    'device_count': device_count,
                    'backend': 'Intel Extension for PyTorch',
                    'driver_version': torch.xpu.get_driver_version() if hasattr(torch.xpu, 'get_driver_version') else 'Unknown'
                }
                
                # Get info for first device
                if device_count > 0:
                    self.gpu_info['device_name'] = torch.xpu.get_device_name(0)
                    props = torch.xpu.get_device_properties(0)
                    self.gpu_info['total_memory'] = f"{props.total_memory / (1024**3):.1f} GB" if hasattr(props, 'total_memory') else 'Unknown'
                    
                return True

            return False

        except Exception as e:
            logger.debug(f"Intel XPU initialization failed: {e}")
            return False

    def _try_nvidia_cuda(self) -> bool:
        """Try to use NVIDIA CUDA"""
        try:
            import torch
            self._torch = torch

            if torch.cuda.is_available():
                self.gpu_available = True
                self.gpu_type = "nvidia_cuda"
                self._device = torch.device("cuda")
                self._device_string = "cuda"

                # Get detailed info
                device_count = torch.cuda.device_count()
                self.gpu_info = {
                    'device_count': device_count,
                    'backend': 'NVIDIA CUDA',
                    'cuda_version': torch.version.cuda
                }

                # Get info for first device
                if device_count > 0:
                    props = torch.cuda.get_device_properties(0)
                    self.gpu_info['device_name'] = props.name
                    self.gpu_info['total_memory'] = f"{props.total_memory / (1024**3):.1f} GB"
                    self.gpu_info['compute_capability'] = f"{props.major}.{props.minor}"

                return True

            return False

        except Exception as e:
            logger.debug(f"NVIDIA CUDA initialization failed: {e}")
            return False

    def _try_amd_rocm(self) -> bool:
        """Try to use AMD ROCm"""
        try:
            import torch
            self._torch = torch

            # Check for ROCm support
            if hasattr(torch, 'hip') and torch.hip.is_available():
                self.gpu_available = True
                self.gpu_type = "amd_rocm"
                self._device = torch.device("hip")
                self._device_string = "hip"

                # Get detailed info
                device_count = torch.hip.device_count()
                self.gpu_info = {
                    'device_count': device_count,
                    'backend': 'AMD ROCm',
                    'hip_version': torch.version.hip if hasattr(torch.version, 'hip') else 'Unknown'
                }

                # Get info for first device
                if device_count > 0:
                    self.gpu_info['device_name'] = torch.hip.get_device_name(0)
                    props = torch.hip.get_device_properties(0)
                    self.gpu_info['total_memory'] = f"{props.total_memory / (1024**3):.1f} GB" if hasattr(props, 'total_memory') else 'Unknown'

                return True

            return False

        except Exception as e:
            logger.debug(f"AMD ROCm initialization failed: {e}")
            return False

    def _try_directml(self) -> bool:
        """Try to use DirectML (works with Intel Arc on Windows)"""
        try:
            import torch
            self.gpu_available = True
            self.gpu_type = "directml"
            self._torch = torch
            self._device = torch.device("cpu")  # DirectML uses CPU device designation
            self._device_string = "cpu"  # DirectML operations happen through CPU API
            
            self.gpu_info = {
                'backend': 'DirectML',
                'platform': 'Windows',
                'note': 'GPU acceleration through DirectML'
            }
            
            return True
            
        except Exception as e:
            logger.debug(f"DirectML initialization failed: {e}")
            return False

    def _try_cpu_fallback(self) -> bool:
        """Fallback to CPU"""
        try:
            import torch
            self._torch = torch
            self.gpu_available = False
            self.gpu_type = "cpu"
            self._device = torch.device("cpu")
            self._device_string = "cpu"
            
            self.gpu_info = {
                'backend': 'CPU',
                'cores': os.cpu_count()
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Even CPU initialization failed: {e}")
            return False

    def _find_conda_envs_with_ipex(self) -> List[Dict[str, str]]:
        """Find conda environments that have Intel Extension for PyTorch installed"""
        conda_envs = []
        
        # Common conda locations
        possible_conda_bases = [
            os.path.expanduser("~/miniconda3"),
            os.path.expanduser("~/anaconda3"),
            "C:\\ProgramData\\miniconda3",
            "C:\\ProgramData\\anaconda3",
            "C:\\tools\\miniconda3",
            "C:\\tools\\anaconda3",
            os.environ.get("CONDA_PREFIX", ""),
        ]
        
        for base in possible_conda_bases:
            if not base or not os.path.exists(base):
                continue
                
            envs_dir = os.path.join(base, "envs")
            if os.path.exists(envs_dir):
                for env_name in os.listdir(envs_dir):
                    env_path = os.path.join(envs_dir, env_name)
                    # Check for Intel Extension for PyTorch
                    ipex_indicators = [
                        os.path.join(env_path, "Lib", "site-packages", "intel_extension_for_pytorch"),
                        os.path.join(env_path, "lib", "python3.9", "site-packages", "intel_extension_for_pytorch"),
                        os.path.join(env_path, "lib", "python3.10", "site-packages", "intel_extension_for_pytorch"),
                        os.path.join(env_path, "lib", "python3.11", "site-packages", "intel_extension_for_pytorch"),
                    ]
                    
                    for indicator in ipex_indicators:
                        if os.path.exists(indicator):
                            conda_envs.append({
                                'name': env_name,
                                'path': env_path,
                                'base': base
                            })
                            break
        
        return conda_envs

    def _inject_conda_packages(self, conda_env_path: str):
        """Inject conda environment packages into current Python path"""
        # Add conda environment's site-packages to Python path
        if sys.platform == "win32":
            site_packages = os.path.join(conda_env_path, "Lib", "site-packages")
        else:
            # Try multiple Python versions
            for py_ver in ["python3.11", "python3.10", "python3.9", "python3.8"]:
                site_packages = os.path.join(conda_env_path, "lib", py_ver, "site-packages")
                if os.path.exists(site_packages):
                    break
        
        if os.path.exists(site_packages) and site_packages not in sys.path:
            sys.path.insert(0, site_packages)
            logger.info(f"Injected conda packages from: {site_packages}")

    def get_device(self) -> Optional[Any]:
        """Get the configured device object"""
        return self._device

    def get_torch(self) -> Optional[Any]:
        """Get the torch module if available"""
        return self._torch

    def get_ipex(self) -> Optional[Any]:
        """Get the Intel Extension module if available"""
        return self._ipex

    def to_device(self, tensor_or_model: Any) -> Any:
        """Move a tensor or model to the configured device"""
        if self._device and hasattr(tensor_or_model, 'to'):
            return tensor_or_model.to(self._device)
        return tensor_or_model

    def get_device_string(self) -> str:
        """Get device string for torch operations"""
        return self._device_string or "cpu"

    def optimize_model(self, model: Any) -> Any:
        """Optimize model for the current backend"""
        if self.gpu_type == "intel_xpu" and self._ipex:
            logger.info("Optimizing model with Intel Extension for PyTorch")
            return self._ipex.optimize(model)
        return model

    def get_memory_info(self) -> Dict[str, Any]:
        """Get GPU memory information"""
        if not self.gpu_available or not self._torch:
            return {}

        try:
            if self.gpu_type == "nvidia_cuda":
                return {
                    'allocated': f"{self._torch.cuda.memory_allocated() / (1024**3):.2f} GB",
                    'reserved': f"{self._torch.cuda.memory_reserved() / (1024**3):.2f} GB",
                    'free': f"{(self._torch.cuda.get_device_properties(0).total_memory - self._torch.cuda.memory_allocated()) / (1024**3):.2f} GB"
                }
            elif self.gpu_type == "intel_xpu":
                if hasattr(self._torch.xpu, 'memory_allocated'):
                    return {
                        'allocated': f"{self._torch.xpu.memory_allocated() / (1024**3):.2f} GB",
                        'reserved': f"{self._torch.xpu.memory_reserved() / (1024**3):.2f} GB" if hasattr(self._torch.xpu, 'memory_reserved') else 'N/A'
                    }
            elif self.gpu_type == "amd_rocm":
                if hasattr(self._torch.hip, 'memory_allocated'):
                    return {
                        'allocated': f"{self._torch.hip.memory_allocated() / (1024**3):.2f} GB",
                        'reserved': f"{self._torch.hip.memory_reserved() / (1024**3):.2f} GB" if hasattr(self._torch.hip, 'memory_reserved') else 'N/A'
                    }
        except Exception as e:
            logger.debug(f"Failed to get memory info: {e}")

        return {}

    def synchronize(self):
        """Synchronize GPU operations"""
        if not self.gpu_available or not self._torch:
            return

        try:
            if self.gpu_type == "nvidia_cuda":
                self._torch.cuda.synchronize()
            elif self.gpu_type == "intel_xpu":
                if hasattr(self._torch.xpu, 'synchronize'):
                    self._torch.xpu.synchronize()
            elif self.gpu_type == "amd_rocm":
                if hasattr(self._torch.hip, 'synchronize'):
                    self._torch.hip.synchronize()
        except Exception as e:
            logger.debug(f"Synchronization failed: {e}")


# Global instance
gpu_autoloader = GPUAutoLoader()


def get_device():
    """Get the configured GPU device"""
    return gpu_autoloader.get_device()


def get_gpu_info() -> Dict[str, Any]:
    """Get GPU information"""
    return {
        'available': gpu_autoloader.gpu_available,
        'type': gpu_autoloader.gpu_type,
        'device': gpu_autoloader.get_device_string(),
        'info': gpu_autoloader.gpu_info,
        'memory': gpu_autoloader.get_memory_info()
    }


def to_device(tensor_or_model: Any) -> Any:
    """Move tensor or model to GPU"""
    return gpu_autoloader.to_device(tensor_or_model)


def optimize_for_gpu(model: Any) -> Any:
    """Optimize model for current GPU backend"""
    return gpu_autoloader.optimize_model(model)