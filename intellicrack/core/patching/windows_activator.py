"""
Windows Activation Module

Provides functionality to manage Windows activation using the MAS (Microsoft Activation Scripts)
approach. This module wraps the WindowsActivator.cmd script functionality in a Python interface.

This module handles various Windows activation methods including:
- HWID activation
- KMS activation  
- Online KMS activation
- Activation status checking

Author: Intellicrack Team
Version: 1.0.0
"""

import os
import subprocess
import tempfile
from enum import Enum
from pathlib import Path
from typing import Dict, List, Tuple

from ...utils.logger import get_logger
from ...utils.system_utils import is_admin

logger = get_logger(__name__)

class ActivationMethod(Enum):
    """Windows activation methods"""
    HWID = "hwid"
    KMS38 = "kms38"
    ONLINE_KMS = "ohook"
    CHECK_ONLY = "check"

class ActivationStatus(Enum):
    """Activation status values"""
    ACTIVATED = "activated"
    NOT_ACTIVATED = "not_activated"
    GRACE_PERIOD = "grace_period"
    UNKNOWN = "unknown"
    ERROR = "error"

class WindowsActivator:
    """
    Windows Activation Manager

    Provides a Python interface to Windows activation functionality
    using the MAS (Microsoft Activation Scripts) approach.
    """

    def __init__(self):
        self.script_path = Path(__file__).parent.parent.parent.parent / "Windows_Patch" / "WindowsActivator.cmd"
        self.temp_dir = Path(tempfile.gettempdir()) / "intellicrack_activation"
        self.temp_dir.mkdir(exist_ok=True)

        if not self.script_path.exists():
            logger.error(f"Windows activator script not found: {self.script_path}")

    def check_prerequisites(self) -> Tuple[bool, List[str]]:
        """
        Check if prerequisites for Windows activation are met

        Returns:
            Tuple of (success, list of issues)
        """
        issues = []

        # Check if script exists
        if not self.script_path.exists():
            issues.append("WindowsActivator.cmd script not found")

        # Check if running on Windows
        if os.name != 'nt':
            issues.append("Windows activation only supported on Windows")

        # Check admin privileges
        if not is_admin():
            issues.append("Administrator privileges required for activation")

        return len(issues) == 0, issues

    def get_activation_status(self) -> Dict[str, str]:
        """
        Get current Windows activation status

        Returns:
            Dictionary with activation information
        """
        try:
            # Use slmgr to check activation status
            result = subprocess.run(
                ['cscript', '//nologo', 'C:\\Windows\\System32\\slmgr.vbs', '/xpr'],
                capture_output=True,
                text=True,
                timeout=30
            )

            status_info = {
                'status': ActivationStatus.UNKNOWN.value,
                'raw_output': result.stdout.strip(),
                'error': result.stderr.strip() if result.stderr else None
            }

            if result.returncode == 0:
                output = result.stdout.lower()
                if 'permanently activated' in output:
                    status_info['status'] = ActivationStatus.ACTIVATED.value
                elif 'grace period' in output:
                    status_info['status'] = ActivationStatus.GRACE_PERIOD.value
                elif 'not activated' in output:
                    status_info['status'] = ActivationStatus.NOT_ACTIVATED.value
            else:
                status_info['status'] = ActivationStatus.ERROR.value

            return status_info

        except Exception as e:
            logger.error(f"Error checking activation status: {e}")
            return {
                'status': ActivationStatus.ERROR.value,
                'error': str(e)
            }

    def activate_windows(self, method: ActivationMethod = ActivationMethod.HWID) -> Dict[str, any]:
        """
        Activate Windows using specified method

        Args:
            method: Activation method to use

        Returns:
            Dictionary with activation result
        """
        prereq_ok, issues = self.check_prerequisites()
        if not prereq_ok:
            return {
                'success': False,
                'error': 'Prerequisites not met',
                'issues': issues
            }

        try:
            # Create command based on method
            if method == ActivationMethod.HWID:
                cmd_args = [str(self.script_path), '/HWID']
            elif method == ActivationMethod.KMS38:
                cmd_args = [str(self.script_path), '/KMS38']
            elif method == ActivationMethod.ONLINE_KMS:
                cmd_args = [str(self.script_path), '/Ohook']
            else:
                return {
                    'success': False,
                    'error': f'Unsupported activation method: {method.value}'
                }

            logger.info(f"Starting Windows activation with method: {method.value}")

            # Run the activation script
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=self.script_path.parent
            )

            success = result.returncode == 0

            activation_result = {
                'success': success,
                'method': method.value,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }

            if success:
                logger.info(f"Windows activation completed successfully with {method.value}")
                # Get updated status
                activation_result['post_activation_status'] = self.get_activation_status()
            else:
                logger.error(f"Windows activation failed with {method.value}: {result.stderr}")

            return activation_result

        except subprocess.TimeoutExpired:
            logger.error("Windows activation timed out")
            return {
                'success': False,
                'error': 'Activation process timed out'
            }
        except Exception as e:
            logger.error(f"Error during Windows activation: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def reset_activation(self) -> Dict[str, any]:
        """
        Reset Windows activation state

        Returns:
            Dictionary with reset result
        """
        try:
            # Reset activation using slmgr
            result = subprocess.run(
                ['cscript', '//nologo', 'C:\\Windows\\System32\\slmgr.vbs', '/rearm'],
                capture_output=True,
                text=True,
                timeout=60
            )

            return {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }

        except Exception as e:
            logger.error(f"Error resetting activation: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_product_key_info(self) -> Dict[str, str]:
        """
        Get information about installed product keys

        Returns:
            Dictionary with product key information
        """
        try:
            result = subprocess.run(
                ['cscript', '//nologo', 'C:\\Windows\\System32\\slmgr.vbs', '/dli'],
                capture_output=True,
                text=True,
                timeout=30
            )

            return {
                'success': result.returncode == 0,
                'product_info': result.stdout.strip(),
                'error': result.stderr.strip() if result.stderr else None
            }

        except Exception as e:
            logger.error(f"Error getting product key info: {e}")
            return {
                'success': False,
                'error': str(e)
            }
            
    def activate_windows_kms(self) -> Dict[str, any]:
        """Activate Windows using KMS method."""
        return self.activate_windows(ActivationMethod.KMS38)
        
    def activate_windows_digital(self) -> Dict[str, any]:
        """Activate Windows using HWID digital method."""
        return self.activate_windows(ActivationMethod.HWID)
        
    def activate_office(self) -> Dict[str, any]:
        """Activate Office (placeholder - would need Office-specific implementation)."""
        return {"error": "Office activation not implemented yet"}


def create_windows_activator() -> WindowsActivator:
    """
    Factory function to create Windows activator instance

    Returns:
        Configured WindowsActivator instance
    """
    return WindowsActivator()


# Convenience functions
def check_windows_activation() -> Dict[str, str]:
    """
    Quick check of Windows activation status

    Returns:
        Dictionary with activation status
    """
    activator = create_windows_activator()
    return activator.get_activation_status()


def activate_windows_hwid() -> Dict[str, any]:
    """
    Activate Windows using HWID method

    Returns:
        Dictionary with activation result
    """
    activator = create_windows_activator()
    return activator.activate_windows(ActivationMethod.HWID)


def activate_windows_kms() -> Dict[str, any]:
    """
    Activate Windows using KMS38 method

    Returns:
        Dictionary with activation result
    """
    activator = create_windows_activator()
    return activator.activate_windows(ActivationMethod.KMS38)
