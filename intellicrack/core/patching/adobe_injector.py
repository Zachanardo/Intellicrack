"""
Adobe License Bypass Module

Provides automated injection capabilities for Adobe Creative Suite applications
to bypass license validation checks using Frida dynamic instrumentation.

This module monitors running Adobe processes and automatically injects
license bypass code via Frida JavaScript hooks.

Author: Intellicrack Team
Version: 1.0.0
"""

import time
from typing import List, Set

try:
    import frida
    import psutil
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    psutil = None
    frida = None

from ...utils.logger import get_logger

logger = get_logger(__name__)

class AdobeInjector:
    """
    Adobe License Bypass Injector

    Monitors and injects Frida scripts into running Adobe Creative Suite
    applications to bypass license validation mechanisms.
    """

    ADOBE_PROCESSES = [
        "Photoshop.exe",
        "Illustrator.exe",
        "PremierePro.exe",
        "AfterFX.exe",
        "MediaEncoder.exe",
        "InDesign.exe",
        "Animate.exe",
        "Audition.exe",
        "CharacterAnimator.exe",
        "Dreamweaver.exe",
        "Lightroom.exe",
        "LightroomClassic.exe",
        "Substance 3D Designer.exe",
        "Substance 3D Painter.exe",
        "Substance 3D Sampler.exe",
        "Substance 3D Stager.exe",
        "Substance 3D Modeler.exe"
    ]

    FRIDA_SCRIPT = '''
// adobe_bypass.js
console.log("[*] Adobe license patch injected.");

const targets = [
    "IsActivated",
    "IsLicenseValid", 
    "GetLicenseStatus",
    "GetSerialNumber",
    "CheckSubscription"
];

for (let name of targets) {
    try {
        let addr = Module.findExportByName("AdobeLM.dll", name);
        if (addr) {
            Interceptor.replace(addr, new NativeCallback(function () {
                console.log("[✓] Spoofed: " + name);
                return 1;
            }, 'int', []));
        }
    } catch (e) {
        console.log("[-] Failed to patch: " + name);
    }
}
'''

    def __init__(self):
        self.injected: Set[str] = set()
        self.running = False

        if not DEPENDENCIES_AVAILABLE:
            logger.warning("Adobe injector dependencies not available (psutil, frida)")

    def inject_process(self, target_name: str) -> bool:
        """
        Inject Frida script into target Adobe process

        Args:
            target_name: Name of the target process

        Returns:
            True if injection successful, False otherwise
        """
        if not DEPENDENCIES_AVAILABLE:
            logger.error("Cannot inject - dependencies not available")
            return False

        try:
            session = frida.attach(target_name)
            script = session.create_script(self.FRIDA_SCRIPT)
            script.load()
            self.injected.add(target_name)
            logger.info("Successfully injected into %s", target_name)
            return True
        except Exception as e:
            logger.debug("Failed to inject into %s: %s", target_name, e)
            return False

    def get_running_adobe_processes(self) -> List[str]:
        """
        Get list of running Adobe processes that haven't been injected

        Returns:
            List of Adobe process names currently running
        """
        if not DEPENDENCIES_AVAILABLE:
            return []

        running = []
        try:
            for proc in psutil.process_iter(attrs=['name']):
                try:
                    pname = proc.info['name']
                    if pname in self.ADOBE_PROCESSES and pname not in self.injected:
                        running.append(pname)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error("Error scanning processes: %s", e)

        return running

    def monitor_and_inject(self, interval: float = 2.0) -> None:
        """
        Continuously monitor for Adobe processes and inject them

        Args:
            interval: Sleep interval between scans in seconds
        """
        if not DEPENDENCIES_AVAILABLE:
            logger.error("Cannot monitor - dependencies not available")
            return

        self.running = True
        logger.info("Starting Adobe process monitoring...")

        try:
            while self.running:
                active_processes = self.get_running_adobe_processes()
                for proc_name in active_processes:
                    self.inject_process(proc_name)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Adobe monitoring stopped by user")
        finally:
            self.running = False

    def stop_monitoring(self) -> None:
        """
        Stop the monitoring loop
        """
        self.running = False
        logger.info("Adobe monitoring stopped")

    def get_injection_status(self) -> dict:
        """
        Get current injection status

        Returns:
            Dictionary with injection statistics
        """
        return {
            'injected_processes': list(self.injected),
            'running_adobe_processes': self.get_running_adobe_processes(),
            'dependencies_available': DEPENDENCIES_AVAILABLE,
            'monitoring_active': self.running
        }


def create_adobe_injector() -> AdobeInjector:
    """
    Factory function to create Adobe injector instance

    Returns:
        Configured AdobeInjector instance
    """
    return AdobeInjector()


# Convenience functions for direct usage
def inject_running_adobe_processes() -> int:
    """
    One-shot injection of all currently running Adobe processes

    Returns:
        Number of processes successfully injected
    """
    injector = create_adobe_injector()
    processes = injector.get_running_adobe_processes()

    success_count = 0
    for proc_name in processes:
        if injector.inject_process(proc_name):
            success_count += 1

    return success_count


def start_adobe_monitoring(interval: float = 2.0) -> AdobeInjector:
    """
    Start continuous Adobe process monitoring

    Args:
        interval: Sleep interval between scans

    Returns:
        AdobeInjector instance for control
    """
    injector = create_adobe_injector()
    injector.monitor_and_inject(interval)
    return injector
