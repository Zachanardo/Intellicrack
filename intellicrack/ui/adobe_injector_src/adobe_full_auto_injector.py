"""Adobe automatic injector interface for the main UI."""

import os
import time

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.utils.logger import logger

from ...utils.constants import ADOBE_PROCESSES

"""
Inject Frida script into the specified Adobe process.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


try:
    from intellicrack.handlers.frida_handler import HAS_FRIDA, frida
except ImportError as e:
    logger.error("Import error in adobe_full_auto_injector: %s", e)
    HAS_FRIDA = False
    frida = None


FRIDA_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "adobe_bypass_frida.js")

# Using shared ADOBE_PROCESSES from constants module

injected = set()


def inject(target_name):
    """Inject Frida script into the specified Adobe process.

    Args:
        target_name: Name of the process to inject into

    Attempts to attach to the process, load the Frida script, and mark
    the process as injected. Fails silently to maintain stealth.

    """
    if not HAS_FRIDA:
        return  # Frida not available, skip injection

    try:
        session = frida.attach(target_name)
        with open(FRIDA_SCRIPT_PATH, encoding="utf-8") as f:
            script = session.create_script(f.read())
            script.load()
        injected.add(target_name)
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in adobe_full_auto_injector: %s", e)
        # Silent fail to remain stealthy


def get_running_adobe_apps():
    """Get list of currently running Adobe applications that haven't been injected yet.

    Returns:
        list: Names of Adobe processes that are running but not yet injected

    Scans running processes and filters for Adobe applications listed in
    ADOBE_PROCESSES that haven't already been marked as injected.

    """
    running = []
    for _proc in psutil.process_iter(attrs=["name"]):
        try:
            pname = _proc.info["name"]
            if pname in ADOBE_PROCESSES and pname not in injected:
                running.append(pname)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error("Error in adobe_full_auto_injector: %s", e)
            continue
    return running


def monitor_loop():
    """Continuously monitor for Adobe applications and inject them as they appear.

    Runs an infinite loop that checks for new Adobe processes every 2 seconds
    and injects the Frida script into any newly detected processes.
    """
    while True:
        active = get_running_adobe_apps()
        for _proc in active:
            inject(_proc)
        time.sleep(2)


if __name__ == "__main__":
    monitor_loop()
