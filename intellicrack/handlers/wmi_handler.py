"""WMI handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import warnings

from intellicrack.utils.logger import logger


HAS_WMI = False
WMI = None

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=SyntaxWarning)
    try:
        import wmi as _wmi

        HAS_WMI = True
        WMI = _wmi.WMI
        logger.debug("WMI successfully loaded")
    except ImportError as e:
        logger.warning("WMI not available (Windows-only library): %s", e)

        class FallbackWMI:
            """Fallback WMI class for non-Windows platforms."""

            def __init__(self) -> None:
                logger.error("WMI fallback activated due to import failure")

            def __getattr__(self, name: str) -> object:
                logger.debug("WMI fallback: Accessing %s", name)
                return lambda *args, **kwargs: (
                    logger.debug("WMI fallback call args: %s kwargs: %s", args, kwargs) or []
                )

        WMI = FallbackWMI

__all__ = ["HAS_WMI", "WMI", "wmi"]
wmi = type("wmi", (), {"WMI": WMI})()
