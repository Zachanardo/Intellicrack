"""UI widgets for Intellicrack.

Copyright (C) 2025 Zachary Flint

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

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .embedded_terminal_widget import (
        EmbeddedTerminalWidget as EmbeddedTerminalWidgetType,
    )
    from .terminal_session_widget import (
        TerminalSessionWidget as TerminalSessionWidgetType,
    )

logger: logging.Logger = logging.getLogger(__name__)

EmbeddedTerminalWidget: type[EmbeddedTerminalWidgetType] | None
TerminalSessionWidget: type[TerminalSessionWidgetType] | None

try:
    from .embedded_terminal_widget import EmbeddedTerminalWidget
except ImportError as e:
    logger.warning("Failed to import embedded_terminal_widget: %s", e)
    EmbeddedTerminalWidget = None

try:
    from .terminal_session_widget import TerminalSessionWidget
except ImportError as e:
    logger.warning("Failed to import terminal_session_widget: %s", e)
    TerminalSessionWidget = None

__all__: list[str] = [
    "EmbeddedTerminalWidget",
    "TerminalSessionWidget",
]

_locals: dict[str, Any] = {
    "EmbeddedTerminalWidget": EmbeddedTerminalWidget,
    "TerminalSessionWidget": TerminalSessionWidget,
}

__all__ = [item for item in __all__ if _locals.get(item) is not None]
