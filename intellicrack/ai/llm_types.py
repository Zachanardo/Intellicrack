"""Shared types and dataclasses for LLM backends and background loading.

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

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any


class LoadingState(Enum):
    """States for background model loading."""

    PENDING = "pending"
    DOWNLOADING = "downloading"
    INITIALIZING = "initializing"
    LOADING = "loading"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class LoadingProgress:
    """Progress information for model loading."""

    state: LoadingState
    progress: float  # 0.0 to 1.0
    message: str
    details: dict[str, Any] | None = None


# Type alias for progress callbacks
ProgressCallback = Callable[[LoadingProgress], None]
