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

from abc import ABC, abstractmethod
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

    model_id: str
    model_name: str
    state: LoadingState
    progress: float
    message: str
    details: dict[str, Any] | None = None
    timestamp: float | None = None


class ProgressCallback(ABC):
    """Abstract base class for progress callbacks during model loading."""

    @abstractmethod
    def on_progress(self, progress: LoadingProgress) -> None:
        """Called when loading progress is updated.

        Args:
            progress: The current loading progress information.
        """
        pass

    @abstractmethod
    def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
        """Called when loading is completed.

        Args:
            model_id: The unique identifier of the model that finished loading.
            success: Whether the loading operation was successful.
            error: Optional error message if loading failed.
        """
        pass
