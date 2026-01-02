"""Production tests for LLM types module.

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

import time

import pytest

from intellicrack.ai.llm_types import LoadingProgress, LoadingState, ProgressCallback


class TestLoadingState:
    """Test LoadingState enum functionality."""

    def test_loading_state_all_states_defined(self) -> None:
        """LoadingState defines all required states for model loading workflow."""
        assert LoadingState.PENDING.value == "pending"
        assert LoadingState.DOWNLOADING.value == "downloading"
        assert LoadingState.INITIALIZING.value == "initializing"
        assert LoadingState.LOADING.value == "loading"
        assert LoadingState.COMPLETED.value == "completed"
        assert LoadingState.FAILED.value == "failed"
        assert LoadingState.CANCELLED.value == "cancelled"

    def test_loading_state_enum_membership(self) -> None:
        """LoadingState values are valid enum members."""
        assert LoadingState.PENDING in LoadingState
        assert LoadingState.DOWNLOADING in LoadingState
        assert LoadingState.INITIALIZING in LoadingState
        assert LoadingState.LOADING in LoadingState
        assert LoadingState.COMPLETED in LoadingState
        assert LoadingState.FAILED in LoadingState
        assert LoadingState.CANCELLED in LoadingState

    def test_loading_state_comparison(self) -> None:
        """LoadingState supports equality comparison."""
        state1 = LoadingState.PENDING
        state2 = LoadingState.PENDING
        state3 = LoadingState.LOADING

        assert state1 == state2
        assert state1 != state3

    def test_loading_state_string_representation(self) -> None:
        """LoadingState provides meaningful string representation."""
        assert str(LoadingState.PENDING) == "LoadingState.PENDING"
        assert LoadingState.DOWNLOADING.value == "downloading"


class TestLoadingProgress:
    """Test LoadingProgress dataclass functionality."""

    def test_loading_progress_creation_minimal(self) -> None:
        """LoadingProgress creates with minimal required fields."""
        progress = LoadingProgress(
            model_id="gpt-4",
            model_name="GPT-4",
            state=LoadingState.DOWNLOADING,
            progress=0.45,
            message="Downloading model weights",
        )

        assert progress.model_id == "gpt-4"
        assert progress.model_name == "GPT-4"
        assert progress.state == LoadingState.DOWNLOADING
        assert progress.progress == 0.45
        assert progress.message == "Downloading model weights"
        assert progress.details is None
        assert progress.timestamp is None

    def test_loading_progress_creation_complete(self) -> None:
        """LoadingProgress creates with all fields including details."""
        details = {
            "downloaded_bytes": 1024000000,
            "total_bytes": 2048000000,
            "download_speed": 5242880,
            "eta_seconds": 195,
        }
        current_time = time.time()

        progress = LoadingProgress(
            model_id="llama-2-70b",
            model_name="Llama 2 70B",
            state=LoadingState.DOWNLOADING,
            progress=0.5,
            message="Downloading: 1.0GB / 2.0GB",
            details=details,
            timestamp=current_time,
        )

        assert progress.model_id == "llama-2-70b"
        assert progress.model_name == "Llama 2 70B"
        assert progress.state == LoadingState.DOWNLOADING
        assert progress.progress == 0.5
        assert progress.details == details
        assert progress.timestamp == current_time

    def test_loading_progress_state_transitions(self) -> None:
        """LoadingProgress tracks state transitions during loading."""
        model_id = "claude-opus"

        progress_pending = LoadingProgress(
            model_id=model_id,
            model_name="Claude Opus",
            state=LoadingState.PENDING,
            progress=0.0,
            message="Queued for loading",
        )

        progress_downloading = LoadingProgress(
            model_id=model_id,
            model_name="Claude Opus",
            state=LoadingState.DOWNLOADING,
            progress=0.3,
            message="Downloading model",
        )

        progress_loading = LoadingProgress(
            model_id=model_id,
            model_name="Claude Opus",
            state=LoadingState.LOADING,
            progress=0.8,
            message="Loading into memory",
        )

        progress_completed = LoadingProgress(
            model_id=model_id,
            model_name="Claude Opus",
            state=LoadingState.COMPLETED,
            progress=1.0,
            message="Model ready",
        )

        assert progress_pending.state == LoadingState.PENDING
        assert progress_downloading.state == LoadingState.DOWNLOADING
        assert progress_loading.state == LoadingState.LOADING
        assert progress_completed.state == LoadingState.COMPLETED

    def test_loading_progress_failure_tracking(self) -> None:
        """LoadingProgress tracks failure state with error details."""
        error_details = {
            "error_type": "NetworkError",
            "error_message": "Connection timeout after 30 seconds",
            "retry_count": 3,
            "last_successful_chunk": 45,
        }

        progress = LoadingProgress(
            model_id="mistral-7b",
            model_name="Mistral 7B",
            state=LoadingState.FAILED,
            progress=0.45,
            message="Download failed: Connection timeout",
            details=error_details,
            timestamp=time.time(),
        )

        assert progress.state == LoadingState.FAILED
        assert progress.details is not None
        assert progress.details["error_type"] == "NetworkError"
        assert progress.details["retry_count"] == 3

    def test_loading_progress_cancellation_tracking(self) -> None:
        """LoadingProgress tracks cancellation state."""
        progress = LoadingProgress(
            model_id="gpt-3.5-turbo",
            model_name="GPT-3.5 Turbo",
            state=LoadingState.CANCELLED,
            progress=0.62,
            message="User cancelled download",
            details={"cancelled_at": 0.62, "cleanup_complete": True},
        )

        assert progress.state == LoadingState.CANCELLED
        assert progress.details is not None
        assert progress.details["cleanup_complete"] is True

    def test_loading_progress_percentage_boundaries(self) -> None:
        """LoadingProgress handles progress percentage boundaries."""
        progress_start = LoadingProgress(
            model_id="test",
            model_name="Test",
            state=LoadingState.PENDING,
            progress=0.0,
            message="Starting",
        )

        progress_half = LoadingProgress(
            model_id="test",
            model_name="Test",
            state=LoadingState.LOADING,
            progress=0.5,
            message="Halfway",
        )

        progress_complete = LoadingProgress(
            model_id="test",
            model_name="Test",
            state=LoadingState.COMPLETED,
            progress=1.0,
            message="Done",
        )

        assert progress_start.progress == 0.0
        assert progress_half.progress == 0.5
        assert progress_complete.progress == 1.0

    def test_loading_progress_detailed_metrics(self) -> None:
        """LoadingProgress stores detailed loading metrics."""
        metrics = {
            "memory_allocated_mb": 8192,
            "memory_peak_mb": 9500,
            "gpu_utilization_percent": 85,
            "loading_time_seconds": 45.3,
            "quantization_applied": "4-bit",
            "shards_loaded": 8,
            "total_shards": 8,
        }

        progress = LoadingProgress(
            model_id="llama-2-70b-gguf",
            model_name="Llama 2 70B GGUF",
            state=LoadingState.COMPLETED,
            progress=1.0,
            message="Model loaded successfully",
            details=metrics,
            timestamp=time.time(),
        )

        assert progress.details is not None
        assert progress.details["memory_allocated_mb"] == 8192
        assert progress.details["gpu_utilization_percent"] == 85
        assert progress.details["quantization_applied"] == "4-bit"

    def test_loading_progress_timestamp_tracking(self) -> None:
        """LoadingProgress timestamps track when progress updates occur."""
        time1 = time.time()
        progress1 = LoadingProgress(
            model_id="test",
            model_name="Test",
            state=LoadingState.DOWNLOADING,
            progress=0.25,
            message="Progress 1",
            timestamp=time1,
        )

        time.sleep(0.01)

        time2 = time.time()
        progress2 = LoadingProgress(
            model_id="test",
            model_name="Test",
            state=LoadingState.DOWNLOADING,
            progress=0.50,
            message="Progress 2",
            timestamp=time2,
        )

        assert progress1.timestamp is not None
        assert progress2.timestamp is not None
        assert progress2.timestamp > progress1.timestamp

    def test_loading_progress_initialization_details(self) -> None:
        """LoadingProgress tracks initialization phase details."""
        init_details = {
            "config_loaded": True,
            "tokenizer_loaded": True,
            "weights_mapped": True,
            "gpu_memory_reserved": 6144,
            "attention_implementation": "flash_attention_2",
        }

        progress = LoadingProgress(
            model_id="mixtral-8x7b",
            model_name="Mixtral 8x7B",
            state=LoadingState.INITIALIZING,
            progress=0.75,
            message="Initializing model components",
            details=init_details,
        )

        assert progress.state == LoadingState.INITIALIZING
        assert progress.details is not None
        assert progress.details["tokenizer_loaded"] is True
        assert progress.details["attention_implementation"] == "flash_attention_2"


class ConcreteProgressCallback(ProgressCallback):
    """Concrete implementation of ProgressCallback for testing."""

    def __init__(self) -> None:
        self.progress_updates: list[LoadingProgress] = []
        self.completions: list[tuple[str, bool, str | None]] = []

    def on_progress(self, progress: LoadingProgress) -> None:
        """Record progress update."""
        self.progress_updates.append(progress)

    def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
        """Record completion."""
        self.completions.append((model_id, success, error))


class TestProgressCallback:
    """Test ProgressCallback abstract base class."""

    def test_progress_callback_implementation(self) -> None:
        """ProgressCallback concrete implementation receives progress updates."""
        callback = ConcreteProgressCallback()

        progress = LoadingProgress(
            model_id="test-model",
            model_name="Test Model",
            state=LoadingState.DOWNLOADING,
            progress=0.5,
            message="Downloading",
        )

        callback.on_progress(progress)

        assert len(callback.progress_updates) == 1
        assert callback.progress_updates[0].model_id == "test-model"
        assert callback.progress_updates[0].progress == 0.5

    def test_progress_callback_completion_success(self) -> None:
        """ProgressCallback receives successful completion notification."""
        callback = ConcreteProgressCallback()

        callback.on_completed("gpt-4", success=True, error=None)

        assert len(callback.completions) == 1
        assert callback.completions[0][0] == "gpt-4"
        assert callback.completions[0][1] is True
        assert callback.completions[0][2] is None

    def test_progress_callback_completion_failure(self) -> None:
        """ProgressCallback receives failure notification with error."""
        callback = ConcreteProgressCallback()

        error_msg = "Failed to download model: Network timeout"
        callback.on_completed("llama-2", success=False, error=error_msg)

        assert len(callback.completions) == 1
        assert callback.completions[0][0] == "llama-2"
        assert callback.completions[0][1] is False
        assert callback.completions[0][2] == error_msg

    def test_progress_callback_multiple_updates(self) -> None:
        """ProgressCallback handles multiple sequential progress updates."""
        callback = ConcreteProgressCallback()

        for i in range(5):
            progress = LoadingProgress(
                model_id="model-id",
                model_name="Model",
                state=LoadingState.DOWNLOADING,
                progress=i * 0.2,
                message=f"Progress {i * 20}%",
            )
            callback.on_progress(progress)

        assert len(callback.progress_updates) == 5
        assert callback.progress_updates[0].progress == 0.0
        assert callback.progress_updates[4].progress == 0.8

    def test_progress_callback_state_transition_tracking(self) -> None:
        """ProgressCallback tracks complete model loading state transitions."""
        callback = ConcreteProgressCallback()

        states_and_progress = [
            (LoadingState.PENDING, 0.0, "Queued"),
            (LoadingState.DOWNLOADING, 0.3, "Downloading"),
            (LoadingState.INITIALIZING, 0.7, "Initializing"),
            (LoadingState.LOADING, 0.9, "Loading"),
            (LoadingState.COMPLETED, 1.0, "Complete"),
        ]

        for state, prog, msg in states_and_progress:
            progress = LoadingProgress(
                model_id="claude-3",
                model_name="Claude 3",
                state=state,
                progress=prog,
                message=msg,
            )
            callback.on_progress(progress)

        callback.on_completed("claude-3", success=True)

        assert len(callback.progress_updates) == 5
        assert callback.progress_updates[0].state == LoadingState.PENDING
        assert callback.progress_updates[-1].state == LoadingState.COMPLETED
        assert callback.completions[0][1] is True

    def test_progress_callback_error_recovery_workflow(self) -> None:
        """ProgressCallback tracks error and retry workflow."""
        callback = ConcreteProgressCallback()

        callback.on_progress(
            LoadingProgress(
                "model", "Model", LoadingState.DOWNLOADING, 0.3, "Downloading"
            )
        )

        callback.on_progress(
            LoadingProgress(
                "model",
                "Model",
                LoadingState.FAILED,
                0.3,
                "Download failed",
                details={"error": "Timeout"},
            )
        )

        callback.on_progress(
            LoadingProgress(
                "model", "Model", LoadingState.DOWNLOADING, 0.4, "Retrying download"
            )
        )

        callback.on_progress(
            LoadingProgress(
                "model", "Model", LoadingState.COMPLETED, 1.0, "Download complete"
            )
        )

        callback.on_completed("model", success=True)

        assert len(callback.progress_updates) == 4
        assert callback.progress_updates[1].state == LoadingState.FAILED
        assert callback.progress_updates[3].state == LoadingState.COMPLETED
        assert callback.completions[0][1] is True
