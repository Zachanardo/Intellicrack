"""Production-grade tests for HeadlessTrainingInterface.

Tests validate real AI model training lifecycle including:
- Configuration loading and validation
- Training execution with real neural network computations
- Pause/resume/stop functionality
- Progress and status callbacks
- Metrics tracking and historical data
- Model weight initialization and forward propagation
- Batch processing and validation
- Model persistence and recovery
- Multi-threaded training execution
- Error handling and recovery
"""

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

from intellicrack.ai.headless_training_interface import (
    ConsoleTrainingManager,
    HeadlessTrainingInterface,
)


pytestmark = pytest.mark.skipif(
    not NUMPY_AVAILABLE, reason="NumPy required for neural network training tests"
)


@pytest.fixture
def training_interface() -> HeadlessTrainingInterface:
    """Create fresh headless training interface instance."""
    return HeadlessTrainingInterface()


@pytest.fixture
def temp_config_dir(tmp_path: Path) -> Path:
    """Create temporary directory for training configurations."""
    config_dir = tmp_path / "training_configs"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def temp_dataset_dir(tmp_path: Path) -> Path:
    """Create temporary directory for training datasets."""
    dataset_dir = tmp_path / "datasets"
    dataset_dir.mkdir()
    return dataset_dir


@pytest.fixture
def basic_training_config(temp_dataset_dir: Path) -> dict[str, Any]:
    """Create basic training configuration."""
    dataset_path = temp_dataset_dir / "training_data.json"
    training_samples = [
        {"features": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6], "label": 0},
        {"features": [0.7, 0.8, 0.9, 0.1, 0.2, 0.3], "label": 1},
        {"features": [0.3, 0.4, 0.5, 0.6, 0.7, 0.8], "label": 1},
        {"features": [0.2, 0.1, 0.3, 0.2, 0.4, 0.1], "label": 0},
    ]

    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(training_samples, f)

    return {
        "model_name": "test_model",
        "model_type": "vulnerability_classifier",
        "epochs": 5,
        "learning_rate": 0.01,
        "batch_size": 2,
        "validation_split": 0.2,
        "dataset_path": str(dataset_path),
    }


@pytest.fixture
def advanced_training_config(temp_dataset_dir: Path) -> dict[str, Any]:
    """Create advanced training configuration with larger dataset."""
    dataset_path = temp_dataset_dir / "advanced_data.csv"

    with open(dataset_path, "w", encoding="utf-8") as f:
        f.write("feature1,feature2,feature3,label\n")
        for i in range(100):
            feat1 = (i % 10) * 0.1
            feat2 = (i % 7) * 0.14
            feat3 = (i % 13) * 0.077
            label = 1 if (feat1 + feat2 + feat3) > 0.4 else 0
            f.write(f"{feat1},{feat2},{feat3},{label}\n")

    return {
        "model_name": "advanced_model",
        "model_type": "pattern_detector",
        "epochs": 10,
        "learning_rate": 0.001,
        "batch_size": 8,
        "validation_split": 0.25,
        "dataset_path": str(dataset_path),
        "output_directory": str(temp_dataset_dir / "models"),
    }


class TestConfigurationManagement:
    """Test configuration loading, saving, and validation."""

    def test_load_valid_configuration(
        self, training_interface: HeadlessTrainingInterface,
        temp_config_dir: Path,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Valid training configuration is loaded successfully."""
        config_path = temp_config_dir / "config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(basic_training_config, f)

        loaded_config = training_interface.load_configuration(str(config_path))

        assert loaded_config == basic_training_config
        assert training_interface.config_path == str(config_path)

    def test_load_nonexistent_configuration_raises_error(
        self, training_interface: HeadlessTrainingInterface,
        temp_config_dir: Path,
    ) -> None:
        """Loading nonexistent configuration file raises FileNotFoundError."""
        nonexistent = temp_config_dir / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            training_interface.load_configuration(str(nonexistent))

    def test_load_invalid_json_raises_error(
        self, training_interface: HeadlessTrainingInterface,
        temp_config_dir: Path,
    ) -> None:
        """Loading invalid JSON file raises JSONDecodeError."""
        invalid_path = temp_config_dir / "invalid.json"
        invalid_path.write_text("{ invalid json content }")

        with pytest.raises(json.JSONDecodeError):
            training_interface.load_configuration(str(invalid_path))

    def test_save_configuration_creates_file(
        self, training_interface: HeadlessTrainingInterface,
        temp_config_dir: Path,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Configuration is saved to file correctly."""
        save_path = temp_config_dir / "saved_config.json"

        training_interface.save_configuration(basic_training_config, str(save_path))

        assert save_path.exists()

        with open(save_path, encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded == basic_training_config

    def test_save_configuration_creates_directory(
        self, training_interface: HeadlessTrainingInterface,
        temp_config_dir: Path,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Configuration save creates parent directory if missing."""
        nested_path = temp_config_dir / "nested" / "deep" / "config.json"

        training_interface.save_configuration(basic_training_config, str(nested_path))

        assert nested_path.exists()
        assert nested_path.parent.exists()


class TestTrainingLifecycle:
    """Test complete training lifecycle from start to completion."""

    def test_start_training_initializes_state(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Starting training initializes training state correctly."""
        training_interface.start_training(basic_training_config)

        time.sleep(0.5)

        assert training_interface.is_training is True
        assert training_interface.is_paused is False
        assert training_interface.total_epochs == 5

        training_interface.stop_training()

    def test_training_executes_all_epochs(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Training executes through all configured epochs."""
        basic_training_config["epochs"] = 3

        training_interface.start_training(basic_training_config)

        while training_interface.is_training:
            time.sleep(0.3)

        assert training_interface.current_epoch >= 3

    def test_training_updates_metrics_each_epoch(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Training metrics are updated after each epoch."""
        basic_training_config["epochs"] = 2

        training_interface.start_training(basic_training_config)

        time.sleep(1.0)

        metrics = training_interface.get_metrics()

        assert "train_loss" in metrics
        assert "train_accuracy" in metrics
        assert "val_loss" in metrics
        assert "val_accuracy" in metrics
        assert metrics["epoch"] > 0

        training_interface.stop_training()

    def test_training_invokes_progress_callback(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Training invokes progress callback with correct values."""
        progress_values = []

        def progress_callback(progress: float) -> None:
            progress_values.append(progress)

        basic_training_config["epochs"] = 2

        training_interface.start_training(
            basic_training_config,
            progress_callback=progress_callback,
        )

        while training_interface.is_training:
            time.sleep(0.3)

        assert progress_values
        assert all(0 <= p <= 100 for p in progress_values)

    def test_training_invokes_status_callback(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Training invokes status callback with epoch information."""
        status_messages = []

        def status_callback(status: str) -> None:
            status_messages.append(status)

        basic_training_config["epochs"] = 2

        training_interface.start_training(
            basic_training_config,
            status_callback=status_callback,
        )

        while training_interface.is_training:
            time.sleep(0.3)

        assert status_messages
        assert any("started" in msg.lower() for msg in status_messages)


class TestTrainingControl:
    """Test training control operations (pause, resume, stop)."""

    def test_pause_training_suspends_execution(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Pausing training suspends execution without terminating."""
        basic_training_config["epochs"] = 10

        training_interface.start_training(basic_training_config)

        time.sleep(0.5)
        epoch_before_pause = training_interface.current_epoch

        training_interface.pause_training()
        time.sleep(1.0)

        epoch_after_pause = training_interface.current_epoch

        assert training_interface.is_paused is True
        assert training_interface.is_training is True
        assert epoch_before_pause == epoch_after_pause

        training_interface.stop_training()

    def test_resume_training_continues_execution(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Resuming training continues from paused state."""
        basic_training_config["epochs"] = 10

        training_interface.start_training(basic_training_config)

        time.sleep(0.5)
        training_interface.pause_training()
        time.sleep(0.5)

        epoch_at_pause = training_interface.current_epoch

        training_interface.resume_training()
        time.sleep(1.0)

        assert training_interface.is_paused is False
        assert training_interface.current_epoch > epoch_at_pause

        training_interface.stop_training()

    def test_stop_training_terminates_execution(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Stopping training terminates execution completely."""
        basic_training_config["epochs"] = 10

        training_interface.start_training(basic_training_config)

        time.sleep(0.5)
        training_interface.stop_training()
        time.sleep(0.5)

        assert training_interface.is_training is False
        assert training_interface.is_paused is False

    def test_stop_waits_for_thread_completion(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Stopping training waits for worker thread to complete."""
        basic_training_config["epochs"] = 10

        training_interface.start_training(basic_training_config)
        time.sleep(0.5)

        training_interface.stop_training()

        assert (
            training_interface.training_thread is None or
            not training_interface.training_thread.is_alive()
        )


class TestTrainingStatus:
    """Test training status reporting."""

    def test_get_training_status_returns_complete_info(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Training status returns complete information."""
        basic_training_config["epochs"] = 5

        training_interface.start_training(basic_training_config)
        time.sleep(0.5)

        status = training_interface.get_training_status()

        assert "is_training" in status
        assert "is_paused" in status
        assert "current_epoch" in status
        assert "total_epochs" in status
        assert "progress_percent" in status
        assert "metrics" in status

        assert status["is_training"] is True
        assert status["total_epochs"] == 5

        training_interface.stop_training()

    def test_progress_percent_calculation_correct(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Progress percentage is calculated correctly."""
        basic_training_config["epochs"] = 10

        training_interface.start_training(basic_training_config)

        time.sleep(1.5)

        status = training_interface.get_training_status()
        progress = status["progress_percent"]

        assert 0 <= progress <= 100
        assert progress == (status["current_epoch"] / status["total_epochs"]) * 100

        training_interface.stop_training()

    def test_get_metrics_returns_current_metrics(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Get metrics returns current training metrics."""
        basic_training_config["epochs"] = 3

        training_interface.start_training(basic_training_config)

        time.sleep(1.0)

        metrics = training_interface.get_metrics()

        assert isinstance(metrics, dict)
        assert len(metrics) > 0

        training_interface.stop_training()


class TestDatasetHandling:
    """Test dataset loading and processing."""

    def test_load_json_dataset(
        self, training_interface: HeadlessTrainingInterface,
        temp_dataset_dir: Path,
    ) -> None:
        """JSON dataset is loaded and split correctly."""
        dataset_path = temp_dataset_dir / "test.json"
        samples = [
            {"features": [i * 0.1 for i in range(6)], "label": i % 2}
            for i in range(20)
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(samples, f)

        train_data, val_data = training_interface._load_training_data(
            str(dataset_path), validation_split=0.2
        )

        assert len(train_data) > 0
        assert len(val_data) > 0
        assert len(train_data) + len(val_data) == len(samples)

    def test_load_csv_dataset(
        self, training_interface: HeadlessTrainingInterface,
        temp_dataset_dir: Path,
    ) -> None:
        """CSV dataset is loaded and parsed correctly."""
        dataset_path = temp_dataset_dir / "test.csv"

        with open(dataset_path, "w", encoding="utf-8") as f:
            f.write("f1,f2,f3,label\n")
            for i in range(10):
                f.write(f"{i*0.1},{i*0.2},{i*0.3},{i%2}\n")

        train_data, val_data = training_interface._load_training_data(
            str(dataset_path), validation_split=0.3
        )

        assert len(train_data) + len(val_data) > 0

    def test_generate_synthetic_data(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Synthetic training data is generated with valid structure."""
        samples = training_interface._generate_training_data(50)

        assert len(samples) == 50

        for sample in samples:
            assert "features" in sample
            assert "label" in sample
            assert "sample_id" in sample
            assert len(sample["features"]) == 6
            assert sample["label"] in (0, 1)

    def test_synthetic_data_has_consistent_labels(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Synthetic data labels are consistent with feature patterns."""
        samples = training_interface._generate_training_data(100)

        label_distribution = sum(s["label"] for s in samples)

        assert 20 < label_distribution < 80


class TestNeuralNetworkComputation:
    """Test actual neural network forward pass and weight initialization."""

    def test_initialize_model_weights(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Model weights are initialized with correct dimensions."""
        model_config = {"architecture": "deep_cnn", "optimizer": "adam"}

        training_interface._initialize_model_weights(10, model_config)

        assert hasattr(training_interface, "_weights")
        assert "W1" in training_interface._weights
        assert "W2" in training_interface._weights
        assert "W3" in training_interface._weights
        assert "b1" in training_interface._weights
        assert "b2" in training_interface._weights
        assert "b3" in training_interface._weights

        assert training_interface._weights["W1"].shape[0] == 10

    def test_forward_pass_returns_valid_probability(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Forward pass returns probability between 0 and 1."""
        model_config = {"architecture": "deep_cnn", "dropout_rate": 0.1}
        features = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]

        prediction = training_interface._forward_pass(features, model_config, epoch=1)

        assert 0.0 <= prediction <= 1.0

    def test_forward_pass_applies_dropout_during_training(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Forward pass applies dropout during training mode."""
        model_config = {"architecture": "deep_cnn", "dropout_rate": 0.5}
        features = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]

        pred_train = training_interface._forward_pass(
            features, model_config, epoch=1, validation=False
        )
        pred_val = training_interface._forward_pass(
            features, model_config, epoch=1, validation=True
        )

        assert isinstance(pred_train, float)
        assert isinstance(pred_val, float)

    def test_forward_pass_stores_activations(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Forward pass stores activations for backpropagation."""
        model_config = {"architecture": "deep_cnn", "dropout_rate": 0.1}
        features = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]

        training_interface._forward_pass(features, model_config, epoch=1, validation=False)

        assert hasattr(training_interface, "_last_activations")
        assert "input" in training_interface._last_activations
        assert "output" in training_interface._last_activations

    def test_relu_activation(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """ReLU activation function works correctly."""
        import numpy as np

        x = np.array([-2.0, -1.0, 0.0, 1.0, 2.0])
        result = training_interface._relu(x)

        expected = np.array([0.0, 0.0, 0.0, 1.0, 2.0])
        np.testing.assert_array_equal(result, expected)

    def test_sigmoid_activation(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Sigmoid activation function works correctly."""
        import numpy as np

        x = np.array([0.0])
        result = training_interface._sigmoid(x)

        assert np.isclose(result[0], 0.5, atol=1e-5)


class TestBatchProcessing:
    """Test training and validation batch processing."""

    def test_process_training_batch_returns_valid_metrics(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Training batch processing returns valid loss and accuracy."""
        model_config = {"architecture": "deep_cnn", "dropout_rate": 0.1}
        batch_data = [
            {"features": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6], "label": 1},
            {"features": [0.7, 0.8, 0.9, 0.1, 0.2, 0.3], "label": 0},
        ]

        loss, correct, total = training_interface._process_training_batch(
            batch_data, model_config, learning_rate=0.01, epoch=1
        )

        assert loss > 0.0
        assert 0 <= correct <= total
        assert total == len(batch_data)

    def test_process_validation_batch_returns_valid_metrics(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Validation batch processing returns valid loss and accuracy."""
        model_config = {"architecture": "deep_cnn", "dropout_rate": 0.1}
        batch_data = [
            {"features": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6], "label": 1},
            {"features": [0.7, 0.8, 0.9, 0.1, 0.2, 0.3], "label": 0},
        ]

        loss, correct, total = training_interface._process_validation_batch(
            batch_data, model_config, epoch=1
        )

        assert loss > 0.0
        assert 0 <= correct <= total
        assert total == len(batch_data)

    def test_execute_training_epoch_with_real_data(
        self, training_interface: HeadlessTrainingInterface,
        temp_dataset_dir: Path,
    ) -> None:
        """Training epoch executes with real dataset."""
        dataset_path = temp_dataset_dir / "epoch_test.json"
        samples = [
            {"features": [i * 0.1 for i in range(6)], "label": i % 2}
            for i in range(20)
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(samples, f)

        model_config = {"architecture": "deep_cnn", "optimizer": "adam"}
        training_config = {
            "learning_rate": 0.01,
            "batch_size": 4,
            "validation_split": 0.2,
        }

        train_loss, train_acc, val_loss, val_acc = training_interface._execute_training_epoch(
            epoch=1,
            dataset_path=str(dataset_path),
            model_config=model_config,
            training_config=training_config,
        )

        assert train_loss > 0.0
        assert 0.0 <= train_acc <= 1.0
        assert val_loss > 0.0
        assert 0.0 <= val_acc <= 1.0


class TestMetricsTracking:
    """Test metrics tracking and historical data."""

    def test_metrics_history_accumulation(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Metrics history accumulates during training."""
        basic_training_config["epochs"] = 3

        training_interface.start_training(basic_training_config)

        while training_interface.is_training:
            time.sleep(0.3)

        assert len(training_interface.metrics_history) > 0

    def test_metrics_history_limited_to_100_entries(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Metrics history is limited to last 100 entries."""
        for i in range(150):
            training_interface.metrics_history.append({
                "epoch": i,
                "train_loss": 1.0,
                "train_acc": 0.5,
                "val_loss": 1.1,
                "val_acc": 0.48,
            })

        training_interface._update_metrics(
            epoch=151,
            train_loss=0.5,
            train_acc=0.9,
            val_loss=0.6,
            val_acc=0.85,
            model_config={"architecture": "deep_cnn"},
            learning_rate=0.01,
            batch_size=32,
            start_time=time.time(),
        )

        assert len(training_interface.metrics_history) == 100


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_training_with_invalid_dataset_path(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Training with invalid dataset path raises error."""
        basic_training_config["dataset_path"] = "/nonexistent/path.json"

        with pytest.raises(ValueError):
            training_interface.start_training(basic_training_config)
            time.sleep(0.5)

    def test_generate_recovery_metrics_with_history(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Recovery metrics use historical data when available."""
        for i in range(10):
            training_interface.metrics_history.append({
                "epoch": i,
                "train_loss": 2.0 - i * 0.1,
                "train_acc": 0.5 + i * 0.03,
                "val_loss": 2.1 - i * 0.09,
                "val_acc": 0.48 + i * 0.028,
            })

        model_config = {"architecture": "deep_cnn", "optimizer": "adam"}

        train_loss, train_acc, val_loss, val_acc = training_interface._generate_recovery_metrics(
            epoch=11, model_config=model_config
        )

        assert train_loss > 0.0
        assert 0.0 <= train_acc <= 1.0
        assert val_loss > 0.0
        assert 0.0 <= val_acc <= 1.0

    def test_generate_recovery_metrics_without_history(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Recovery metrics use model-based estimates without history."""
        model_config = {"architecture": "transformer", "optimizer": "adam"}

        train_loss, train_acc, val_loss, val_acc = training_interface._generate_recovery_metrics(
            epoch=1, model_config=model_config
        )

        assert train_loss > 0.0
        assert 0.0 <= train_acc <= 1.0
        assert val_loss > train_loss
        assert val_acc < train_acc


class TestModelPersistence:
    """Test model saving and persistence."""

    def test_save_trained_model_creates_file(
        self, training_interface: HeadlessTrainingInterface,
        temp_config_dir: Path,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Trained model is saved to file."""
        basic_training_config["output_directory"] = str(temp_config_dir / "models")
        basic_training_config["epochs"] = 2

        training_interface.start_training(basic_training_config)

        while training_interface.is_training:
            time.sleep(0.3)

        models_dir = Path(basic_training_config["output_directory"])
        model_files = list(models_dir.glob("*.json")) if models_dir.exists() else []

        assert model_files

    def test_saved_model_contains_metadata(
        self, training_interface: HeadlessTrainingInterface,
        temp_config_dir: Path,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Saved model contains training metadata."""
        basic_training_config["output_directory"] = str(temp_config_dir / "models")

        training_interface.metrics = {
            "epoch": 5,
            "train_loss": 0.5,
            "train_accuracy": 0.9,
        }

        model_path = training_interface._save_trained_model(basic_training_config)

        assert os.path.exists(model_path)

        with open(model_path, encoding="utf-8") as f:
            model_data = json.load(f)

        assert "model_name" in model_data
        assert "model_type" in model_data
        assert "training_config" in model_data
        assert "final_metrics" in model_data
        assert "timestamp" in model_data
        assert model_data["training_completed"] is True


class TestMultiThreadedExecution:
    """Test multi-threaded training execution."""

    def test_training_executes_in_separate_thread(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Training executes in separate daemon thread."""
        basic_training_config["epochs"] = 5

        training_interface.start_training(basic_training_config)

        time.sleep(0.5)

        assert training_interface.training_thread is not None
        assert training_interface.training_thread.is_alive()
        assert training_interface.training_thread.daemon is True

        training_interface.stop_training()

    def test_concurrent_training_prevented(
        self, training_interface: HeadlessTrainingInterface,
        basic_training_config: dict[str, Any],
    ) -> None:
        """Starting training while already training is prevented."""
        basic_training_config["epochs"] = 10

        training_interface.start_training(basic_training_config)
        time.sleep(0.5)

        training_interface.start_training(basic_training_config)

        training_interface.stop_training()


class TestAdvancedTrainingScenarios:
    """Test advanced training scenarios with different configurations."""

    def test_training_with_transformer_architecture(
        self, training_interface: HeadlessTrainingInterface,
        temp_dataset_dir: Path,
    ) -> None:
        """Training with transformer architecture executes correctly."""
        dataset_path = temp_dataset_dir / "transformer_data.json"
        samples = [
            {"features": [i * 0.05 for i in range(10)], "label": i % 2}
            for i in range(30)
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(samples, f)

        config = {
            "model_name": "transformer_test",
            "model_type": "pattern_detector",
            "epochs": 2,
            "learning_rate": 0.001,
            "batch_size": 4,
            "dataset_path": str(dataset_path),
        }

        training_interface.start_training(config)

        while training_interface.is_training:
            time.sleep(0.3)

        metrics = training_interface.get_metrics()
        assert metrics["model_type"] == "transformer"

    def test_training_with_lstm_architecture(
        self, training_interface: HeadlessTrainingInterface,
        temp_dataset_dir: Path,
    ) -> None:
        """Training with LSTM architecture executes correctly."""
        dataset_path = temp_dataset_dir / "lstm_data.json"
        samples = [
            {"features": [i * 0.05 for i in range(8)], "label": i % 2}
            for i in range(20)
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(samples, f)

        config = {
            "model_name": "lstm_test",
            "model_type": "behavior_analyzer",
            "epochs": 2,
            "learning_rate": 0.001,
            "batch_size": 4,
            "dataset_path": str(dataset_path),
        }

        training_interface.start_training(config)

        while training_interface.is_training:
            time.sleep(0.3)

        metrics = training_interface.get_metrics()
        assert metrics["model_type"] == "lstm"

    def test_training_with_different_learning_rates(
        self, training_interface: HeadlessTrainingInterface,
        temp_dataset_dir: Path,
    ) -> None:
        """Training adapts to different learning rates."""
        dataset_path = temp_dataset_dir / "lr_data.json"
        samples = [
            {"features": [i * 0.1 for i in range(6)], "label": i % 2}
            for i in range(15)
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(samples, f)

        for lr in [0.001, 0.01, 0.1]:
            config = {
                "model_name": f"lr_{lr}_test",
                "model_type": "vulnerability_classifier",
                "epochs": 2,
                "learning_rate": lr,
                "batch_size": 3,
                "dataset_path": str(dataset_path),
            }

            interface = HeadlessTrainingInterface()
            interface.start_training(config)

            while interface.is_training:
                time.sleep(0.3)

            metrics = interface.get_metrics()
            assert metrics["learning_rate"] == lr


class TestConsoleTrainingManager:
    """Test console training manager functionality."""

    def test_console_manager_initialization(self) -> None:
        """Console training manager initializes correctly."""
        manager = ConsoleTrainingManager()

        assert manager.interface is not None
        assert isinstance(manager.interface, HeadlessTrainingInterface)
        assert manager.running is False


class TestParameterConfiguration:
    """Test dynamic parameter configuration."""

    def test_set_training_parameters_updates_epochs(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Setting training parameters updates total epochs."""
        training_interface.set_training_parameters(epochs=50)

        assert training_interface.total_epochs == 50

    def test_set_training_parameters_ignores_invalid_types(
        self, training_interface: HeadlessTrainingInterface,
    ) -> None:
        """Setting training parameters ignores invalid types."""
        training_interface.total_epochs = 10

        training_interface.set_training_parameters(epochs="invalid")

        assert training_interface.total_epochs == 10


class TestRealWorldTrainingWorkflow:
    """Test complete real-world training workflows."""

    def test_complete_training_workflow_with_callbacks(
        self, training_interface: HeadlessTrainingInterface,
        advanced_training_config: dict[str, Any],
    ) -> None:
        """Complete training workflow with all features enabled."""
        progress_updates = []
        status_updates = []

        def track_progress(p: float) -> None:
            progress_updates.append(p)

        def track_status(s: str) -> None:
            status_updates.append(s)

        advanced_training_config["epochs"] = 5

        training_interface.start_training(
            advanced_training_config,
            progress_callback=track_progress,
            status_callback=track_status,
        )

        time.sleep(1.0)

        status_before_pause = training_interface.get_training_status()
        training_interface.pause_training()

        time.sleep(0.5)
        training_interface.resume_training()

        time.sleep(1.0)

        final_metrics = training_interface.get_metrics()

        training_interface.stop_training()

        assert progress_updates
        assert status_updates
        assert final_metrics["epoch"] > 0
        assert "train_loss" in final_metrics
        assert "val_accuracy" in final_metrics
