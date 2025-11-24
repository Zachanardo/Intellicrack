"""Simple test runner for enhanced training interface tests.

Runs tests directly without pytest to validate functionality.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["QT_LOGGING_RULES"] = "*.debug=false"
os.environ["INTELLICRACK_TESTING"] = "1"


def run_tests() -> None:
    """Run all tests for enhanced training interface."""
    try:
        from intellicrack.ai.enhanced_training_interface import (
            TrainingConfiguration,
            TrainingThread,
            ModelMetrics,
        )

        print("✓ Successfully imported enhanced_training_interface")

        print("\n=== Running TestTrainingConfiguration ===")
        config = TrainingConfiguration()
        assert config.model_name == "intellicrack_model"
        assert config.learning_rate == 0.001
        assert config.batch_size == 32
        assert config.epochs == 100
        print("✓ test_default_configuration_values PASSED")

        config2 = TrainingConfiguration(
            model_name="custom_model",
            learning_rate=0.0001,
            batch_size=64,
        )
        assert config2.model_name == "custom_model"
        assert config2.learning_rate == 0.0001
        assert config2.batch_size == 64
        print("✓ test_custom_configuration_values PASSED")

        print("\n=== Running TestModelMetrics ===")
        metrics = ModelMetrics()
        assert metrics.accuracy == 0.0
        assert metrics.loss == 0.0
        print("✓ test_default_metrics_initialization PASSED")

        metrics2 = ModelMetrics(accuracy=0.95, loss=0.15, epoch=10)
        assert metrics2.accuracy == 0.95
        assert metrics2.loss == 0.15
        assert metrics2.epoch == 10
        print("✓ test_custom_metrics_values PASSED")

        print("\n=== Running TestTrainingThread ===")
        config3 = TrainingConfiguration(epochs=10, batch_size=16)
        thread = TrainingThread(config3)
        assert thread.config == config3
        assert thread.should_stop is False
        assert thread.paused is False
        print("✓ test_training_thread_initialization PASSED")

        print("\n=== Running Real Training Test ===")
        config4 = TrainingConfiguration(
            epochs=2,
            batch_size=4,
            learning_rate=0.01,
            use_early_stopping=False,
        )
        thread2 = TrainingThread(config4)

        metrics_captured = []

        def capture_metrics(m):
            metrics_captured.append(m.copy())

        thread2.metrics_updated.connect(capture_metrics)
        thread2.run()

        assert len(metrics_captured) == 2, f"Expected 2 metrics, got {len(metrics_captured)}"
        for m in metrics_captured:
            assert "accuracy" in m
            assert "loss" in m
            assert 0.0 <= m["accuracy"] <= 1.0
            assert m["loss"] >= 0.0
        print("✓ test_real_training_with_synthetic_data PASSED")

        print("\n=== Running Forward Pass Test ===")
        features = [0.5, 0.3, 0.8, 0.2, 0.6, 0.4, 0.7]
        prediction = thread2._forward_pass(features, epoch=0, validation=True)
        assert isinstance(prediction, float)
        assert 0.0 <= prediction <= 1.0
        print("✓ test_forward_pass_with_real_features PASSED")

        print("\n=== Running Model Weight Initialization Test ===")
        thread2._initialize_model_weights(10)
        assert hasattr(thread2, "_weights")
        assert "W1" in thread2._weights
        assert "b1" in thread2._weights
        assert hasattr(thread2, "_adam_params")
        print("✓ test_model_weight_initialization PASSED")

        print("\n=== Running Loss Computation Test ===")
        loss_correct = thread2._compute_loss(0.95, 1)
        loss_wrong = thread2._compute_loss(0.95, 0)
        assert loss_correct < loss_wrong
        print("✓ test_loss_computation_binary_crossentropy PASSED")

        print("\n=== Running Prediction Accuracy Test ===")
        assert thread2._is_correct_prediction(0.8, 1) is True
        assert thread2._is_correct_prediction(0.3, 0) is True
        assert thread2._is_correct_prediction(0.8, 0) is False
        print("✓ test_prediction_accuracy_check PASSED")

        print("\n=== Running Learning Rate Scheduling Test ===")
        config5 = TrainingConfiguration(
            learning_rate=0.001,
            epochs=100,
            warmup_epochs=5,
            lr_schedule="cosine",
        )
        thread3 = TrainingThread(config5)
        lr_0 = thread3._get_learning_rate(0)
        lr_50 = thread3._get_learning_rate(50)
        lr_90 = thread3._get_learning_rate(90)
        assert lr_90 < lr_50, "Learning rate should decay"
        print("✓ test_learning_rate_scheduling_cosine PASSED")

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
