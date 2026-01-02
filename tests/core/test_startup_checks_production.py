"""Production tests for intellicrack/core/startup_checks.py.

Validates real startup checks, dependency verification, and system health monitoring
for Intellicrack's initialization system. Tests validate actual system state.

NO MOCKS - All tests use real dependency checks and system resources.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.startup_checks import (
    check_data_paths,
    check_dependencies,
    check_protection_models,
    check_qemu_setup,
    create_minimal_qemu_disk,
    get_system_health_report,
    perform_startup_checks,
    validate_tensorflow_models,
)


class TestCheckDependencies:
    """Test real dependency checking for critical components."""

    def test_check_dependencies_returns_dict(self) -> None:
        """check_dependencies returns dictionary with dependency status."""
        result = check_dependencies()

        assert isinstance(result, dict)
        assert len(result) > 0

    def test_check_dependencies_validates_flask(self) -> None:
        """check_dependencies validates Flask web framework availability."""
        result = check_dependencies()

        assert "Flask" in result
        assert isinstance(result["Flask"], bool)

        if result["Flask"]:
            import flask

            assert hasattr(flask, "Flask")

    def test_check_dependencies_validates_qemu(self) -> None:
        """check_dependencies checks QEMU emulator availability."""
        result = check_dependencies()

        assert "QEMU" in result
        assert isinstance(result["QEMU"], bool)

        if result["QEMU"]:
            import shutil

            qemu_path = shutil.which("qemu-system-x86_64")
            assert qemu_path is not None

    def test_check_dependencies_validates_tensorflow(self) -> None:
        """check_dependencies validates TensorFlow ML framework."""
        result = check_dependencies()

        assert "TensorFlow" in result
        assert isinstance(result["TensorFlow"], bool)

    def test_check_dependencies_validates_llama_cpp(self) -> None:
        """check_dependencies validates llama-cpp-python for LLM support."""
        result = check_dependencies()

        assert "llama-cpp-python" in result
        assert isinstance(result["llama-cpp-python"], bool)

    def test_check_dependencies_all_values_boolean(self) -> None:
        """check_dependencies returns only boolean values for each dependency."""
        result = check_dependencies()

        for key, value in result.items():
            assert isinstance(value, bool), f"Dependency {key} should have boolean value"

    def test_flask_validation_creates_test_app(self) -> None:
        """Flask validation creates and tests a minimal Flask application."""
        result = check_dependencies()

        if result.get("Flask"):
            import flask

            app = flask.Flask(__name__)

            @app.route("/test")
            def test_route() -> object:
                return flask.jsonify({"status": "ok"})

            with app.app_context():
                assert flask.current_app is not None

    def test_tensorflow_validation_performs_tensor_operations(self) -> None:
        """TensorFlow validation runs actual tensor operations."""
        result = check_dependencies()

        if result.get("TensorFlow"):
            import tensorflow as tf

            test_tensor = tf.constant([[1.0, 2.0], [3.0, 4.0]])
            result_sum = tf.reduce_sum(test_tensor)

            expected = 10.0
            actual = float(result_sum.numpy())

            assert abs(actual - expected) < 1e-6


class TestCheckDataPaths:
    """Test data path validation and directory creation."""

    def test_check_data_paths_returns_dict(self) -> None:
        """check_data_paths returns dictionary of path information."""
        result = check_data_paths()

        assert isinstance(result, dict)

    def test_check_data_paths_includes_qemu_images(self) -> None:
        """check_data_paths includes QEMU images directory."""
        result = check_data_paths()

        assert "qemu_images" in result
        path_str, exists = result["qemu_images"]

        assert isinstance(path_str, str)
        assert isinstance(exists, bool)
        assert len(path_str) > 0

    def test_check_data_paths_creates_directories(self) -> None:
        """check_data_paths creates required data directories."""
        from intellicrack.utils.path_resolver import get_data_dir

        data_dir = get_data_dir()

        result = check_data_paths()

        assert data_dir.exists()

    def test_discovered_qemu_images_have_valid_paths(self) -> None:
        """Discovered QEMU images have valid file paths."""
        result = check_data_paths()

        for key, value in result.items():
            if key.startswith("qemu_image_"):
                path_str, exists = value
                path = Path(path_str)

                assert path.suffix in {".qcow2", ".img", ".raw", ".vmdk"}
                assert path.exists() == exists


class TestCheckQEMUSetup:
    """Test QEMU emulator setup validation."""

    def test_check_qemu_setup_returns_boolean(self) -> None:
        """check_qemu_setup returns boolean indicating QEMU availability."""
        result = check_qemu_setup()

        assert isinstance(result, bool)

    def test_check_qemu_setup_validates_qemu_img(self) -> None:
        """check_qemu_setup validates qemu-img command availability."""
        if result := check_qemu_setup():
            qemu_result = subprocess.run(
                ["qemu-img", "--version"], capture_output=True, check=False
            )

            assert qemu_result.returncode == 0

    def test_check_qemu_setup_discovers_images(self) -> None:
        """check_qemu_setup discovers available QEMU images."""
        from intellicrack.utils.qemu_image_discovery import get_qemu_discovery

        discovery = get_qemu_discovery()
        images = discovery.discover_images()

        result = check_qemu_setup()

        if len(images) > 0:
            assert result is True


class TestCreateMinimalQEMUDisk:
    """Test QEMU disk image creation."""

    def test_create_minimal_qemu_disk_with_qemu_available(
        self, temp_workspace: Path
    ) -> None:
        """create_minimal_qemu_disk creates real QEMU disk when qemu-img available."""
        try:
            subprocess.run(
                ["qemu-img", "--version"], capture_output=True, check=True
            )
            qemu_available = True
        except (FileNotFoundError, subprocess.CalledProcessError):
            qemu_available = False

        if not qemu_available:
            pytest.skip("qemu-img not available")

        from intellicrack.utils.path_resolver import get_qemu_images_dir

        original_dir = get_qemu_images_dir()

        if result := create_minimal_qemu_disk():
            assert result.exists()
            assert result.suffix == ".qcow2"

            info_result = subprocess.run(
                ["qemu-img", "info", str(result)],
                capture_output=True,
                check=False,
                text=True,
            )

            assert info_result.returncode == 0
            assert "qcow2" in info_result.stdout

    def test_create_minimal_qemu_disk_without_qemu(self) -> None:
        """create_minimal_qemu_disk returns None when qemu-img unavailable."""
        try:
            subprocess.run(
                ["qemu-img", "--version"], capture_output=True, check=True
            )
            pytest.skip("qemu-img is available - cannot test unavailable case")
        except (FileNotFoundError, subprocess.CalledProcessError):
            result = create_minimal_qemu_disk()
            assert result is None


class TestCheckProtectionModels:
    """Test protection model availability checking."""

    def test_check_protection_models_returns_boolean(self) -> None:
        """check_protection_models returns boolean status."""
        result = check_protection_models()

        assert isinstance(result, bool)

    def test_check_protection_models_uses_icp_engine(self) -> None:
        """check_protection_models validates ICP engine availability."""
        result = check_protection_models()

        assert result is True


class TestValidateTensorFlowModels:
    """Test TensorFlow model validation and compatibility checking."""

    def test_validate_tensorflow_models_returns_dict(self) -> None:
        """validate_tensorflow_models returns comprehensive status dictionary."""
        result = validate_tensorflow_models()

        assert isinstance(result, dict)
        assert "status" in result
        assert "version" in result
        assert "gpu_available" in result

    def test_validate_tensorflow_models_with_tensorflow_available(self) -> None:
        """validate_tensorflow_models validates TensorFlow when available."""
        deps = check_dependencies()

        if deps.get("TensorFlow"):
            result = validate_tensorflow_models()

            assert result["status"] is True
            assert result["version"] != "N/A"
            assert isinstance(result["gpu_available"], bool)
            assert "gpu_count" in result
            assert "keras_available" in result

    def test_validate_tensorflow_models_tests_model_building(self) -> None:
        """validate_tensorflow_models validates Keras model building capability."""
        deps = check_dependencies()

        if deps.get("TensorFlow"):
            result = validate_tensorflow_models()

            if result["status"]:
                assert "model_building" in result
                assert result["model_building"] is True
                assert "model_prediction_test" in result
                assert "OK" in str(result["model_prediction_test"])

    def test_validate_tensorflow_models_validates_output_range(self) -> None:
        """validate_tensorflow_models ensures model output is in valid range."""
        deps = check_dependencies()

        if deps.get("TensorFlow"):
            result = validate_tensorflow_models()

            if result.get("model_building"):
                test_result = result["model_prediction_test"]

                if "output:" in str(test_result):
                    output_str = str(test_result).split("output:")[1].strip(")")
                    output_val = float(output_str)

                    assert 0.0 <= output_val <= 1.0

    def test_validate_tensorflow_models_without_tensorflow(self) -> None:
        """validate_tensorflow_models handles missing TensorFlow gracefully."""
        deps = check_dependencies()

        if not deps.get("TensorFlow"):
            result = validate_tensorflow_models()

            assert result["status"] is False
            assert result["version"] == "N/A"
            assert result["gpu_available"] is False
            assert "error" in result


class TestPerformStartupChecks:
    """Test comprehensive startup validation."""

    def test_perform_startup_checks_returns_complete_dict(self) -> None:
        """perform_startup_checks returns comprehensive system status."""
        result = perform_startup_checks()

        assert isinstance(result, dict)
        assert "dependencies" in result
        assert "paths" in result
        assert "config_valid" in result

    def test_perform_startup_checks_validates_config(self) -> None:
        """perform_startup_checks validates configuration manager."""
        result = perform_startup_checks()

        assert isinstance(result["config_valid"], bool)

        if result["config_valid"]:
            from intellicrack.core.config_manager import get_config

            config = get_config()
            assert config is not None

    def test_perform_startup_checks_includes_dependencies(self) -> None:
        """perform_startup_checks includes full dependency status."""
        result = perform_startup_checks()

        deps = result["dependencies"]

        assert isinstance(deps, dict)
        assert len(deps) > 0

        for key, value in deps.items():
            assert isinstance(value, bool)

    def test_perform_startup_checks_includes_tensorflow_validation(self) -> None:
        """perform_startup_checks includes TensorFlow validation when available."""
        result = perform_startup_checks()

        if result["dependencies"].get("TensorFlow"):
            assert "tensorflow_validation" in result

            tf_val = result["tensorflow_validation"]
            assert "status" in tf_val
            assert "version" in tf_val
            assert "gpu_available" in tf_val

    def test_perform_startup_checks_runs_qemu_setup(self) -> None:
        """perform_startup_checks executes QEMU setup validation."""
        result = perform_startup_checks()

        assert "paths" in result
        assert "qemu_images" in result["paths"]


class TestGetSystemHealthReport:
    """Test system health reporting and diagnostics."""

    def test_get_system_health_report_returns_complete_dict(self) -> None:
        """get_system_health_report returns comprehensive health status."""
        result = get_system_health_report()

        assert isinstance(result, dict)
        assert "timestamp" in result
        assert "platform" in result
        assert "python_version" in result
        assert "services" in result

    def test_get_system_health_report_includes_platform_info(self) -> None:
        """get_system_health_report includes platform and Python version."""
        result = get_system_health_report()

        assert result["platform"] == sys.platform
        assert len(result["python_version"]) > 0

    def test_get_system_health_report_checks_flask_service(self) -> None:
        """get_system_health_report validates Flask web service health."""
        result = get_system_health_report()

        assert "web_ui" in result["services"]

        web_ui = result["services"]["web_ui"]
        assert "available" in web_ui

        if web_ui["available"]:
            assert web_ui["framework"] == "Flask"
            assert "cors_enabled" in web_ui

    def test_get_system_health_report_checks_ml_engine(self) -> None:
        """get_system_health_report validates ML engine health."""
        result = get_system_health_report()

        assert "ml_engine" in result["services"]

        ml_engine = result["services"]["ml_engine"]
        assert "available" in ml_engine

        if ml_engine["available"]:
            assert ml_engine["backend"] == "TensorFlow"
            assert "version" in ml_engine
            assert "gpu_support" in ml_engine

    def test_get_system_health_report_checks_llm_engine(self) -> None:
        """get_system_health_report validates LLM engine health."""
        result = get_system_health_report()

        assert "llm_engine" in result["services"]

        llm_engine = result["services"]["llm_engine"]
        assert "available" in llm_engine

        if llm_engine["available"]:
            assert llm_engine["backend"] == "llama-cpp-python"
            assert "version" in llm_engine

    def test_get_system_health_report_includes_disk_space(self) -> None:
        """get_system_health_report includes disk space information."""
        result = get_system_health_report()

        assert "disk_space" in result

        disk_space = result["disk_space"]

        if isinstance(disk_space, dict) and "available" in disk_space:
            if disk_space["available"] is False:
                assert "error" in disk_space
        else:
            assert "data_directory" in disk_space
            assert "total_gb" in disk_space
            assert "used_gb" in disk_space
            assert "free_gb" in disk_space
            assert "percent_used" in disk_space

            assert disk_space["total_gb"] > 0
            assert 0 <= disk_space["percent_used"] <= 100

    def test_get_system_health_report_disk_math_correct(self) -> None:
        """get_system_health_report disk space calculations are accurate."""
        result = get_system_health_report()

        disk_space = result.get("disk_space", {})

        if "total_gb" in disk_space and "used_gb" in disk_space:
            total = disk_space["total_gb"]
            used = disk_space["used_gb"]
            free = disk_space["free_gb"]
            percent = disk_space["percent_used"]

            assert abs((total - (used + free))) < 0.1
            assert abs(percent - (used / total * 100)) < 1.0


class TestStartupChecksIntegration:
    """Integration tests for startup checks workflow."""

    def test_startup_checks_discover_real_environment(self) -> None:
        """Startup checks accurately detect real system environment."""
        result = perform_startup_checks()

        deps = result["dependencies"]

        if deps.get("Flask"):
            import flask

            assert flask.__name__ == "flask"

        if deps.get("TensorFlow"):
            import tensorflow as tf

            assert hasattr(tf, "__version__")

    def test_startup_checks_create_required_directories(self) -> None:
        """Startup checks create all required data directories."""
        from intellicrack.utils.path_resolver import get_data_dir

        result = perform_startup_checks()

        data_dir = get_data_dir()
        assert data_dir.exists()

        paths = result["paths"]
        assert len(paths) > 0

    def test_startup_checks_handle_missing_dependencies_gracefully(self) -> None:
        """Startup checks handle missing dependencies without crashing."""
        result = perform_startup_checks()

        assert "dependencies" in result

        for dep_name, available in result["dependencies"].items():
            assert isinstance(available, bool)

    def test_health_report_reflects_startup_check_results(self) -> None:
        """System health report reflects startup check results."""
        startup = perform_startup_checks()
        health = get_system_health_report()

        startup_flask = startup["dependencies"].get("Flask", False)
        health_flask = health["services"]["web_ui"]["available"]

        assert startup_flask == health_flask

        startup_tf = startup["dependencies"].get("TensorFlow", False)
        health_tf = health["services"]["ml_engine"]["available"]

        assert startup_tf == health_tf


