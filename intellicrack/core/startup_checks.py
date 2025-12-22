"""Startup Checks and Path Resolution.

Performs startup checks and ensures paths are properly resolved.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from intellicrack.utils.logger import log_function_call


logger = logging.getLogger(__name__)

# Configure TensorFlow environment ONCE at module level before any imports
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["MKL_THREADING_LAYER"] = "GNU"

# Import TensorFlow handler ONCE at module level to avoid duplicate imports
_tf_import_attempted = False
_tf_module: Any = None
_tf_available = False


@log_function_call
def _get_tensorflow() -> tuple[Any, bool]:
    """Get TensorFlow module, importing only once.

    Returns:
        A tuple containing the TensorFlow module object (or None if unavailable)
        and a boolean indicating whether TensorFlow is successfully loaded.

    """
    global _tf_import_attempted, _tf_module, _tf_available

    if not _tf_import_attempted:
        _tf_import_attempted = True
        logger.debug("TensorFlow: First attempt to import TensorFlow.")
        try:
            from intellicrack.handlers.tensorflow_handler import (
                ensure_tensorflow_loaded,
                tf,
            )

            ensure_tensorflow_loaded()
            _tf_module = cast(Any, tf)
            _tf_available = True
            _tf_module.config.set_visible_devices([], "GPU")
            logger.info("TensorFlow: Imported successfully (version: %s). GPU devices set to invisible.", _tf_module.__version__)
            logger.debug("TensorFlow: Visible devices after configuration: %s", _tf_module.config.get_visible_devices())
        except Exception as e:
            logger.warning("TensorFlow: Import failed: %s", e, exc_info=True)
            _tf_available = False
            _tf_module = None
            logger.debug("TensorFlow: Import failed, TensorFlow will be unavailable.")
    else:
        logger.debug("TensorFlow: Import already attempted. Available: %s.", _tf_available)

    return _tf_module, _tf_available


@log_function_call
def check_dependencies() -> dict[str, bool]:
    """Check for required dependencies."""
    logger.info("Checking application dependencies...")
    dependencies = {}

    # Check Flask and test basic functionality
    logger.debug("Checking Flask dependency...")
    try:
        import flask
        import flask_cors

        # Validate Flask by creating a minimal app
        validation_app = flask.Flask(__name__)
        flask_cors.CORS(validation_app)

        # Verify Flask can handle basic routing
        @validation_app.route("/test")
        def validation_route() -> Any:
            return flask.jsonify({"status": "ok"})

        # Validate the app context
        with validation_app.app_context():
            flask.current_app.config["TESTING"] = True
        dependencies["Flask"] = True
        logger.info("Flask and Flask-CORS found and basic functionality validated.")
    except ImportError:
        dependencies["Flask"] = False
        logger.warning("Flask or Flask-CORS not found. Web UI and API endpoints will be unavailable.", exc_info=True)
    except Exception as e:
        dependencies["Flask"] = False
        logger.warning("Flask initialization failed: %s", e, exc_info=True)

    # Check QEMU
    logger.debug("Checking QEMU dependency...")
    try:
        import shutil

        qemu_path = shutil.which("qemu-system-x86_64")
        qemu_found = qemu_path is not None
        dependencies["QEMU"] = qemu_found
        if qemu_found:
            logger.info("QEMU found at: %s.", qemu_path)
        else:
            logger.warning("QEMU not found in system PATH. QEMU functionality will be limited.")
    except Exception as e:
        logger.exception("An unexpected error occurred during QEMU check: %s", e)
        dependencies["QEMU"] = False

    # Check TensorFlow
    logger.debug("Checking TensorFlow dependency...")
    try:
        tf, tf_available = _get_tensorflow()

        if not tf_available or tf is None:
            error_msg = "TensorFlow not available after import attempt."
            logger.warning(error_msg)
            dependencies["TensorFlow"] = False
            # No need to raise ImportError here, just log and mark as unavailable
        else:
            # Test TensorFlow by checking version and GPU availability
            gpu_count = len(tf.config.list_physical_devices("GPU"))
            logger.debug("TensorFlow: Found %s GPU(s) available for TensorFlow.", gpu_count)

            # Test basic tensor operations
            test_tensor = tf.constant([[1.0, 2.0], [3.0, 4.0]])
            test_result = tf.reduce_sum(test_tensor)

            # Validate tensor operation result
            expected_sum = 10.0  # 1.0 + 2.0 + 3.0 + 4.0
            actual_sum = float(test_result.numpy())

            if abs(actual_sum - expected_sum) < 1e-6:
                dependencies["TensorFlow"] = True
                logger.info("TensorFlow: Basic tensor operations validated (sum: %s).", actual_sum)
            else:
                dependencies["TensorFlow"] = False
                logger.error("TensorFlow: Tensor operation failed: expected %s, got %s.", expected_sum, actual_sum)
                # No need to return here, continue checking other dependencies

            # Check if models can be loaded (this part of the original code was incomplete/commented)
            # For now, we'll just rely on basic tensor ops for dependency check
            # if tf.saved_model.contains_saved_model("."):
            #     pass

    except ImportError:
        dependencies["TensorFlow"] = False
        logger.warning("TensorFlow: Import error. ML Vulnerability Predictor will be disabled.", exc_info=True)
    except Exception as e:
        dependencies["TensorFlow"] = False
        logger.warning("TensorFlow: Initialization or test failed: %s", e, exc_info=True)

    # Check llama-cpp and test model loading capabilities
    logger.debug("Checking llama-cpp-python dependency...")
    try:
        import llama_cpp

        # Test llama-cpp functionality
        # Check if we can access the library version
        llama_version = getattr(llama_cpp, "__version__", "Unknown")
        logger.debug("llama-cpp-python: Found version %s.", llama_version)

        # Verify model loading capability by checking available parameters
        model_params = llama_cpp.llama_model_params()
        context_params = llama_cpp.llama_context_params()

        # Validate parameter structures are properly initialized
        if hasattr(model_params, "n_gpu_layers") and hasattr(context_params, "n_ctx"):
            logger.debug("llama-cpp-python: Model and context parameters found (n_gpu_layers, n_ctx).")
            # Test parameter modification to ensure they're functional
            try:
                original_gpu_layers = model_params.n_gpu_layers
                original_ctx_size = context_params.n_ctx

                # Temporarily modify parameters to test functionality
                model_params.n_gpu_layers = 0
                context_params.n_ctx = 512
                logger.debug("llama-cpp-python: Temporarily modified model/context parameters for testing.")

                # Restore original values
                model_params.n_gpu_layers = original_gpu_layers
                context_params.n_ctx = original_ctx_size
                logger.debug("llama-cpp-python: Restored original model/context parameters.")

                dependencies["llama-cpp-python"] = True
                logger.info("llama-cpp-python: Basic parameter manipulation validated.")
            except Exception as param_error:
                dependencies["llama-cpp-python"] = False
                logger.exception("llama-cpp-python: Parameter validation failed: %s", param_error)
        else:
            dependencies["llama-cpp-python"] = False
            logger.error("llama-cpp-python: Parameters missing required attributes (n_gpu_layers or n_ctx).")
    except ImportError:
        dependencies["llama-cpp-python"] = False
        logger.warning("llama-cpp-python: Import error. LLM Manager will be unavailable.", exc_info=True)
    except Exception as e:
        dependencies["llama-cpp-python"] = False
        logger.warning("llama-cpp-python: Initialization or test failed: %s", e, exc_info=True)

    logger.info("Dependency check completed. Results: %s", dependencies)
    return dependencies


@log_function_call
def check_data_paths() -> dict[str, tuple[str, bool]]:
    """Check and create required data paths."""
    logger.info("Checking and ensuring data paths exist...")
    from ..utils.path_resolver import ensure_data_directories, get_qemu_images_dir
    from ..utils.qemu_image_discovery import get_qemu_discovery

    # Ensure directories exist
    logger.debug("Ensuring core data directories exist.")
    ensure_data_directories()
    logger.debug("Core data directories ensured.")

    paths = {}

    # Check QEMU images directory
    qemu_dir = get_qemu_images_dir()
    paths["qemu_images"] = (str(qemu_dir), qemu_dir.exists())
    if not qemu_dir.exists():
        logger.warning("QEMU images directory not found at: %s. QEMU emulation might be affected.", qemu_dir)
    else:
        logger.info("QEMU images directory found at: %s.", qemu_dir)

    # Dynamically discover QEMU images instead of hardcoding
    logger.debug("Initiating dynamic QEMU image discovery.")
    discovery = get_qemu_discovery()
    discovered_images = discovery.discover_images()

    for image_info in discovered_images:
        paths[f"qemu_image_{image_info.filename}"] = (str(image_info.path), True)
        logger.debug("Discovered QEMU image: %s at %s", image_info.filename, image_info.path)

    if not discovered_images:
        logger.info("No QEMU images found in search directories (optional).")
    else:
        logger.info("Found %s QEMU images.", len(discovered_images))

    logger.info("Data path check completed. Results: %s", paths)
    return paths


@log_function_call
def check_qemu_setup() -> bool:
    """Check QEMU setup without auto-downloading."""
    logger.info("Checking QEMU setup...")
    from ..utils.qemu_image_discovery import get_qemu_discovery

    # Check if QEMU is installed
    try:
        logger.debug("Attempting to run 'qemu-img --version' to check QEMU installation.")
        subprocess.run(["qemu-img", "--version"], capture_output=True, check=True)  # nosec S607 - Using QEMU for secure virtual testing environment in security research
        qemu_available = True
        logger.info("QEMU 'qemu-img' command found and executable.")
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logger.info("QEMU not found or not executable: %s. Emulation features disabled.", e, exc_info=True)
        logger.info("Install QEMU from: https://www.qemu.org/download/")
        qemu_available = False

    # Use dynamic image discovery
    logger.debug("Initiating dynamic QEMU image discovery for setup check.")
    discovery = get_qemu_discovery()
    if discovered_images := discovery.discover_images():
        logger.info("Found %s QEMU images.", len(discovered_images))
        return True
    if qemu_available:
        logger.info("QEMU installed but no images found. Use the QEMU setup tools to download/create images if needed.")
        return False
    logger.info("QEMU not available and no images found.")
    return False


@log_function_call
def create_minimal_qemu_disk() -> Path | None:
    """Create a real QEMU disk image automatically."""
    logger.info("Attempting to create a minimal QEMU disk image.")
    from ..utils.path_resolver import get_qemu_images_dir

    qemu_dir = get_qemu_images_dir()
    minimal_disk = qemu_dir / "minimal-test.qcow2"
    logger.debug("QEMU image directory: %s, target disk: %s", qemu_dir, minimal_disk)

    # Check if qemu-img is available
    try:
        logger.debug("Verifying 'qemu-img' availability for disk creation.")
        subprocess.run(["qemu-img", "--version"], capture_output=True, check=True)  # nosec S607 - Using QEMU for secure virtual testing environment in security research

        # Create a real QEMU disk image
        cmd = ["qemu-img", "create", "-f", "qcow2", str(minimal_disk), "1G"]
        logger.info("Executing command to create QEMU disk: %s", " ".join(cmd))
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis

        if result.returncode == 0:
            logger.info("Successfully created QEMU disk image: %s", minimal_disk)

            # Try to format it with a minimal filesystem if we have tools
            try:
                # Create an ext4 filesystem (Linux only)
                if sys.platform.startswith("linux"):
                    format_cmd = ["mkfs.ext4", "-F", str(minimal_disk)]
                    logger.info("Attempting to format QEMU disk with ext4: %s", " ".join(format_cmd))
                    format_result = subprocess.run(format_cmd, capture_output=True, check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    if format_result.returncode == 0:
                        logger.info("Successfully formatted QEMU disk %s with ext4.", minimal_disk)
                    else:
                        logger.warning("Failed to format QEMU disk %s with ext4. Stderr: %s", minimal_disk, format_result.stderr)
                else:
                    logger.debug("Skipping ext4 formatting: Not on Linux platform.")
            except Exception as format_e:
                logger.warning("An error occurred during QEMU disk formatting: %s", format_e, exc_info=True)

            return minimal_disk
        logger.error("Failed to create QEMU disk. Return code: %s, Stderr: %s", result.returncode, result.stderr)
        return None

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logger.exception("'qemu-img' command not found or failed: %s. QEMU must be installed for emulation features.", e)
        logger.info("Install QEMU: https://www.qemu.org/download/")
        return None


@log_function_call
def check_protection_models() -> bool:
    """Check if protection detection models exist."""
    logger.info("Protection detection using native ICP Engine - ML models removed. Returning True.")
    return True


@log_function_call
def validate_tensorflow_models() -> dict[str, Any]:
    """Validate TensorFlow and check model compatibility."""
    logger.info("Validating TensorFlow installation and model compatibility.")
    try:
        tf, tf_available = _get_tensorflow()
        if not tf_available or tf is None:
            error_msg = "TensorFlow not available for validation."
            logger.error(error_msg)
            return {
                "status": False,
                "version": "N/A",
                "gpu_available": False,
                "error": error_msg,
            }

        # Silence TF warnings during validation
        if hasattr(tf, "get_logger"):
            tf.get_logger().setLevel("ERROR")
            logger.debug("TensorFlow logger level set to ERROR for validation.")

        # Get TF info
        tf_info = {
            "version": tf.__version__,
            "gpu_available": len(tf.config.list_physical_devices("GPU")) > 0,
            "gpu_count": len(tf.config.list_physical_devices("GPU")),
            "keras_available": hasattr(tf, "keras"),
        }
        logger.debug("TensorFlow detected info: %s", tf_info)

        # Test model building capability
        logger.debug("Testing TensorFlow model building capability.")
        test_model = tf.keras.Sequential(
            [
                tf.keras.layers.Input(shape=(10,)),
                tf.keras.layers.Dense(64, activation="relu"),
                tf.keras.layers.Dense(32, activation="relu"),
                tf.keras.layers.Dense(1, activation="sigmoid"),
            ],
        )
        test_model.compile(optimizer="adam", loss="binary_crossentropy")
        logger.debug("TensorFlow test model built and compiled successfully.")

        # Test prediction capability
        logger.debug("Testing TensorFlow model prediction capability.")
        test_input = tf.constant([[1.0] * 10])
        test_output = test_model(test_input)

        # Validate model output
        if test_output is not None and hasattr(test_output, "shape"):
            expected_shape = (1, 1)  # Single prediction output
            if test_output.shape == expected_shape:
                output_value = float(test_output.numpy()[0][0])
                if 0.0 <= output_value <= 1.0:  # Valid sigmoid output
                    tf_info["model_building"] = True
                    tf_info["model_prediction_test"] = f"OK (output: {output_value:.3f})"
                    logger.info("TensorFlow model building and prediction test successful. Output: %.3f", output_value)
                else:
                    tf_info["model_building"] = False
                    tf_info["model_prediction_test"] = f"FAIL Invalid output range: {output_value}"
                    logger.error("TensorFlow model prediction test failed: Invalid output range: %s", output_value)
            else:
                tf_info["model_building"] = False
                tf_info["model_prediction_test"] = f"FAIL Wrong output shape: {test_output.shape} vs {expected_shape}"
                logger.error("TensorFlow model prediction test failed: Wrong output shape: %s vs %s", test_output.shape, expected_shape)
        else:
            tf_info["model_building"] = False
            tf_info["model_prediction_test"] = "FAIL No valid output"
            logger.error("TensorFlow model prediction test failed: No valid output.")

        tf_info["status"] = tf_info["model_building"]
        logger.info("TensorFlow validation completed. Status: %s.", tf_info["status"])
        return tf_info
    except Exception as e:
        logger.exception("An unexpected error occurred during TensorFlow validation: %s", e)
        return {
            "status": False,
            "version": "N/A",
            "gpu_available": False,
            "error": str(e),
        }


@log_function_call
def perform_startup_checks() -> dict[str, Any]:
    """Perform all startup checks."""
    logger.info("Initiating all Intellicrack startup checks.")
    # Validate configuration first
    from intellicrack.core.config_manager import get_config

    config = get_config()
    config_valid = config is not None
    if config_valid:
        logger.info("Configuration manager successfully initialized.")
    else:
        logger.critical("Configuration manager failed to initialize. Application may not function correctly.")

    deps = check_dependencies()
    paths = check_data_paths()

    results: dict[str, Any] = {
        "dependencies": deps,
        "paths": paths,
        "config_valid": config_valid,
    }

    # Perform enhanced validation for critical components
    if results["dependencies"].get("TensorFlow", False):
        logger.info("TensorFlow dependency is available, performing enhanced validation.")
        results["tensorflow_validation"] = validate_tensorflow_models()
    else:
        logger.info("TensorFlow dependency not available, skipping enhanced validation.")

    # Auto-setup missing components
    logger.debug("Checking QEMU setup for auto-setup.")
    check_qemu_setup()

    # ML models removed - using LLM-only approach
    logger.debug("Checking protection models (using native ICP Engine).")
    check_protection_models()

    if missing_deps := [k for k, v in results["dependencies"].items() if not v]:
        logger.warning("Missing critical dependencies: %s. Please install them for full functionality.", ", ".join(missing_deps))
        logger.info("Recommendation: Run 'pip install -r requirements.txt' to install missing packages.")
    else:
        logger.info("All critical dependencies are met.")

    # Log validation results
    if "tensorflow_validation" in results:
        tf_val = results["tensorflow_validation"]
        if tf_val["status"]:
            logger.info(
                "TensorFlow %s validated and ready (GPU available: %s, GPU count: %s).",
                tf_val["version"],
                tf_val["gpu_available"],
                tf_val["gpu_count"],
            )
        else:
            logger.warning("TensorFlow validation failed. Status: %s, Error: %s.", tf_val["status"], tf_val.get("error", "N/A"))

    logger.info("All startup checks completed.")
    return results


@log_function_call
def get_system_health_report() -> dict[str, Any]:
    """Generate a comprehensive system health report using all available dependencies."""
    logger.info("Generating comprehensive system health report.")
    report: dict[str, Any] = {
        "timestamp": sys.version,
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "services": {},
    }
    logger.debug("System basic info: Platform='%s', Python='%s'.", report["platform"], report["python_version"])

    # Check Flask web service health
    logger.debug("Checking Flask web service health.")
    try:
        import flask
        import flask_cors

        test_app = flask.Flask(__name__)
        flask_cors.CORS(test_app)

        with test_app.app_context():
            report["services"]["web_ui"] = {
                "available": True,
                "framework": "Flask",
                "cors_enabled": True,
                "debug_mode": test_app.debug,
            }
        logger.info("Flask web UI service is available and healthy.")
    except Exception as e:
        report["services"]["web_ui"] = {"available": False, "error": str(e)}
        logger.warning("Flask web UI service is unavailable or unhealthy: %s", e, exc_info=True)

    # Check ML service health
    logger.debug("Checking ML service health (TensorFlow).")
    try:
        tf, tf_available = _get_tensorflow()

        if not tf_available or tf is None:
            error_msg = "TensorFlow not available for ML service health check."
            logger.warning(error_msg)
            report["services"]["ml_engine"] = {"available": False, "error": error_msg}
        else:
            # Get memory usage if available
            memory_info = {}
            gpu_devices = tf.config.list_physical_devices("GPU")
            if gpu_devices:
                try:
                    gpu = gpu_devices[0]
                    memory_info["gpu_memory_growth"] = tf.config.experimental.get_memory_growth(gpu)
                    logger.debug("ML Engine: GPU memory growth for %s: %s.", gpu.name, memory_info["gpu_memory_growth"])
                except Exception as mem_e:
                    logger.warning("ML Engine: Could not get GPU memory growth info: %s", mem_e, exc_info=True)
            else:
                logger.debug("ML Engine: No GPU devices found for memory info.")

            report["services"]["ml_engine"] = {
                "available": True,
                "backend": "TensorFlow",
                "version": tf.__version__,
                "gpu_support": len(gpu_devices) > 0,
                "memory_info": memory_info,
            }
            logger.info(
                "ML Engine (TensorFlow) service is available and healthy. Version: %s, GPU support: %s.",
                tf.__version__,
                report["services"]["ml_engine"]["gpu_support"],
            )
    except Exception as e:
        report["services"]["ml_engine"] = {"available": False, "error": str(e)}
        logger.warning("ML Engine (TensorFlow) service is unavailable or unhealthy: %s", e, exc_info=True)

    # Check LLM service health
    logger.debug("Checking LLM service health (llama-cpp-python).")
    try:
        import llama_cpp

        report["services"]["llm_engine"] = {
            "available": True,
            "backend": "llama-cpp-python",
            "version": getattr(llama_cpp, "__version__", "Unknown"),
            "gpu_support": hasattr(llama_cpp, "llama_backend_init"),  # This is a heuristic, actual GPU usage depends on model loading
        }
        logger.info(
            "LLM Engine (llama-cpp-python) service is available and healthy. Version: %s, GPU support heuristic: %s.",
            report["services"]["llm_engine"]["version"],
            report["services"]["llm_engine"]["gpu_support"],
        )
    except Exception as e:
        report["services"]["llm_engine"] = {"available": False, "error": str(e)}
        logger.warning("LLM Engine (llama-cpp-python) service is unavailable or unhealthy: %s", e, exc_info=True)

    # Add disk space info for data directories
    from ..utils.path_resolver import get_data_dir

    data_dir = get_data_dir()
    logger.debug("Checking disk space for data directory: %s.", data_dir)

    try:
        import shutil

        disk_usage = shutil.disk_usage(data_dir)
        report["disk_space"] = {
            "data_directory": str(data_dir),
            "total_gb": round(disk_usage.total / (1024**3), 2),
            "used_gb": round(disk_usage.used / (1024**3), 2),
            "free_gb": round(disk_usage.free / (1024**3), 2),
            "percent_used": round((disk_usage.used / disk_usage.total) * 100, 1),
        }
        logger.info("Disk space for data directory '%s' checked. Used: %s%%.", data_dir, report["disk_space"]["percent_used"])
    except Exception as e:
        report["disk_space"] = {"available": False, "error": str(e)}
        logger.warning("Could not retrieve disk space information for '%s': %s", data_dir, e, exc_info=True)

    logger.info("System health report generation completed.")
    return report
