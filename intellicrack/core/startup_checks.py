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

from intellicrack.utils.logger import log_function_call

logger = logging.getLogger(__name__)

# Configure TensorFlow environment ONCE at module level before any imports
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["MKL_THREADING_LAYER"] = "GNU"

# Import TensorFlow handler ONCE at module level to avoid duplicate imports
_tf_import_attempted = False
_tf_module = None
_tf_available = False


@log_function_call
def _get_tensorflow() -> tuple[object, bool]:
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
            )
            from intellicrack.handlers.tensorflow_handler import (
                tensorflow as tf,
            )

            ensure_tensorflow_loaded()
            _tf_module = tf
            _tf_available = True
            _tf_module.config.set_visible_devices([], "GPU")
            logger.info(f"TensorFlow: Imported successfully (version: {tf.__version__}). GPU devices set to invisible.")
            logger.debug(f"TensorFlow: Visible devices after configuration: {tf.config.get_visible_devices()}")
        except Exception as e:
            logger.warning(f"TensorFlow: Import failed: {e}", exc_info=True)
            _tf_available = False
            _tf_module = None
            logger.debug("TensorFlow: Import failed, TensorFlow will be unavailable.")
    else:
        logger.debug(f"TensorFlow: Import already attempted. Available: {_tf_available}.")

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
        def validation_route() -> object:
            return flask.jsonify({"status": "ok"})

        # Validate the app context
        with validation_app.app_context():
            flask.current_app.config["TESTING"] = True
        dependencies["Flask"] = True
        logger.info("Flask and Flask-CORS found and basic functionality validated.")
    except ImportError:
        dependencies["Flask"] = False
        logger.warning("Flask or Flask-CORS not found. Web UI and API endpoints will be unavailable.")
    except Exception as e:
        dependencies["Flask"] = False
        logger.warning(f"Flask initialization failed: {e}", exc_info=True)

    # Check QEMU
    logger.debug("Checking QEMU dependency...")
    try:
        import shutil

        qemu_path = shutil.which("qemu-system-x86_64")
        qemu_found = qemu_path is not None
        dependencies["QEMU"] = qemu_found
        if qemu_found:
            logger.info(f"QEMU found at: {qemu_path}.")
        else:
            logger.warning("QEMU not found in system PATH. QEMU functionality will be limited.")
    except Exception as e:
        logger.error("An unexpected error occurred during QEMU check: %s", e, exc_info=True)
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
            logger.debug(f"TensorFlow: Found {gpu_count} GPU(s) available for TensorFlow.")

            # Test basic tensor operations
            test_tensor = tf.constant([[1.0, 2.0], [3.0, 4.0]])
            test_result = tf.reduce_sum(test_tensor)

            # Validate tensor operation result
            expected_sum = 10.0  # 1.0 + 2.0 + 3.0 + 4.0
            actual_sum = float(test_result.numpy())

            if abs(actual_sum - expected_sum) < 1e-6:
                dependencies["TensorFlow"] = True
                logger.info(f"TensorFlow: Basic tensor operations validated (sum: {actual_sum}).")
            else:
                dependencies["TensorFlow"] = False
                logger.error(f"TensorFlow: Tensor operation failed: expected {expected_sum}, got {actual_sum}.")
                # No need to return here, continue checking other dependencies

            # Check if models can be loaded (this part of the original code was incomplete/commented)
            # For now, we'll just rely on basic tensor ops for dependency check
            # if tf.saved_model.contains_saved_model("."):
            #     pass

    except ImportError:
        dependencies["TensorFlow"] = False
        logger.warning("TensorFlow: Import error. ML Vulnerability Predictor will be disabled.")
    except Exception as e:
        dependencies["TensorFlow"] = False
        logger.warning(f"TensorFlow: Initialization or test failed: {e}", exc_info=True)

    # Check llama-cpp and test model loading capabilities
    logger.debug("Checking llama-cpp-python dependency...")
    try:
        import llama_cpp

        # Test llama-cpp functionality
        # Check if we can access the library version
        llama_version = getattr(llama_cpp, "__version__", "Unknown")
        logger.debug(f"llama-cpp-python: Found version {llama_version}.")

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
                logger.error(f"llama-cpp-python: Parameter validation failed: {param_error}", exc_info=True)
        else:
            dependencies["llama-cpp-python"] = False
            logger.error("llama-cpp-python: Parameters missing required attributes (n_gpu_layers or n_ctx).")
    except ImportError:
        dependencies["llama-cpp-python"] = False
        logger.warning("llama-cpp-python: Import error. LLM Manager will be unavailable.")
    except Exception as e:
        dependencies["llama-cpp-python"] = False
        logger.warning(f"llama-cpp-python: Initialization or test failed: {e}", exc_info=True)

    logger.info(f"Dependency check completed. Results: {dependencies}")
    return dependencies


@log_function_call
def check_data_paths() -> dict[str, tuple[str, bool]]:
    """Check and create required data paths."""
    logger.info("Checking and ensuring data paths exist...")
    from ..utils.path_resolver import (
        ensure_data_directories,
        get_qemu_images_dir,
    )
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
        logger.warning(f"QEMU images directory not found at: {qemu_dir}. QEMU emulation might be affected.")
    else:
        logger.info(f"QEMU images directory found at: {qemu_dir}.")

    # Dynamically discover QEMU images instead of hardcoding
    logger.debug("Initiating dynamic QEMU image discovery.")
    discovery = get_qemu_discovery()
    discovered_images = discovery.discover_images()

    for image_info in discovered_images:
        paths[f"qemu_image_{image_info.filename}"] = (str(image_info.path), True)
        logger.debug(f"Discovered QEMU image: {image_info.filename} at {image_info.path}")

    if not discovered_images:
        logger.info("No QEMU images found in search directories (optional).")
    else:
        logger.info(f"Found {len(discovered_images)} QEMU images.")

    logger.info(f"Data path check completed. Results: {paths}")
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
        logger.info(f"QEMU not found or not executable: {e}. Emulation features disabled.")
        logger.info("Install QEMU from: https://www.qemu.org/download/")
        qemu_available = False

    # Use dynamic image discovery
    logger.debug("Initiating dynamic QEMU image discovery for setup check.")
    discovery = get_qemu_discovery()
    discovered_images = discovery.discover_images()

    if discovered_images:
        logger.info(f"Found {len(discovered_images)} QEMU images.")
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
    logger.debug(f"QEMU image directory: {qemu_dir}, target disk: {minimal_disk}")

    # Check if qemu-img is available
    try:
        logger.debug("Verifying 'qemu-img' availability for disk creation.")
        subprocess.run(["qemu-img", "--version"], capture_output=True, check=True)  # nosec S607 - Using QEMU for secure virtual testing environment in security research

        # Create a real QEMU disk image
        cmd = ["qemu-img", "create", "-f", "qcow2", str(minimal_disk), "1G"]
        logger.info(f"Executing command to create QEMU disk: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis

        if result.returncode == 0:
            logger.info(f"Successfully created QEMU disk image: {minimal_disk}")

            # Try to format it with a minimal filesystem if we have tools
            try:
                # Create an ext4 filesystem (Linux only)
                if sys.platform.startswith("linux"):
                    format_cmd = ["mkfs.ext4", "-F", str(minimal_disk)]
                    logger.info(f"Attempting to format QEMU disk with ext4: {' '.join(format_cmd)}")
                    format_result = subprocess.run(format_cmd, capture_output=True, check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    if format_result.returncode == 0:
                        logger.info(f"Successfully formatted QEMU disk {minimal_disk} with ext4.")
                    else:
                        logger.warning(f"Failed to format QEMU disk {minimal_disk} with ext4. Stderr: {format_result.stderr}")
                else:
                    logger.debug("Skipping ext4 formatting: Not on Linux platform.")
            except Exception as format_e:
                logger.warning(f"An error occurred during QEMU disk formatting: {format_e}", exc_info=True)

            return minimal_disk
        logger.error(f"Failed to create QEMU disk. Return code: {result.returncode}, Stderr: {result.stderr}")
        return None

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logger.error(f"'qemu-img' command not found or failed: {e}. QEMU must be installed for emulation features.")
        logger.info("Install QEMU: https://www.qemu.org/download/")
        return None


@log_function_call
def check_protection_models() -> bool:
    """Check if protection detection models exist."""
    logger.info("Protection detection using native ICP Engine - ML models removed. Returning True.")
    return True


@log_function_call
def validate_tensorflow_models() -> dict[str, any]:
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
        logger.debug(f"TensorFlow detected info: {tf_info}")

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
                    logger.info(f"TensorFlow model building and prediction test successful. Output: {output_value:.3f}")
                else:
                    tf_info["model_building"] = False
                    tf_info["model_prediction_test"] = f"FAIL Invalid output range: {output_value}"
                    logger.error(f"TensorFlow model prediction test failed: Invalid output range: {output_value}")
            else:
                tf_info["model_building"] = False
                tf_info["model_prediction_test"] = f"FAIL Wrong output shape: {test_output.shape} vs {expected_shape}"
                logger.error(f"TensorFlow model prediction test failed: Wrong output shape: {test_output.shape} vs {expected_shape}")
        else:
            tf_info["model_building"] = False
            tf_info["model_prediction_test"] = "FAIL No valid output"
            logger.error("TensorFlow model prediction test failed: No valid output.")

        tf_info["status"] = tf_info["model_building"]
        logger.info(f"TensorFlow validation completed. Status: {tf_info['status']}.")
        return tf_info
    except Exception as e:
        logger.exception(f"An unexpected error occurred during TensorFlow validation: {e}")
        return {
            "status": False,
            "version": "N/A",
            "gpu_available": False,
            "error": str(e),
        }


@log_function_call
def perform_startup_checks() -> dict[str, any]:
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

    results = {
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

    # Log summary
    missing_deps = [k for k, v in results["dependencies"].items() if not v]
    if missing_deps:
        logger.warning(f"Missing critical dependencies: {', '.join(missing_deps)}. Please install them for full functionality.")
        logger.info("Recommendation: Run 'pip install -r requirements.txt' to install missing packages.")
    else:
        logger.info("All critical dependencies are met.")

    # Log validation results
    if "tensorflow_validation" in results:
        tf_val = results["tensorflow_validation"]
        if tf_val["status"]:
            logger.info(f"TensorFlow {tf_val['version']} validated and ready (GPU available: {tf_val['gpu_available']}, GPU count: {tf_val['gpu_count']}).")
        else:
            logger.warning(f"TensorFlow validation failed. Status: {tf_val['status']}, Error: {tf_val.get('error', 'N/A')}.")

    logger.info("All startup checks completed.")
    return results


@log_function_call
def get_system_health_report() -> dict[str, any]:
    """Generate a comprehensive system health report using all available dependencies."""
    logger.info("Generating comprehensive system health report.")
    report = {
        "timestamp": sys.version,
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "services": {},
    }
    logger.debug(f"System basic info: Platform='{report['platform']}', Python='{report['python_version']}'.")

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
        logger.warning(f"Flask web UI service is unavailable or unhealthy: {e}", exc_info=True)

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
                    logger.debug(f"ML Engine: GPU memory growth for {gpu.name}: {memory_info['gpu_memory_growth']}.")
                except Exception as mem_e:
                    logger.warning(f"ML Engine: Could not get GPU memory growth info: {mem_e}")
            else:
                logger.debug("ML Engine: No GPU devices found for memory info.")

            report["services"]["ml_engine"] = {
                "available": True,
                "backend": "TensorFlow",
                "version": tf.__version__,
                "gpu_support": len(gpu_devices) > 0,
                "memory_info": memory_info,
            }
            logger.info(f"ML Engine (TensorFlow) service is available and healthy. Version: {tf.__version__}, GPU support: {report['services']['ml_engine']['gpu_support']}.")
    except Exception as e:
        report["services"]["ml_engine"] = {"available": False, "error": str(e)}
        logger.warning(f"ML Engine (TensorFlow) service is unavailable or unhealthy: {e}", exc_info=True)

    # Check LLM service health
    logger.debug("Checking LLM service health (llama-cpp-python).")
    try:
        import llama_cpp

        report["services"]["llm_engine"] = {
            "available": True,
            "backend": "llama-cpp-python",
            "version": getattr(llama_cpp, "__version__", "Unknown"),
            "gpu_support": hasattr(llama_cpp, "llama_backend_init"), # This is a heuristic, actual GPU usage depends on model loading
        }
        logger.info(f"LLM Engine (llama-cpp-python) service is available and healthy. Version: {report['services']['llm_engine']['version']}, GPU support heuristic: {report['services']['llm_engine']['gpu_support']}.")
    except Exception as e:
        report["services"]["llm_engine"] = {"available": False, "error": str(e)}
        logger.warning(f"LLM Engine (llama-cpp-python) service is unavailable or unhealthy: {e}", exc_info=True)

    # Add disk space info for data directories
    from ..utils.path_resolver import get_data_dir

    data_dir = get_data_dir()
    logger.debug(f"Checking disk space for data directory: {data_dir}.")

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
        logger.info(f"Disk space for data directory '{data_dir}' checked. Used: {report['disk_space']['percent_used']}%.")
    except Exception as e:
        report["disk_space"] = {"available": False, "error": str(e)}
        logger.warning(f"Could not retrieve disk space information for '{data_dir}': {e}", exc_info=True)

    logger.info("System health report generation completed.")
    return report
