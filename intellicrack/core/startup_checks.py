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
def _get_tensorflow():
    """Get TensorFlow module, importing only once."""
    global _tf_import_attempted, _tf_module, _tf_available

    if not _tf_import_attempted:
        _tf_import_attempted = True
        logger.debug("Attempting to import TensorFlow.")
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
            logger.debug("TensorFlow imported successfully.")
        except Exception as e:
            logger.warning(f"TensorFlow import failed: {e}")
            _tf_available = False
            _tf_module = None
            logger.debug("TensorFlow import failed.")

    return _tf_module, _tf_available


@log_function_call
def check_dependencies() -> dict[str, bool]:
    """Check for required dependencies."""
    logger.info("Starting dependency checks...")
    dependencies = {}

    # Check Flask and test basic functionality
    logger.info("Checking for Flask...")
    try:
        import flask
        import flask_cors

        # Validate Flask by creating a minimal app
        validation_app = flask.Flask(__name__)
        flask_cors.CORS(validation_app)
        logger.debug("Flask app created and CORS enabled.")

        # Verify Flask can handle basic routing
        @validation_app.route("/test")
        def validation_route():
            return flask.jsonify({"status": "ok"})

        # Validate the app context
        with validation_app.app_context():
            flask.current_app.config["TESTING"] = True
        dependencies["Flask"] = True
        logger.info("Flask verification successful.")
        logger.debug("Flask dependency check: PASSED.")
    except ImportError:
        dependencies["Flask"] = False
        logger.warning("Flask not found. Web UI and API endpoints will be unavailable.")
        logger.debug("Flask dependency check: FAILED (ImportError).")
    except Exception as e:
        dependencies["Flask"] = False
        logger.warning(f"Flask initialization failed: {e}", exc_info=True)
        logger.debug(f"Flask dependency check: FAILED (Exception: {e}).")

    # Check QEMU
    logger.info("Checking for QEMU...")
    try:
        import shutil

        qemu_found = shutil.which("qemu-system-x86_64") is not None
        dependencies["QEMU"] = qemu_found
        if qemu_found:
            logger.info("QEMU found.")
            logger.debug("QEMU dependency check: PASSED.")
        else:
            logger.warning("QEMU not found. QEMU functionality will be limited.")
            logger.debug("QEMU dependency check: FAILED (Not found).")
    except Exception as e:
        logger.error("An unexpected error occurred during QEMU check: %s", e, exc_info=True)
        dependencies["QEMU"] = False
        logger.debug(f"QEMU dependency check: FAILED (Exception: {e}).")

    # Check ML dependencies and test TensorFlow functionality
    logger.info("Checking for TensorFlow...")
    try:
        tf, tf_available = _get_tensorflow()

        if not tf_available or tf is None:
            raise ImportError("TensorFlow not available")

        # Test TensorFlow by checking version and GPU availability
        tf_version = tf.__version__
        gpu_available = len(tf.config.list_physical_devices("GPU")) > 0
        logger.debug(f"TensorFlow version: {tf_version}, GPU available: {gpu_available}")

        # Test basic tensor operations
        logger.debug("Performing basic TensorFlow tensor operations test.")
        test_tensor = tf.constant([[1.0, 2.0], [3.0, 4.0]])
        test_result = tf.reduce_sum(test_tensor)

        # Validate tensor operation result
        expected_sum = 10.0  # 1.0 + 2.0 + 3.0 + 4.0
        actual_sum = float(test_result.numpy())

        if abs(actual_sum - expected_sum) < 1e-6:
            dependencies["TensorFlow"] = True
            logger.info(f"TensorFlow {tf_version} verified (GPU: {gpu_available}, tensor ops: OK)")
            logger.debug("TensorFlow dependency check: PASSED.")
        else:
            dependencies["TensorFlow"] = False
            logger.error(f"TensorFlow tensor operation failed: expected {expected_sum}, got {actual_sum}")
            logger.debug("TensorFlow dependency check: FAILED (Tensor operation mismatch).")
            return dependencies

        # Check if models can be loaded
        if tf.saved_model.contains_saved_model("."):
            logger.debug("TensorFlow SavedModel support verified.")

    except ImportError:
        dependencies["TensorFlow"] = False
        logger.warning("TensorFlow not available. ML Vulnerability Predictor will be disabled.")
        logger.debug("TensorFlow dependency check: FAILED (ImportError).")
    except Exception as e:
        dependencies["TensorFlow"] = False
        logger.warning(f"TensorFlow initialization failed: {e}", exc_info=True)
        logger.debug(f"TensorFlow dependency check: FAILED (Exception: {e}).")

    # Check llama-cpp and test model loading capabilities
    logger.info("Checking for llama-cpp-python...")
    try:
        import llama_cpp

        # Test llama-cpp functionality
        # Check if we can access the library version
        if hasattr(llama_cpp, "__version__"):
            llama_version = llama_cpp.__version__
            logger.info(f"llama-cpp-python version {llama_version} found.")

        # Verify model loading capability by checking available parameters
        logger.debug("Validating llama-cpp model and context parameters.")
        model_params = llama_cpp.llama_model_params()
        context_params = llama_cpp.llama_context_params()

        # Validate parameter structures are properly initialized
        if hasattr(model_params, "n_gpu_layers") and hasattr(context_params, "n_ctx"):
            # Test parameter modification to ensure they're functional
            try:
                original_gpu_layers = model_params.n_gpu_layers
                original_ctx_size = context_params.n_ctx
                logger.debug(f"Original llama-cpp params: n_gpu_layers={original_gpu_layers}, n_ctx={original_ctx_size}")

                # Temporarily modify parameters to test functionality
                model_params.n_gpu_layers = 0
                context_params.n_ctx = 512

                # Restore original values
                model_params.n_gpu_layers = original_gpu_layers
                context_params.n_ctx = original_ctx_size
                logger.debug("llama-cpp parameter modification test successful.")

                dependencies["llama-cpp-python"] = True
                logger.info(
                    f"LLM Manager available with llama-cpp backend (ctx_size: {original_ctx_size}, gpu_layers: {original_gpu_layers})",
                )
                logger.debug("llama-cpp-python dependency check: PASSED.")
            except Exception as param_error:
                dependencies["llama-cpp-python"] = False
                logger.error(f"llama-cpp parameter validation failed: {param_error}", exc_info=True)
                logger.debug(f"llama-cpp-python dependency check: FAILED (Parameter validation: {param_error}).")
        else:
            dependencies["llama-cpp-python"] = False
            logger.error("llama-cpp parameters missing required attributes (n_gpu_layers or n_ctx).")
            logger.debug("llama-cpp-python dependency check: FAILED (Missing attributes).")
    except ImportError:
        dependencies["llama-cpp-python"] = False
        logger.warning("llama-cpp-python not found. LLM Manager will be unavailable.")
        logger.debug("llama-cpp-python dependency check: FAILED (ImportError).")
    except Exception as e:
        dependencies["llama-cpp-python"] = False
        logger.warning(f"llama-cpp initialization failed: {e}", exc_info=True)
        logger.debug(f"llama-cpp-python dependency check: FAILED (Exception: {e}).")

    logger.info("Dependency check completed.")
    logger.debug(f"Final dependency check results: {dependencies}")
    return dependencies


@log_function_call
def check_data_paths() -> dict[str, tuple[str, bool]]:
    """Check and create required data paths."""
    logger.info("Checking and creating required data paths.")
    from ..utils.path_resolver import (
        ensure_data_directories,
        get_qemu_images_dir,
    )
    from ..utils.qemu_image_discovery import get_qemu_discovery

    # Ensure directories exist
    logger.debug("Ensuring all data directories exist.")
    ensure_data_directories()
    logger.debug("Data directories ensured.")

    paths = {}

    # ML models directory removed - using LLM-only approach

    # Check QEMU images directory
    logger.debug("Checking QEMU images directory.")
    qemu_dir = get_qemu_images_dir()
    paths["qemu_images"] = (str(qemu_dir), qemu_dir.exists())
    if qemu_dir.exists():
        logger.debug(f"QEMU images directory found at: {qemu_dir}")
    else:
        logger.warning(f"QEMU images directory not found at: {qemu_dir}")
        logger.debug(f"QEMU images directory check: FAILED (Not found at {qemu_dir}).")

    # Protection model files removed - using LLM-only approach

    # Dynamically discover QEMU images instead of hardcoding
    logger.debug("Dynamically discovering QEMU images.")
    discovery = get_qemu_discovery()
    discovered_images = discovery.discover_images()

    for image_info in discovered_images:
        paths[f"qemu_image_{image_info.filename}"] = (str(image_info.path), True)
        logger.debug(f"Discovered QEMU image: {image_info.filename} at {image_info.path}")

    if not discovered_images:
        logger.info("No QEMU images found in search directories (optional).")
        logger.debug("QEMU image discovery: No images found.")
    else:
        logger.info(f"Found {len(discovered_images)} QEMU images.")
        logger.debug(f"QEMU image discovery: Found {len(discovered_images)} images.")

    logger.info("Data path check completed.")
    logger.debug(f"Final data path check results: {paths}")
    return paths


@log_function_call
def check_qemu_setup() -> bool:
    """Check QEMU setup without auto-downloading."""
    from ..utils.qemu_image_discovery import get_qemu_discovery
    logger.debug("Starting QEMU setup check.")
    # Check if QEMU is installed
    try:
        subprocess.run(["qemu-img", "--version"], capture_output=True, check=True)  # nosec S607 - Using QEMU for secure virtual testing environment in security research
        logger.info("QEMU is installed")
        qemu_available = True
        logger.debug("QEMU executable found.")
    except (FileNotFoundError, subprocess.CalledProcessError):
        logger.info("QEMU not found - emulation features disabled")
        logger.info("Install QEMU from: https://www.qemu.org/download/")
        qemu_available = False
        logger.debug("QEMU executable not found.")

    # Use dynamic image discovery
    discovery = get_qemu_discovery()
    discovered_images = discovery.discover_images()

    if discovered_images:
        logger.info(f"Found {len(discovered_images)} QEMU images")
        logger.debug(f"Discovered {len(discovered_images)} QEMU images.")
        return True
    if qemu_available:
        logger.info("QEMU installed but no images found")
        logger.info("Use the QEMU setup tools to download/create images if needed")
        logger.debug("QEMU installed but no images discovered.")
        return False
    logger.debug("QEMU not installed and no images found.")
    return False


@log_function_call
def create_minimal_qemu_disk() -> Path | None:
    """Create a real QEMU disk image automatically."""
    from ..utils.path_resolver import get_qemu_images_dir
    logger.debug("Starting minimal QEMU disk creation.")
    qemu_dir = get_qemu_images_dir()
    minimal_disk = qemu_dir / "minimal-test.qcow2"
    logger.debug(f"Target minimal disk path: {minimal_disk}")

    # Check if qemu-img is available
    try:
        logger.debug("Checking for qemu-img availability.")
        subprocess.run(["qemu-img", "--version"], capture_output=True, check=True)  # nosec S607 - Using QEMU for secure virtual testing environment in security research
        logger.debug("qemu-img found.")

        # Create a real QEMU disk image
        cmd = ["qemu-img", "create", "-f", "qcow2", str(minimal_disk), "1G"]
        logger.debug(f"Executing QEMU disk creation command: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis

        if result.returncode == 0:
            logger.info(f"Created QEMU disk image: {minimal_disk}")
            logger.debug("QEMU disk image created successfully.")

            # Try to format it with a minimal filesystem if we have tools
            try:
                # Create an ext4 filesystem (Linux only)
                if sys.platform.startswith("linux"):
                    format_cmd = ["mkfs.ext4", "-F", str(minimal_disk)]
                    logger.debug(f"Attempting to format QEMU disk with: {' '.join(format_cmd)}")
                    subprocess.run(format_cmd, capture_output=True, check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    logger.debug("QEMU disk format attempt completed.")
            except Exception as e:
                logger.debug(f"Failed to format QEMU disk (optional): {e}")

            return minimal_disk
        logger.error(f"Failed to create QEMU disk: {result.stderr}")
        logger.debug(f"QEMU disk creation failed. Stderr: {result.stderr}")
        return None

    except (FileNotFoundError, subprocess.CalledProcessError):
        logger.error("qemu-img not found. QEMU must be installed for emulation features.")
        logger.info("Install QEMU: https://www.qemu.org/download/")
        logger.debug("qemu-img not found during minimal disk creation.")
        return None


@log_function_call
def check_protection_models() -> bool:
    """Check if protection detection models exist."""
    # ML models removed - using LLM-only approach with native ICP Engine for protection detection
    logger.info("Protection detection using native ICP Engine - ML models removed")
    return True


@log_function_call
def validate_tensorflow_models() -> dict[str, any]:
    """Validate TensorFlow and check model compatibility."""
    try:
        tf, tf_available = _get_tensorflow()
        logger.debug("Starting TensorFlow model validation.")
        if not tf_available or tf is None:
            logger.debug("TensorFlow not available for model validation.")
            raise ImportError("TensorFlow not available")

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
        logger.debug(f"TensorFlow info: {tf_info}")

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
        logger.debug("Test model built and compiled successfully.")

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
                    logger.debug(f"Model prediction test OK. Output: {output_value:.3f}")
                else:
                    tf_info["model_building"] = False
                    tf_info["model_prediction_test"] = f"FAIL Invalid output range: {output_value}"
                    logger.debug(f"Model prediction test FAILED: Invalid output range {output_value}.")
            else:
                tf_info["model_building"] = False
                tf_info["model_prediction_test"] = f"FAIL Wrong output shape: {test_output.shape} vs {expected_shape}"
                logger.debug(f"Model prediction test FAILED: Wrong output shape {test_output.shape}.")
        else:
            tf_info["model_building"] = False
            tf_info["model_prediction_test"] = "FAIL No valid output"
            logger.debug("Model prediction test FAILED: No valid output.")

        tf_info["status"] = tf_info["model_building"]
        logger.debug(f"TensorFlow model validation completed. Status: {tf_info['status']}")
        return tf_info
    except Exception as e:
        logger.debug(f"TensorFlow model validation failed with exception: {e}", exc_info=True)
        return {
            "status": False,
            "version": "N/A",
            "gpu_available": False,
            "error": str(e),
        }


@log_function_call
def perform_startup_checks() -> dict[str, any]:
    """Perform all startup checks."""
    logger.info("Performing startup checks...")
    logger.debug("Starting comprehensive startup checks.")

    # Validate configuration first
    logger.info("Validating configuration...")
    from intellicrack.core.config_manager import get_config

    config = get_config()
    config_valid = config is not None
    logger.info("Configuration validation complete")
    logger.debug(f"Configuration valid: {config_valid}")

    logger.info("Checking dependencies...")
    deps = check_dependencies()
    logger.info("Dependencies checked")
    logger.debug(f"Dependency check results: {deps}")

    logger.info("Checking data paths...")
    paths = check_data_paths()
    logger.info("Data paths checked")
    logger.debug(f"Data path check results: {paths}")

    results = {
        "dependencies": deps,
        "paths": paths,
        "config_valid": config_valid,
    }

    # Perform enhanced validation for critical components
    if results["dependencies"].get("TensorFlow", False):
        logger.debug("Performing TensorFlow model validation.")
        results["tensorflow_validation"] = validate_tensorflow_models()
        logger.debug(f"TensorFlow validation results: {results['tensorflow_validation']}")

    # Auto-setup missing components
    logger.info("Auto-configuring missing components...")
    logger.debug("Starting auto-configuration of missing components.")

    # Check QEMU setup (no auto-download)
    logger.debug("Checking QEMU setup.")
    check_qemu_setup()

    # ML models removed - using LLM-only approach
    logger.debug("Checking protection models (using native ICP Engine).")
    check_protection_models()

    # Log summary
    missing_deps = [k for k, v in results["dependencies"].items() if not v]
    if missing_deps:
        logger.warning(f"Missing dependencies: {', '.join(missing_deps)}")
        logger.info("Run 'pip install -r requirements.txt' to install missing packages")
        logger.debug(f"Missing dependencies detected: {missing_deps}")
    else:
        logger.debug("All required dependencies found.")

    # Log validation results
    if "tensorflow_validation" in results and results["tensorflow_validation"]["status"]:
        tf_val = results["tensorflow_validation"]
        logger.info(f"TensorFlow {tf_val['version']} ready (GPU: {tf_val['gpu_available']})")
        logger.debug("TensorFlow validation successful.")
    else:
        logger.debug("TensorFlow validation not performed or failed.")
    logger.info("Startup checks completed.")
    logger.debug(f"Final startup check results: {results}")
    return results


@log_function_call
    def get_system_health_report() -> dict[str, any]:
        """Generate a comprehensive system health report using all available dependencies."""
        logger.debug("Generating system health report.")
        report = {
            "timestamp": sys.version,
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
            "services": {},
        }

        # Check Flask web service health
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
            logger.debug("Web UI service check: PASSED.")
        except Exception as e:
            logger.debug(f"Web UI check failed: {e}")
            report["services"]["web_ui"] = {"available": False}
            logger.debug("Web UI service check: FAILED.")

        # Check ML service health
        try:
            tf, tf_available = _get_tensorflow()

            if not tf_available or tf is None:
                raise ImportError("TensorFlow not available")

            # Get memory usage if available
            memory_info = {}
            if tf.config.list_physical_devices("GPU"):
                try:
                    gpu = tf.config.list_physical_devices("GPU")[0]
                    memory_info["gpu_memory_growth"] = tf.config.experimental.get_memory_growth(gpu)
                    logger.debug(f"GPU memory growth: {memory_info['gpu_memory_growth']}")
                except Exception as e:
                    logger.debug(f"GPU memory check failed: {e}")

            report["services"]["ml_engine"] = {
                "available": True,
                "backend": "TensorFlow",
                "version": tf.__version__,
                "gpu_support": len(tf.config.list_physical_devices("GPU")) > 0,
                "memory_info": memory_info,
            }
            logger.debug("ML engine service check: PASSED.")
        except Exception as e:
            logger.debug(f"ML engine check failed: {e}")
            report["services"]["ml_engine"] = {"available": False}
            logger.debug("ML engine service check: FAILED.")

        # Check LLM service health
        try:
            import llama_cpp

            report["services"]["llm_engine"] = {
                "available": True,
                "backend": "llama-cpp-python",
                "version": getattr(llama_cpp, "__version__", "Unknown"),
                "gpu_support": hasattr(llama_cpp, "llama_backend_init"),
            }
            logger.debug("LLM engine service check: PASSED.")
        except Exception as e:
            logger.debug(f"LLM engine check failed: {e}")
            report["services"]["llm_engine"] = {"available": False}
            logger.debug("LLM engine service check: FAILED.")

        # Add disk space info for data directories
        from ..utils.path_resolver import get_data_dir

        data_dir = get_data_dir()

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
            logger.debug(f"Disk space check: PASSED. Data directory: {data_dir}, Free GB: {report['disk_space']['free_gb']}")
        except Exception as e:
            logger.debug(f"Disk space check failed: {e}")
            report["disk_space"] = {"available": False}
            logger.debug("Disk space check: FAILED.")
        logger.debug("System health report generation completed.")
        return report
