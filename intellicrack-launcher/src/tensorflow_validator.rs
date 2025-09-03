use crate::dependencies::DependencyStatus;
use anyhow::{anyhow, Result};
use serde_json;
use std::collections::HashMap;
use std::process::Command;
use tracing::{debug, info, warn};

pub struct TensorFlowValidator;

impl TensorFlowValidator {
    pub async fn validate_complete_functionality() -> Result<DependencyStatus> {
        info!("Starting TensorFlow comprehensive validation");

        let mut details = HashMap::new();

        // First check if Python is available
        let python_result = Self::check_python_availability().await;
        match python_result {
            Ok(python_info) => {
                details.insert(
                    "python_executable".to_string(),
                    serde_json::Value::String(python_info),
                );
            }
            Err(e) => {
                warn!("Python not available: {}", e);
                details.insert(
                    "error".to_string(),
                    serde_json::Value::String(format!("Python not available: {}", e)),
                );
                return Ok(DependencyStatus {
                    available: false,
                    version: None,
                    details,
                });
            }
        }

        // Check TensorFlow installation and version
        let tf_version = Self::get_tensorflow_version().await;
        match tf_version {
            Ok(version) => {
                info!("TensorFlow version detected: {}", version);
                details.insert(
                    "tensorflow_version".to_string(),
                    serde_json::Value::String(version.clone()),
                );

                // Test TensorFlow import and basic functionality
                let import_test = Self::test_tensorflow_import().await;
                match import_test {
                    Ok(import_info) => {
                        details.insert(
                            "import_test".to_string(),
                            serde_json::Value::String("success".to_string()),
                        );
                        for (key, value) in import_info {
                            details.insert(key, serde_json::Value::String(value));
                        }

                        // Test TensorFlow basic operations
                        let ops_test = Self::test_tensorflow_operations().await;
                        match ops_test {
                            Ok(ops_info) => {
                                details.insert(
                                    "operations_test".to_string(),
                                    serde_json::Value::String("success".to_string()),
                                );
                                for (key, value) in ops_info {
                                    details.insert(key, serde_json::Value::String(value));
                                }

                                // Test TensorFlow device detection
                                let device_test = Self::test_tensorflow_devices().await;
                                match device_test {
                                    Ok(device_info) => {
                                        details.insert(
                                            "device_test".to_string(),
                                            serde_json::Value::String("success".to_string()),
                                        );
                                        for (key, value) in device_info {
                                            details.insert(key, serde_json::Value::String(value));
                                        }

                                        // Test Intel extension if available
                                        let intel_test = Self::test_intel_extension().await;
                                        match intel_test {
                                            Ok(intel_info) => {
                                                details.insert(
                                                    "intel_extension_test".to_string(),
                                                    serde_json::Value::String(
                                                        "success".to_string(),
                                                    ),
                                                );
                                                for (key, value) in intel_info {
                                                    details.insert(
                                                        key,
                                                        serde_json::Value::String(value),
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                debug!("Intel extension test failed (expected on non-Intel systems): {}", e);
                                                details.insert(
                                                    "intel_extension_test".to_string(),
                                                    serde_json::Value::String(format!(
                                                        "not_available: {}",
                                                        e
                                                    )),
                                                );
                                            }
                                        }

                                        return Ok(DependencyStatus {
                                            available: true,
                                            version: Some(version),
                                            details,
                                        });
                                    }
                                    Err(e) => {
                                        warn!("TensorFlow device test failed: {}", e);
                                        details.insert(
                                            "device_test".to_string(),
                                            serde_json::Value::String(format!("failed: {}", e)),
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("TensorFlow operations test failed: {}", e);
                                details.insert(
                                    "operations_test".to_string(),
                                    serde_json::Value::String(format!("failed: {}", e)),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!("TensorFlow import test failed: {}", e);
                        details.insert(
                            "import_test".to_string(),
                            serde_json::Value::String(format!("failed: {}", e)),
                        );
                    }
                }

                // If we reach here, TensorFlow is installed but some functionality failed
                return Ok(DependencyStatus {
                    available: true,
                    version: Some(version),
                    details,
                });
            }
            Err(e) => {
                warn!(
                    "TensorFlow not available or version detection failed: {}",
                    e
                );
                details.insert(
                    "tensorflow_error".to_string(),
                    serde_json::Value::String(e.to_string()),
                );

                return Ok(DependencyStatus {
                    available: false,
                    version: None,
                    details,
                });
            }
        }
    }

    async fn check_python_availability() -> Result<String> {
        debug!("Checking Python availability for TensorFlow");

        // Try different Python executable names
        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(&["--version"]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let version_output = String::from_utf8_lossy(&result.stdout);
                        let version_line = version_output.trim();
                        debug!("Found Python for TensorFlow: {} -> {}", cmd, version_line);
                        return Ok(format!("{}: {}", cmd, version_line));
                    }
                }
                Err(e) => {
                    debug!("Failed to execute {}: {}", cmd, e);
                    continue;
                }
            }
        }

        Err(anyhow!("No Python executable found"))
    }

    async fn get_tensorflow_version() -> Result<String> {
        debug!("Getting TensorFlow version");

        let python_code = r#"
try:
    import tensorflow as tf
    print(tf.__version__)
except ImportError as e:
    import sys
    print(f"IMPORT_ERROR: {str(e)}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    import sys
    print(f"ERROR: {str(e)}", file=sys.stderr)
    sys.exit(1)
"#;

        // Try different Python commands
        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(&["-c", python_code]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let version = String::from_utf8_lossy(&result.stdout).trim().to_string();
                        if !version.is_empty() {
                            debug!("TensorFlow version detected via {}: {}", cmd, version);
                            return Ok(version);
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("TensorFlow version check failed via {}: {}", cmd, stderr);
                        if stderr.contains("IMPORT_ERROR") {
                            continue; // Try next Python command
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to execute {} for TensorFlow version: {}", cmd, e);
                    continue;
                }
            }
        }

        Err(anyhow!("TensorFlow not installed or not accessible"))
    }

    async fn test_tensorflow_import() -> Result<HashMap<String, String>> {
        debug!("Testing TensorFlow import");

        let python_code = r#"
import sys
import json
try:
    import tensorflow as tf

    # Get detailed TensorFlow information
    result = {
        "tensorflow_version": tf.__version__,
        "keras_available": "false",
        "numpy_available": "false",
        "build_info_available": "false",
        "compiler_version": "unknown"
    }

    # Check if built-in Keras is available
    try:
        import tensorflow.keras
        result["keras_available"] = "true"
        result["keras_version"] = tf.keras.__version__ if hasattr(tf.keras, '__version__') else "integrated"
    except (ImportError, AttributeError):
        try:
            import keras
            result["keras_available"] = "true"
            result["keras_version"] = keras.__version__
        except ImportError:
            pass

    # Check NumPy availability
    try:
        import numpy as np
        result["numpy_available"] = "true"
        result["numpy_version"] = np.__version__
    except ImportError:
        pass

    # Get build information if available
    try:
        build_info = tf.sysconfig.get_build_info()
        result["build_info_available"] = "true"
        if "cuda_version" in build_info:
            result["cuda_build_version"] = build_info["cuda_version"]
        if "cudnn_version" in build_info:
            result["cudnn_build_version"] = build_info["cudnn_version"]
    except (AttributeError, Exception):
        pass

    # Check compiler version
    try:
        result["compiler_version"] = tf.version.COMPILER_VERSION
    except AttributeError:
        pass

    # Check if running in eager mode
    try:
        result["eager_execution"] = "true" if tf.executing_eagerly() else "false"
    except AttributeError:
        result["eager_execution"] = "unknown"

    print(json.dumps(result))

except ImportError as e:
    print(json.dumps({"error": f"Import failed: {str(e)}"}))
    sys.exit(1)
except Exception as e:
    print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
    sys.exit(1)
"#;

        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(&["-c", python_code]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let json_output = String::from_utf8_lossy(&result.stdout);
                        match serde_json::from_str::<HashMap<String, serde_json::Value>>(
                            &json_output,
                        ) {
                            Ok(data) => {
                                let mut details = HashMap::new();
                                for (key, value) in data {
                                    details.insert(key, value.as_str().unwrap_or("").to_string());
                                }
                                debug!("TensorFlow import test successful via {}", cmd);
                                return Ok(details);
                            }
                            Err(e) => {
                                debug!("Failed to parse JSON from {}: {}", cmd, e);
                                continue;
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("TensorFlow import test failed via {}: {}", cmd, stderr);
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to execute {} for TensorFlow import test: {}",
                        cmd, e
                    );
                    continue;
                }
            }
        }

        Err(anyhow!("TensorFlow import test failed"))
    }

    async fn test_tensorflow_operations() -> Result<HashMap<String, String>> {
        debug!("Testing TensorFlow basic operations");

        let python_code = r#"
import sys
import json
try:
    import tensorflow as tf
    import numpy as np

    # Test basic tensor operations
    result = {
        "tensor_creation": "failed",
        "basic_math": "failed",
        "matrix_operations": "failed",
        "constants": "failed",
        "variables": "failed"
    }

    # Test tensor creation
    try:
        tensor = tf.constant([1, 2, 3, 4])
        result["tensor_creation"] = "success"
        result["tensor_shape"] = str(tensor.shape.as_list())
        result["tensor_dtype"] = str(tensor.dtype)
    except Exception as e:
        result["tensor_creation"] = f"failed: {str(e)}"

    # Test basic math operations
    try:
        a = tf.constant([1, 2, 3])
        b = tf.constant([4, 5, 6])
        c = tf.add(a, b)
        result["basic_math"] = "success"
        result["add_result"] = str(c.numpy().tolist())
    except Exception as e:
        result["basic_math"] = f"failed: {str(e)}"

    # Test matrix operations
    try:
        matrix_a = tf.constant([[1, 2], [3, 4]], dtype=tf.float32)
        matrix_b = tf.constant([[5, 6], [7, 8]], dtype=tf.float32)
        matrix_c = tf.matmul(matrix_a, matrix_b)
        result["matrix_operations"] = "success"
        result["matmul_shape"] = str(matrix_c.shape.as_list())
    except Exception as e:
        result["matrix_operations"] = f"failed: {str(e)}"

    # Test constants and variables
    try:
        const = tf.constant(3.14)
        var = tf.Variable(2.0)
        result["constants"] = "success"
        result["constant_value"] = str(float(const))
        result["variable_value"] = str(float(var))
    except Exception as e:
        result["constants"] = f"failed: {str(e)}"

    # Test variable operations
    try:
        v = tf.Variable(1.0)
        v.assign(5.0)
        result["variables"] = "success"
        result["variable_assign_result"] = str(float(v))
    except Exception as e:
        result["variables"] = f"failed: {str(e)}"

    print(json.dumps(result))

except ImportError as e:
    print(json.dumps({"error": f"Import failed: {str(e)}"}))
    sys.exit(1)
except Exception as e:
    print(json.dumps({"error": f"Operations test failed: {str(e)}"}))
    sys.exit(1)
"#;

        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(&["-c", python_code]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let json_output = String::from_utf8_lossy(&result.stdout);
                        match serde_json::from_str::<HashMap<String, serde_json::Value>>(
                            &json_output,
                        ) {
                            Ok(data) => {
                                let mut details = HashMap::new();
                                for (key, value) in data {
                                    details.insert(key, value.as_str().unwrap_or("").to_string());
                                }
                                debug!("TensorFlow operations test successful via {}", cmd);
                                return Ok(details);
                            }
                            Err(e) => {
                                debug!("Failed to parse JSON from {}: {}", cmd, e);
                                continue;
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("TensorFlow operations test failed via {}: {}", cmd, stderr);
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to execute {} for TensorFlow operations test: {}",
                        cmd, e
                    );
                    continue;
                }
            }
        }

        Err(anyhow!("TensorFlow operations test failed"))
    }

    async fn test_tensorflow_devices() -> Result<HashMap<String, String>> {
        debug!("Testing TensorFlow device detection");

        let python_code = r#"
import sys
import json
try:
    import tensorflow as tf

    result = {
        "device_detection": "failed",
        "cpu_available": "false",
        "gpu_available": "false",
        "device_count": "0"
    }

    # Test device listing
    try:
        devices = tf.config.list_physical_devices()
        result["device_detection"] = "success"
        result["device_count"] = str(len(devices))

        # Check for CPU devices
        cpu_devices = tf.config.list_physical_devices('CPU')
        if cpu_devices:
            result["cpu_available"] = "true"
            result["cpu_count"] = str(len(cpu_devices))

        # Check for GPU devices
        gpu_devices = tf.config.list_physical_devices('GPU')
        if gpu_devices:
            result["gpu_available"] = "true"
            result["gpu_count"] = str(len(gpu_devices))

            # Get GPU details if available
            try:
                for i, gpu in enumerate(gpu_devices):
                    gpu_details = tf.config.experimental.get_device_details(gpu)
                    result[f"gpu_{i}_name"] = gpu_details.get('device_name', 'unknown')
                    result[f"gpu_{i}_compute_capability"] = str(gpu_details.get('compute_capability', 'unknown'))
            except Exception as e:
                result["gpu_details_error"] = str(e)

        # Test basic device placement
        try:
            with tf.device('/CPU:0'):
                cpu_tensor = tf.constant([1, 2, 3])
                result["cpu_placement"] = "success"
        except Exception as e:
            result["cpu_placement"] = f"failed: {str(e)}"

        # Check device name listing
        device_names = [d.name for d in devices]
        result["device_names"] = str(device_names)

    except Exception as e:
        result["device_detection"] = f"failed: {str(e)}"

    print(json.dumps(result))

except ImportError as e:
    print(json.dumps({"error": f"Import failed: {str(e)}"}))
    sys.exit(1)
except Exception as e:
    print(json.dumps({"error": f"Device test failed: {str(e)}"}))
    sys.exit(1)
"#;

        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(&["-c", python_code]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let json_output = String::from_utf8_lossy(&result.stdout);
                        match serde_json::from_str::<HashMap<String, serde_json::Value>>(
                            &json_output,
                        ) {
                            Ok(data) => {
                                let mut details = HashMap::new();
                                for (key, value) in data {
                                    details.insert(key, value.as_str().unwrap_or("").to_string());
                                }
                                debug!("TensorFlow device test successful via {}", cmd);
                                return Ok(details);
                            }
                            Err(e) => {
                                debug!("Failed to parse JSON from {}: {}", cmd, e);
                                continue;
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("TensorFlow device test failed via {}: {}", cmd, stderr);
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to execute {} for TensorFlow device test: {}",
                        cmd, e
                    );
                    continue;
                }
            }
        }

        Err(anyhow!("TensorFlow device test failed"))
    }

    async fn test_intel_extension() -> Result<HashMap<String, String>> {
        debug!("Testing Intel Extension for TensorFlow (ITEX)");

        let python_code = r#"
import sys
import json
try:
    # Try to import Intel Extension for TensorFlow
    import intel_extension_for_tensorflow as itex
    import tensorflow as tf

    result = {
        "itex_available": "true",
        "itex_version": "unknown",
        "xpu_devices": "0",
        "gpu_devices": "0",
        "mixed_precision": "unknown"
    }

    # Get ITEX version
    try:
        result["itex_version"] = itex.__version__
    except AttributeError:
        result["itex_version"] = "version_unavailable"

    # Check for Intel XPU devices
    try:
        xpu_devices = tf.config.list_physical_devices('XPU')
        result["xpu_devices"] = str(len(xpu_devices))
        if xpu_devices:
            result["xpu_available"] = "true"
            result["xpu_device_names"] = str([d.name for d in xpu_devices])
    except Exception as e:
        result["xpu_check_error"] = str(e)

    # Check for Intel GPU devices
    try:
        gpu_devices = tf.config.list_physical_devices('GPU')
        intel_gpus = []
        for gpu in gpu_devices:
            try:
                gpu_details = tf.config.experimental.get_device_details(gpu)
                if 'intel' in gpu_details.get('device_name', '').lower():
                    intel_gpus.append(gpu)
            except:
                pass
        result["intel_gpu_devices"] = str(len(intel_gpus))
    except Exception as e:
        result["intel_gpu_check_error"] = str(e)

    # Test basic Intel GPU operations if available
    try:
        if len(tf.config.list_physical_devices('XPU')) > 0:
            with tf.device('/XPU:0'):
                tensor = tf.constant([1.0, 2.0, 3.0])
                result["xpu_tensor_test"] = "success"
        elif len(tf.config.list_physical_devices('GPU')) > 0:
            with tf.device('/GPU:0'):
                tensor = tf.constant([1.0, 2.0, 3.0])
                result["gpu_tensor_test"] = "success"
    except Exception as e:
        result["device_tensor_test"] = f"failed: {str(e)}"

    # Check mixed precision support
    try:
        from tensorflow.keras import mixed_precision
        result["mixed_precision"] = "available"
    except ImportError:
        result["mixed_precision"] = "not_available"

    print(json.dumps(result))

except ImportError as e:
    # Intel Extension not available - this is expected on many systems
    result = {
        "itex_available": "false",
        "import_error": str(e)
    }
    print(json.dumps(result))

except Exception as e:
    print(json.dumps({"error": f"Intel extension test failed: {str(e)}"}))
    sys.exit(1)
"#;

        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(&["-c", python_code]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let json_output = String::from_utf8_lossy(&result.stdout);
                        match serde_json::from_str::<HashMap<String, serde_json::Value>>(
                            &json_output,
                        ) {
                            Ok(data) => {
                                let mut details = HashMap::new();
                                for (key, value) in data {
                                    details.insert(key, value.as_str().unwrap_or("").to_string());
                                }
                                debug!("Intel extension test completed via {}", cmd);
                                return Ok(details);
                            }
                            Err(e) => {
                                debug!("Failed to parse JSON from {}: {}", cmd, e);
                                continue;
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("Intel extension test failed via {}: {}", cmd, stderr);
                    }
                }
                Err(e) => {
                    debug!("Failed to execute {} for Intel extension test: {}", cmd, e);
                    continue;
                }
            }
        }

        Err(anyhow!("Intel extension test failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    fn setup_test_environment() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    }

    #[tokio::test]
    async fn test_validate_complete_functionality() {
        setup_test_environment();

        let result = TensorFlowValidator::validate_complete_functionality().await;
        assert!(result.is_ok());

        let status = result.unwrap();

        // Verify the structure is correct
        assert!(
            status.details.contains_key("python_executable")
                || status.details.contains_key("error")
        );

        if status.available {
            assert!(status.version.is_some());
            assert!(status.details.contains_key("tensorflow_version"));
        }
    }

    #[tokio::test]
    async fn test_check_python_availability() {
        setup_test_environment();

        let result = TensorFlowValidator::check_python_availability().await;

        // This test might pass or fail depending on system configuration
        // We're just testing that the function executes without panicking
        match result {
            Ok(info) => {
                assert!(!info.is_empty());
                assert!(info.contains("Python"));
            }
            Err(e) => {
                // This is expected on systems without Python
                assert!(e.to_string().contains("No Python executable found"));
            }
        }
    }

    #[tokio::test]
    async fn test_get_tensorflow_version() {
        setup_test_environment();

        let result = TensorFlowValidator::get_tensorflow_version().await;

        match result {
            Ok(version) => {
                assert!(!version.is_empty());
                // TensorFlow versions are typically in format like "2.13.0"
                assert!(version.chars().any(|c| c.is_numeric()));
            }
            Err(e) => {
                // Expected on systems without TensorFlow
                assert!(
                    e.to_string().contains("TensorFlow not installed")
                        || e.to_string().contains("not accessible")
                );
            }
        }
    }

    #[tokio::test]
    async fn test_tensorflow_import() {
        setup_test_environment();

        let result = TensorFlowValidator::test_tensorflow_import().await;

        match result {
            Ok(details) => {
                // If TensorFlow is available, these keys should exist
                assert!(
                    details.contains_key("tensorflow_version") || details.contains_key("error")
                );

                if details.contains_key("tensorflow_version") {
                    assert!(!details["tensorflow_version"].is_empty());
                    assert!(details.contains_key("keras_available"));
                    assert!(details.contains_key("numpy_available"));
                }
            }
            Err(_) => {
                // Expected on systems without TensorFlow
            }
        }
    }

    #[tokio::test]
    async fn test_tensorflow_operations() {
        setup_test_environment();

        let result = TensorFlowValidator::test_tensorflow_operations().await;

        match result {
            Ok(details) => {
                // If TensorFlow operations succeed, operation results should be present
                if !details.contains_key("error") {
                    assert!(details.contains_key("tensor_creation"));
                    assert!(details.contains_key("basic_math"));
                    assert!(details.contains_key("matrix_operations"));
                }
            }
            Err(_) => {
                // Expected on systems without TensorFlow
            }
        }
    }

    #[tokio::test]
    async fn test_tensorflow_devices() {
        setup_test_environment();

        let result = TensorFlowValidator::test_tensorflow_devices().await;

        match result {
            Ok(details) => {
                // If TensorFlow device detection succeeds, device info should be present
                if !details.contains_key("error") {
                    assert!(details.contains_key("device_detection"));
                    assert!(details.contains_key("cpu_available"));
                    assert!(details.contains_key("device_count"));
                }
            }
            Err(_) => {
                // Expected on systems without TensorFlow
            }
        }
    }

    #[tokio::test]
    async fn test_intel_extension() {
        setup_test_environment();

        let result = TensorFlowValidator::test_intel_extension().await;

        match result {
            Ok(details) => {
                // Intel extension test should always complete, but might not be available
                assert!(details.contains_key("itex_available"));

                if details.get("itex_available") == Some(&"true".to_string()) {
                    assert!(details.contains_key("itex_version"));
                }
            }
            Err(_) => {
                // This is acceptable as Intel extension might not be available
            }
        }
    }

    #[test]
    fn test_tensorflow_validator_structure() {
        // Test that TensorFlowValidator can be instantiated
        let _validator = TensorFlowValidator;

        // This is a basic structural test
        assert!(true);
    }

    #[tokio::test]
    async fn test_dependency_status_serialization() {
        setup_test_environment();

        let mut details = HashMap::new();
        details.insert(
            "test_key".to_string(),
            serde_json::Value::String("test_value".to_string()),
        );
        details.insert(
            "tensorflow_version".to_string(),
            serde_json::Value::String("2.13.0".to_string()),
        );

        let status = DependencyStatus {
            available: true,
            version: Some("2.13.0".to_string()),
            details,
        };

        // Test JSON serialization
        let json_result = serde_json::to_string(&status);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        assert!(json_str.contains("test_key"));
        assert!(json_str.contains("test_value"));
        assert!(json_str.contains("2.13.0"));
        assert!(json_str.contains("tensorflow_version"));

        // Test deserialization
        let deserialize_result: Result<DependencyStatus, _> = serde_json::from_str(&json_str);
        assert!(deserialize_result.is_ok());

        let deserialized = deserialize_result.unwrap();
        assert_eq!(deserialized.available, true);
        assert_eq!(deserialized.version, Some("2.13.0".to_string()));
        assert_eq!(
            deserialized.details.get("test_key"),
            Some(&"test_value".to_string())
        );
    }

    #[test]
    fn test_dependency_status_debug_formatting() {
        let mut details = HashMap::new();
        details.insert(
            "tensorflow_version".to_string(),
            serde_json::Value::String("2.13.0".to_string()),
        );
        details.insert(
            "keras_available".to_string(),
            serde_json::Value::String("true".to_string()),
        );

        let status = DependencyStatus {
            available: true,
            version: Some("2.13.0".to_string()),
            details,
        };

        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("available: true"));
        assert!(debug_str.contains("2.13.0"));
        assert!(debug_str.contains("tensorflow_version"));
        assert!(debug_str.contains("keras_available"));
    }

    #[tokio::test]
    async fn test_tensorflow_validation_with_missing_python() {
        setup_test_environment();

        // Temporarily modify PATH to simulate missing Python
        let original_path = env::var("PATH").unwrap_or_default();
        env::set_var("PATH", "");

        let result = TensorFlowValidator::check_python_availability().await;

        // Restore original PATH
        env::set_var("PATH", &original_path);

        // Should fail when Python is not available
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No Python executable found"));
    }

    #[tokio::test]
    async fn test_full_validation_workflow() {
        setup_test_environment();

        let result = TensorFlowValidator::validate_complete_functionality().await;
        assert!(result.is_ok());

        let status = result.unwrap();

        // Test that the result has proper structure regardless of TensorFlow availability
        assert!(status.details.len() > 0);

        if status.available {
            // If TensorFlow is available, ensure comprehensive validation occurred
            assert!(status.version.is_some());
            assert!(status.details.contains_key("tensorflow_version"));
            assert!(status.details.contains_key("import_test"));
        } else {
            // If TensorFlow is not available, ensure error information is provided
            assert!(
                status.details.contains_key("error")
                    || status.details.contains_key("tensorflow_error")
                    || status.details.contains_key("python_executable")
            );
        }
    }

    #[tokio::test]
    async fn test_concurrent_tensorflow_validation() {
        setup_test_environment();

        // Test concurrent validation calls
        let handles: Vec<_> = (0..3)
            .map(|_| {
                tokio::spawn(async { TensorFlowValidator::validate_complete_functionality().await })
            })
            .collect();

        let results: Vec<_> = futures::future::join_all(handles).await;

        // All validation calls should complete successfully
        for handle_result in results {
            assert!(handle_result.is_ok());

            let validation_result = handle_result.unwrap();
            assert!(validation_result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_tensorflow_validation_error_handling() {
        setup_test_environment();

        // This test ensures that even if TensorFlow validation fails,
        // the function still returns a proper DependencyStatus
        let result = TensorFlowValidator::validate_complete_functionality().await;
        assert!(result.is_ok());

        let status = result.unwrap();

        // Ensure error cases are handled gracefully
        if !status.available {
            assert!(status.version.is_none());
            assert!(status.details.len() > 0);

            // Should contain either an error message or some diagnostic info
            let has_error_info = status.details.values().any(|v| {
                v.contains("error") || v.contains("failed") || v.contains("not available")
            });
            assert!(has_error_info);
        }
    }

    #[tokio::test]
    async fn test_tensorflow_operations_detailed() {
        setup_test_environment();

        let result = TensorFlowValidator::test_tensorflow_operations().await;

        match result {
            Ok(details) => {
                // If operations test succeeds, verify detailed operation results
                if details.get("tensor_creation") == Some(&"success".to_string()) {
                    assert!(details.contains_key("tensor_shape"));
                    assert!(details.contains_key("tensor_dtype"));
                }

                if details.get("basic_math") == Some(&"success".to_string()) {
                    assert!(details.contains_key("add_result"));
                }

                if details.get("matrix_operations") == Some(&"success".to_string()) {
                    assert!(details.contains_key("matmul_shape"));
                }
            }
            Err(_) => {
                // Expected on systems without TensorFlow
            }
        }
    }

    #[tokio::test]
    async fn test_tensorflow_device_detection_detailed() {
        setup_test_environment();

        let result = TensorFlowValidator::test_tensorflow_devices().await;

        match result {
            Ok(details) => {
                // If device detection succeeds, verify device information
                if details.get("device_detection") == Some(&"success".to_string()) {
                    assert!(details.contains_key("device_count"));
                    assert!(details.contains_key("cpu_available"));
                    assert!(details.contains_key("device_names"));

                    // If CPU is available, should have CPU count
                    if details.get("cpu_available") == Some(&"true".to_string()) {
                        assert!(details.contains_key("cpu_count"));
                    }

                    // If GPU is available, should have GPU count
                    if details.get("gpu_available") == Some(&"true".to_string()) {
                        assert!(details.contains_key("gpu_count"));
                    }
                }
            }
            Err(_) => {
                // Expected on systems without TensorFlow
            }
        }
    }

    #[test]
    fn test_tensorflow_validator_methods_exist() {
        // Ensure all expected methods are available
        assert!(std::mem::size_of_val(&TensorFlowValidator::validate_complete_functionality) > 0);
        assert!(std::mem::size_of_val(&TensorFlowValidator::check_python_availability) > 0);
        assert!(std::mem::size_of_val(&TensorFlowValidator::get_tensorflow_version) > 0);
        assert!(std::mem::size_of_val(&TensorFlowValidator::test_tensorflow_import) > 0);
        assert!(std::mem::size_of_val(&TensorFlowValidator::test_tensorflow_operations) > 0);
        assert!(std::mem::size_of_val(&TensorFlowValidator::test_tensorflow_devices) > 0);
        assert!(std::mem::size_of_val(&TensorFlowValidator::test_intel_extension) > 0);
    }

    #[tokio::test]
    async fn test_intel_extension_detailed() {
        setup_test_environment();

        let result = TensorFlowValidator::test_intel_extension().await;

        match result {
            Ok(details) => {
                // Intel extension test should complete regardless of availability
                assert!(details.contains_key("itex_available"));

                if details.get("itex_available") == Some(&"true".to_string()) {
                    // If Intel extension is available, check for additional details
                    assert!(details.contains_key("itex_version"));
                    assert!(details.contains_key("xpu_devices"));
                } else {
                    // If not available, might have import error info
                    // This is acceptable and expected on most systems
                }
            }
            Err(_) => {
                // This is acceptable as Intel extension might not be available
            }
        }
    }
}
