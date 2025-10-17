use crate::dependencies::DependencyStatus;
use anyhow::{anyhow, Result};
use serde_json;
use std::collections::HashMap;
use std::process::Command;
use tracing::{debug, info, warn};

pub struct FlaskValidator;

impl FlaskValidator {
    pub async fn validate_flask_functionality() -> Result<DependencyStatus> {
        info!("Starting Flask dependency validation");

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

        // Check Flask installation and version
        let flask_version = Self::get_flask_version().await;
        match flask_version {
            Ok(version) => {
                info!("Flask version detected: {}", version);
                details.insert(
                    "flask_version".to_string(),
                    serde_json::Value::String(version.clone()),
                );

                // Test Flask import and basic functionality
                let import_test = Self::test_flask_import().await;
                match import_test {
                    Ok(import_info) => {
                        details.insert(
                            "import_test".to_string(),
                            serde_json::Value::String("success".to_string()),
                        );
                        for (key, value) in import_info {
                            details.insert(key, serde_json::Value::String(value));
                        }

                        // Test Flask application creation
                        let app_test = Self::test_flask_app_creation().await;
                        match app_test {
                            Ok(app_info) => {
                                details.insert(
                                    "app_creation_test".to_string(),
                                    serde_json::Value::String("success".to_string()),
                                );
                                for (key, value) in app_info {
                                    details.insert(key, serde_json::Value::String(value));
                                }

                                // Test Flask routing functionality
                                let routing_test = Self::test_flask_routing().await;
                                match routing_test {
                                    Ok(routing_info) => {
                                        details.insert(
                                            "routing_test".to_string(),
                                            serde_json::Value::String("success".to_string()),
                                        );
                                        for (key, value) in routing_info {
                                            details.insert(key, serde_json::Value::String(value));
                                        }

                                        return Ok(DependencyStatus {
                                            available: true,
                                            version: Some(version),
                                            details,
                                        });
                                    }
                                    Err(e) => {
                                        warn!("Flask routing test failed: {}", e);
                                        details.insert(
                                            "routing_test".to_string(),
                                            serde_json::Value::String(format!("failed: {}", e)),
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Flask app creation test failed: {}", e);
                                details.insert(
                                    "app_creation_test".to_string(),
                                    serde_json::Value::String(format!("failed: {}", e)),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Flask import test failed: {}", e);
                        details.insert(
                            "import_test".to_string(),
                            serde_json::Value::String(format!("failed: {}", e)),
                        );
                    }
                }

                // If we reach here, Flask is installed but some functionality failed
                Ok(DependencyStatus {
                    available: true,
                    version: Some(version),
                    details,
                })
            }
            Err(e) => {
                warn!("Flask not available or version detection failed: {}", e);
                details.insert(
                    "flask_error".to_string(),
                    serde_json::Value::String(e.to_string()),
                );

                Ok(DependencyStatus {
                    available: false,
                    version: None,
                    details,
                })
            }
        }
    }

    async fn check_python_availability() -> Result<String> {
        debug!("Checking Python availability");

        // Try different Python executable names
        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(["--version"]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let version_output = String::from_utf8_lossy(&result.stdout);
                        let version_line = version_output.trim();
                        debug!("Found Python: {} -> {}", cmd, version_line);
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

    async fn get_flask_version() -> Result<String> {
        debug!("Getting Flask version");

        let python_code = r#"
try:
    import flask
    print(flask.__version__)
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
            let output = Command::new(cmd).args(["-c", python_code]).output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        let version = String::from_utf8_lossy(&result.stdout).trim().to_string();
                        if !version.is_empty() {
                            debug!("Flask version detected via {}: {}", cmd, version);
                            return Ok(version);
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("Flask version check failed via {}: {}", cmd, stderr);
                        if stderr.contains("IMPORT_ERROR") {
                            continue; // Try next Python command
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to execute {} for Flask version: {}", cmd, e);
                    continue;
                }
            }
        }

        Err(anyhow!("Flask not installed or not accessible"))
    }

    async fn test_flask_import() -> Result<HashMap<String, String>> {
        debug!("Testing Flask import");

        let python_code = r#"
import sys
import json
try:
    import flask
    from flask import Flask

    # Get detailed Flask information
    result = {
        "flask_version": flask.__version__,
        "flask_file": flask.__file__,
        "werkzeug_available": "false",
        "jinja2_available": "false",
        "click_available": "false"
    }

    try:
        import werkzeug
        result["werkzeug_available"] = "true"
        result["werkzeug_version"] = werkzeug.__version__
    except ImportError:
        pass

    try:
        import jinja2
        result["jinja2_available"] = "true"
        result["jinja2_version"] = jinja2.__version__
    except ImportError:
        pass

    try:
        import click
        result["click_available"] = "true"
        result["click_version"] = click.__version__
    except ImportError:
        pass

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
            let output = Command::new(cmd).args(["-c", python_code]).output();

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
                                debug!("Flask import test successful via {}", cmd);
                                return Ok(details);
                            }
                            Err(e) => {
                                debug!("Failed to parse JSON from {}: {}", cmd, e);
                                continue;
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("Flask import test failed via {}: {}", cmd, stderr);
                    }
                }
                Err(e) => {
                    debug!("Failed to execute {} for Flask import test: {}", cmd, e);
                    continue;
                }
            }
        }

        Err(anyhow!("Flask import test failed"))
    }

    async fn test_flask_app_creation() -> Result<HashMap<String, String>> {
        debug!("Testing Flask app creation");

        let python_code = r#"
import sys
import json
try:
    from flask import Flask

    # Create a test Flask app
    app = Flask(__name__)

    # Test basic app properties
    result = {
        "app_name": app.name,
        "app_instance_path": app.instance_path,
        "app_root_path": app.root_path,
        "config_available": "true" if hasattr(app, 'config') else "false",
        "url_map_available": "true" if hasattr(app, 'url_map') else "false",
        "blueprints_available": "true" if hasattr(app, 'blueprints') else "false"
    }

    # Test configuration access
    try:
        app.config['TESTING'] = True
        result["config_writable"] = "true"
    except Exception as e:
        result["config_writable"] = f"false: {str(e)}"

    print(json.dumps(result))

except ImportError as e:
    print(json.dumps({"error": f"Import failed: {str(e)}"}))
    sys.exit(1)
except Exception as e:
    print(json.dumps({"error": f"App creation failed: {str(e)}"}))
    sys.exit(1)
"#;

        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(["-c", python_code]).output();

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
                                debug!("Flask app creation test successful via {}", cmd);
                                return Ok(details);
                            }
                            Err(e) => {
                                debug!("Failed to parse JSON from {}: {}", cmd, e);
                                continue;
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("Flask app creation test failed via {}: {}", cmd, stderr);
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to execute {} for Flask app creation test: {}",
                        cmd, e
                    );
                    continue;
                }
            }
        }

        Err(anyhow!("Flask app creation test failed"))
    }

    async fn test_flask_routing() -> Result<HashMap<String, String>> {
        debug!("Testing Flask routing functionality");

        let python_code = r#"
import sys
import json
try:
    from flask import Flask

    # Create a test Flask app
    app = Flask(__name__)

    # Test route registration
    @app.route('/')
    def home():
        return 'Hello, World!'

    @app.route('/test')
    def test():
        return 'Test route'

    @app.route('/user/<name>')
    def user(name):
        return f'Hello, {name}!'

    # Test app context and URL building
    with app.app_context():
        result = {
            "routes_registered": str(len(app.url_map._rules)),
            "url_map_available": "true",
            "test_client_available": "true" if hasattr(app, 'test_client') else "false"
        }

        # Test URL building
        try:
            from flask import url_for
            home_url = url_for('home')
            test_url = url_for('test')
            user_url = url_for('user', name='testuser')

            result["url_building"] = "success"
            result["home_url"] = home_url
            result["test_url"] = test_url
            result["user_url"] = user_url
        except Exception as e:
            result["url_building"] = f"failed: {str(e)}"

        # Test basic client functionality
        try:
            client = app.test_client()
            response = client.get('/')
            result["test_client_functional"] = "true"
            result["test_response_status"] = str(response.status_code)
            result["test_response_data"] = response.get_data(as_text=True)
        except Exception as e:
            result["test_client_functional"] = f"false: {str(e)}"

    print(json.dumps(result))

except ImportError as e:
    print(json.dumps({"error": f"Import failed: {str(e)}"}))
    sys.exit(1)
except Exception as e:
    print(json.dumps({"error": f"Routing test failed: {str(e)}"}))
    sys.exit(1)
"#;

        let python_commands = vec!["python", "python3", "py"];

        for cmd in python_commands {
            let output = Command::new(cmd).args(["-c", python_code]).output();

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
                                debug!("Flask routing test successful via {}", cmd);
                                return Ok(details);
                            }
                            Err(e) => {
                                debug!("Failed to parse JSON from {}: {}", cmd, e);
                                continue;
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        debug!("Flask routing test failed via {}: {}", cmd, stderr);
                    }
                }
                Err(e) => {
                    debug!("Failed to execute {} for Flask routing test: {}", cmd, e);
                    continue;
                }
            }
        }

        Err(anyhow!("Flask routing test failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn setup_test_environment() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    }

    #[tokio::test]
    async fn test_validate_flask_functionality() {
        setup_test_environment();

        let result = FlaskValidator::validate_flask_functionality().await;
        assert!(result.is_ok());

        let status = result.unwrap();

        // Verify the structure is correct
        assert!(
            status.details.contains_key("python_executable")
                || status.details.contains_key("error")
        );

        if status.available {
            assert!(status.version.is_some());
            assert!(status.details.contains_key("flask_version"));
        }
    }

    #[tokio::test]
    async fn test_check_python_availability() {
        setup_test_environment();

        let result = FlaskValidator::check_python_availability().await;

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
    async fn test_get_flask_version() {
        setup_test_environment();

        let result = FlaskValidator::get_flask_version().await;

        match result {
            Ok(version) => {
                assert!(!version.is_empty());
                // Flask versions are typically in format like "2.3.3"
                assert!(version.chars().any(|c| c.is_numeric()));
            }
            Err(e) => {
                // Expected on systems without Flask
                assert!(
                    e.to_string().contains("Flask not installed")
                        || e.to_string().contains("not accessible")
                );
            }
        }
    }

    #[tokio::test]
    async fn test_flask_import() {
        setup_test_environment();

        let result = FlaskValidator::test_flask_import().await;

        match result {
            Ok(details) => {
                // If Flask is available, these keys should exist
                assert!(details.contains_key("flask_version") || details.contains_key("error"));

                if details.contains_key("flask_version") {
                    assert!(!details["flask_version"].is_empty());
                    assert!(details.contains_key("flask_file"));
                }
            }
            Err(_) => {
                // Expected on systems without Flask
            }
        }
    }

    #[tokio::test]
    async fn test_flask_app_creation() {
        setup_test_environment();

        let result = FlaskValidator::test_flask_app_creation().await;

        match result {
            Ok(details) => {
                // If Flask app creation succeeds, basic properties should be present
                if !details.contains_key("error") {
                    assert!(details.contains_key("app_name"));
                    assert!(details.contains_key("config_available"));
                }
            }
            Err(_) => {
                // Expected on systems without Flask
            }
        }
    }

    #[tokio::test]
    async fn test_flask_routing() {
        setup_test_environment();

        let result = FlaskValidator::test_flask_routing().await;

        match result {
            Ok(details) => {
                // If Flask routing succeeds, routing info should be present
                if !details.contains_key("error") {
                    assert!(details.contains_key("routes_registered"));
                    assert!(details.contains_key("url_map_available"));
                }
            }
            Err(_) => {
                // Expected on systems without Flask
            }
        }
    }

    #[test]
    fn test_flask_validator_structure() {
        // Test that FlaskValidator can be instantiated
        let _validator = FlaskValidator;

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

        let status = DependencyStatus {
            available: true,
            version: Some("1.0.0".to_string()),
            details,
        };

        // Test JSON serialization
        let json_result = serde_json::to_string(&status);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        assert!(json_str.contains("test_key"));
        assert!(json_str.contains("test_value"));
        assert!(json_str.contains("1.0.0"));

        // Test deserialization
        let deserialize_result: Result<DependencyStatus, _> = serde_json::from_str(&json_str);
        assert!(deserialize_result.is_ok());

        let deserialized = deserialize_result.unwrap();
        assert_eq!(deserialized.available, true);
        assert_eq!(deserialized.version, Some("1.0.0".to_string()));
        assert_eq!(
            deserialized.details.get("test_key"),
            Some(&serde_json::Value::String("test_value".to_string()))
        );
    }

    #[test]
    fn test_dependency_status_debug_formatting() {
        let mut details = HashMap::new();
        details.insert(
            "flask_version".to_string(),
            serde_json::Value::String("2.3.3".to_string()),
        );

        let status = DependencyStatus {
            available: true,
            version: Some("2.3.3".to_string()),
            details,
        };

        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("available: true"));
        assert!(debug_str.contains("2.3.3"));
        assert!(debug_str.contains("flask_version"));
    }

    #[tokio::test]
    async fn test_flask_validation_with_missing_python() {
        setup_test_environment();

        // Temporarily modify PATH to simulate missing Python
        let original_path = env::var("PATH").unwrap_or_default();
        unsafe { env::set_var("PATH", ""); }

        let result = FlaskValidator::check_python_availability().await;

        // Restore original PATH
        unsafe { env::set_var("PATH", &original_path); }

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

        let result = FlaskValidator::validate_flask_functionality().await;
        assert!(result.is_ok());

        let status = result.unwrap();

        // Test that the result has proper structure regardless of Flask availability
        assert!(status.details.len() > 0);

        if status.available {
            // If Flask is available, ensure comprehensive validation occurred
            assert!(status.version.is_some());
            assert!(status.details.contains_key("flask_version"));
            assert!(status.details.contains_key("import_test"));
        } else {
            // If Flask is not available, ensure error information is provided
            assert!(
                status.details.contains_key("error")
                    || status.details.contains_key("flask_error")
                    || status.details.contains_key("python_executable")
            );
        }
    }

    #[tokio::test]
    async fn test_concurrent_flask_validation() {
        setup_test_environment();

        // Test concurrent validation calls
        let handles: Vec<_> = (0..3)
            .map(|_| tokio::spawn(async { FlaskValidator::validate_flask_functionality().await }))
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
    async fn test_flask_validation_error_handling() {
        setup_test_environment();

        // This test ensures that even if Python/Flask validation fails,
        // the function still returns a proper DependencyStatus
        let result = FlaskValidator::validate_flask_functionality().await;
        assert!(result.is_ok());

        let status = result.unwrap();

        // Ensure error cases are handled gracefully
        if !status.available {
            assert!(status.version.is_none());
            assert!(status.details.len() > 0);

            // Should contain either an error message or some diagnostic info
            let has_error_info = status.details.values().any(|v| {
                v.as_str().unwrap_or("").contains("error") ||
                v.as_str().unwrap_or("").contains("failed") ||
                v.as_str().unwrap_or("").contains("not available")
            });
            assert!(has_error_info);
        }
    }

    #[test]
    fn test_flask_validator_methods_exist() {
        // Ensure all expected methods are available
        assert!(std::mem::size_of_val(&FlaskValidator::validate_flask_functionality) > 0);
        assert!(std::mem::size_of_val(&FlaskValidator::check_python_availability) > 0);
        assert!(std::mem::size_of_val(&FlaskValidator::get_flask_version) > 0);
        assert!(std::mem::size_of_val(&FlaskValidator::test_flask_import) > 0);
        assert!(std::mem::size_of_val(&FlaskValidator::test_flask_app_creation) > 0);
        assert!(std::mem::size_of_val(&FlaskValidator::test_flask_routing) > 0);
    }
}
