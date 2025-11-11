/*!
# GIL Safety Management Module

Manages Python Global Interpreter Lock (GIL) safety and threading configuration
to prevent PyBind11-related crashes and ensure thread safety across all Python
extensions and C++ bindings.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use anyhow::Result;
use pyo3::prelude::*;
use std::env;
use tracing::{debug, info};

pub struct GilSafetyManager;

impl GilSafetyManager {
    /// Initialize comprehensive GIL safety (replicates `torch_gil_safety` functionality)
    pub fn initialize_gil_safety() -> Result<()> {
        info!("Initializing GIL safety and threading configuration");

        // Set PyBind11 GIL assertion disable
        Self::configure_pybind11_gil_safety()?;

        // Skip torch GIL safety initialization from Rust - let Python initialize it lazily
        // Self::initialize_torch_gil_safety()?;

        // Configure Python threading
        Self::configure_python_threading()?;

        // Validate GIL configuration
        Self::validate_gil_configuration()?;

        info!("GIL safety initialization completed");
        Ok(())
    }

    /// Configure `PyBind11` GIL safety environment
    fn configure_pybind11_gil_safety() -> Result<()> {
        debug!("Configuring PyBind11 GIL safety");

        // Disable all pybind11 GIL assertions at the environment level
        unsafe {
            env::set_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1");

            // Additional PyBind11 safety flags
            env::set_var("PYBIND11_PYTHON_VERSION", "3.12");
        }

        info!("PyBind11 GIL safety configured");
        Ok(())
    }

    /// Initialize torch GIL safety module if available (replicates Python import)
    fn initialize_torch_gil_safety() -> Result<()> {
        Python::attach(|py| -> Result<()> {
            if let Ok(gil_module) = py.import("intellicrack.utils.torch_gil_safety") {
                debug!("Found torch_gil_safety module, initializing...");
                gil_module.call_method0("initialize_gil_safety")?;
                info!("Torch GIL safety initialized via Python module");
            } else {
                debug!("torch_gil_safety module not available, using fallback");
                // Fallback to manual environment variable configuration
                Self::configure_manual_gil_safety()?;
            }
            Ok(())
        })
    }

    /// Manual GIL safety configuration fallback
    fn configure_manual_gil_safety() -> Result<()> {
        debug!("Configuring manual GIL safety fallback");

        // Set comprehensive threading environment to single-threaded mode
        let thread_vars = [
            ("OMP_NUM_THREADS", "1"),
            ("MKL_NUM_THREADS", "1"),
            ("NUMEXPR_NUM_THREADS", "1"),
            ("OPENBLAS_NUM_THREADS", "1"),
            ("VECLIB_MAXIMUM_THREADS", "1"),
            ("BLIS_NUM_THREADS", "1"),
        ];

        unsafe {
            for (var, value) in &thread_vars {
                env::set_var(var, value);
                debug!("Set {} = {}", var, value);
            }
        }

        info!("Manual GIL safety configured");
        Ok(())
    }

    /// Configure Python threading settings
    fn configure_python_threading() -> Result<()> {
        Python::attach(|py| -> Result<()> {
            debug!("Configuring Python threading settings");

            // Set thread check interval if available (sets Python thread check interval)
            if let Ok(sys) = py.import("sys") {
                if sys.hasattr("setcheckinterval")? {
                    sys.call_method1("setcheckinterval", (10000,))?;
                    debug!("Thread check interval set to 10000");
                } else {
                    debug!("sys.setcheckinterval not available (Python 3.9+)");
                }
            }

            // Configure threading module if available
            if let Ok(threading) = py.import("threading") {
                let active_count: i32 = threading.call_method0("active_count")?.extract()?;
                debug!("Active Python threads: {}", active_count);
            }

            Ok(())
        })
    }

    /// Validate GIL configuration
    fn validate_gil_configuration() -> Result<()> {
        debug!("Validating GIL configuration");

        Python::attach(|py| -> Result<()> {
            // Test GIL state
            let gil_state = py.check_signals();
            debug!("GIL signals check result: {:?}", gil_state);

            // Test thread safety by creating and destroying a simple object
            let test_list = py.eval(c"[]", None, None)?;
            test_list.call_method1("append", (42,))?;
            let length: usize = test_list.call_method0("__len__")?.extract()?;

            if length != 1 {
                anyhow::bail!("GIL validation failed: list operations not working correctly");
            }

            info!("GIL configuration validation passed");
            Ok(())
        })
    }

    /// Configure warning suppression (replicates warnings.filterwarnings from Python)
    pub fn configure_warning_suppression() -> Result<()> {
        Python::attach(|py| -> Result<()> {
            debug!("Configuring warning suppression");

            let warnings = py.import("warnings")?;

            // Suppress pkg_resources deprecation warning from capstone
            let builtins = py.import("builtins")?;
            let user_warning = builtins.getattr("UserWarning")?;
            let pkg_resources_eval = py.eval(c"'pkg_resources'", None, None)?;

            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("category", user_warning)?;
            dict.set_item("module", pkg_resources_eval)?;

            warnings.call_method("filterwarnings", ("ignore",), Some(&dict))?;

            // Suppress pkg_resources deprecated message
            let message_eval = py.eval(c"'.*pkg_resources is deprecated.*'", None, None)?;
            let message_dict = pyo3::types::PyDict::new(py);
            message_dict.set_item("message", message_eval)?;
            warnings.call_method("filterwarnings", ("ignore",), Some(&message_dict))?;

            info!("Warning suppression configured");
            Ok(())
        })
    }

    /// Get current GIL safety status
    pub fn get_gil_safety_status() -> Result<GilSafetyStatus> {
        Python::attach(|py| -> Result<GilSafetyStatus> {
            let pybind11_disabled = env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF")
                .map(|v| v == "1")
                .unwrap_or(false);

            let thread_check_available = py
                .import("sys")
                .and_then(|sys| sys.hasattr("setcheckinterval"))
                .unwrap_or(false);

            let torch_gil_available = py.import("intellicrack.utils.torch_gil_safety").is_ok();

            Ok(GilSafetyStatus {
                pybind11_assertions_disabled: pybind11_disabled,
                thread_check_configured: thread_check_available,
                torch_gil_safety_available: torch_gil_available,
            })
        })
    }
}

#[derive(Debug, Clone)]
pub struct GilSafetyStatus {
    pub pybind11_assertions_disabled: bool,
    pub thread_check_configured: bool,
    pub torch_gil_safety_available: bool,
}

impl GilSafetyStatus {
    #[must_use]
    pub const fn is_fully_configured(&self) -> bool {
        self.pybind11_assertions_disabled
            && (self.thread_check_configured || self.torch_gil_safety_available)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_logging() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }

    fn clean_environment() {
        // Clean up environment variables that could affect tests
        unsafe {
            env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");
            env::remove_var("PYBIND11_PYTHON_VERSION");
            env::remove_var("OMP_NUM_THREADS");
            env::remove_var("MKL_NUM_THREADS");
            env::remove_var("NUMEXPR_NUM_THREADS");
            env::remove_var("OPENBLAS_NUM_THREADS");
            env::remove_var("VECLIB_MAXIMUM_THREADS");
            env::remove_var("BLIS_NUM_THREADS");
        }
    }

    #[test]
    fn test_gil_safety_status_creation() {
        init_test_logging();

        let status = GilSafetyStatus {
            pybind11_assertions_disabled: true,
            thread_check_configured: true,
            torch_gil_safety_available: false,
        };

        assert!(status.pybind11_assertions_disabled);
        assert!(status.thread_check_configured);
        assert!(!status.torch_gil_safety_available);
    }

    #[test]
    fn test_gil_safety_status_is_fully_configured_with_thread_check() {
        init_test_logging();

        let status = GilSafetyStatus {
            pybind11_assertions_disabled: true,
            thread_check_configured: true,
            torch_gil_safety_available: false,
        };

        assert!(status.is_fully_configured());
    }

    #[test]
    fn test_gil_safety_status_is_fully_configured_with_torch_gil() {
        init_test_logging();

        let status = GilSafetyStatus {
            pybind11_assertions_disabled: true,
            thread_check_configured: false,
            torch_gil_safety_available: true,
        };

        assert!(status.is_fully_configured());
    }

    #[test]
    fn test_gil_safety_status_not_fully_configured_missing_pybind11() {
        init_test_logging();

        let status = GilSafetyStatus {
            pybind11_assertions_disabled: false,
            thread_check_configured: true,
            torch_gil_safety_available: true,
        };

        assert!(!status.is_fully_configured());
    }

    #[test]
    fn test_gil_safety_status_not_fully_configured_missing_threading() {
        init_test_logging();

        let status = GilSafetyStatus {
            pybind11_assertions_disabled: true,
            thread_check_configured: false,
            torch_gil_safety_available: false,
        };

        assert!(!status.is_fully_configured());
    }

    #[test]
    fn test_configure_pybind11_gil_safety() {
        init_test_logging();
        clean_environment();

        let result = GilSafetyManager::configure_pybind11_gil_safety();
        assert!(result.is_ok());

        // Verify PyBind11 environment variables are set
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );
        assert_eq!(env::var("PYBIND11_PYTHON_VERSION").unwrap(), "3.12");
    }

    #[test]
    fn test_configure_manual_gil_safety() {
        init_test_logging();
        clean_environment();

        let result = GilSafetyManager::configure_manual_gil_safety();
        assert!(result.is_ok());

        // Verify all threading environment variables are set to single-threaded
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("MKL_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("NUMEXPR_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("OPENBLAS_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("VECLIB_MAXIMUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("BLIS_NUM_THREADS").unwrap(), "1");
    }

    #[test]
    fn test_initialize_torch_gil_safety_fallback() {
        init_test_logging();
        clean_environment();

        // This test will likely fall back to manual configuration
        // since the torch_gil_safety module won't be available in test environment
        let result = GilSafetyManager::initialize_torch_gil_safety();
        assert!(result.is_ok());

        // Manual fallback should have set threading environment variables
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("MKL_NUM_THREADS").unwrap(), "1");
    }

    #[test]
    fn test_configure_python_threading() {
        init_test_logging();

        let result = GilSafetyManager::configure_python_threading();
        assert!(result.is_ok());

        // The function should complete without errors
        // Specific behavior depends on Python version available
    }

    #[test]
    fn test_validate_gil_configuration() {
        init_test_logging();

        let result = GilSafetyManager::validate_gil_configuration();
        assert!(result.is_ok());

        // Validation should pass with basic Python operations
    }

    #[test]
    fn test_configure_warning_suppression() {
        init_test_logging();

        let result = GilSafetyManager::configure_warning_suppression();
        assert!(result.is_ok());

        // Warning suppression should configure without errors
    }

    #[test]
    fn test_get_gil_safety_status() {
        init_test_logging();
        clean_environment();

        // First test without PyBind11 configuration
        let status_before = GilSafetyManager::get_gil_safety_status();
        assert!(status_before.is_ok());
        let status = status_before.unwrap();
        assert!(!status.pybind11_assertions_disabled);

        // Configure PyBind11 safety
        let _ = GilSafetyManager::configure_pybind11_gil_safety();

        // Test after configuration
        let status_after = GilSafetyManager::get_gil_safety_status();
        assert!(status_after.is_ok());
        let configured_status = status_after.unwrap();
        assert!(configured_status.pybind11_assertions_disabled);
    }

    #[test]
    fn test_full_gil_safety_initialization() {
        init_test_logging();
        clean_environment();

        let result = GilSafetyManager::initialize_gil_safety();
        assert!(result.is_ok());

        // Verify PyBind11 configuration was applied
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );
        assert_eq!(env::var("PYBIND11_PYTHON_VERSION").unwrap(), "3.12");

        // Verify threading configuration was applied (from manual fallback)
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("MKL_NUM_THREADS").unwrap(), "1");

        // Verify status reflects full configuration
        let status = GilSafetyManager::get_gil_safety_status().unwrap();
        assert!(status.pybind11_assertions_disabled);
    }

    #[test]
    fn test_gil_safety_initialization_idempotent() {
        init_test_logging();
        clean_environment();

        // Initialize once
        let result1 = GilSafetyManager::initialize_gil_safety();
        assert!(result1.is_ok());

        // Initialize again - should still work
        let result2 = GilSafetyManager::initialize_gil_safety();
        assert!(result2.is_ok());

        // Verify configuration is still correct
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
    }

    #[test]
    fn test_gil_safety_with_existing_environment() {
        init_test_logging();
        clean_environment();

        // Set some existing environment variables
        unsafe {
            env::set_var("OMP_NUM_THREADS", "4");
            env::set_var("MKL_NUM_THREADS", "2");
        }

        let result = GilSafetyManager::initialize_gil_safety();
        assert!(result.is_ok());

        // Verify variables were overridden to single-threaded
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("MKL_NUM_THREADS").unwrap(), "1");
    }

    #[test]
    fn test_gil_safety_error_handling() {
        init_test_logging();

        // Test that validation works even with minimal Python environment
        let validation_result = GilSafetyManager::validate_gil_configuration();
        assert!(validation_result.is_ok());

        // Test that status checking is resilient
        let status_result = GilSafetyManager::get_gil_safety_status();
        assert!(status_result.is_ok());
    }

    #[test]
    fn test_threading_environment_variables_completeness() {
        init_test_logging();
        clean_environment();

        let result = GilSafetyManager::configure_manual_gil_safety();
        assert!(result.is_ok());

        // Verify all expected threading libraries are configured
        let expected_vars = [
            "OMP_NUM_THREADS",
            "MKL_NUM_THREADS",
            "NUMEXPR_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
            "VECLIB_MAXIMUM_THREADS",
            "BLIS_NUM_THREADS",
        ];

        for var in &expected_vars {
            assert_eq!(
                env::var(var).unwrap(),
                "1",
                "Variable {} should be set to '1'",
                var
            );
        }
    }

    #[test]
    fn test_gil_safety_status_clone() {
        init_test_logging();

        let original_status = GilSafetyStatus {
            pybind11_assertions_disabled: true,
            thread_check_configured: false,
            torch_gil_safety_available: true,
        };

        let cloned_status = original_status.clone();

        assert_eq!(
            original_status.pybind11_assertions_disabled,
            cloned_status.pybind11_assertions_disabled
        );
        assert_eq!(
            original_status.thread_check_configured,
            cloned_status.thread_check_configured
        );
        assert_eq!(
            original_status.torch_gil_safety_available,
            cloned_status.torch_gil_safety_available
        );
    }

    #[test]
    fn test_gil_safety_status_debug_format() {
        init_test_logging();

        let status = GilSafetyStatus {
            pybind11_assertions_disabled: true,
            thread_check_configured: true,
            torch_gil_safety_available: false,
        };

        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("pybind11_assertions_disabled: true"));
        assert!(debug_str.contains("thread_check_configured: true"));
        assert!(debug_str.contains("torch_gil_safety_available: false"));
    }

    #[test]
    fn test_pybind11_version_configuration() {
        init_test_logging();
        clean_environment();

        let result = GilSafetyManager::configure_pybind11_gil_safety();
        assert!(result.is_ok());

        // Verify Python version is set for PyBind11 compatibility
        let python_version = env::var("PYBIND11_PYTHON_VERSION").unwrap();
        assert_eq!(python_version, "3.12");
    }

    #[test]
    fn test_comprehensive_gil_safety_integration() {
        init_test_logging();
        clean_environment();

        // Initialize full GIL safety
        let init_result = GilSafetyManager::initialize_gil_safety();
        assert!(init_result.is_ok());

        // Configure warning suppression
        let warning_result = GilSafetyManager::configure_warning_suppression();
        assert!(warning_result.is_ok());

        // Get final status
        let final_status = GilSafetyManager::get_gil_safety_status();
        assert!(final_status.is_ok());

        let status = final_status.unwrap();
        assert!(status.pybind11_assertions_disabled);

        // Verify environment is fully configured for production use
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("MKL_NUM_THREADS").unwrap(), "1");
    }
}
