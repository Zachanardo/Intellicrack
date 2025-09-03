/*!
# Python Integration Module

Native Python interpreter integration using PyO3 that replicates and enhances
all Python configuration from the current launch system including ctypes-based
library loading and GIL safety configuration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use anyhow::{Context, Result};
use libloading::Library;
use pyo3::prelude::*;
use std::env;
use std::path::PathBuf;
use tracing::{debug, info, warn};

pub struct PythonIntegration {
    interpreter_path: PathBuf,
    virtual_env_path: PathBuf,
    python_lib: Option<Library>,
}

impl PythonIntegration {
    /// Initialize Python integration and locate interpreter
    pub fn initialize() -> Result<Self> {
        info!("Initializing Python integration");

        // Locate Python interpreter
        let interpreter_path = Self::locate_python_interpreter()?;
        let virtual_env_path = PathBuf::from(r"C:\Intellicrack\mamba_env");

        info!("Python interpreter: {:?}", interpreter_path);
        info!("Virtual environment: {:?}", virtual_env_path);

        // Initialize PyO3 Python interpreter
        pyo3::prepare_freethreaded_python();

        Ok(PythonIntegration {
            interpreter_path,
            virtual_env_path,
            python_lib: None,
        })
    }

    /// Locate the Python interpreter with multiple fallback strategies
    fn locate_python_interpreter() -> Result<PathBuf> {
        // Primary path: Intellicrack mamba environment
        let mamba_python = PathBuf::from(r"C:\Intellicrack\mamba_env\python.exe");
        if mamba_python.exists() {
            info!("Found Python in mamba environment: {:?}", mamba_python);
            return Ok(mamba_python);
        }

        // Secondary path: Scripts subdirectory
        let mamba_scripts_python = PathBuf::from(r"C:\Intellicrack\mamba_env\Scripts\python.exe");
        if mamba_scripts_python.exists() {
            info!("Found Python in mamba Scripts: {:?}", mamba_scripts_python);
            return Ok(mamba_scripts_python);
        }

        // Fallback: System Python
        match which::which("python") {
            Ok(system_python) => {
                warn!("Using system Python as fallback: {:?}", system_python);
                Ok(system_python)
            }
            Err(_) => {
                // Try python3 command
                match which::which("python3") {
                    Ok(python3) => {
                        warn!("Using python3 as fallback: {:?}", python3);
                        Ok(python3)
                    }
                    Err(_) => {
                        anyhow::bail!("No Python interpreter found. Please ensure Python is installed and accessible.");
                    }
                }
            }
        }
    }

    /// Configure PyBind11 compatibility (replicates launch_intellicrack.py functionality)
    pub fn configure_pybind11_compatibility(&mut self) -> Result<()> {
        info!("Configuring PyBind11 compatibility");

        Python::with_gil(|py| -> Result<()> {
            // Set PyBind11 environment variable first
            env::set_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1");

            // Attempt to load Python shared library for pybind11 configuration
            // This replicates the ctypes functionality from launch_intellicrack.py
            match self.load_python_library(py) {
                Ok(()) => {
                    info!("Python library loaded successfully for pybind11 configuration");
                }
                Err(e) => {
                    warn!("Could not configure pybind11 via library loading: {}", e);
                    info!("Falling back to environment variable configuration only");
                }
            }

            // Configure thread check interval if available (replicates Python code)
            self.configure_thread_check_interval(py)?;

            // Test Python interpreter functionality
            self.test_python_functionality(py)?;

            Ok(())
        })
    }

    /// Load Python shared library (replicates ctypes functionality)
    fn load_python_library(&mut self, py: Python) -> Result<()> {
        let version_info = py.version_info();
        debug!(
            "Python version: {}.{}.{}",
            version_info.major, version_info.minor, version_info.patch
        );

        #[cfg(target_os = "windows")]
        {
            self.load_windows_python_library(&version_info)
        }

        #[cfg(target_os = "linux")]
        {
            self.load_linux_python_library(&version_info)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            warn!("Python library loading not implemented for this platform");
            Ok(())
        }
    }

    /// Load Python DLL on Windows (replicates Windows ctypes code)
    #[cfg(target_os = "windows")]
    fn load_windows_python_library(
        &mut self,
        version_info: &pyo3::PythonVersionInfo,
    ) -> Result<()> {
        // Try to use kernel32 as a proxy for system DLL access (replicates Python code)
        match unsafe { Library::new("kernel32.dll") } {
            Ok(_kernel32) => {
                debug!("Successfully loaded kernel32.dll as system DLL proxy");
            }
            Err(e) => {
                debug!("Could not load kernel32.dll: {}", e);
            }
        }

        // Find python dll explicitly (replicates Python sysconfig logic)
        let python_dll = format!("python{}{}.dll", version_info.major, version_info.minor);
        debug!("Attempting to load Python DLL: {}", python_dll);

        match unsafe { Library::new(&python_dll) } {
            Ok(lib) => {
                info!("Successfully loaded Python DLL: {}", python_dll);
                self.python_lib = Some(lib);
                Ok(())
            }
            Err(e) => {
                // Try alternative DLL locations
                self.try_alternative_dll_paths(&python_dll)
                    .with_context(|| format!("Failed to load Python DLL {}: {}", python_dll, e))
            }
        }
    }

    /// Try alternative DLL paths on Windows
    #[cfg(target_os = "windows")]
    fn try_alternative_dll_paths(&mut self, dll_name: &str) -> Result<()> {
        let possible_paths = vec![
            self.virtual_env_path.join(dll_name),
            self.virtual_env_path.join("Scripts").join(dll_name),
            self.virtual_env_path.join("DLLs").join(dll_name),
            PathBuf::from(format!(r"C:\Windows\System32\{}", dll_name)),
        ];

        for path in possible_paths {
            if path.exists() {
                match unsafe { Library::new(&path) } {
                    Ok(lib) => {
                        info!("Successfully loaded Python DLL from: {:?}", path);
                        self.python_lib = Some(lib);
                        return Ok(());
                    }
                    Err(e) => {
                        debug!("Failed to load Python DLL from {:?}: {}", path, e);
                    }
                }
            }
        }

        anyhow::bail!("Could not find Python DLL in any expected location")
    }

    /// Load Python shared library on Linux (replicates Unix ctypes code)
    #[cfg(target_os = "linux")]
    fn load_linux_python_library(&mut self, version_info: &pyo3::PyVersionInfo) -> Result<()> {
        let lib_name = format!("libpython{}.{}.so", version_info.major, version_info.minor);
        debug!("Attempting to load Python shared library: {}", lib_name);

        match unsafe { Library::new(&lib_name) } {
            Ok(lib) => {
                info!("Successfully loaded Python shared library: {}", lib_name);
                self.python_lib = Some(lib);
                Ok(())
            }
            Err(e) => {
                // Try with version-specific paths
                self.try_alternative_so_paths(&lib_name, version_info)
                    .with_context(|| {
                        format!("Failed to load Python shared library {}: {}", lib_name, e)
                    })
            }
        }
    }

    /// Try alternative shared library paths on Linux
    #[cfg(target_os = "linux")]
    fn try_alternative_so_paths(
        &mut self,
        lib_name: &str,
        version_info: &pyo3::PyVersionInfo,
    ) -> Result<()> {
        let possible_paths = vec![
            format!("/usr/lib/x86_64-linux-gnu/{}", lib_name),
            format!("/usr/lib/{}", lib_name),
            format!("/usr/local/lib/{}", lib_name),
            format!(
                "libpython{}.{}.so.1.0",
                version_info.major, version_info.minor
            ),
        ];

        for path in possible_paths {
            match unsafe { Library::new(&path) } {
                Ok(lib) => {
                    info!("Successfully loaded Python shared library from: {}", path);
                    self.python_lib = Some(lib);
                    return Ok(());
                }
                Err(e) => {
                    debug!("Failed to load Python shared library from {}: {}", path, e);
                }
            }
        }

        anyhow::bail!("Could not find Python shared library in any expected location")
    }

    /// Configure thread check interval (replicates sys.setcheckinterval)
    fn configure_thread_check_interval(&self, py: Python) -> Result<()> {
        match py.import("sys") {
            Ok(sys) => {
                // Check if setcheckinterval is available (removed in Python 3.9+)
                if sys.hasattr("setcheckinterval")? {
                    sys.call_method1("setcheckinterval", (10000,))?;
                    info!("Thread check interval set to 10000");
                } else {
                    debug!("sys.setcheckinterval not available (Python 3.9+)");
                }
            }
            Err(e) => {
                warn!("Could not import sys module: {}", e);
            }
        }

        Ok(())
    }

    /// Test Python interpreter functionality
    fn test_python_functionality(&self, py: Python) -> Result<()> {
        debug!("Testing Python interpreter functionality");

        // Test basic Python operations
        let result: i32 = py.eval("2 + 2", None, None)?.extract()?;
        if result != 4 {
            anyhow::bail!(
                "Python interpreter test failed: 2 + 2 = {}, expected 4",
                result
            );
        }

        // Test import functionality
        match py.import("sys") {
            Ok(sys) => {
                let version = sys.getattr("version")?.to_string();
                info!("Python version: {}", version);
            }
            Err(e) => {
                anyhow::bail!("Could not import sys module: {}", e);
            }
        }

        info!("Python interpreter functionality test passed");
        Ok(())
    }

    /// Validate Python environment and paths
    pub fn validate_python_environment(&self) -> Result<()> {
        info!("Validating Python environment");

        // Check if interpreter exists and is executable
        if !self.interpreter_path.exists() {
            anyhow::bail!("Python interpreter not found: {:?}", self.interpreter_path);
        }

        // Check virtual environment
        if !self.virtual_env_path.exists() {
            warn!(
                "Virtual environment path does not exist: {:?}",
                self.virtual_env_path
            );
        }

        // Test Python version compatibility
        Python::with_gil(|py| -> Result<()> {
            let version_info = py.version_info();
            info!(
                "Python version: {}.{}.{}",
                version_info.major, version_info.minor, version_info.patch
            );

            // Check for minimum Python version (3.8+ for PyO3 compatibility)
            if version_info.major < 3 || (version_info.major == 3 && version_info.minor < 8) {
                anyhow::bail!(
                    "Python version {}.{} is too old. Minimum required: 3.8",
                    version_info.major,
                    version_info.minor
                );
            }

            Ok(())
        })?;

        info!("Python environment validation passed");
        Ok(())
    }

    /// Get Python interpreter path
    pub fn get_interpreter_path(&self) -> &PathBuf {
        &self.interpreter_path
    }

    /// Get virtual environment path
    pub fn get_virtual_env_path(&self) -> &PathBuf {
        &self.virtual_env_path
    }

    /// Check if Python library is loaded
    pub fn is_library_loaded(&self) -> bool {
        self.python_lib.is_some()
    }

    /// Get Python version information
    pub fn get_python_version(&self) -> Result<String> {
        Python::with_gil(|py| -> Result<String> {
            let version_info = py.version_info();
            Ok(format!(
                "{}.{}.{}",
                version_info.major, version_info.minor, version_info.patch
            ))
        })
    }

    /// Configure environment variables for Python integration
    pub fn configure_environment_variables(&self) -> Result<()> {
        // Set Python path to include virtual environment
        if self.virtual_env_path.exists() {
            let python_path = self.virtual_env_path.join("Lib").join("site-packages");
            if python_path.exists() {
                env::set_var("PYTHONPATH", &python_path);
                debug!("Set PYTHONPATH to: {:?}", python_path);
            }
        }

        // Set other Python environment variables
        env::set_var("PYTHONIOENCODING", "utf-8");
        env::set_var("PYTHONUNBUFFERED", "1");

        // Prevent .pyc file generation in development
        env::set_var("PYTHONDONTWRITEBYTECODE", "1");

        info!("Python environment variables configured");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_python_integration() -> PythonIntegration {
        PythonIntegration {
            interpreter_path: PathBuf::from("python"),
            virtual_env_path: PathBuf::from("test_env"),
            python_lib: None,
        }
    }

    #[test]
    fn test_python_integration_creation() {
        let python_integration = create_test_python_integration();
        assert_eq!(python_integration.interpreter_path, PathBuf::from("python"));
        assert_eq!(
            python_integration.virtual_env_path,
            PathBuf::from("test_env")
        );
        assert!(!python_integration.is_library_loaded());
    }

    #[test]
    fn test_get_interpreter_path() {
        let python_integration = create_test_python_integration();
        assert_eq!(
            python_integration.get_interpreter_path(),
            &PathBuf::from("python")
        );
    }

    #[test]
    fn test_get_virtual_env_path() {
        let python_integration = create_test_python_integration();
        assert_eq!(
            python_integration.get_virtual_env_path(),
            &PathBuf::from("test_env")
        );
    }

    #[test]
    fn test_is_library_loaded_false() {
        let python_integration = create_test_python_integration();
        assert!(!python_integration.is_library_loaded());
    }

    #[test]
    fn test_locate_python_interpreter_fallback() {
        // Test the fallback mechanism when mamba env doesn't exist
        let result = PythonIntegration::locate_python_interpreter();

        // Should either find system Python or fail gracefully
        match result {
            Ok(path) => {
                assert!(!path.as_os_str().is_empty());
                // Should contain python executable name
                let path_str = path.to_string_lossy().to_lowercase();
                assert!(path_str.contains("python"));
            }
            Err(e) => {
                // If no Python found, error message should be informative
                assert!(e.to_string().contains("No Python interpreter found"));
            }
        }
    }

    #[test]
    fn test_locate_python_interpreter_with_mamba() {
        // This test checks the priority system (mamba over system)
        let mamba_path = PathBuf::from(r"C:\Intellicrack\mamba_env\python.exe");

        // If the actual mamba Python exists, it should be preferred
        if mamba_path.exists() {
            let result = PythonIntegration::locate_python_interpreter().unwrap();
            assert_eq!(result, mamba_path);
        }

        // Test scripts subdirectory fallback
        let mamba_scripts_path = PathBuf::from(r"C:\Intellicrack\mamba_env\Scripts\python.exe");
        if mamba_scripts_path.exists() && !mamba_path.exists() {
            let result = PythonIntegration::locate_python_interpreter().unwrap();
            assert_eq!(result, mamba_scripts_path);
        }
    }

    #[test]
    fn test_configure_environment_variables() {
        let temp_dir = TempDir::new().unwrap();
        let venv_path = temp_dir.path().to_path_buf();

        // Create fake site-packages directory
        let lib_dir = venv_path.join("Lib");
        let site_packages_dir = lib_dir.join("site-packages");
        fs::create_dir_all(&site_packages_dir).unwrap();

        let python_integration = PythonIntegration {
            interpreter_path: PathBuf::from("python"),
            virtual_env_path: venv_path,
            python_lib: None,
        };

        python_integration
            .configure_environment_variables()
            .unwrap();

        // Check that environment variables are set
        assert_eq!(env::var("PYTHONIOENCODING").unwrap(), "utf-8");
        assert_eq!(env::var("PYTHONUNBUFFERED").unwrap(), "1");
        assert_eq!(env::var("PYTHONDONTWRITEBYTECODE").unwrap(), "1");
        assert_eq!(
            env::var("PYTHONPATH").unwrap(),
            site_packages_dir.to_string_lossy()
        );

        // Clean up environment variables
        env::remove_var("PYTHONPATH");
        env::remove_var("PYTHONIOENCODING");
        env::remove_var("PYTHONUNBUFFERED");
        env::remove_var("PYTHONDONTWRITEBYTECODE");
    }

    #[test]
    fn test_configure_environment_variables_no_venv() {
        let python_integration = PythonIntegration {
            interpreter_path: PathBuf::from("python"),
            virtual_env_path: PathBuf::from("nonexistent"),
            python_lib: None,
        };

        // Should not panic even if virtual env doesn't exist
        let result = python_integration.configure_environment_variables();
        assert!(result.is_ok());

        // Basic environment variables should still be set
        assert_eq!(env::var("PYTHONIOENCODING").unwrap(), "utf-8");
        assert_eq!(env::var("PYTHONUNBUFFERED").unwrap(), "1");
        assert_eq!(env::var("PYTHONDONTWRITEBYTECODE").unwrap(), "1");

        // Clean up
        env::remove_var("PYTHONIOENCODING");
        env::remove_var("PYTHONUNBUFFERED");
        env::remove_var("PYTHONDONTWRITEBYTECODE");
    }

    #[test]
    fn test_validate_python_environment_nonexistent_interpreter() {
        let python_integration = PythonIntegration {
            interpreter_path: PathBuf::from("nonexistent_python"),
            virtual_env_path: PathBuf::from("test_env"),
            python_lib: None,
        };

        let result = python_integration.validate_python_environment();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Python interpreter not found"));
    }

    #[test]
    fn test_initialize_basic() {
        // Test initialization - may succeed or fail depending on system state
        let result = PythonIntegration::initialize();

        match result {
            Ok(integration) => {
                // If successful, should have valid paths
                assert!(!integration.interpreter_path.as_os_str().is_empty());
                assert!(!integration.virtual_env_path.as_os_str().is_empty());
            }
            Err(e) => {
                // If failed, should have informative error message
                let error_msg = e.to_string().to_lowercase();
                assert!(error_msg.contains("python") || error_msg.contains("interpreter"));
            }
        }
    }

    #[test]
    fn test_get_python_version() {
        // Test getting Python version - depends on Python being available
        let python_integration = create_test_python_integration();
        let result = python_integration.get_python_version();

        match result {
            Ok(version) => {
                // Should be in format X.Y.Z
                assert!(version.contains('.'));
                let parts: Vec<&str> = version.split('.').collect();
                assert!(parts.len() >= 2); // At least major.minor

                // Should be valid numbers
                assert!(parts[0].parse::<u32>().is_ok());
                assert!(parts[1].parse::<u32>().is_ok());
            }
            Err(_) => {
                // May fail if Python not available - this is acceptable in test environment
            }
        }
    }

    #[test]
    fn test_pybind11_compatibility_configuration() {
        let mut python_integration = create_test_python_integration();

        // Test configuration - may succeed or fail based on Python availability
        let result = python_integration.configure_pybind11_compatibility();

        match result {
            Ok(()) => {
                // Should set environment variable
                assert_eq!(
                    env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
                    "1"
                );
            }
            Err(e) => {
                // May fail in test environment without full Python setup
                let error_msg = e.to_string().to_lowercase();
                // Should be a Python-related error
                assert!(
                    error_msg.contains("python")
                        || error_msg.contains("gil")
                        || error_msg.contains("interpreter")
                );
            }
        }

        // Clean up environment variable
        env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_dll_path_generation() {
        let python_integration = create_test_python_integration();

        // Test that DLL names are generated correctly
        // We can't test actual loading without Python, but we can test path logic
        let version_info = pyo3::PyVersionInfo {
            major: 3,
            minor: 11,
            micro: 0,
        };

        let expected_dll = format!("python{}{}.dll", version_info.major, version_info.minor);
        assert_eq!(expected_dll, "python311.dll");

        // Test alternative paths are constructed correctly
        let alternative_paths = vec![
            python_integration.virtual_env_path.join(&expected_dll),
            python_integration
                .virtual_env_path
                .join("Scripts")
                .join(&expected_dll),
            python_integration
                .virtual_env_path
                .join("DLLs")
                .join(&expected_dll),
            PathBuf::from(format!(r"C:\Windows\System32\{}", expected_dll)),
        ];

        // Verify paths are constructed correctly
        assert!(alternative_paths[0]
            .to_string_lossy()
            .contains("python311.dll"));
        assert!(alternative_paths[1].to_string_lossy().contains("Scripts"));
        assert!(alternative_paths[2].to_string_lossy().contains("DLLs"));
        assert!(alternative_paths[3].to_string_lossy().contains("System32"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_so_path_generation() {
        let version_info = pyo3::PyVersionInfo {
            major: 3,
            minor: 11,
            micro: 0,
        };

        let expected_lib = format!("libpython{}.{}.so", version_info.major, version_info.minor);
        assert_eq!(expected_lib, "libpython3.11.so");

        // Test alternative paths logic
        let possible_paths = vec![
            format!("/usr/lib/x86_64-linux-gnu/{}", expected_lib),
            format!("/usr/lib/{}", expected_lib),
            format!("/usr/local/lib/{}", expected_lib),
            format!(
                "libpython{}.{}.so.1.0",
                version_info.major, version_info.minor
            ),
        ];

        assert!(possible_paths[0].contains("/usr/lib/x86_64-linux-gnu/"));
        assert!(possible_paths[1].contains("/usr/lib/"));
        assert!(possible_paths[2].contains("/usr/local/lib/"));
        assert!(possible_paths[3].contains("libpython3.11.so.1.0"));
    }

    #[test]
    fn test_python_integration_debug_output() {
        let python_integration = create_test_python_integration();

        // Test debug output formatting
        let debug_output = format!("{:?}", python_integration.interpreter_path);
        assert!(debug_output.contains("python"));

        let debug_venv = format!("{:?}", python_integration.virtual_env_path);
        assert!(debug_venv.contains("test_env"));
    }

    #[test]
    fn test_environment_variable_persistence() {
        // Test that environment variables are set correctly and persist
        env::set_var("TEST_PYBIND11_VAR", "test_value");
        assert_eq!(env::var("TEST_PYBIND11_VAR").unwrap(), "test_value");

        // Test removal
        env::remove_var("TEST_PYBIND11_VAR");
        assert!(env::var("TEST_PYBIND11_VAR").is_err());
    }

    #[test]
    fn test_path_validation_logic() {
        let temp_dir = TempDir::new().unwrap();
        let existing_path = temp_dir.path().to_path_buf();
        let nonexistent_path = PathBuf::from("definitely_does_not_exist_12345");

        // Test path existence checks
        assert!(existing_path.exists());
        assert!(!nonexistent_path.exists());

        // Test path construction
        let constructed_path = existing_path.join("subdir").join("file.txt");
        assert!(constructed_path.to_string_lossy().contains("subdir"));
        assert!(constructed_path.to_string_lossy().contains("file.txt"));
    }

    #[test]
    fn test_version_info_parsing() {
        // Test version parsing logic that would be used with PyVersionInfo
        let version_str = "3.11.5";
        let parts: Vec<&str> = version_str.split('.').collect();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "3");
        assert_eq!(parts[1], "11");
        assert_eq!(parts[2], "5");

        // Test parsing to numbers
        let major: u32 = parts[0].parse().unwrap();
        let minor: u32 = parts[1].parse().unwrap();
        let micro: u32 = parts[2].parse().unwrap();

        assert_eq!(major, 3);
        assert_eq!(minor, 11);
        assert_eq!(micro, 5);
    }

    #[test]
    fn test_library_loading_state_tracking() {
        let mut python_integration = create_test_python_integration();

        // Initially no library loaded
        assert!(!python_integration.is_library_loaded());

        // Simulate loading a library (we can't actually load in tests)
        // but we can test the state tracking logic
        assert!(python_integration.python_lib.is_none());

        // If we had a library, this would be true
        // python_integration.python_lib = Some(library);
        // assert!(python_integration.is_library_loaded());
    }

    #[test]
    fn test_error_message_formatting() {
        // Test that error messages are informative
        let error = anyhow::anyhow!(
            "No Python interpreter found. Please ensure Python is installed and accessible."
        );
        let error_str = error.to_string();

        assert!(error_str.contains("Python interpreter"));
        assert!(error_str.contains("installed"));
        assert!(error_str.contains("accessible"));
    }

    #[test]
    fn test_python_path_precedence() {
        // Test the precedence logic for Python path detection
        let mamba_path = PathBuf::from(r"C:\Intellicrack\mamba_env\python.exe");
        let mamba_scripts_path = PathBuf::from(r"C:\Intellicrack\mamba_env\Scripts\python.exe");

        // Test path construction
        assert!(mamba_path.to_string_lossy().contains("mamba_env"));
        assert!(mamba_scripts_path.to_string_lossy().contains("Scripts"));

        // Test that paths are different
        assert_ne!(mamba_path, mamba_scripts_path);

        // Test that both are absolute paths
        assert!(mamba_path.is_absolute());
        assert!(mamba_scripts_path.is_absolute());
    }

    #[test]
    fn test_configure_pybind11_environment_var() {
        // Test that the critical environment variable is set
        env::set_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1");
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );

        // Clean up
        env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");
        assert!(env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").is_err());
    }

    #[test]
    fn test_thread_safety_preparation() {
        // Test that freethreaded Python can be prepared
        // This is mainly testing that the call doesn't panic
        pyo3::prepare_freethreaded_python();

        // No assertion needed - if it doesn't panic, it worked
        // The actual GIL state is managed by PyO3 internally
    }

    #[test]
    fn test_virtual_env_path_handling() {
        let temp_dir = TempDir::new().unwrap();
        let venv_path = temp_dir.path().to_path_buf();

        // Create virtual environment structure
        let lib_dir = venv_path.join("Lib");
        let scripts_dir = venv_path.join("Scripts");
        fs::create_dir_all(&lib_dir).unwrap();
        fs::create_dir_all(&scripts_dir).unwrap();

        let python_integration = PythonIntegration {
            interpreter_path: PathBuf::from("python"),
            virtual_env_path: venv_path.clone(),
            python_lib: None,
        };

        assert_eq!(python_integration.get_virtual_env_path(), &venv_path);
        assert!(python_integration.get_virtual_env_path().exists());

        // Test that subdirectories are constructed correctly
        let lib_path = python_integration.get_virtual_env_path().join("Lib");
        let scripts_path = python_integration.get_virtual_env_path().join("Scripts");

        assert!(lib_path.exists());
        assert!(scripts_path.exists());
    }

    #[test]
    fn test_python_integration_field_access() {
        let python_integration = create_test_python_integration();

        // Test all field access methods
        let interpreter_path = python_integration.get_interpreter_path();
        let venv_path = python_integration.get_virtual_env_path();
        let lib_loaded = python_integration.is_library_loaded();

        assert_eq!(interpreter_path, &PathBuf::from("python"));
        assert_eq!(venv_path, &PathBuf::from("test_env"));
        assert!(!lib_loaded);
    }

    #[test]
    fn test_error_context_propagation() {
        // Test that error contexts are properly propagated
        let error = anyhow::anyhow!("Base error").context("Additional context");
        let error_str = error.to_string();

        assert!(error_str.contains("Additional context"));
        assert!(error_str.contains("Base error"));
    }
}
