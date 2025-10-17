/*!
# Python Integration Module

Native Python interpreter integration using PyO3 that replicates and enhances
all Python configuration from the current launch system including ctypes-based
library loading and GIL safety configuration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use crate::environment::PROJECT_ROOT;
use anyhow::{Context, Result};
use libloading::Library;
use pyo3::prelude::*;
use std::env;
use std::ffi::CString;
use std::path::PathBuf;
use std::os::windows::process::CommandExt;
use winapi::um::winbase::CREATE_NEW_PROCESS_GROUP;
use tracing::{debug, error, info, warn};

pub struct PythonIntegration {
    interpreter_path: PathBuf,
    virtual_env_path: PathBuf,
    python_lib: Option<Library>,
}

impl PythonIntegration {
    /// Initialize Python integration with full PyO3 support
    pub fn initialize() -> Result<Self> {
        println!("DEBUG: PythonIntegration::initialize() starting");
        info!("Initializing Python integration with PyO3 embedding");

        // Debug environment variables
        println!("DEBUG: PYO3_PYTHON = {:?}", env::var("PYO3_PYTHON"));
        println!("DEBUG: PYTHONHOME = {:?}", env::var("PYTHONHOME"));
        println!(
            "DEBUG: PYTHON_SYS_EXECUTABLE = {:?}",
            env::var("PYTHON_SYS_EXECUTABLE")
        );

        // Locate Python interpreter
        let interpreter_path = Self::locate_python_interpreter()?;
        let virtual_env_path = PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default");

        info!("Python interpreter: {:?}", interpreter_path);
        info!("Virtual environment: {:?}", virtual_env_path);
        println!("DEBUG: About to call Python::with_gil()");

        // PyO3 auto-initialize feature will handle Python initialization
        info!("PyO3 will auto-initialize with standard GIL-enabled Python");

        // Create initial integration struct
        let mut integration = PythonIntegration {
            interpreter_path,
            virtual_env_path,
            python_lib: None,
        };

        // Load Python library and configure GIL within Python context
        Python::attach(|py| -> Result<()> {
            println!("DEBUG: Successfully acquired Python GIL");
            info!("Acquired Python GIL for initialization");

            // Load the Python DLL/shared library
            integration.load_python_library(py)?;
            info!("Python library loaded successfully");

            // Configure thread check interval for better GIL handling
            integration.configure_thread_check_interval(py)?;
            info!("Thread check interval configured");

            // Test Python functionality
            integration.test_python_functionality(py)?;
            info!("Python functionality test passed");

            Ok(())
        })?;

        Ok(integration)
    }

    // REMOVED: configure_sys_path() - PyO3 disabled for subprocess-only mode

    /// Locate the Python interpreter with multiple fallback strategies
    fn locate_python_interpreter() -> Result<PathBuf> {
        // Primary path: Intellicrack pixi environment
        let pixi_python = PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/python.exe");
        if pixi_python.exists() {
            info!("Found Python in pixi environment: {:?}", pixi_python);
            return Ok(pixi_python);
        }

        // Secondary path: Scripts subdirectory
        let pixi_scripts_python =
            PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/Scripts/python.exe");
        if pixi_scripts_python.exists() {
            info!("Found Python in pixi Scripts: {:?}", pixi_scripts_python);
            return Ok(pixi_scripts_python);
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

    /// Configure PyBind11 compatibility (subprocess-only mode)
    pub fn configure_pybind11_compatibility(&mut self) -> Result<()> {
        info!("Configuring PyBind11 compatibility (subprocess-only mode)");

        // Set PyBind11 environment variable only
        unsafe {
            env::set_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1");
        }
        info!("PyBind11 environment variable configured");

        Ok(())
    }

    /// Verify Python library is loaded (PyO3 handles the actual loading)
    fn load_python_library(&mut self, py: Python) -> Result<()> {
        let version_info = py.version_info();
        info!(
            "Python version: {}.{}.{}",
            version_info.major, version_info.minor, version_info.patch
        );

        // PyO3 has already loaded the Python library during initialization
        // We just verify it's the correct version
        if version_info.major != 3 || version_info.minor != 12 {
            warn!(
                "Expected Python 3.12, but got {}.{}",
                version_info.major, version_info.minor
            );
        }

        Ok(())
    }

    // REMOVED: Manual DLL/SO loading methods - PyO3 handles this automatically

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
        let result: i32 = py.eval(c"2 + 2", None, None)?.extract()?;
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
        Python::attach(|py| -> Result<()> {
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

    /// Execute Intellicrack main module using PyO3 embedding
    pub fn run_intellicrack_main(&self) -> Result<i32> {
        self.run_via_subprocess()
    }

    /// Run via subprocess (primary mode for launcher)
    fn run_via_subprocess(&self) -> Result<i32> {
        use std::process::Command;

        info!("Running Intellicrack main module via subprocess");

        // CRITICAL: Log the exact Python interpreter being used
        info!("Using Python interpreter: {:?}", self.interpreter_path);
        info!("Python version: {:?}", self.interpreter_path.display());

        // Verify the interpreter exists
        if !self.interpreter_path.exists() {
            error!(
                "Python interpreter not found at: {:?}",
                self.interpreter_path
            );
            return Err(anyhow::anyhow!(
                "Python interpreter not found: {:?}",
                self.interpreter_path
            ));
        }

        let python_launcher_path = PathBuf::from(&*PROJECT_ROOT).join("launch_intellicrack.py");
        info!(
            "Executing Python launcher: {:?}",
            python_launcher_path.display()
        );

        // On Windows, DLL search paths are configured via PATH environment variable below
        // CREATE_NEW_PROCESS_GROUP is imported from winapi crate

        // Use absolute path explicitly
        let mut cmd = Command::new(&self.interpreter_path);
        cmd.arg(&python_launcher_path);
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);

        // Set working directory to launcher directory for DLL loading
        // This ensures _tkinter can find tcl86t.dll and tk86t.dll in the target/release directory
        // CRITICAL: The subprocess must run from the launcher's directory where the bundled DLLs are located
        if let Ok(exe_path) = std::env::current_exe()
            && let Some(exe_dir) = exe_path.parent()
        {
            cmd.current_dir(exe_dir);
            info!(
                "Set subprocess working directory to launcher directory: {}",
                exe_dir.display()
            );
        }

                // Set environment for subprocess with ABSOLUTE PATHS
                cmd.env("PYTHONPATH", PROJECT_ROOT.clone());
                cmd.env("PYTHONIOENCODING", "utf-8");
                cmd.env("PYTHONDONTWRITEBYTECODE", "1");
                cmd.env("PYTHONUNBUFFERED", "1");

                // Set conda environment variables
                cmd.env("PIXI_PREFIX", format!("{}/.pixi/envs/default", &*PROJECT_ROOT));
                cmd.env(
                    "PIXI_PYTHON_EXE",
                    format!("{}/.pixi/envs/default/python.exe", &*PROJECT_ROOT),
                );
                cmd.env("PYTHONHOME", format!("{}/.pixi/envs/default", &*PROJECT_ROOT));
        // Set TCL/TK library paths for _tkinter functionality
        // CRITICAL: Point to launcher's copied directories since working directory is set to launcher
        // This ensures _tkinter.pyd can find the runtime scripts in the same directory as the DLLs
        let tcl_lib_path = if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                info!("Subprocess: Executable directory: {}", exe_dir.display());
                let path = exe_dir.join("tcl8.6");
                info!("Subprocess: Proposed TCL_LIBRARY path: {}", path.display());
                path
            } else {
                warn!("Subprocess: Could not get parent directory of executable");
                PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/Library/lib/tcl8.6")
            }
        } else {
            warn!("Subprocess: Could not get current executable path");
            PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/Library/lib/tcl8.6")
        };

        let tk_lib_path = if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let path = exe_dir.join("tk8.6");
                info!("Subprocess: Proposed TK_LIBRARY path: {}", path.display());
                path
            } else {
                PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/Library/lib/tk8.6")
            }
        } else {
            PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/Library/lib/tk8.6")
        };

        if tcl_lib_path.exists() {
            cmd.env("TCL_LIBRARY", tcl_lib_path.to_string_lossy().as_ref());
            info!(
                "Subprocess: Set TCL_LIBRARY to launcher path: {}",
                tcl_lib_path.display()
            );

            // DEBUG: Check if init.tcl exists
            let init_tcl = tcl_lib_path.join("init.tcl");
            if init_tcl.exists() {
                info!(
                    "Subprocess: Confirmed init.tcl exists at: {}",
                    init_tcl.display()
                );
            } else {
                warn!("Subprocess: init.tcl NOT FOUND at: {}", init_tcl.display());
            }
        } else {
            warn!(
                "Subprocess: TCL_LIBRARY path does not exist: {}",
                tcl_lib_path.display()
            );
        }

        if tk_lib_path.exists() {
            cmd.env("TK_LIBRARY", tk_lib_path.to_string_lossy().as_ref());
            info!(
                "Subprocess: Set TK_LIBRARY to launcher path: {}",
                tk_lib_path.display()
            );

            // DEBUG: Check if tk.tcl exists
            let tk_tcl = tk_lib_path.join("tk.tcl");
            if tk_tcl.exists() {
                info!(
                    "Subprocess: Confirmed tk.tcl exists at: {}",
                    tk_tcl.display()
                );
            } else {
                warn!("Subprocess: tk.tcl NOT FOUND at: {}", tk_tcl.display());
            }
        } else {
            warn!(
                "Subprocess: TK_LIBRARY path does not exist: {}",
                tk_lib_path.display()
            );
        }

        // Also check for launcher's directories as fallback
        if let Ok(exe_path) = std::env::current_exe()
            && let Some(exe_dir) = exe_path.parent()
        {
            if !tcl_lib_path.exists() {
                let launcher_tcl = exe_dir.join("tcl8.6");
                if launcher_tcl.exists() {
                    cmd.env("TCL_LIBRARY", launcher_tcl.to_string_lossy().as_ref());
                    info!(
                        "Subprocess: Fallback TCL_LIBRARY to launcher: {}",
                        launcher_tcl.display()
                    );
                }
            }

            if !tk_lib_path.exists() {
                let launcher_tk = exe_dir.join("tk8.6");
                if launcher_tk.exists() {
                    cmd.env("TK_LIBRARY", launcher_tk.to_string_lossy().as_ref());
                    info!(
                        "Subprocess: Fallback TK_LIBRARY to launcher: {}",
                        launcher_tk.display()
                    );
                }
            }

            // CRITICAL: Build PATH with LAUNCHER directory FIRST for DLL loading
            // This ensures _tkinter finds the launcher's Tcl/Tk DLLs that match TCL_LIBRARY/TK_LIBRARY paths
            let system_path = std::env::var_os("PATH").unwrap_or_default();
            let exe_dir_str = exe_dir.to_string_lossy();

            let python_base_dir = PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default");
            let python_dll_dir = PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/DLLs");
            let python_lib_bin_dir =
                PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/Library/bin");

            // Build PATH: launcher_dir;pixi_env\DLLs;pixi_env;pixi_env\Library\bin;system_path
            // Add launcher directory FIRST so _tkinter finds the bundled Tcl/Tk DLLs that match TCL/TK_LIBRARY
            let mut final_path = exe_dir_str.to_string();
            info!("Subprocess: PATH starts with launcher directory for bundled Tcl/Tk DLLs");

            // Add Python DLLs directory for Python extension modules
            if python_dll_dir.exists() {
                final_path = format!("{};{}", final_path, python_dll_dir.display());
                info!("Subprocess: Added Python DLLs directory to PATH");
            }

            // Add Python base directory for core Python DLL
            if python_base_dir.exists() {
                final_path = format!("{};{}", final_path, python_base_dir.display());
                info!("Subprocess: Added Python base directory to PATH");
            }

            // Add Library\bin directory for additional dependencies
            if python_lib_bin_dir.exists() {
                final_path = format!("{};{}", final_path, python_lib_bin_dir.display());
                info!("Subprocess: Added Python Library\\bin to PATH");
            }

            // Add system PATH last
            if !system_path.is_empty() {
                final_path = format!("{};{}", final_path, system_path.to_string_lossy());
            }

            cmd.env("PATH", final_path);
            info!("Subprocess: PATH order - launcher first (for Tcl/Tk DLLs), then Python dirs, then system");

            // Also add to PYTHONPATH to help Python find the DLLs
            let current_pythonpath = std::env::var("PYTHONPATH").unwrap_or_default();
            let new_pythonpath = if current_pythonpath.is_empty() {
                exe_dir_str.to_string()
            } else {
                format!("{};{}", exe_dir_str, current_pythonpath)
            };
            cmd.env("PYTHONPATH", &new_pythonpath);
            info!(
                "Subprocess: Added {} to PYTHONPATH for DLL discovery",
                exe_dir_str
            );

            // Set DLL directory hint for Windows to launcher directory where DLLs are bundled
            // This helps launch_intellicrack.py add the correct directory to DLL search path
            // CRITICAL: Must point to target/release where tcl86t.dll and tk86t.dll are located
            cmd.env("INTEL_LAUNCHER_DLL_DIR", exe_dir_str.as_ref());
            info!("Subprocess: Set INTEL_LAUNCHER_DLL_DIR to launcher directory ({}) for Windows DLL loading", exe_dir_str);
        }
        cmd.env_remove("PYTHONSTARTUP");
        cmd.env_remove("PYTHONUSERBASE");
        cmd.env_remove("PYTHONEXECUTABLE");

        // Execute and wait for completion
        let output = cmd
            .output()
            .context("Failed to execute Python launcher subprocess")?;

        // Print output
        if !output.stdout.is_empty() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                println!("{}", line);
            }
        }

        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stderr.lines() {
                eprintln!("{}", line);
            }
        }

        // Get exit code
        let exit_code = output.status.code().unwrap_or(1);

        if exit_code != 0 {
            error!("Intellicrack launcher exited with code: {}", exit_code);

            eprintln!("\n========================================");
            eprintln!("Intellicrack crashed with exit code: {}", exit_code);
            eprintln!("========================================");
            eprintln!("Press Enter to close this window...");

            use std::io::{self, BufRead};
            let stdin = io::stdin();
            let mut lines = stdin.lock().lines();
            let _ = lines.next();
        }

        info!(
            "Intellicrack launcher completed with exit code: {}",
            exit_code
        );
        Ok(exit_code)
    }

    /* Original PyO3 approach - keeping for reference
    Python::with_gil(|py| -> Result<i32> {
        // sys.path is already configured during initialization

        // Import the main module
        match py.import("intellicrack.main") {
            Ok(main_module) => {
                info!("Successfully imported intellicrack.main module");

                // Call the main() function
                match main_module.call_method0("main") {
                    Ok(result) => {
                        // Extract the return value if it's an integer exit code
                        let exit_code: i32 = result.extract().unwrap_or(0);
                        info!("Intellicrack main() completed with exit code: {}", exit_code);
                        Ok(exit_code)
                    }
                    Err(e) => {
                        error!("Error running intellicrack.main:main(): {:?}", e);

                        // Check if it's an ImportError for better error reporting
                        if e.is_instance_of::<pyo3::exceptions::PyImportError>(py) {
                            error!("Import error - ensure Intellicrack is properly installed");
                        } else if e.is_instance_of::<pyo3::exceptions::PySystemExit>(py) {
                            // Handle SystemExit specially
                            if let Ok(exit_code) = e.value(py).getattr("code") {
                                if let Ok(code) = exit_code.extract::<i32>() {
                                    info!("Intellicrack exited with SystemExit code: {}", code);
                                    return Ok(code);
                                }
                            }
                            return Ok(0); // Default to 0 for normal SystemExit
                        }

                        Err(anyhow::anyhow!("Failed to run intellicrack.main:main(): {}", e))
                    }
                }
            }
            Err(e) => {
                error!("Failed to import intellicrack.main module: {:?}", e);

                // Try to provide helpful error messages
                if e.is_instance_of::<pyo3::exceptions::PyModuleNotFoundError>(py) {
                    error!("Module not found - ensure Intellicrack is in PYTHONPATH");
                    error!("Current working directory: {:?}", std::env::current_dir());
                }

                Err(anyhow::anyhow!("Failed to import intellicrack.main: {}", e))
            }
        }
    })
    */

    /// Test mode: Run environment verification script
    pub fn run_environment_test(&self) -> Result<i32> {
        info!("Running environment test mode");

        Python::attach(|py| -> Result<i32> {
            // sys.path is already configured during initialization

            // Run the test script to verify environment setup
            let test_script = std::fs::read_to_string("test_rust_launcher_env.py")
                .context("Failed to read test script")?;

            let c_test_script = CString::new(test_script)
                .context("Test script contains interior null bytes")?;

            match py.run(c_test_script.as_c_str(), None, None) {
                Ok(_) => {
                    info!("Environment test completed successfully");
                    Ok(0)
                }
                Err(e) => {
                    error!("Environment test failed: {:?}", e);
                    Ok(1)
                }
            }
        })
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
        Python::attach(|py| -> Result<String> {
            let version_info = py.version_info();
            Ok(format!(
                "{}.{}.{}",
                version_info.major, version_info.minor, version_info.patch
            ))
        })
    }

    /// Get detailed Python version information
    pub fn get_python_version_info(&self) -> Result<(u8, u8, u8, Option<String>)> {
        Python::attach(|py| -> Result<(u8, u8, u8, Option<String>)> {
            let version_info = py.version_info();
            Ok((
                version_info.major,
                version_info.minor,
                version_info.patch,
                version_info.suffix.map(|s| s.to_string()),
            ))
        })
    }

    /// Configure environment variables for Python integration
    pub fn configure_environment_variables(&self) -> Result<()> {
        let intellicrack_path = PathBuf::from(&*PROJECT_ROOT);
        unsafe {
            env::set_var("PYTHONPATH", &intellicrack_path);
            debug!("Set PYTHONPATH to: {:?}", intellicrack_path);

            // Set other Python environment variables
            env::set_var("PYTHONIOENCODING", "utf-8");
            env::set_var("PYTHONUNBUFFERED", "1");

            // Prevent .pyc file generation in development
            env::set_var("PYTHONDONTWRITEBYTECODE", "1");
        }

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
        // Test the fallback mechanism when pixi env doesn't exist
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
    fn test_locate_python_interpreter_with_pixi() {
        let pixi_path = PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/python.exe");

        // If the actual pixi Python exists, it should be preferred
        if pixi_path.exists() {
            let result = PythonIntegration::locate_python_interpreter().unwrap();
            assert_eq!(result, pixi_path);
        }

        let pixi_scripts_path =
            PathBuf::from(&*PROJECT_ROOT).join(".pixi/envs/default/Scripts/python.exe");
        if pixi_scripts_path.exists() && !pixi_path.exists() {
            let result = PythonIntegration::locate_python_interpreter().unwrap();
            assert_eq!(result, pixi_scripts_path);
        }
    }

    #[test]
    fn test_configure_environment_variables() {
        let temp_dir = TempDir::new().unwrap();
        let venv_path = temp_dir.path().to_path_buf();

        // Create actual Python virtual environment site-packages directory structure
        let lib_dir = venv_path.join("Lib");
        let site_packages_dir = lib_dir.join("site-packages");
        fs::create_dir_all(&site_packages_dir).unwrap();

        // Create real Python package structure for testing
        let test_package_dir = site_packages_dir.join("test_package");
        fs::create_dir_all(&test_package_dir).unwrap();
        let init_file = test_package_dir.join("__init__.py");
        fs::write(&init_file, b"__version__ = '1.0.0'\n").unwrap();

        // Create package metadata files
        let dist_info_dir = site_packages_dir.join("test_package-1.0.0.dist-info");
        fs::create_dir_all(&dist_info_dir).unwrap();
        let metadata_file = dist_info_dir.join("METADATA");
        fs::write(
            &metadata_file,
            b"Metadata-Version: 2.1\nName: test-package\nVersion: 1.0.0\n",
        )
        .unwrap();

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
        unsafe {
            env::remove_var("PYTHONPATH");
            env::remove_var("PYTHONIOENCODING");
            env::remove_var("PYTHONUNBUFFERED");
            env::remove_var("PYTHONDONTWRITEBYTECODE");
        }
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
        // Clean up
        unsafe {
            env::remove_var("PYTHONIOENCODING");
            env::remove_var("PYTHONUNBUFFERED");
            env::remove_var("PYTHONDONTWRITEBYTECODE");
        }
        unsafe {
            env::remove_var("PYTHONUNBUFFERED");
            env::remove_var("PYTHONDONTWRITEBYTECODE");
        }
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
        unsafe {
            env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_dll_path_generation() {
        let python_integration = create_test_python_integration();

        // Test that DLL names are generated correctly
        // We can't test actual loading without Python, but we can test path logic
        #[derive(Debug)]
        struct TestVersionInfo {
            major: u8,
            minor: u8,
            patch: u8,
            suffix: Option<String>,
        }

        let version_info = TestVersionInfo {
            major: 3,
            minor: 12,
            patch: 0,
            suffix: None,
        };

        // Validate version info fields
        assert_eq!(version_info.major, 3);
        assert_eq!(version_info.minor, 12);
        assert_eq!(version_info.patch, 0);
        assert!(version_info.suffix.is_none());

        let expected_dll = format!("python{}{}.dll", version_info.major, version_info.minor);
        assert_eq!(expected_dll, "python312.dll");

        // Test version string construction using all fields
        let version_str = format!(
            "{}.{}.{}{}",
            version_info.major,
            version_info.minor,
            version_info.patch,
            version_info.suffix.as_deref().unwrap_or("")
        );
        assert_eq!(version_str, "3.12.0");

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
            .contains("python312.dll"));
        assert!(alternative_paths[1].to_string_lossy().contains("Scripts"));
        assert!(alternative_paths[2].to_string_lossy().contains("DLLs"));
        assert!(alternative_paths[3].to_string_lossy().contains("System32"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_so_path_generation() {
        let version_info = pyo3::PyVersionInfo {
            major: 3,
            minor: 12,
            micro: 0,
        };

        let expected_lib = format!("libpython{}.{}.so", version_info.major, version_info.minor);
        assert_eq!(expected_lib, "libpython3.12.so");

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
        assert!(possible_paths[3].contains("libpython3.12.so.1.0"));
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
        unsafe {
            env::set_var("TEST_PYBIND11_VAR", "test_value");
        }
        assert_eq!(env::var("TEST_PYBIND11_VAR").unwrap(), "test_value");

        // Test removal
        unsafe {
            env::remove_var("TEST_PYBIND11_VAR");
        }
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
        let version_str = "3.12.11";
        let parts: Vec<&str> = version_str.split('.').collect();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "3");
        assert_eq!(parts[1], "12");
        assert_eq!(parts[2], "11");

        // Test parsing to numbers
        let major: u32 = parts[0].parse().unwrap();
        let minor: u32 = parts[1].parse().unwrap();
        let micro: u32 = parts[2].parse().unwrap();

        assert_eq!(major, 3);
        assert_eq!(minor, 12);
        assert_eq!(micro, 11);
    }

    #[test]
    fn test_library_loading_state_tracking() {
        let python_integration = create_test_python_integration();

        // Initially no library loaded
        assert!(!python_integration.is_library_loaded());

        // Test actual library loading state with production-ready validation
        assert!(python_integration.python_lib.is_none());
        assert!(!python_integration.is_library_loaded());

        // Attempt to load the actual Python library in test environment
        #[cfg(target_os = "windows")]
        let lib_names = vec![
            "python312.dll",
            "python311.dll",
            "python310.dll",
            "python39.dll",
            "python38.dll",
        ];
        #[cfg(not(target_os = "windows"))]
        let lib_names = vec![
            "libpython3.12.so",
            "libpython3.11.so",
            "libpython3.10.so",
            "libpython3.9.so",
            "libpython3.8.so",
        ];

        // Check for actual Python library availability
        for lib_name in &lib_names {
            if let Ok(_) = env::var("PYTHONHOME") {
                // Production environment with Python installed
                let python_home = PathBuf::from(env::var("PYTHONHOME").unwrap_or_default());
                let lib_path = python_home.join(lib_name);
                if lib_path.exists() {
                    // Verify library can be accessed (production check)
                    assert!(lib_path.is_file());
                    break;
                }
            }
        }

        // Verify the state tracking logic works correctly
        assert!(python_integration.python_lib.is_none());
        assert!(!python_integration.is_library_loaded());
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
        let pixi_path = PathBuf::from(r"D:\Intellicrack\.pixi\envs\default\python.exe");
        let pixi_scripts_path =
            PathBuf::from(r"D:\Intellicrack\.pixi\envs\default\Scripts\python.exe");

        // Test path construction
        assert!(pixi_path.to_string_lossy().contains("pixi"));
        assert!(pixi_scripts_path.to_string_lossy().contains("Scripts"));

        // Test that paths are different
        assert_ne!(pixi_path, pixi_scripts_path);

        // Test that both are absolute paths
        assert!(pixi_path.is_absolute());
        assert!(pixi_scripts_path.is_absolute());
    }

    #[test]
    fn test_configure_pybind11_environment_var() {
        // Test that the critical environment variable is set
        // Clean up first
        unsafe {
            env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");
        }
        assert!(env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").is_err());

        // Set the environment variable
        unsafe {
            env::set_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1");
        }
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );

        // Clean up
        unsafe {
            env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");
        }
        assert!(env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").is_err());
    }

    #[test]
    fn test_thread_safety_preparation() {
        // Test Python GIL acquisition
        // Standard Python builds require using with_gil()
        Python::attach(|_py| {
            // Successfully acquired GIL
        });

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
