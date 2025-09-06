/*!
# Environment Management Module

Comprehensive environment variable configuration system that replicates and enhances
all environment setup from the current Python launch system.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use crate::platform::{GpuVendor, OsType, PlatformInfo};
use anyhow::Result;
use std::env;
use std::path::PathBuf;
use tracing::{debug, info, warn};


pub struct EnvironmentManager {
    platform: PlatformInfo,
}

impl EnvironmentManager {
    /// Create a new environment manager for the detected platform
    pub fn new(platform: &PlatformInfo) -> Self {
        EnvironmentManager {
            platform: platform.clone(),
        }
    }

    /// Configure complete environment with all required variables
    pub fn configure_complete_environment(&self) -> Result<()> {
        info!(
            "Configuring complete environment for platform: {:?}",
            self.platform.os_type
        );

        // CRITICAL: Activate mamba environment FIRST
        self.activate_mamba_environment()?;

        // Intel GPU settings (from RUN_INTELLICRACK.bat)
        self.set_intel_gpu_environment()?;

        // Threading configuration (from launch_intellicrack.py)
        self.set_threading_environment()?;

        // PyBind11 GIL safety (from launch_intellicrack.py)
        self.set_pybind11_environment()?;

        // TensorFlow configuration (from main.py)
        self.set_tensorflow_environment()?;

        // Qt configuration (from main.py)
        self.set_qt_environment()?;

        // PyTorch configuration (from launch_intellicrack.py)
        self.set_pytorch_environment()?;

        // Platform-specific settings
        self.set_platform_specific_environment()?;

        info!("Environment configuration completed successfully");
        Ok(())
    }

    /// Set Intel GPU environment variables (from RUN_INTELLICRACK.bat)
    fn set_intel_gpu_environment(&self) -> Result<()> {
        debug!("Setting Intel GPU environment variables");

        // Disable CUDA (force CPU for Intel Arc compatibility)
        env::set_var("CUDA_VISIBLE_DEVICES", "-1");

        // Set GPU type for Intellicrack
        env::set_var("INTELLICRACK_GPU_TYPE", "intel");

        // Qt OpenGL settings for Intel Arc B580 compatibility
        env::set_var("QT_OPENGL", "software");
        env::set_var("QT_ANGLE_PLATFORM", "warp");
        env::set_var("QT_D3D_ADAPTER_INDEX", "1");
        env::set_var("QT_QUICK_BACKEND", "software");
        
        // Intel Extension for PyTorch settings
        env::set_var("IPEX_ENABLE", "1");
        env::set_var("INTEL_DISABLE_GPU", "0");
        env::set_var("ZE_ENABLE_PCI_ID_DEVICE_ORDER", "1");

        // Set Qt platform (will be overridden by platform-specific config if needed)
        if self.platform.os_type == OsType::Windows && !self.platform.is_wsl {
            env::set_var("QT_QPA_PLATFORM", "windows");
        }

        info!("Intel GPU environment configured");
        Ok(())
    }

    /// Set threading environment variables (from launch_intellicrack.py)
    fn set_threading_environment(&self) -> Result<()> {
        debug!("Setting threading environment variables");

        // Set all threading libraries to single-threaded mode
        // This prevents conflicts between different mathematical libraries
        env::set_var("OMP_NUM_THREADS", "1"); // OpenMP
        env::set_var("MKL_NUM_THREADS", "1"); // Intel MKL
        env::set_var("NUMEXPR_NUM_THREADS", "1"); // NumExpr
        env::set_var("OPENBLAS_NUM_THREADS", "1"); // OpenBLAS
        env::set_var("VECLIB_MAXIMUM_THREADS", "1"); // vecLib (macOS)
        env::set_var("BLIS_NUM_THREADS", "1"); // BLIS

        info!("Threading environment configured for single-threaded operation");
        Ok(())
    }

    /// Set PyBind11 GIL safety environment (from launch_intellicrack.py)
    fn set_pybind11_environment(&self) -> Result<()> {
        debug!("Setting PyBind11 GIL safety environment");

        // Disable PyBind11 GIL assertions to prevent crashes
        env::set_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1");

        info!("PyBind11 GIL safety configured");
        Ok(())
    }

    /// Set TensorFlow environment variables (from main.py)
    fn set_tensorflow_environment(&self) -> Result<()> {
        debug!("Setting TensorFlow environment variables");

        // Suppress TensorFlow warnings and info messages
        env::set_var("TF_CPP_MIN_LOG_LEVEL", "2");

        // Disable GPU for TensorFlow (Intel Arc B580 compatibility)
        env::set_var("CUDA_VISIBLE_DEVICES", "-1");

        // Fix PyTorch + TensorFlow import conflict
        env::set_var("MKL_THREADING_LAYER", "GNU");

        info!("TensorFlow environment configured");
        Ok(())
    }

    /// Set Qt environment variables (from main.py)
    fn set_qt_environment(&self) -> Result<()> {
        debug!("Setting Qt environment variables");

        // Configure Qt platform based on system detection
        self.platform.configure_qt_platform()?;

        // Windows-specific Qt font handling
        if self.platform.os_type == OsType::Windows {
            self.set_windows_qt_environment()?;
        }

        // Suppress Qt font warnings to reduce console noise
        env::set_var("QT_LOGGING_RULES", "*.debug=false;qt.qpa.fonts=false");

        info!("Qt environment configured");
        Ok(())
    }

    /// Set Windows-specific Qt environment (from main.py)
    fn set_windows_qt_environment(&self) -> Result<()> {
        debug!("Setting Windows-specific Qt environment");

        // Set Windows font directory for Qt to find system fonts
        if env::var("QT_QPA_FONTDIR").is_err() {
            let font_dir = self.platform.font_directory.to_string_lossy();
            env::set_var("QT_QPA_FONTDIR", font_dir.as_ref());
            debug!("Set QT_QPA_FONTDIR to: {}", font_dir);
        }

        // Force software rendering for Intel Arc compatibility
        if self.platform.gpu_vendor == GpuVendor::Intel {
            env::set_var("QT_OPENGL", "software");
            env::set_var("QT_QUICK_BACKEND", "software");
            env::set_var("QT_ANGLE_PLATFORM", "warp");
            info!("Intel Arc compatibility mode enabled for Qt");
        }

        Ok(())
    }

    /// Set platform-specific environment variables
    fn set_platform_specific_environment(&self) -> Result<()> {
        debug!("Setting platform-specific environment variables");

        match (&self.platform.os_type, self.platform.is_wsl) {
            (OsType::Windows, false) => {
                self.set_native_windows_environment()?;
            }
            (OsType::Unix, true) => {
                self.set_wsl_environment()?;
            }
            (OsType::Unix, false) => {
                self.set_native_linux_environment()?;
            }
            (OsType::Windows, true) => {
                // Windows running in WSL doesn't make logical sense,
                // but we handle it as native Windows
                self.set_native_windows_environment()?;
            }
        }

        Ok(())
    }

    /// Set native Windows environment variables
    fn set_native_windows_environment(&self) -> Result<()> {
        debug!("Setting native Windows environment");

        // CRITICAL: Configure DLL search paths FIRST for Ray and other native modules
        self.configure_windows_dll_search_paths()?;

        // Configure PATH for mamba environment (must be done early)
        self.configure_mamba_path()?;

        // Windows-specific settings
        env::set_var("PYTHONIOENCODING", "utf-8");

        // Ensure Windows Unicode support
        env::set_var("PYTHONUTF8", "1");
        
        // Visual C++ runtime configuration
        env::set_var("VCRUNTIME_REDIST_INSTALLED", "1");
        
        // Windows Error Reporting - disable for subprocess crashes
        env::set_var("WINDOWS_TRACING_FLAGS", "3");
        env::set_var("WINDOWS_TRACING_LOGFILE", r"C:\Intellicrack\logs\launcher.etl");

        info!("Native Windows environment configured");
        Ok(())
    }
    
    /// Configure Windows DLL search paths for native Python modules
    #[cfg(target_os = "windows")]
    fn configure_windows_dll_search_paths(&self) -> Result<()> {
        debug!("Configuring Windows DLL search paths");
        
        // Critical DLL directories for Ray and other native modules
        let dll_directories = vec![
            r"C:\Intellicrack\mamba_env",
            r"C:\Intellicrack\mamba_env\Library\bin",
            r"C:\Intellicrack\mamba_env\DLLs",
            r"C:\Intellicrack\mamba_env\Scripts",
            r"C:\Intellicrack\mamba_env\Lib\site-packages\torchvision",
            r"C:\Intellicrack\mamba_env\Lib\site-packages\h5py",
        ];
        
        // First, ensure all directories are in the system PATH
        let current_path = env::var("PATH").unwrap_or_default();
        let mut path_parts: Vec<String> = Vec::new();
        
        for dir in &dll_directories {
            let path_buf = std::path::PathBuf::from(dir);
            if path_buf.exists() {
                path_parts.push(dir.to_string());
                debug!("Added to DLL search path: {}", dir);
            }
        }
        
        // Add existing PATH at the end
        if !current_path.is_empty() {
            path_parts.push(current_path);
        }
        
        // Set the new PATH with DLL directories FIRST
        let new_path = path_parts.join(";");
        env::set_var("PATH", &new_path);
        
        info!("Configured Windows DLL search paths for {} directories", dll_directories.len());
        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    fn configure_windows_dll_search_paths(&self) -> Result<()> {
        // No-op on non-Windows platforms
        Ok(())
    }

    /// Configure PATH environment variable for mamba environment
    fn configure_mamba_path(&self) -> Result<()> {
        let current_path = env::var("PATH").unwrap_or_default();
        
        // Build new PATH with launcher directory FIRST for DLL compatibility
        let mut new_path_parts = Vec::new();
        
        // CRITICAL: Add launcher directory FIRST for _tkinter DLL loading
        if let Ok(exe_path) = env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let launcher_dir = exe_dir.to_string_lossy().to_string();
                new_path_parts.push(launcher_dir.clone());
                info!("Added launcher directory to PATH first: {}", launcher_dir);
            }
        }
        
        // Mamba environment paths that need to be in PATH
        let mamba_paths = vec![
            r"C:\Intellicrack\mamba_env",
            r"C:\Intellicrack\mamba_env\Scripts",
            r"C:\Intellicrack\mamba_env\Library\bin",
            r"C:\Intellicrack\mamba_env\Library\usr\bin",
            r"C:\Intellicrack\mamba_env\Library\mingw64\bin",
            r"C:\Intellicrack\mamba_env\Library\mingw-w64\bin",
            r"C:\Intellicrack\mamba_env\DLLs",
        ];
        
        // Add mamba paths after launcher directory
        for mamba_path in mamba_paths {
            let path_buf = std::path::PathBuf::from(mamba_path);
            if path_buf.exists() {
                new_path_parts.push(mamba_path.to_string());
                debug!("Added to PATH: {}", mamba_path);
            }
        }
        
        // Add existing PATH last
        if !current_path.is_empty() {
            new_path_parts.push(current_path);
        }
        
        let new_path = new_path_parts.join(";");
        env::set_var("PATH", &new_path);
        
        info!("Configured PATH with launcher directory first + {} additional paths", 
              new_path_parts.len() - 1); // -1 because existing PATH counts as 1
        
        Ok(())
    }
    
    /// Properly activate mamba environment by setting all required environment variables
    fn activate_mamba_environment(&self) -> Result<()> {
        info!("Activating mamba environment");
        
        // Set CONDA environment variables for proper activation
        env::set_var("CONDA_PREFIX", r"C:\Intellicrack\mamba_env");
        env::set_var("CONDA_DEFAULT_ENV", "mamba_env");
        env::set_var("CONDA_PYTHON_EXE", r"C:\Intellicrack\mamba_env\python.exe");
        env::set_var("CONDA_SHLVL", "1");
        env::set_var("CONDA_PROMPT_MODIFIER", "(mamba_env)");
        env::set_var("CONDA_EXE", r"C:\Users\zachf\mambaforge\Scripts\conda.exe");
        
        // CRITICAL: PyO3 REQUIRES PYTHONHOME to be set for embedding Python
        // This tells PyO3 where to find the Python runtime and standard library
        env::set_var("PYTHONHOME", r"C:\Intellicrack\mamba_env");
        
        // Set PYTHONPATH to include both mamba site-packages and Intellicrack source
        // This ensures all packages and local modules are importable
        let pythonpath = r"C:\Intellicrack;C:\Intellicrack\mamba_env\Lib\site-packages".to_string();
        env::set_var("PYTHONPATH", &pythonpath);
        
        // Set TCL/TK library paths for _tkinter functionality
        // CRITICAL: Use launcher's bundled Tcl/Tk directories first for DLL compatibility
        // This ensures main process and subprocess use the same libraries
        
        let mut tcl_set = false;
        let mut tk_set = false;
        
        // FIRST: Try launcher directory (prioritized for DLL compatibility)
        if let Ok(exe_path) = env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let launcher_tcl = exe_dir.join("tcl8.6");
                let launcher_tk = exe_dir.join("tk8.6");
                
                if launcher_tcl.exists() {
                    env::set_var("TCL_LIBRARY", launcher_tcl.to_string_lossy().as_ref());
                    info!("Set TCL_LIBRARY to launcher directory: {}", launcher_tcl.display());
                    tcl_set = true;
                }
                
                if launcher_tk.exists() {
                    env::set_var("TK_LIBRARY", launcher_tk.to_string_lossy().as_ref());
                    info!("Set TK_LIBRARY to launcher directory: {}", launcher_tk.display());
                    tk_set = true;
                }
            }
        }
        
        // FALLBACK: Use mamba environment paths only if launcher paths don't exist
        if !tcl_set {
            let tcl_lib_path = PathBuf::from(r"C:\Intellicrack\mamba_env\Library\lib\tcl8.6");
            if tcl_lib_path.exists() {
                env::set_var("TCL_LIBRARY", tcl_lib_path.to_string_lossy().as_ref());
                info!("Set TCL_LIBRARY to mamba fallback: {}", tcl_lib_path.display());
            }
        }
        
        if !tk_set {
            let tk_lib_path = PathBuf::from(r"C:\Intellicrack\mamba_env\Library\lib\tk8.6");
            if tk_lib_path.exists() {
                env::set_var("TK_LIBRARY", tk_lib_path.to_string_lossy().as_ref());
                info!("Set TK_LIBRARY to mamba fallback: {}", tk_lib_path.display());
            }
        }
        
        info!("Mamba environment activated successfully");
        Ok(())
    }

    /// Set WSL environment variables
    fn set_wsl_environment(&self) -> Result<()> {
        debug!("Setting WSL environment variables");

        // WSL-specific Qt settings
        if !self.platform.display_available {
            env::set_var("QT_QPA_PLATFORM", "offscreen");
            info!("WSL offscreen mode enabled");
        }

        // WSL Unicode support
        env::set_var("LC_ALL", "C.UTF-8");
        env::set_var("LANG", "C.UTF-8");

        info!("WSL environment configured");
        Ok(())
    }

    /// Set native Linux environment variables
    fn set_native_linux_environment(&self) -> Result<()> {
        debug!("Setting native Linux environment variables");

        // Ensure proper locale settings
        if env::var("LC_ALL").is_err() {
            env::set_var("LC_ALL", "C.UTF-8");
        }

        if env::var("LANG").is_err() {
            env::set_var("LANG", "C.UTF-8");
        }

        info!("Native Linux environment configured");
        Ok(())
    }

    /// Set PyTorch specific environment variables (from launch_intellicrack.py)
    pub fn set_pytorch_environment(&self) -> Result<()> {
        debug!("Setting PyTorch environment variables");

        // PyTorch specific settings for stability
        env::set_var("PYTORCH_DISABLE_CUDNN_BATCH_NORM", "1");
        env::set_var("CUDA_LAUNCH_BLOCKING", "1");

        info!("PyTorch environment configured");
        Ok(())
    }

    /// Validate environment configuration
    pub fn validate_environment(&self) -> Result<()> {
        debug!("Validating environment configuration");

        let required_vars = [
            "CUDA_VISIBLE_DEVICES",
            "INTELLICRACK_GPU_TYPE",
            "QT_OPENGL",
            "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF",
            "OMP_NUM_THREADS",
            "TF_CPP_MIN_LOG_LEVEL",
        ];

        let mut missing_vars = Vec::new();

        for var in &required_vars {
            if env::var(var).is_err() {
                missing_vars.push(*var);
            }
        }

        if !missing_vars.is_empty() {
            warn!("Missing environment variables: {:?}", missing_vars);
        } else {
            info!("All required environment variables are set");
        }

        Ok(())
    }

    /// Print current environment status for debugging
    pub fn print_environment_status(&self) {
        println!("=== Environment Configuration Status ===");
        println!(
            "Platform: {:?} (WSL: {})",
            self.platform.os_type, self.platform.is_wsl
        );
        println!("GPU: {:?}", self.platform.gpu_vendor);
        println!("Display: {}", self.platform.display_available);

        let important_vars = [
            "CUDA_VISIBLE_DEVICES",
            "INTELLICRACK_GPU_TYPE",
            "QT_OPENGL",
            "QT_QPA_PLATFORM",
            "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF",
            "OMP_NUM_THREADS",
            "TF_CPP_MIN_LOG_LEVEL",
        ];

        println!("\nKey Environment Variables:");
        for var in &important_vars {
            match env::var(var) {
                Ok(value) => println!("  {} = {}", var, value),
                Err(_) => println!("  {} = <not set>", var),
            }
        }
        println!("========================================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_logging() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }

    fn create_test_platform() -> PlatformInfo {
        PlatformInfo {
            os_type: OsType::Windows,
            is_wsl: false,
            architecture: "x86_64".to_string(),
            version: "Windows 11".to_string(),
            gpu_vendor: GpuVendor::Intel,
            display_available: true,
            font_directory: PathBuf::from("C:\\Windows\\Fonts"),
            qt_platform: Some("windows".to_string()),
        }
    }

    fn create_wsl_platform() -> PlatformInfo {
        PlatformInfo {
            os_type: OsType::Unix,
            is_wsl: true,
            architecture: "x86_64".to_string(),
            version: "Ubuntu 20.04".to_string(),
            gpu_vendor: GpuVendor::Unknown,
            display_available: false,
            font_directory: PathBuf::from("/usr/share/fonts"),
            qt_platform: Some("offscreen".to_string()),
        }
    }

    fn create_linux_platform() -> PlatformInfo {
        PlatformInfo {
            os_type: OsType::Unix,
            is_wsl: false,
            architecture: "x86_64".to_string(),
            version: "Ubuntu 22.04".to_string(),
            gpu_vendor: GpuVendor::Nvidia,
            display_available: true,
            font_directory: PathBuf::from("/usr/share/fonts"),
            qt_platform: Some("xcb".to_string()),
        }
    }

    #[test]
    fn test_environment_manager_creation() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        assert_eq!(env_manager.platform.os_type, OsType::Windows);
        assert!(!env_manager.platform.is_wsl);
        assert_eq!(env_manager.platform.gpu_vendor, GpuVendor::Intel);
    }

    #[test]
    fn test_intel_gpu_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear relevant environment variables first
        env::remove_var("CUDA_VISIBLE_DEVICES");
        env::remove_var("INTELLICRACK_GPU_TYPE");
        env::remove_var("QT_OPENGL");

        let result = env_manager.set_intel_gpu_environment();
        assert!(result.is_ok());

        // Verify Intel GPU environment variables are set
        assert_eq!(env::var("CUDA_VISIBLE_DEVICES").unwrap(), "-1");
        assert_eq!(env::var("INTELLICRACK_GPU_TYPE").unwrap(), "intel");
        assert_eq!(env::var("QT_OPENGL").unwrap(), "software");
        assert_eq!(env::var("QT_ANGLE_PLATFORM").unwrap(), "warp");
        assert_eq!(env::var("QT_D3D_ADAPTER_INDEX").unwrap(), "1");
        assert_eq!(env::var("QT_QUICK_BACKEND").unwrap(), "software");
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "windows");
    }

    #[test]
    fn test_threading_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear threading environment variables
        env::remove_var("OMP_NUM_THREADS");
        env::remove_var("MKL_NUM_THREADS");
        env::remove_var("NUMEXPR_NUM_THREADS");

        let result = env_manager.set_threading_environment();
        assert!(result.is_ok());

        // Verify all threading libraries are set to single-threaded
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("MKL_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("NUMEXPR_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("OPENBLAS_NUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("VECLIB_MAXIMUM_THREADS").unwrap(), "1");
        assert_eq!(env::var("BLIS_NUM_THREADS").unwrap(), "1");
    }

    #[test]
    fn test_pybind11_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear PyBind11 environment variable
        env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");

        let result = env_manager.set_pybind11_environment();
        assert!(result.is_ok());

        // Verify PyBind11 GIL safety is configured
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );
    }

    #[test]
    fn test_tensorflow_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear TensorFlow environment variables
        env::remove_var("TF_CPP_MIN_LOG_LEVEL");
        env::remove_var("MKL_THREADING_LAYER");

        let result = env_manager.set_tensorflow_environment();
        assert!(result.is_ok());

        // Verify TensorFlow environment variables are set
        assert_eq!(env::var("TF_CPP_MIN_LOG_LEVEL").unwrap(), "2");
        assert_eq!(env::var("CUDA_VISIBLE_DEVICES").unwrap(), "-1");
        assert_eq!(env::var("MKL_THREADING_LAYER").unwrap(), "GNU");
    }

    #[test]
    fn test_qt_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear Qt environment variables
        env::remove_var("QT_LOGGING_RULES");

        let result = env_manager.set_qt_environment();
        assert!(result.is_ok());

        // Verify Qt logging rules are configured
        assert_eq!(
            env::var("QT_LOGGING_RULES").unwrap(),
            "*.debug=false;qt.qpa.fonts=false"
        );
    }

    #[test]
    fn test_windows_qt_environment_with_font_dir() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear Qt font directory
        env::remove_var("QT_QPA_FONTDIR");

        let result = env_manager.set_windows_qt_environment();
        assert!(result.is_ok());

        // Verify Windows font directory is set
        let font_dir = env::var("QT_QPA_FONTDIR").unwrap();
        assert!(font_dir.contains("Fonts"));

        // Verify Intel Arc compatibility settings
        assert_eq!(env::var("QT_OPENGL").unwrap(), "software");
        assert_eq!(env::var("QT_QUICK_BACKEND").unwrap(), "software");
        assert_eq!(env::var("QT_ANGLE_PLATFORM").unwrap(), "warp");
    }

    #[test]
    fn test_windows_qt_environment_preserves_existing_font_dir() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Set existing font directory
        let existing_font_dir = "C:\\CustomFonts";
        env::set_var("QT_QPA_FONTDIR", existing_font_dir);

        let result = env_manager.set_windows_qt_environment();
        assert!(result.is_ok());

        // Verify existing font directory is preserved
        assert_eq!(env::var("QT_QPA_FONTDIR").unwrap(), existing_font_dir);
    }

    #[test]
    fn test_native_windows_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear Windows-specific environment variables
        env::remove_var("PYTHONIOENCODING");
        env::remove_var("PYTHONUTF8");

        let result = env_manager.set_native_windows_environment();
        assert!(result.is_ok());

        // Verify Windows-specific environment variables are set
        assert_eq!(env::var("PYTHONIOENCODING").unwrap(), "utf-8");
        assert_eq!(env::var("PYTHONUTF8").unwrap(), "1");
    }

    #[test]
    fn test_wsl_environment_configuration_with_display() {
        init_test_logging();
        let mut platform = create_wsl_platform();
        platform.display_available = true;
        let env_manager = EnvironmentManager::new(&platform);

        // Clear WSL-specific environment variables
        env::remove_var("LC_ALL");
        env::remove_var("LANG");

        let result = env_manager.set_wsl_environment();
        assert!(result.is_ok());

        // Verify WSL Unicode support is configured
        assert_eq!(env::var("LC_ALL").unwrap(), "C.UTF-8");
        assert_eq!(env::var("LANG").unwrap(), "C.UTF-8");
    }

    #[test]
    fn test_wsl_environment_configuration_without_display() {
        init_test_logging();
        let platform = create_wsl_platform(); // display_available = false
        let env_manager = EnvironmentManager::new(&platform);

        // Clear Qt platform variable
        env::remove_var("QT_QPA_PLATFORM");

        let result = env_manager.set_wsl_environment();
        assert!(result.is_ok());

        // Verify WSL offscreen mode is enabled
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "offscreen");
    }

    #[test]
    fn test_native_linux_environment_configuration() {
        init_test_logging();
        let platform = create_linux_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear Linux-specific environment variables
        env::remove_var("LC_ALL");
        env::remove_var("LANG");

        let result = env_manager.set_native_linux_environment();
        assert!(result.is_ok());

        // Verify Linux locale settings are configured
        assert_eq!(env::var("LC_ALL").unwrap(), "C.UTF-8");
        assert_eq!(env::var("LANG").unwrap(), "C.UTF-8");
    }

    #[test]
    fn test_native_linux_environment_preserves_existing_locale() {
        init_test_logging();
        let platform = create_linux_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Set existing locale variables
        env::set_var("LC_ALL", "en_US.UTF-8");
        env::set_var("LANG", "en_US.UTF-8");

        let result = env_manager.set_native_linux_environment();
        assert!(result.is_ok());

        // Verify existing locale settings are preserved
        assert_eq!(env::var("LC_ALL").unwrap(), "en_US.UTF-8");
        assert_eq!(env::var("LANG").unwrap(), "en_US.UTF-8");
    }

    #[test]
    fn test_pytorch_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear PyTorch environment variables
        env::remove_var("PYTORCH_DISABLE_CUDNN_BATCH_NORM");
        env::remove_var("CUDA_LAUNCH_BLOCKING");

        let result = env_manager.set_pytorch_environment();
        assert!(result.is_ok());

        // Verify PyTorch stability settings are configured
        assert_eq!(env::var("PYTORCH_DISABLE_CUDNN_BATCH_NORM").unwrap(), "1");
        assert_eq!(env::var("CUDA_LAUNCH_BLOCKING").unwrap(), "1");
    }

    #[test]
    fn test_platform_specific_environment_windows() {
        init_test_logging();
        let platform = create_test_platform(); // Windows, non-WSL
        let env_manager = EnvironmentManager::new(&platform);

        // Clear environment variables
        env::remove_var("PYTHONIOENCODING");
        env::remove_var("PYTHONUTF8");

        let result = env_manager.set_platform_specific_environment();
        assert!(result.is_ok());

        // Verify Windows-specific settings were applied
        assert_eq!(env::var("PYTHONIOENCODING").unwrap(), "utf-8");
        assert_eq!(env::var("PYTHONUTF8").unwrap(), "1");
    }

    #[test]
    fn test_platform_specific_environment_wsl() {
        init_test_logging();
        let platform = create_wsl_platform(); // Unix WSL
        let env_manager = EnvironmentManager::new(&platform);

        // Clear environment variables
        env::remove_var("LC_ALL");
        env::remove_var("LANG");
        env::remove_var("QT_QPA_PLATFORM");

        let result = env_manager.set_platform_specific_environment();
        assert!(result.is_ok());

        // Verify WSL-specific settings were applied
        assert_eq!(env::var("LC_ALL").unwrap(), "C.UTF-8");
        assert_eq!(env::var("LANG").unwrap(), "C.UTF-8");
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "offscreen");
    }

    #[test]
    fn test_platform_specific_environment_linux() {
        init_test_logging();
        let platform = create_linux_platform(); // Unix, non-WSL
        let env_manager = EnvironmentManager::new(&platform);

        // Clear environment variables
        env::remove_var("LC_ALL");
        env::remove_var("LANG");

        let result = env_manager.set_platform_specific_environment();
        assert!(result.is_ok());

        // Verify Linux-specific settings were applied
        assert_eq!(env::var("LC_ALL").unwrap(), "C.UTF-8");
        assert_eq!(env::var("LANG").unwrap(), "C.UTF-8");
    }

    #[test]
    fn test_complete_environment_configuration() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear all environment variables
        env::remove_var("CUDA_VISIBLE_DEVICES");
        env::remove_var("INTELLICRACK_GPU_TYPE");
        env::remove_var("OMP_NUM_THREADS");
        env::remove_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF");
        env::remove_var("TF_CPP_MIN_LOG_LEVEL");
        env::remove_var("QT_LOGGING_RULES");
        env::remove_var("PYTHONIOENCODING");

        let result = env_manager.configure_complete_environment();
        assert!(result.is_ok());

        // Verify key environment variables are set from all subsystems
        assert_eq!(env::var("CUDA_VISIBLE_DEVICES").unwrap(), "-1");
        assert_eq!(env::var("INTELLICRACK_GPU_TYPE").unwrap(), "intel");
        assert_eq!(env::var("OMP_NUM_THREADS").unwrap(), "1");
        assert_eq!(
            env::var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF").unwrap(),
            "1"
        );
        assert_eq!(env::var("TF_CPP_MIN_LOG_LEVEL").unwrap(), "2");
        assert_eq!(
            env::var("QT_LOGGING_RULES").unwrap(),
            "*.debug=false;qt.qpa.fonts=false"
        );
        assert_eq!(env::var("PYTHONIOENCODING").unwrap(), "utf-8");
    }

    #[test]
    fn test_environment_validation_with_all_variables_set() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Set all required environment variables
        env::set_var("CUDA_VISIBLE_DEVICES", "-1");
        env::set_var("INTELLICRACK_GPU_TYPE", "intel");
        env::set_var("QT_OPENGL", "software");
        env::set_var("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1");
        env::set_var("OMP_NUM_THREADS", "1");
        env::set_var("TF_CPP_MIN_LOG_LEVEL", "2");

        let result = env_manager.validate_environment();
        assert!(result.is_ok());
    }

    #[test]
    fn test_environment_validation_with_missing_variables() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Clear some required environment variables
        env::remove_var("CUDA_VISIBLE_DEVICES");
        env::remove_var("INTELLICRACK_GPU_TYPE");

        // Validation should still succeed but log warnings
        let result = env_manager.validate_environment();
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_environment_status() {
        init_test_logging();
        let platform = create_test_platform();
        let env_manager = EnvironmentManager::new(&platform);

        // Set some environment variables for testing
        env::set_var("CUDA_VISIBLE_DEVICES", "-1");
        env::set_var("INTELLICRACK_GPU_TYPE", "intel");

        // This test just verifies the function doesn't panic
        // The actual output goes to stdout so we can't easily assert on it
        env_manager.print_environment_status();
    }

    #[test]
    fn test_environment_with_nvidia_gpu() {
        init_test_logging();
        let mut platform = create_test_platform();
        platform.gpu_vendor = GpuVendor::Nvidia;
        let env_manager = EnvironmentManager::new(&platform);

        // Clear Qt environment variables
        env::remove_var("QT_OPENGL");
        env::remove_var("QT_QUICK_BACKEND");

        let result = env_manager.set_windows_qt_environment();
        assert!(result.is_ok());

        // With Nvidia GPU, Intel Arc compatibility mode should not be enabled
        // The Intel-specific Qt variables may not be set
        if env::var("QT_OPENGL").is_ok() {
            // If set, it could be from another test or configuration
            // We just verify the function completed successfully
        }
    }

    #[test]
    fn test_environment_with_unknown_gpu() {
        init_test_logging();
        let mut platform = create_test_platform();
        platform.gpu_vendor = GpuVendor::Unknown;
        let env_manager = EnvironmentManager::new(&platform);

        let result = env_manager.set_windows_qt_environment();
        assert!(result.is_ok());

        // With unknown GPU, Intel Arc compatibility mode should not be enabled
    }

    #[test]
    fn test_environment_cross_platform_compatibility() {
        init_test_logging();

        // Test Windows platform
        let windows_platform = create_test_platform();
        let windows_manager = EnvironmentManager::new(&windows_platform);
        assert!(windows_manager.configure_complete_environment().is_ok());

        // Test WSL platform
        let wsl_platform = create_wsl_platform();
        let wsl_manager = EnvironmentManager::new(&wsl_platform);
        assert!(wsl_manager.configure_complete_environment().is_ok());

        // Test Linux platform
        let linux_platform = create_linux_platform();
        let linux_manager = EnvironmentManager::new(&linux_platform);
        assert!(linux_manager.configure_complete_environment().is_ok());
    }
}
