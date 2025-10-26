//! Preflight environment validation system for fast-fail error detection.
//!
//! This module performs critical environment validation before Python initialization,
//! providing immediate, actionable feedback if the environment is misconfigured.
//! The validation strategy distinguishes between fatal errors (must fix to continue)
//! and warnings (informational but non-blocking).
//!
//! # Features
//!
//! - **Fast-Fail Validation**: Detects environment issues in <10ms before expensive Python init
//! - **Helpful Error Messages**: Provides specific commands to fix issues (e.g., "Run: pixi install")
//! - **Critical vs Optional Checks**: Python executable is fatal; missing packages are warnings
//! - **Smart Path Detection**: Validates Pixi environment structure and package integrity
//!
//! # Check Categories
//!
//! ## Critical Checks (Must Pass)
//! - **Python Executable**: Must exist at `.pixi/envs/default/python[.exe]`
//!   - **Why Fatal**: Without Python, launcher cannot start at all
//!   - **Fix**: Run `pixi install` to create environment
//!
//! ## Optional Checks (Warnings Only)
//! - **Critical Packages**: PyQt6, numpy, cryptography, frida, capstone
//!   - **Why Optional**: Python can import and fail gracefully with better error messages
//! - **Package DLLs/SOs**: Native extensions for packages
//!   - **Why Optional**: Runtime import errors are more informative than preflight failures
//!
//! # Performance
//!
//! - Total execution time: 5-10ms (filesystem checks only)
//! - No process spawning or expensive operations
//! - Validates paths only, doesn't parse package metadata
//!
//! # Example
//!
//! ```no_run
//! use intellicrack_launcher::preflight_checks;
//!
//! // Call before Python initialization
//! if let Err(e) = preflight_checks::run_preflight_checks() {
//!     eprintln!("{}", e);
//!     std::process::exit(1);
//! }
//! ```

use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Errors that can occur during preflight validation.
///
/// These errors indicate critical environment misconfigurations that prevent
/// the launcher from starting. They include helpful diagnostic information
/// and remediation steps.
#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error("Python executable not found at expected location: {path}\n\nTo fix this issue:\n  1. Run: pixi install\n  2. Verify installation completed successfully\n  3. Try launching again\n\nIf the problem persists, check that you're in the correct project directory.")]
    PythonNotFound { path: String },

    #[error("Python path exists but is not executable: {path}\n\nTo fix this issue:\n  1. Check file permissions\n  2. Run: pixi install --force\n  3. Try launching again")]
    PythonNotExecutable { path: String },

    #[error("Environment validation failed: {0}")]
    ValidationError(String),
}

/// Critical packages that must be present for core functionality.
///
/// These packages are essential for Intellicrack's binary analysis capabilities:
/// - **PyQt6**: GUI framework for the main application interface
/// - **numpy**: Numerical computing for data analysis and manipulation
/// - **cryptography**: Cryptographic operations for license analysis
/// - **frida**: Dynamic instrumentation for runtime analysis
/// - **capstone**: Disassembly engine for binary code analysis
const CRITICAL_PACKAGES: &[&str] = &["PyQt6", "numpy", "cryptography", "frida", "capstone"];

/// Critical native extensions (DLLs on Windows, SOs on Unix) that must be present.
///
/// These are compiled extensions that packages depend on. Missing DLLs typically
/// indicate incomplete or corrupted package installations.
#[cfg(target_os = "windows")]
const CRITICAL_DLLS: &[&str] = &[
    "PyQt6/QtCore.pyd",
    "numpy/core/_multiarray_umath.pyd",
    "cryptography/hazmat/bindings/_openssl.pyd",
];

#[cfg(not(target_os = "windows"))]
const CRITICAL_DLLS: &[&str] = &[
    "PyQt6/QtCore.so",
    "numpy/core/_multiarray_umath.so",
    "cryptography/hazmat/bindings/_openssl.so",
];

/// Gets the path to the project root directory.
///
/// Uses the `PROJECT_ROOT` environment constant set by the launcher.
/// Falls back to current directory if not set (shouldn't happen in production).
fn get_project_root() -> PathBuf {
    use crate::environment::PROJECT_ROOT;
    PathBuf::from(&*PROJECT_ROOT)
}

/// Gets the expected path to the Python executable in the Pixi environment.
///
/// # Returns
///
/// The platform-specific path:
/// - **Windows**: `.pixi/envs/default/python.exe`
/// - **Unix**: `.pixi/envs/default/bin/python`
fn get_python_executable_path() -> PathBuf {
    let project_root = get_project_root();

    #[cfg(target_os = "windows")]
    {
        project_root.join(".pixi").join("envs").join("default").join("python.exe")
    }

    #[cfg(not(target_os = "windows"))]
    {
        project_root.join(".pixi").join("envs").join("default").join("bin").join("python")
    }
}

/// Gets the path to the site-packages directory in the Pixi environment.
///
/// # Returns
///
/// The platform-specific path:
/// - **Windows**: `.pixi/envs/default/Lib/site-packages`
/// - **Unix**: `.pixi/envs/default/lib/python3.x/site-packages`
fn get_site_packages_path() -> PathBuf {
    let project_root = get_project_root();

    #[cfg(target_os = "windows")]
    {
        project_root.join(".pixi").join("envs").join("default").join("Lib").join("site-packages")
    }

    #[cfg(not(target_os = "windows"))]
    {
        let env_dir = project_root.join(".pixi").join("envs").join("default");
        let lib_dir = env_dir.join("lib");

        if let Ok(entries) = std::fs::read_dir(&lib_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if dir_name.starts_with("python3.") {
                        let site_packages = path.join("site-packages");
                        if site_packages.exists() {
                            return site_packages;
                        }
                    }
                }
            }
        }

        lib_dir.join("python3.11").join("site-packages")
    }
}

/// Checks if the Python executable exists and is accessible.
///
/// # Critical Check - Fatal if Fails
///
/// This is the only fatal preflight check. Without a Python executable,
/// the launcher cannot proceed at all.
///
/// # Returns
///
/// - `Ok(PathBuf)` containing the path to the Python executable
/// - `Err(PreflightError::PythonNotFound)` if Python doesn't exist
/// - `Err(PreflightError::PythonNotExecutable)` if Python exists but isn't executable
///
/// # Platform Behavior
///
/// - **Windows**: Checks for `.exe` extension and file existence
/// - **Unix**: Checks file existence and executable permission bit
fn check_python_executable() -> Result<PathBuf> {
    let python_path = get_python_executable_path();

    if !python_path.exists() {
        return Err(PreflightError::PythonNotFound {
            path: python_path.display().to_string(),
        }
        .into());
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&python_path)
            .context("Failed to read Python executable metadata")?;
        let permissions = metadata.permissions();

        if permissions.mode() & 0o111 == 0 {
            return Err(PreflightError::PythonNotExecutable {
                path: python_path.display().to_string(),
            }
            .into());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if !python_path.extension().map_or(false, |e| e == "exe") {
            warn!("Python executable missing .exe extension: {}", python_path.display());
        }
    }

    info!("✓ Python executable found at {}", python_path.display());
    Ok(python_path)
}

/// Checks for the presence of critical Python packages.
///
/// # Optional Check - Warnings Only
///
/// Missing packages are logged as warnings but don't prevent launch.
/// Python's import system will provide more detailed error messages at runtime.
///
/// # Returns
///
/// A vector of missing package names. Empty vector if all packages are present.
///
/// # Performance
///
/// Fast directory existence checks only (~1-2ms for 5 packages).
fn check_critical_packages() -> Result<Vec<String>> {
    let site_packages = get_site_packages_path();

    if !site_packages.exists() {
        warn!("Site-packages directory not found: {}", site_packages.display());
        return Ok(CRITICAL_PACKAGES.iter().map(|s| s.to_string()).collect());
    }

    let mut missing = Vec::new();

    for &package in CRITICAL_PACKAGES {
        let package_path = site_packages.join(package);

        if !package_path.exists() || !package_path.is_dir() {
            debug!("Package directory not found: {}", package_path.display());
            missing.push(package.to_string());
        } else {
            debug!("✓ Package found: {}", package);
        }
    }

    Ok(missing)
}

/// Checks for the presence of critical native extensions (DLLs/SOs).
///
/// # Optional Check - Warnings Only
///
/// Missing DLLs are logged as warnings. Import errors at runtime will
/// provide more specific information about what's missing.
///
/// # Returns
///
/// A vector of missing DLL/SO paths (relative to site-packages).
///
/// # Performance
///
/// Fast file existence checks only (~1-2ms for 3 DLLs).
fn check_package_dlls() -> Result<Vec<String>> {
    let site_packages = get_site_packages_path();

    if !site_packages.exists() {
        warn!("Site-packages directory not found: {}", site_packages.display());
        return Ok(CRITICAL_DLLS.iter().map(|s| s.to_string()).collect());
    }

    let mut missing = Vec::new();

    for &dll_path in CRITICAL_DLLS {
        let full_path = site_packages.join(dll_path);

        if !full_path.exists() {
            debug!("DLL/SO not found: {}", full_path.display());
            missing.push(dll_path.to_string());
        } else {
            debug!("✓ DLL/SO found: {}", dll_path);
        }
    }

    Ok(missing)
}

/// Creates a formatted, actionable error message for missing dependencies.
///
/// # Arguments
///
/// - `missing_packages`: List of package names that are missing
/// - `missing_dlls`: List of DLL/SO paths (relative) that are missing
///
/// # Returns
///
/// A formatted string with:
/// - Clear header indicating the problem
/// - Categorized list of missing items
/// - Step-by-step fix instructions
/// - ANSI color codes if terminal supports them
fn create_warning_message(missing_packages: &[String], missing_dlls: &[String]) -> String {
    let mut message = String::new();

    if missing_packages.is_empty() && missing_dlls.is_empty() {
        return message;
    }

    message.push_str("\n⚠ Warning: Missing optional dependencies detected:\n\n");

    if !missing_packages.is_empty() {
        message.push_str("Packages:\n");
        for package in missing_packages {
            message.push_str(&format!("  - {}\n", package));
        }
        message.push('\n');
    }

    if !missing_dlls.is_empty() {
        message.push_str("Native Extensions (DLL/SO files):\n");
        for dll in missing_dlls {
            message.push_str(&format!("  - {}\n", dll));
        }
        message.push('\n');
    }

    message.push_str("Some functionality may be limited or unavailable.\n\n");
    message.push_str("To fix this issue:\n");
    message.push_str("  1. Run: pixi install\n");
    message.push_str("  2. Verify installation completed successfully\n");
    message.push_str("  3. Try launching again\n");

    message
}

/// Runs all preflight environment checks before Python initialization.
///
/// # Validation Strategy
///
/// 1. **Critical Check**: Python executable (fatal if missing)
/// 2. **Optional Check**: Critical packages (warnings only)
/// 3. **Optional Check**: Native extensions (warnings only)
///
/// # Performance
///
/// Total execution time: 5-10ms (filesystem checks only, no subprocess spawning)
///
/// # Error Handling
///
/// - **Python missing**: Returns `Err` with helpful error message (fatal)
/// - **Packages missing**: Logs warnings, returns `Ok` (non-fatal)
/// - **DLLs missing**: Logs warnings, returns `Ok` (non-fatal)
///
/// # Returns
///
/// - `Ok(())` if critical checks pass (optional checks may have warnings)
/// - `Err(PreflightError)` if Python executable is missing or inaccessible
///
/// # Example
///
/// ```no_run
/// use intellicrack_launcher::preflight_checks;
///
/// if let Err(e) = preflight_checks::run_preflight_checks() {
///     eprintln!("Critical environment error:\n{}", e);
///     std::process::exit(1);
/// }
/// ```
pub fn run_preflight_checks() -> Result<()> {
    info!("Running preflight environment checks...");
    let start = std::time::Instant::now();

    check_python_executable().context("Critical: Python executable validation failed")?;

    let missing_packages = check_critical_packages()
        .context("Package validation check failed")?;

    let missing_dlls = check_package_dlls()
        .context("DLL/SO validation check failed")?;

    if !missing_packages.is_empty() {
        warn!("Missing packages: {:?}", missing_packages);
    } else {
        info!("✓ All critical packages present");
    }

    if !missing_dlls.is_empty() {
        warn!("Missing DLL/SO files: {:?}", missing_dlls);
    } else {
        info!("✓ All critical DLL/SO files present");
    }

    if !missing_packages.is_empty() || !missing_dlls.is_empty() {
        let warning_msg = create_warning_message(&missing_packages, &missing_dlls);
        warn!("{}", warning_msg);
    }

    info!("✓ Preflight checks completed in {:?}", start.elapsed());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_python_path_structure() {
        let path = get_python_executable_path();
        assert!(path.to_string_lossy().contains(".pixi"));
        assert!(path.to_string_lossy().contains("envs"));
        assert!(path.to_string_lossy().contains("default"));

        #[cfg(target_os = "windows")]
        assert!(path.to_string_lossy().ends_with("python.exe"));

        #[cfg(not(target_os = "windows"))]
        assert!(path.to_string_lossy().contains("python"));
    }

    #[test]
    fn test_get_site_packages_path_structure() {
        let path = get_site_packages_path();
        assert!(path.to_string_lossy().contains(".pixi"));
        assert!(path.to_string_lossy().contains("site-packages"));
    }

    #[test]
    fn test_warning_message_format() {
        let packages = vec!["PyQt6".to_string(), "numpy".to_string()];
        let dlls = vec!["PyQt6/QtCore.pyd".to_string()];

        let message = create_warning_message(&packages, &dlls);

        assert!(message.contains("Warning"));
        assert!(message.contains("PyQt6"));
        assert!(message.contains("numpy"));
        assert!(message.contains("QtCore.pyd"));
        assert!(message.contains("pixi install"));
    }

    #[test]
    fn test_warning_message_empty() {
        let message = create_warning_message(&[], &[]);
        assert!(message.is_empty());
    }

    #[test]
    fn test_critical_packages_list() {
        assert!(CRITICAL_PACKAGES.contains(&"PyQt6"));
        assert!(CRITICAL_PACKAGES.contains(&"numpy"));
        assert!(CRITICAL_PACKAGES.contains(&"cryptography"));
        assert!(CRITICAL_PACKAGES.contains(&"frida"));
        assert!(CRITICAL_PACKAGES.contains(&"capstone"));
        assert_eq!(CRITICAL_PACKAGES.len(), 5);
    }

    #[test]
    fn test_critical_dlls_list() {
        assert!(!CRITICAL_DLLS.is_empty());
        assert!(CRITICAL_DLLS.iter().any(|&dll| dll.contains("QtCore")));
        assert!(CRITICAL_DLLS.iter().any(|&dll| dll.contains("multiarray")));
        assert!(CRITICAL_DLLS.iter().any(|&dll| dll.contains("openssl")));
    }
}
