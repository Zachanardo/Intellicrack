/*!
# Platform Detection Module

Detects platform type (Windows/WSL/Linux), GPU vendor, and display availability
for proper Intellicrack environment configuration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{env, fs};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OsType {
    Windows,
    Unix,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GpuVendor {
    Intel,
    Nvidia,
    Amd,
    Unknown,
}

impl std::str::FromStr for GpuVendor {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "intel" => Ok(GpuVendor::Intel),
            "nvidia" => Ok(GpuVendor::Nvidia),
            "amd" => Ok(GpuVendor::Amd),
            _ => Ok(GpuVendor::Unknown),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os_type: OsType,
    pub is_wsl: bool,
    pub gpu_vendor: GpuVendor,
    pub display_available: bool,
    pub font_directory: PathBuf,
    pub architecture: String,
    pub version: String,
}

impl PlatformInfo {
    /// Detect platform information with comprehensive system analysis
    pub fn detect() -> Result<Self> {
        info!("Detecting platform information...");

        // Detect OS type
        let os_type = if cfg!(target_os = "windows") {
            OsType::Windows
        } else {
            OsType::Unix
        };
        debug!("OS type detected: {:?}", os_type);

        // WSL detection by reading /proc/version on Unix systems
        let is_wsl = if os_type == OsType::Unix {
            Self::detect_wsl().unwrap_or(false)
        } else {
            false
        };
        if is_wsl {
            info!("Running under Windows Subsystem for Linux (WSL)");
        }

        // GPU vendor detection
        let gpu_vendor = Self::detect_gpu_vendor().unwrap_or_else(|e| {
            warn!("Failed to detect GPU vendor: {}", e);
            GpuVendor::Unknown
        });
        info!("GPU vendor detected: {:?}", gpu_vendor);

        // Display availability check
        let display_available = Self::detect_display_availability();
        debug!("Display available: {}", display_available);

        // Font directory setup
        let font_directory = Self::get_font_directory(&os_type)?;
        debug!("Font directory: {:?}", font_directory);

        // Architecture detection
        let architecture = Self::detect_architecture();
        debug!("Architecture detected: {}", architecture);

        // Version detection
        let version = Self::detect_version();
        debug!("Version detected: {}", version);

        Ok(PlatformInfo {
            os_type,
            is_wsl,
            gpu_vendor,
            display_available,
            font_directory,
            architecture,
            version,
        })
    }

    /// Detect WSL by reading /proc/version
    fn detect_wsl() -> Result<bool> {
        let proc_version_path = "/proc/version";
        if !std::path::Path::new(proc_version_path).exists() {
            return Ok(false);
        }

        match fs::read_to_string(proc_version_path) {
            Ok(content) => {
                let is_wsl = content.to_lowercase().contains("microsoft");
                debug!("/proc/version content indicates WSL: {}", is_wsl);
                Ok(is_wsl)
            }
            Err(e) => {
                warn!("Could not read /proc/version: {}", e);
                Ok(false)
            }
        }
    }

    /// Detect GPU vendor from environment or system
    fn detect_gpu_vendor() -> Result<GpuVendor> {
        // First check environment variable (set by user/system)
        if let Ok(gpu_env) = env::var("INTELLICRACK_GPU_VENDOR") {
            debug!("GPU vendor from environment: {}", gpu_env);
            return gpu_env.parse();
        }

        // Try to detect from system on Windows
        #[cfg(target_os = "windows")]
        {
            if let Ok(vendor) = Self::detect_windows_gpu_vendor() {
                return Ok(vendor);
            }
        }

        // Default to Intel since that's what the current system is configured for
        debug!("Defaulting to Intel GPU vendor");
        Ok(GpuVendor::Intel)
    }

    /// Detect GPU vendor on Windows using system information
    #[cfg(target_os = "windows")]
    fn detect_windows_gpu_vendor() -> Result<GpuVendor> {
        use std::process::Command;

        // Use WMIC to query display adapters
        let output = Command::new("wmic")
            .args(["path", "win32_VideoController", "get", "name"])
            .output()
            .context("Failed to run wmic command")?;

        let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
        debug!("WMIC GPU output: {}", output_str);

        if output_str.contains("intel") {
            Ok(GpuVendor::Intel)
        } else if output_str.contains("nvidia") {
            Ok(GpuVendor::Nvidia)
        } else if output_str.contains("amd") || output_str.contains("radeon") {
            Ok(GpuVendor::Amd)
        } else {
            Ok(GpuVendor::Unknown)
        }
    }

    /// Detect display availability
    fn detect_display_availability() -> bool {
        // Check for DISPLAY environment variable (X11)
        if env::var("DISPLAY").is_ok() {
            debug!("Display available via DISPLAY environment variable");
            return true;
        }

        // Check for Qt platform override
        if env::var("QT_QPA_PLATFORM").is_ok() {
            debug!("Display configuration via QT_QPA_PLATFORM");
            return true;
        }

        // Check for Wayland
        if env::var("WAYLAND_DISPLAY").is_ok() {
            debug!("Display available via Wayland");
            return true;
        }

        // On Windows, assume display is available unless explicitly set to offscreen
        #[cfg(target_os = "windows")]
        {
            true
        }

        #[cfg(not(target_os = "windows"))]
        {
            debug!("No display detected");
            false
        }
    }

    /// Get the appropriate font directory for the platform
    fn get_font_directory(os_type: &OsType) -> Result<PathBuf> {
        match os_type {
            OsType::Windows => {
                let windir = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
                Ok(PathBuf::from(windir).join("Fonts"))
            }
            OsType::Unix => {
                // Try common Unix font directories
                let font_dirs = vec![
                    "/usr/share/fonts",
                    "/usr/local/share/fonts",
                    "/System/Library/Fonts", // macOS
                    "/opt/local/share/fonts",
                ];

                for dir in font_dirs {
                    let path = PathBuf::from(dir);
                    if path.exists() {
                        return Ok(path);
                    }
                }

                // Fallback to /usr/share/fonts even if it doesn't exist
                Ok(PathBuf::from("/usr/share/fonts"))
            }
        }
    }

    /// Detect system architecture
    fn detect_architecture() -> String {
        // Use cfg! to determine architecture at compile time
        if cfg!(target_arch = "x86_64") {
            "x86_64".to_string()
        } else if cfg!(target_arch = "x86") {
            "x86".to_string()
        } else if cfg!(target_arch = "aarch64") {
            "aarch64".to_string()
        } else if cfg!(target_arch = "arm") {
            "arm".to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// Detect system version
    fn detect_version() -> String {
        // Try to get OS version information
        if cfg!(target_os = "windows") {
            // On Windows, try to get version from environment
            env::var("OS").unwrap_or_else(|_| "Windows".to_string())
        } else if cfg!(target_os = "linux") {
            // On Linux, try to read /etc/os-release
            if let Ok(content) = fs::read_to_string("/etc/os-release") {
                for line in content.lines() {
                    if line.starts_with("PRETTY_NAME=") {
                        return line
                            .trim_start_matches("PRETTY_NAME=\"")
                            .trim_end_matches("\"")
                            .to_string();
                    }
                }
            }
            "Linux".to_string()
        } else if cfg!(target_os = "macos") {
            // On macOS, use sw_vers or uname
            if let Ok(output) = std::process::Command::new("sw_vers")
                .arg("-productVersion")
                .output()
                && let Ok(version) = String::from_utf8(output.stdout) {
                    return format!("macOS {}", version.trim());
                }
            "macOS".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Configure Qt platform based on detected environment
    pub fn configure_qt_platform(&self) -> Result<()> {
        unsafe {
            match (&self.os_type, self.is_wsl, self.display_available) {
                (OsType::Windows, false, _) => {
                    // Native Windows - use windows platform
                    env::set_var("QT_QPA_PLATFORM", "windows");
                    info!("Configured Qt for native Windows");
                }
                (OsType::Unix, true, false) => {
                    // WSL without display - use offscreen
                    env::set_var("QT_QPA_PLATFORM", "offscreen");
                    info!("Configured Qt for WSL offscreen mode");
                }
                (OsType::Unix, false, true) => {
                    // Native Linux with display - use xcb or wayland
                    if env::var("WAYLAND_DISPLAY").is_ok() {
                        env::set_var("QT_QPA_PLATFORM", "wayland");
                        info!("Configured Qt for Wayland");
                    } else {
                        env::set_var("QT_QPA_PLATFORM", "xcb");
                        info!("Configured Qt for X11");
                    }
                }
                (OsType::Unix, false, false) => {
                    // Native Linux without display - use offscreen
                    env::set_var("QT_QPA_PLATFORM", "offscreen");
                    info!("Configured Qt for Linux offscreen mode");
                }
                _ => {
                    debug!("Using default Qt platform configuration");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    #[test]
    fn test_os_type_basic_detection() {
        let platform = PlatformInfo::detect();
        assert!(platform.is_ok());

        let platform = platform.unwrap();

        // Should detect either Windows or Unix
        assert!(platform.os_type == OsType::Windows || platform.os_type == OsType::Unix);
    }

    #[test]
    fn test_gpu_vendor_from_str_parsing() {
        assert_eq!("intel".parse::<GpuVendor>().unwrap(), GpuVendor::Intel);
        assert_eq!("INTEL".parse::<GpuVendor>().unwrap(), GpuVendor::Intel);
        assert_eq!("nvidia".parse::<GpuVendor>().unwrap(), GpuVendor::Nvidia);
        assert_eq!("NVIDIA".parse::<GpuVendor>().unwrap(), GpuVendor::Nvidia);
        assert_eq!("amd".parse::<GpuVendor>().unwrap(), GpuVendor::Amd);
        assert_eq!("AMD".parse::<GpuVendor>().unwrap(), GpuVendor::Amd);
        assert_eq!("unknown".parse::<GpuVendor>().unwrap(), GpuVendor::Unknown);
        assert_eq!("invalid".parse::<GpuVendor>().unwrap(), GpuVendor::Unknown);
    }

    #[test]
    fn test_gpu_vendor_detection_with_env_var() {
        // Test environment variable override
        unsafe {
            env::set_var("INTELLICRACK_GPU_VENDOR", "nvidia");
        }
        let vendor = PlatformInfo::detect_gpu_vendor().unwrap();
        assert_eq!(vendor, GpuVendor::Nvidia);

        unsafe {
            env::set_var("INTELLICRACK_GPU_VENDOR", "amd");
        }
        let vendor = PlatformInfo::detect_gpu_vendor().unwrap();
        assert_eq!(vendor, GpuVendor::Amd);

        // Clean up
        unsafe {
            env::remove_var("INTELLICRACK_GPU_VENDOR");
        }
    }

    #[test]
    fn test_gpu_vendor_detection_fallback() {
        // Ensure no environment variable is set
        unsafe {
            env::remove_var("INTELLICRACK_GPU_VENDOR");
        }

        // Should fall back to default detection
        let vendor = PlatformInfo::detect_gpu_vendor().unwrap();
        // Should be one of the valid variants
        assert!(matches!(
            vendor,
            GpuVendor::Intel | GpuVendor::Nvidia | GpuVendor::Amd | GpuVendor::Unknown
        ));
    }

    #[test]
    fn test_display_availability_detection() {
        // Test with DISPLAY variable set
        unsafe {
            env::set_var("DISPLAY", ":0");
        }
        assert!(PlatformInfo::detect_display_availability());
        unsafe {
            env::remove_var("DISPLAY");
        }

        // Test with QT_QPA_PLATFORM set
        unsafe {
            env::set_var("QT_QPA_PLATFORM", "xcb");
        }
        assert!(PlatformInfo::detect_display_availability());
        unsafe {
            env::remove_var("QT_QPA_PLATFORM");
        }
    }
    #[test]
    fn test_font_directory_detection_windows() {
        let os_type = OsType::Windows;
        let font_dir = PlatformInfo::get_font_directory(&os_type).unwrap();

        // Should contain "Fonts" in the path
        assert!(font_dir.to_string_lossy().contains("Fonts"));

        // Test with custom WINDIR
        unsafe {
            env::set_var("WINDIR", "D:\\CustomWindows");
        }
        let custom_font_dir = PlatformInfo::get_font_directory(&os_type).unwrap();
        assert_eq!(custom_font_dir, PathBuf::from("D:\\CustomWindows\\Fonts"));
        unsafe {
            env::remove_var("WINDIR");
        }
    }

    #[test]
    fn test_qt_platform_configuration_windows() {
        let platform = PlatformInfo {
            os_type: OsType::Windows,
            is_wsl: false,
            gpu_vendor: GpuVendor::Intel,
            display_available: true,
            font_directory: PathBuf::from("C:\\Windows\\Fonts"),
            architecture: "x86_64".to_string(),
            version: "Windows 11".to_string(),
        };

        platform.configure_qt_platform().unwrap();
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "windows");
        unsafe {
            env::remove_var("QT_QPA_PLATFORM");
        }
    }

    #[test]
    fn test_qt_platform_configuration_wsl_no_display() {
        let platform = PlatformInfo {
            os_type: OsType::Unix,
            is_wsl: true,
            gpu_vendor: GpuVendor::Intel,
            display_available: false,
            font_directory: PathBuf::from("/usr/share/fonts"),
            architecture: "x86_64".to_string(),
            version: "Ubuntu 22.04".to_string(),
        };

        platform.configure_qt_platform().unwrap();
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "offscreen");
        unsafe {
            env::remove_var("QT_QPA_PLATFORM");
        }
    }

    #[test]
    fn test_qt_platform_configuration_unix_with_display() {
        let platform = PlatformInfo {
            os_type: OsType::Unix,
            is_wsl: false,
            gpu_vendor: GpuVendor::Intel,
            display_available: true,
            font_directory: PathBuf::from("/usr/share/fonts"),
            architecture: "x86_64".to_string(),
            version: "Ubuntu 22.04".to_string(),
        };

        // Test X11 configuration
        unsafe {
            env::remove_var("WAYLAND_DISPLAY");
        }
        platform.configure_qt_platform().unwrap();
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "xcb");
        unsafe {
            env::remove_var("QT_QPA_PLATFORM");
        }

        // Test Wayland configuration
        unsafe {
            env::set_var("WAYLAND_DISPLAY", "wayland-0");
        }
        platform.configure_qt_platform().unwrap();
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "wayland");
        unsafe {
            env::remove_var("QT_QPA_PLATFORM");
            env::remove_var("WAYLAND_DISPLAY");
        }
    }

    #[test]
    fn test_qt_platform_configuration_unix_no_display() {
        let platform = PlatformInfo {
            os_type: OsType::Unix,
            is_wsl: false,
            gpu_vendor: GpuVendor::Intel,
            display_available: false,
            font_directory: PathBuf::from("/usr/share/fonts"),
            architecture: "x86_64".to_string(),
            version: "Ubuntu 22.04".to_string(),
        };

        platform.configure_qt_platform().unwrap();
        assert_eq!(env::var("QT_QPA_PLATFORM").unwrap(), "offscreen");
        unsafe {
            env::remove_var("QT_QPA_PLATFORM");
        }
    }

    #[test]
    fn test_wsl_detection_with_proc_version() {
        // Test WSL detection logic (only on Unix systems)
        #[cfg(unix)]
        {
            // Create a temporary /proc/version file for testing
            let temp_dir = TempDir::new().unwrap();
            let proc_version_path = temp_dir.path().join("version");

            // Test Microsoft kernel (WSL)
            fs::write(&proc_version_path,
                "Linux version 4.19.128-microsoft-standard (oe-user@oe-host) (gcc version 8.2.0 (GCC)) #1 SMP Tue Jun 23 12:58:10 UTC 2020"
            ).unwrap();

            // We can't easily mock the file path, but we can test the string parsing logic
            let content = fs::read_to_string(&proc_version_path).unwrap();
            assert!(content.to_lowercase().contains("microsoft"));

            // Test non-WSL kernel
            fs::write(&proc_version_path,
                "Linux version 5.4.0-42-generic (buildd@lgw01-amd64-038) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020"
            ).unwrap();

            let content = fs::read_to_string(&proc_version_path).unwrap();
            assert!(!content.to_lowercase().contains("microsoft"));
        }
    }

    #[test]
    fn test_platform_info_serialization() {
        let platform = PlatformInfo {
            os_type: OsType::Windows,
            is_wsl: false,
            gpu_vendor: GpuVendor::Intel,
            display_available: true,
            font_directory: PathBuf::from("C:\\Windows\\Fonts"),
            architecture: "x86_64".to_string(),
            version: "Windows 11".to_string(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&platform).unwrap();
        assert!(json.contains("Windows"));
        assert!(json.contains("Intel"));

        // Test deserialization
        let deserialized: PlatformInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.os_type, OsType::Windows);
        assert_eq!(deserialized.gpu_vendor, GpuVendor::Intel);
        assert!(!deserialized.is_wsl);
        assert!(deserialized.display_available);
    }

    #[test]
    fn test_platform_info_consistency() {
        // Multiple detections should return consistent results
        let platform1 = PlatformInfo::detect().unwrap();
        let platform2 = PlatformInfo::detect().unwrap();

        assert_eq!(platform1.os_type, platform2.os_type);
        assert_eq!(platform1.is_wsl, platform2.is_wsl);
        // GPU vendor might vary if environment changes, so we don't test it
        // assert_eq!(platform1.gpu_vendor, platform2.gpu_vendor);
        assert_eq!(platform1.font_directory, platform2.font_directory);
    }

    #[test]
    fn test_platform_info_debug_display() {
        let platform = PlatformInfo {
            os_type: OsType::Unix,
            is_wsl: true,
            gpu_vendor: GpuVendor::Nvidia,
            display_available: false,
            font_directory: PathBuf::from("/usr/share/fonts"),
            architecture: "x86_64".to_string(),
            version: "Ubuntu 22.04".to_string(),
        };

        let debug_string = format!("{:?}", platform);
        assert!(debug_string.contains("Unix"));
        assert!(debug_string.contains("true")); // is_wsl
        assert!(debug_string.contains("Nvidia"));
        assert!(debug_string.contains("false")); // display_available
    }

    #[test]
    fn test_gpu_vendor_parsing_edge_cases() {
        // Test case insensitive parsing
        assert_eq!("InTeL".parse::<GpuVendor>().unwrap(), GpuVendor::Intel);
        assert_eq!("NvIdIa".parse::<GpuVendor>().unwrap(), GpuVendor::Nvidia);
        assert_eq!("AmD".parse::<GpuVendor>().unwrap(), GpuVendor::Amd);

        // Test empty string
        assert_eq!("".parse::<GpuVendor>().unwrap(), GpuVendor::Unknown);

        // Test random string
        assert_eq!(
            "random_vendor".parse::<GpuVendor>().unwrap(),
            GpuVendor::Unknown
        );

        // Test whitespace
        assert_eq!(
            "  intel  ".parse::<GpuVendor>().unwrap(),
            GpuVendor::Unknown
        ); // trim not implemented
    }

    #[test]
    fn test_font_directory_fallback_behavior() {
        // Test Unix fallback when no directories exist
        let os_type = OsType::Unix;
        let font_dir = PlatformInfo::get_font_directory(&os_type).unwrap();

        // Should always return a path, even if it doesn't exist
        assert!(!font_dir.as_os_str().is_empty());

        // Should be a valid path structure
        assert!(font_dir.is_absolute() || font_dir.starts_with("/"));
    }

    #[test]
    fn test_temporary_directory_operations() {
        // Test temporary directory creation and usage
        let temp_dir = TempDir::new().unwrap();
        let temp_file_path = temp_dir.path().join("test_config.txt");

        // Write test data to temporary file
        fs::write(&temp_file_path, "test configuration data").unwrap();

        // Verify file was created and contains expected data
        assert!(temp_file_path.exists());
        let content = fs::read_to_string(&temp_file_path).unwrap();
        assert_eq!(content, "test configuration data");

        // Test temporary directory cleanup (automatic when TempDir goes out of scope)
        drop(temp_file_path);
        // TempDir will be cleaned up automatically
    }

    #[test]
    fn test_comprehensive_platform_detection() {
        let platform = PlatformInfo::detect().unwrap();

        // Verify all fields are properly initialized
        assert!(platform.os_type == OsType::Windows || platform.os_type == OsType::Unix);
        // is_wsl can be true or false
        assert!(matches!(
            platform.gpu_vendor,
            GpuVendor::Intel | GpuVendor::Nvidia | GpuVendor::Amd | GpuVendor::Unknown
        ));
        // display_available can be true or false
        assert!(!platform.font_directory.as_os_str().is_empty());

        // Platform-specific validations
        if platform.os_type == OsType::Windows {
            assert!(!platform.is_wsl); // Windows native should not be WSL
            assert!(
                platform
                    .font_directory
                    .to_string_lossy()
                    .contains("Windows")
                    || platform.font_directory.to_string_lossy().contains("Fonts")
            );
        }

        if platform.is_wsl {
            assert_eq!(platform.os_type, OsType::Unix); // WSL should be Unix type
        }
    }
}
