use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StartupCheckResult {
    pub component: String,
    pub status: StartupStatus,
    pub message: String,
    pub details: HashMap<String, String>,
    pub severity: CheckSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StartupStatus {
    Pass,
    Warning,
    Fail,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemRequirements {
    pub min_memory_mb: u64,
    pub min_disk_space_mb: u64,
    pub required_permissions: Vec<String>,
    pub required_environment_vars: Vec<String>,
    pub critical_dependencies: Vec<String>,
}

impl Default for SystemRequirements {
    fn default() -> Self {
        Self {
            min_memory_mb: 2048,     // 2GB minimum
            min_disk_space_mb: 5120, // 5GB minimum
            required_permissions: vec![
                "file_read".to_string(),
                "file_write".to_string(),
                "process_create".to_string(),
            ],
            required_environment_vars: vec!["PATH".to_string(), "HOME".to_string()],
            critical_dependencies: vec!["python".to_string(), "pip".to_string()],
        }
    }
}

#[derive(Debug)]
pub struct StartupValidator {
    requirements: SystemRequirements,
    check_results: Vec<StartupCheckResult>,
}

impl Default for StartupValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupValidator {
    pub fn new() -> Self {
        Self {
            requirements: SystemRequirements::default(),
            check_results: Vec::new(),
        }
    }

    pub fn with_requirements(requirements: SystemRequirements) -> Self {
        Self {
            requirements,
            check_results: Vec::new(),
        }
    }

    pub async fn perform_comprehensive_checks() -> Result<Vec<StartupCheckResult>> {
        let mut validator = StartupValidator::new();
        validator.run_all_checks().await?;
        Ok(validator.check_results)
    }

    pub async fn run_all_checks(&mut self) -> Result<()> {
        info!("Starting comprehensive startup validation");

        // Clear previous results
        self.check_results.clear();

        // Run all validation checks
        self.check_operating_system().await;
        self.check_system_architecture().await;
        self.check_memory_requirements().await;
        self.check_disk_space().await;
        self.check_permissions().await;
        self.check_environment_variables().await;
        self.check_python_installation().await;
        self.check_critical_dependencies().await;
        self.check_network_connectivity().await;
        self.check_security_configuration().await;
        self.check_file_system_access().await;
        self.check_process_permissions().await;

        // Log summary
        self.log_validation_summary();

        Ok(())
    }

    async fn check_operating_system(&mut self) {
        debug!("Checking operating system compatibility");

        let os = env::consts::OS;
        let mut details = HashMap::new();
        details.insert("detected_os".to_string(), os.to_string());
        details.insert("family".to_string(), env::consts::FAMILY.to_string());

        let (status, message, severity) = match os {
            "windows" => {
                details.insert("version".to_string(), self.get_windows_version().await);
                (
                    StartupStatus::Pass,
                    "Windows OS detected and supported".to_string(),
                    CheckSeverity::Info,
                )
            }
            "linux" => {
                details.insert(
                    "distribution".to_string(),
                    self.get_linux_distribution().await,
                );
                (
                    StartupStatus::Pass,
                    "Linux OS detected and supported".to_string(),
                    CheckSeverity::Info,
                )
            }
            "macos" => (
                StartupStatus::Warning,
                "macOS detected - limited support".to_string(),
                CheckSeverity::Medium,
            ),
            _ => (
                StartupStatus::Fail,
                format!("Unsupported operating system: {}", os),
                CheckSeverity::High,
            ),
        };

        self.check_results.push(StartupCheckResult {
            component: "Operating System".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_system_architecture(&mut self) {
        debug!("Checking system architecture");

        let arch = env::consts::ARCH;
        let mut details = HashMap::new();
        details.insert("detected_arch".to_string(), arch.to_string());

        let (status, message, severity) = match arch {
            "x86_64" | "aarch64" => (
                StartupStatus::Pass,
                format!("Supported architecture: {}", arch),
                CheckSeverity::Info,
            ),
            "x86" => (
                StartupStatus::Warning,
                "32-bit architecture detected - performance may be limited".to_string(),
                CheckSeverity::Medium,
            ),
            _ => (
                StartupStatus::Fail,
                format!("Unsupported architecture: {}", arch),
                CheckSeverity::High,
            ),
        };

        self.check_results.push(StartupCheckResult {
            component: "System Architecture".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_memory_requirements(&mut self) {
        debug!("Checking memory requirements");

        let mut details = HashMap::new();
        details.insert(
            "required_memory_mb".to_string(),
            self.requirements.min_memory_mb.to_string(),
        );

        match self.get_available_memory().await {
            Ok(available_mb) => {
                details.insert("available_memory_mb".to_string(), available_mb.to_string());

                let (status, message, severity) = if available_mb >= self.requirements.min_memory_mb
                {
                    (
                        StartupStatus::Pass,
                        "Memory requirements satisfied".to_string(),
                        CheckSeverity::Info,
                    )
                } else if available_mb >= (self.requirements.min_memory_mb / 2) {
                    (
                        StartupStatus::Warning,
                        "Low memory detected - may impact performance".to_string(),
                        CheckSeverity::Medium,
                    )
                } else {
                    (
                        StartupStatus::Critical,
                        "Insufficient memory for operation".to_string(),
                        CheckSeverity::Critical,
                    )
                };

                self.check_results.push(StartupCheckResult {
                    component: "Memory Requirements".to_string(),
                    status,
                    message,
                    details,
                    severity,
                });
            }
            Err(e) => {
                details.insert("error".to_string(), e.to_string());
                self.check_results.push(StartupCheckResult {
                    component: "Memory Requirements".to_string(),
                    status: StartupStatus::Warning,
                    message: "Unable to determine available memory".to_string(),
                    details,
                    severity: CheckSeverity::Medium,
                });
            }
        }
    }

    async fn check_disk_space(&mut self) {
        debug!("Checking disk space requirements");

        let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut details = HashMap::new();
        details.insert(
            "required_space_mb".to_string(),
            self.requirements.min_disk_space_mb.to_string(),
        );
        details.insert("check_path".to_string(), current_dir.display().to_string());

        match self.get_available_disk_space(&current_dir).await {
            Ok(available_mb) => {
                details.insert("available_space_mb".to_string(), available_mb.to_string());

                let (status, message, severity) =
                    if available_mb >= self.requirements.min_disk_space_mb {
                        (
                            StartupStatus::Pass,
                            "Disk space requirements satisfied".to_string(),
                            CheckSeverity::Info,
                        )
                    } else if available_mb >= (self.requirements.min_disk_space_mb / 2) {
                        (
                            StartupStatus::Warning,
                            "Low disk space - may impact operation".to_string(),
                            CheckSeverity::Medium,
                        )
                    } else {
                        (
                            StartupStatus::Critical,
                            "Insufficient disk space for operation".to_string(),
                            CheckSeverity::Critical,
                        )
                    };

                self.check_results.push(StartupCheckResult {
                    component: "Disk Space".to_string(),
                    status,
                    message,
                    details,
                    severity,
                });
            }
            Err(e) => {
                details.insert("error".to_string(), e.to_string());
                self.check_results.push(StartupCheckResult {
                    component: "Disk Space".to_string(),
                    status: StartupStatus::Warning,
                    message: "Unable to determine available disk space".to_string(),
                    details,
                    severity: CheckSeverity::Medium,
                });
            }
        }
    }

    async fn check_permissions(&mut self) {
        debug!("Checking required permissions");

        let mut details = HashMap::new();
        let mut all_passed = true;
        let mut warnings = Vec::new();

        for permission in &self.requirements.required_permissions {
            let has_permission = match permission.as_str() {
                "file_read" => self.test_file_read_permission().await,
                "file_write" => self.test_file_write_permission().await,
                "process_create" => self.test_process_create_permission().await,
                _ => {
                    warnings.push(format!("Unknown permission: {}", permission));
                    false
                }
            };

            details.insert(permission.clone(), has_permission.to_string());
            if !has_permission {
                all_passed = false;
            }
        }

        let (status, message, severity) = if all_passed && warnings.is_empty() {
            (
                StartupStatus::Pass,
                "All required permissions available".to_string(),
                CheckSeverity::Info,
            )
        } else if !warnings.is_empty() {
            details.insert("warnings".to_string(), warnings.join(", "));
            (
                StartupStatus::Warning,
                "Some permission checks skipped".to_string(),
                CheckSeverity::Medium,
            )
        } else {
            (
                StartupStatus::Critical,
                "Missing required permissions".to_string(),
                CheckSeverity::Critical,
            )
        };

        self.check_results.push(StartupCheckResult {
            component: "Permissions".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_environment_variables(&mut self) {
        debug!("Checking required environment variables");

        let mut details = HashMap::new();
        let mut missing_vars = Vec::new();

        for var in &self.requirements.required_environment_vars {
            match env::var(var) {
                Ok(value) => {
                    details.insert(var.clone(), "present".to_string());
                    if var == "PATH" {
                        details.insert(
                            "path_entries".to_string(),
                            value.split(';').count().to_string(),
                        );
                    }
                }
                Err(_) => {
                    details.insert(var.clone(), "missing".to_string());
                    missing_vars.push(var.clone());
                }
            }
        }

        let (status, message, severity) = if missing_vars.is_empty() {
            (
                StartupStatus::Pass,
                "All required environment variables present".to_string(),
                CheckSeverity::Info,
            )
        } else {
            details.insert("missing_variables".to_string(), missing_vars.join(", "));
            (
                StartupStatus::Warning,
                "Some environment variables missing".to_string(),
                CheckSeverity::Medium,
            )
        };

        self.check_results.push(StartupCheckResult {
            component: "Environment Variables".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_python_installation(&mut self) {
        debug!("Checking Python installation");

        let mut details = HashMap::new();
        let python_commands = ["python", "python3", "py"];

        let mut python_found = false;
        let mut python_version = String::new();
        let mut python_executable = String::new();

        for cmd in &python_commands {
            match timeout(
                Duration::from_secs(10),
                Command::new(cmd).arg("--version").output(),
            )
            .await
            {
                Ok(Ok(output)) => {
                    if output.status.success() {
                        python_found = true;
                        python_executable = cmd.to_string();
                        python_version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        break;
                    }
                }
                _ => continue,
            }
        }

        details.insert("executable".to_string(), python_executable);
        details.insert("version".to_string(), python_version.clone());

        let (status, message, severity) = if python_found {
            // Check if version is adequate
            if python_version.contains("Python 3.") && !python_version.contains("Python 3.6") {
                (
                    StartupStatus::Pass,
                    "Python installation found and compatible".to_string(),
                    CheckSeverity::Info,
                )
            } else if python_version.contains("Python 3.6") {
                (
                    StartupStatus::Warning,
                    "Python 3.6 detected - consider upgrading".to_string(),
                    CheckSeverity::Medium,
                )
            } else if python_version.contains("Python 2.") {
                (
                    StartupStatus::Fail,
                    "Python 2.x detected - Python 3.x required".to_string(),
                    CheckSeverity::High,
                )
            } else {
                (
                    StartupStatus::Pass,
                    "Python installation detected".to_string(),
                    CheckSeverity::Info,
                )
            }
        } else {
            (
                StartupStatus::Critical,
                "Python installation not found".to_string(),
                CheckSeverity::Critical,
            )
        };

        self.check_results.push(StartupCheckResult {
            component: "Python Installation".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_critical_dependencies(&mut self) {
        debug!("Checking critical dependencies");

        let mut details = HashMap::new();
        let mut missing_deps = Vec::new();
        let mut available_deps = Vec::new();

        for dep in &self.requirements.critical_dependencies {
            let is_available = match dep.as_str() {
                "python" => {
                    self.check_command_available("python").await
                        || self.check_command_available("python3").await
                        || self.check_command_available("py").await
                }
                "pip" => {
                    self.check_command_available("pip").await
                        || self.check_command_available("pip3").await
                }
                "git" => self.check_command_available("git").await,
                "gcc" => self.check_command_available("gcc").await,
                "cmake" => self.check_command_available("cmake").await,
                _ => self.check_command_available(dep).await,
            };

            details.insert(dep.clone(), is_available.to_string());

            if is_available {
                available_deps.push(dep.clone());
            } else {
                missing_deps.push(dep.clone());
            }
        }

        details.insert(
            "available_count".to_string(),
            available_deps.len().to_string(),
        );
        details.insert("missing_count".to_string(), missing_deps.len().to_string());

        let (status, message, severity) = if missing_deps.is_empty() {
            (
                StartupStatus::Pass,
                "All critical dependencies available".to_string(),
                CheckSeverity::Info,
            )
        } else if missing_deps.len() <= available_deps.len() {
            details.insert("missing_dependencies".to_string(), missing_deps.join(", "));
            (
                StartupStatus::Warning,
                "Some dependencies missing".to_string(),
                CheckSeverity::Medium,
            )
        } else {
            details.insert("missing_dependencies".to_string(), missing_deps.join(", "));
            (
                StartupStatus::Critical,
                "Critical dependencies missing".to_string(),
                CheckSeverity::Critical,
            )
        };

        self.check_results.push(StartupCheckResult {
            component: "Critical Dependencies".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_network_connectivity(&mut self) {
        debug!("Checking network connectivity");

        let mut details = HashMap::new();

        // Test basic connectivity
        let connectivity_test =
            timeout(Duration::from_secs(5), self.test_network_connection()).await;

        let (status, message, severity) = match connectivity_test {
            Ok(Ok(true)) => {
                details.insert("connectivity".to_string(), "available".to_string());
                (
                    StartupStatus::Pass,
                    "Network connectivity available".to_string(),
                    CheckSeverity::Info,
                )
            }
            Ok(Ok(false)) => {
                details.insert("connectivity".to_string(), "limited".to_string());
                (
                    StartupStatus::Warning,
                    "Limited network connectivity".to_string(),
                    CheckSeverity::Low,
                )
            }
            _ => {
                details.insert("connectivity".to_string(), "unknown".to_string());
                (
                    StartupStatus::Warning,
                    "Unable to test network connectivity".to_string(),
                    CheckSeverity::Low,
                )
            }
        };

        self.check_results.push(StartupCheckResult {
            component: "Network Connectivity".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_security_configuration(&mut self) {
        debug!("Checking security configuration");

        let mut details = HashMap::new();
        let mut security_issues = Vec::new();

        // Check if running as administrator/root (should not be for security)
        let is_elevated = self.check_elevated_privileges().await;
        details.insert("elevated_privileges".to_string(), is_elevated.to_string());

        if is_elevated {
            security_issues.push("Running with elevated privileges - security risk".to_string());
        }

        // Check antivirus interference potential
        let av_interference = self.check_antivirus_interference().await;
        details.insert(
            "antivirus_interference".to_string(),
            av_interference.to_string(),
        );

        if av_interference {
            security_issues.push("Potential antivirus interference detected".to_string());
        }

        details.insert(
            "security_issues_count".to_string(),
            security_issues.len().to_string(),
        );

        let (status, message, severity) = if security_issues.is_empty() {
            (
                StartupStatus::Pass,
                "Security configuration acceptable".to_string(),
                CheckSeverity::Info,
            )
        } else if security_issues.len() == 1 {
            details.insert("security_issues".to_string(), security_issues.join(", "));
            (
                StartupStatus::Warning,
                "Minor security configuration issues".to_string(),
                CheckSeverity::Medium,
            )
        } else {
            details.insert("security_issues".to_string(), security_issues.join(", "));
            (
                StartupStatus::Fail,
                "Security configuration issues detected".to_string(),
                CheckSeverity::High,
            )
        };

        self.check_results.push(StartupCheckResult {
            component: "Security Configuration".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_file_system_access(&mut self) {
        debug!("Checking file system access");

        let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut details = HashMap::new();
        let mut access_issues = Vec::new();

        // Test read access
        let can_read = fs::read_dir(&current_dir).is_ok();
        details.insert("read_access".to_string(), can_read.to_string());

        if !can_read {
            access_issues.push("Cannot read current directory".to_string());
        }

        // Test write access
        let test_file = current_dir.join("test_write_access.tmp");
        let can_write = fs::write(&test_file, "test").is_ok();
        details.insert("write_access".to_string(), can_write.to_string());

        if can_write {
            let _ = fs::remove_file(&test_file);
        } else {
            access_issues.push("Cannot write to current directory".to_string());
        }

        // Test subdirectory creation
        let test_dir = current_dir.join("test_dir_access");
        let can_create_dir = fs::create_dir(&test_dir).is_ok();
        details.insert("directory_creation".to_string(), can_create_dir.to_string());

        if can_create_dir {
            let _ = fs::remove_dir(&test_dir);
        } else {
            access_issues.push("Cannot create subdirectories".to_string());
        }

        details.insert(
            "access_issues_count".to_string(),
            access_issues.len().to_string(),
        );

        let (status, message, severity) = if access_issues.is_empty() {
            (
                StartupStatus::Pass,
                "File system access validated".to_string(),
                CheckSeverity::Info,
            )
        } else {
            details.insert("access_issues".to_string(), access_issues.join(", "));
            (
                StartupStatus::Critical,
                "File system access issues detected".to_string(),
                CheckSeverity::Critical,
            )
        };

        self.check_results.push(StartupCheckResult {
            component: "File System Access".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    async fn check_process_permissions(&mut self) {
        debug!("Checking process permissions");

        let mut details = HashMap::new();
        let mut permission_issues = Vec::new();

        // Test process creation
        let can_spawn = timeout(
            Duration::from_secs(5),
            Command::new("echo").arg("test").output(),
        )
        .await
        .is_ok();

        details.insert("process_creation".to_string(), can_spawn.to_string());

        if !can_spawn {
            permission_issues.push("Cannot create processes".to_string());
        }

        // Check if we can get process information
        let process_info_available = self.can_access_process_info().await;
        details.insert(
            "process_info_access".to_string(),
            process_info_available.to_string(),
        );

        if !process_info_available {
            permission_issues.push("Limited process information access".to_string());
        }

        details.insert(
            "permission_issues_count".to_string(),
            permission_issues.len().to_string(),
        );

        let (status, message, severity) = if permission_issues.is_empty() {
            (
                StartupStatus::Pass,
                "Process permissions adequate".to_string(),
                CheckSeverity::Info,
            )
        } else {
            details.insert(
                "permission_issues".to_string(),
                permission_issues.join(", "),
            );
            (
                StartupStatus::Warning,
                "Some process permission limitations".to_string(),
                CheckSeverity::Medium,
            )
        };

        self.check_results.push(StartupCheckResult {
            component: "Process Permissions".to_string(),
            status,
            message,
            details,
            severity,
        });
    }

    // Helper methods

    async fn get_windows_version(&self) -> String {
        if cfg!(windows) {
            match Command::new("ver").output().await {
                Ok(output) if output.status.success() => {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                }
                _ => "Unknown".to_string(),
            }
        } else {
            "N/A".to_string()
        }
    }

    async fn get_linux_distribution(&self) -> String {
        if cfg!(unix)
            && let Ok(content) = fs::read_to_string("/etc/os-release")
        {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return line.replace("PRETTY_NAME=", "").replace('"', "");
                }
            }
        }
        "Unknown".to_string()
    }

    async fn get_available_memory(&self) -> Result<u64> {
        #[cfg(windows)]
        {
            match Command::new("wmic")
                .args(["computersystem", "get", "TotalPhysicalMemory", "/value"])
                .output()
                .await
            {
                Ok(output) if output.status.success() => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    for line in output_str.lines() {
                        if line.starts_with("TotalPhysicalMemory=")
                            && let Ok(bytes) = line
                                .replace("TotalPhysicalMemory=", "")
                                .trim()
                                .parse::<u64>()
                        {
                            return Ok(bytes / (1024 * 1024)); // Convert to MB
                        }
                    }
                    Err(anyhow!("Could not parse memory information"))
                }
                _ => Err(anyhow!("Failed to get memory information")),
            }
        }

        #[cfg(unix)]
        {
            match fs::read_to_string("/proc/meminfo") {
                Ok(content) => {
                    for line in content.lines() {
                        if line.starts_with("MemTotal:") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                if let Ok(kb) = parts[1].parse::<u64>() {
                                    return Ok(kb / 1024); // Convert KB to MB
                                }
                            }
                        }
                    }
                    Err(anyhow!("Could not parse /proc/meminfo"))
                }
                Err(e) => Err(anyhow!("Could not read /proc/meminfo: {}", e)),
            }
        }

        #[cfg(not(any(windows, unix)))]
        {
            Err(anyhow!("Memory detection not supported on this platform"))
        }
    }

    async fn get_available_disk_space(&self, path: &Path) -> Result<u64> {
        #[cfg(windows)]
        {
            let drive = path
                .ancestors()
                .last()
                .and_then(|root| root.to_str())
                .unwrap_or("C:");

            match Command::new("dir").args([drive, "/-c"]).output().await {
                Ok(output) if output.status.success() => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    for line in output_str.lines() {
                        if line.contains("bytes free") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            for (i, part) in parts.iter().enumerate() {
                                if *part == "bytes" && i > 0 {
                                    let bytes_str = parts[i - 1].replace(",", "");
                                    if let Ok(bytes) = bytes_str.parse::<u64>() {
                                        return Ok(bytes / (1024 * 1024)); // Convert to MB
                                    }
                                }
                            }
                        }
                    }
                    Err(anyhow!("Could not parse disk space information"))
                }
                _ => Err(anyhow!("Failed to get disk space information")),
            }
        }

        #[cfg(unix)]
        {
            match Command::new("df")
                .args(&["-m", path.to_str().unwrap_or(".")])
                .output()
                .await
            {
                Ok(output) if output.status.success() => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    let lines: Vec<&str> = output_str.lines().collect();
                    if lines.len() >= 2 {
                        let parts: Vec<&str> = lines[1].split_whitespace().collect();
                        if parts.len() >= 4 {
                            if let Ok(available_mb) = parts[3].parse::<u64>() {
                                return Ok(available_mb);
                            }
                        }
                    }
                    Err(anyhow!("Could not parse df output"))
                }
                _ => Err(anyhow!("Failed to run df command")),
            }
        }

        #[cfg(not(any(windows, unix)))]
        {
            Err(anyhow!(
                "Disk space detection not supported on this platform"
            ))
        }
    }

    async fn test_file_read_permission(&self) -> bool {
        let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        fs::read_dir(&current_dir).is_ok()
    }

    async fn test_file_write_permission(&self) -> bool {
        let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let test_file = current_dir.join("temp_write_test.tmp");
        let result = fs::write(&test_file, "test").is_ok();
        if result {
            let _ = fs::remove_file(&test_file);
        }
        result
    }

    async fn test_process_create_permission(&self) -> bool {
        timeout(
            Duration::from_secs(5),
            Command::new("echo").arg("test").output(),
        )
        .await
        .is_ok()
    }

    async fn check_command_available(&self, command: &str) -> bool {
        timeout(
            Duration::from_secs(5),
            Command::new(command).arg("--help").output(),
        )
        .await
        .is_ok_and(|result| result.is_ok_and(|output| output.status.success()))
    }

    async fn test_network_connection(&self) -> Result<bool> {
        // Simple network test - try to resolve a hostname
        match timeout(
            Duration::from_secs(5),
            Command::new("ping")
                .args(["-c", "1", "8.8.8.8"]) // Linux/macOS
                .output(),
        )
        .await
        {
            Ok(Ok(output)) if output.status.success() => Ok(true),
            _ => {
                // Try Windows ping format
                match timeout(
                    Duration::from_secs(5),
                    Command::new("ping")
                        .args(["-n", "1", "8.8.8.8"]) // Windows
                        .output(),
                )
                .await
                {
                    Ok(Ok(output)) if output.status.success() => Ok(true),
                    _ => Ok(false),
                }
            }
        }
    }

    async fn check_elevated_privileges(&self) -> bool {
        #[cfg(windows)]
        {
            // On Windows, check if running as administrator
            match Command::new("net").args(["session"]).output().await {
                Ok(output) => output.status.success(),
                Err(_) => false,
            }
        }

        #[cfg(unix)]
        {
            // On Unix, check if running as root
            unsafe { libc::getuid() == 0 }
        }

        #[cfg(not(any(windows, unix)))]
        {
            false
        }
    }

    async fn check_antivirus_interference(&self) -> bool {
        // Basic heuristic - check for common AV directories or processes
        #[cfg(windows)]
        {
            let av_paths = [
                r"C:\Program Files\Windows Defender",
                r"C:\Program Files (x86)\Windows Defender",
                r"C:\Program Files\Malwarebytes",
                r"C:\Program Files\Norton",
                r"C:\Program Files\McAfee",
            ];

            for path in &av_paths {
                if Path::new(path).exists() {
                    return true;
                }
            }
        }

        false
    }

    async fn can_access_process_info(&self) -> bool {
        #[cfg(windows)]
        {
            Command::new("tasklist")
                .output()
                .await
                .is_ok_and(|output| output.status.success())
        }

        #[cfg(unix)]
        {
            Path::new("/proc").exists()
        }

        #[cfg(not(any(windows, unix)))]
        {
            false
        }
    }

    fn log_validation_summary(&self) {
        let total_checks = self.check_results.len();
        let passed = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Pass)
            .count();
        let warnings = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Warning)
            .count();
        let failures = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Fail)
            .count();
        let critical = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Critical)
            .count();

        info!(
            "Startup validation complete: {} total checks, {} passed, {} warnings, {} failures, {} critical",
            total_checks, passed, warnings, failures, critical
        );

        if critical > 0 {
            error!(
                "Critical startup validation failures detected - system may not function properly"
            );
        } else if failures > 0 {
            warn!("Startup validation failures detected - some functionality may be limited");
        } else if warnings > 0 {
            warn!("Startup validation completed with warnings - performance may be impacted");
        } else {
            info!("All startup validation checks passed successfully");
        }
    }

    pub fn get_results(&self) -> &[StartupCheckResult] {
        &self.check_results
    }

    pub fn has_critical_failures(&self) -> bool {
        self.check_results
            .iter()
            .any(|r| r.status == StartupStatus::Critical)
    }

    pub fn has_failures(&self) -> bool {
        self.check_results
            .iter()
            .any(|r| matches!(r.status, StartupStatus::Fail | StartupStatus::Critical))
    }

    pub fn get_summary_report(&self) -> String {
        let total = self.check_results.len();
        let passed = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Pass)
            .count();
        let warnings = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Warning)
            .count();
        let failures = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Fail)
            .count();
        let critical = self
            .check_results
            .iter()
            .filter(|r| r.status == StartupStatus::Critical)
            .count();

        format!(
            "Startup Validation Summary:\n\
            Total Checks: {}\n\
            Passed: {}\n\
            Warnings: {}\n\
            Failures: {}\n\
            Critical: {}",
            total, passed, warnings, failures, critical
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::test;

    #[test]
    async fn test_startup_validator_creation() {
        let validator = StartupValidator::new();
        assert!(validator.check_results.is_empty());
        assert_eq!(validator.requirements.min_memory_mb, 2048);
        assert_eq!(validator.requirements.min_disk_space_mb, 5120);
    }

    #[test]
    async fn test_startup_validator_with_custom_requirements() {
        let requirements = SystemRequirements {
            min_memory_mb: 1024,
            min_disk_space_mb: 2048,
            required_permissions: vec!["file_read".to_string()],
            required_environment_vars: vec!["PATH".to_string()],
            critical_dependencies: vec!["python".to_string()],
        };

        let validator = StartupValidator::with_requirements(requirements);
        assert_eq!(validator.requirements.min_memory_mb, 1024);
        assert_eq!(validator.requirements.min_disk_space_mb, 2048);
        assert_eq!(validator.requirements.required_permissions.len(), 1);
    }

    #[test]
    async fn test_startup_check_result_serialization() {
        let mut details = HashMap::new();
        details.insert("test_key".to_string(), "test_value".to_string());

        let result = StartupCheckResult {
            component: "Test Component".to_string(),
            status: StartupStatus::Pass,
            message: "Test message".to_string(),
            details,
            severity: CheckSeverity::Info,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: StartupCheckResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result, deserialized);
        assert_eq!(deserialized.component, "Test Component");
        assert_eq!(deserialized.status, StartupStatus::Pass);
        assert_eq!(deserialized.severity, CheckSeverity::Info);
    }

    #[test]
    async fn test_system_requirements_default() {
        let requirements = SystemRequirements::default();
        assert_eq!(requirements.min_memory_mb, 2048);
        assert_eq!(requirements.min_disk_space_mb, 5120);
        assert!(
            requirements
                .required_permissions
                .contains(&"file_read".to_string())
        );
        assert!(
            requirements
                .required_environment_vars
                .contains(&"PATH".to_string())
        );
        assert!(
            requirements
                .critical_dependencies
                .contains(&"python".to_string())
        );
    }

    #[test]
    async fn test_system_requirements_serialization() {
        let requirements = SystemRequirements::default();
        let json = serde_json::to_string(&requirements).unwrap();
        let deserialized: SystemRequirements = serde_json::from_str(&json).unwrap();

        assert_eq!(requirements.min_memory_mb, deserialized.min_memory_mb);
        assert_eq!(
            requirements.min_disk_space_mb,
            deserialized.min_disk_space_mb
        );
        assert_eq!(
            requirements.required_permissions,
            deserialized.required_permissions
        );
    }

    #[test]
    async fn test_perform_comprehensive_checks() {
        let results = StartupValidator::perform_comprehensive_checks()
            .await
            .unwrap();

        // Should have results from all check methods
        assert!(!results.is_empty());

        // Check that we have expected components
        let component_names: Vec<&str> = results.iter().map(|r| r.component.as_str()).collect();
        assert!(component_names.contains(&"Operating System"));
        assert!(component_names.contains(&"System Architecture"));
        assert!(component_names.contains(&"Python Installation"));
    }

    #[test]
    async fn test_operating_system_check() {
        let mut validator = StartupValidator::new();
        validator.check_operating_system().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Operating System");

        // Should detect the current OS
        let detected_os = result.details.get("detected_os").unwrap();
        assert!(["windows", "linux", "macos"].contains(&detected_os.as_str()));
    }

    #[test]
    async fn test_system_architecture_check() {
        let mut validator = StartupValidator::new();
        validator.check_system_architecture().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "System Architecture");

        // Should detect the current architecture
        let detected_arch = result.details.get("detected_arch").unwrap();
        assert!(!detected_arch.is_empty());
    }

    #[test]
    async fn test_memory_requirements_check() {
        let mut validator = StartupValidator::new();
        validator.check_memory_requirements().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Memory Requirements");

        // Should have required memory in details
        let required_memory = result.details.get("required_memory_mb").unwrap();
        assert_eq!(required_memory, "2048");
    }

    #[test]
    async fn test_disk_space_check() {
        let mut validator = StartupValidator::new();
        validator.check_disk_space().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Disk Space");

        // Should have required space in details
        let required_space = result.details.get("required_space_mb").unwrap();
        assert_eq!(required_space, "5120");
    }

    #[test]
    async fn test_permissions_check() {
        let mut validator = StartupValidator::new();
        validator.check_permissions().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Permissions");

        // Should test all required permissions
        assert!(result.details.contains_key("file_read"));
        assert!(result.details.contains_key("file_write"));
        assert!(result.details.contains_key("process_create"));
    }

    #[test]
    async fn test_environment_variables_check() {
        let mut validator = StartupValidator::new();
        validator.check_environment_variables().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Environment Variables");

        // Should check PATH (which should exist)
        let path_status = result.details.get("PATH").unwrap();
        assert_eq!(path_status, "present");
    }

    #[test]
    async fn test_python_installation_check() {
        let mut validator = StartupValidator::new();
        validator.check_python_installation().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Python Installation");

        // Should have executable info
        assert!(result.details.contains_key("executable"));
        assert!(result.details.contains_key("version"));
    }

    #[test]
    async fn test_critical_dependencies_check() {
        let mut validator = StartupValidator::new();
        validator.check_critical_dependencies().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Critical Dependencies");

        // Should have counts
        assert!(result.details.contains_key("available_count"));
        assert!(result.details.contains_key("missing_count"));
    }

    #[test]
    async fn test_network_connectivity_check() {
        let mut validator = StartupValidator::new();
        validator.check_network_connectivity().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Network Connectivity");

        // Should have connectivity status
        assert!(result.details.contains_key("connectivity"));
    }

    #[test]
    async fn test_security_configuration_check() {
        let mut validator = StartupValidator::new();
        validator.check_security_configuration().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Security Configuration");

        // Should check elevated privileges
        assert!(result.details.contains_key("elevated_privileges"));
        assert!(result.details.contains_key("antivirus_interference"));
        assert!(result.details.contains_key("security_issues_count"));
    }

    #[test]
    async fn test_file_system_access_check() {
        let mut validator = StartupValidator::new();
        validator.check_file_system_access().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "File System Access");

        // Should test various access types
        assert!(result.details.contains_key("read_access"));
        assert!(result.details.contains_key("write_access"));
        assert!(result.details.contains_key("directory_creation"));
    }

    #[test]
    async fn test_process_permissions_check() {
        let mut validator = StartupValidator::new();
        validator.check_process_permissions().await;

        assert_eq!(validator.check_results.len(), 1);
        let result = &validator.check_results[0];
        assert_eq!(result.component, "Process Permissions");

        // Should test process capabilities
        assert!(result.details.contains_key("process_creation"));
        assert!(result.details.contains_key("process_info_access"));
    }

    #[test]
    async fn test_file_read_permission() {
        let validator = StartupValidator::new();
        let can_read = validator.test_file_read_permission().await;

        // Should be able to read current directory
        assert!(can_read);
    }

    #[test]
    async fn test_file_write_permission() {
        let validator = StartupValidator::new();
        let can_write = validator.test_file_write_permission().await;

        // Result depends on current directory permissions
        // Just ensure the test runs without panicking
        let _ = can_write;
    }

    #[test]
    async fn test_process_create_permission() {
        let validator = StartupValidator::new();
        let can_create = validator.test_process_create_permission().await;

        // Should be able to create basic processes
        assert!(can_create);
    }

    #[test]
    async fn test_check_command_available() {
        let validator = StartupValidator::new();

        // Test with a command that should exist
        let echo_available = validator.check_command_available("echo").await;
        assert!(echo_available);

        // Test with a command that doesn't exist
        let nonexistent_available = validator
            .check_command_available("this_command_definitely_does_not_exist_12345")
            .await;
        assert!(!nonexistent_available);
    }

    #[test]
    async fn test_validator_summary_methods() {
        let mut validator = StartupValidator::new();

        validator.check_results.push(StartupCheckResult {
            component: "Test Pass".to_string(),
            status: StartupStatus::Pass,
            message: "Test passed".to_string(),
            details: HashMap::new(),
            severity: CheckSeverity::Info,
        });

        validator.check_results.push(StartupCheckResult {
            component: "Test Warning".to_string(),
            status: StartupStatus::Warning,
            message: "Test warning".to_string(),
            details: HashMap::new(),
            severity: CheckSeverity::Medium,
        });

        validator.check_results.push(StartupCheckResult {
            component: "Test Critical".to_string(),
            status: StartupStatus::Critical,
            message: "Test critical".to_string(),
            details: HashMap::new(),
            severity: CheckSeverity::Critical,
        });

        // Test summary methods
        assert_eq!(validator.get_results().len(), 3);
        assert!(validator.has_critical_failures());
        assert!(validator.has_failures());

        let summary = validator.get_summary_report();
        assert!(summary.contains("Total Checks: 3"));
        assert!(summary.contains("Passed: 1"));
        assert!(summary.contains("Warnings: 1"));
        assert!(summary.contains("Critical: 1"));
    }

    #[test]
    async fn test_run_all_checks_integration() {
        let mut validator = StartupValidator::new();
        let result = validator.run_all_checks().await;

        assert!(result.is_ok());

        // Should have multiple check results
        assert!(!validator.check_results.is_empty());

        // All results should have non-empty component names
        for check_result in &validator.check_results {
            assert!(!check_result.component.is_empty());
            assert!(!check_result.message.is_empty());
        }
    }

    #[test]
    async fn test_startup_status_serialization() {
        let statuses = vec![
            StartupStatus::Pass,
            StartupStatus::Warning,
            StartupStatus::Fail,
            StartupStatus::Critical,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: StartupStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    async fn test_check_severity_serialization() {
        let severities = vec![
            CheckSeverity::Info,
            CheckSeverity::Low,
            CheckSeverity::Medium,
            CheckSeverity::High,
            CheckSeverity::Critical,
        ];

        for severity in severities {
            let json = serde_json::to_string(&severity).unwrap();
            let deserialized: CheckSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(severity, deserialized);
        }
    }

    #[test]
    async fn test_validator_with_minimal_requirements() {
        let requirements = SystemRequirements {
            min_memory_mb: 512,
            min_disk_space_mb: 1024,
            required_permissions: vec!["file_read".to_string()],
            required_environment_vars: vec!["PATH".to_string()],
            critical_dependencies: vec!["python".to_string()],
        };

        let mut validator = StartupValidator::with_requirements(requirements);
        let result = validator.run_all_checks().await;

        assert!(result.is_ok());
        assert!(!validator.check_results.is_empty());
    }

    #[test]
    async fn test_helper_method_error_handling() {
        let validator = StartupValidator::new();

        // Test get_available_memory error handling
        let memory_result = validator.get_available_memory().await;
        // Should either succeed or fail gracefully
        if let Ok(mb) = memory_result {
            assert!(mb > 0)
        }

        // Test get_available_disk_space error handling
        let disk_result = validator
            .get_available_disk_space(&PathBuf::from("."))
            .await;
        if let Ok(mb) = disk_result {
            // Verify disk space is greater than zero (meaningful non-zero space detected)
            assert!(mb > 0);
            // Additional validation: ensure reasonable disk space for testing
            assert!(mb < 100 * 1024 * 1024);
        }
    }

    #[test]
    async fn test_cleanup_behavior() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_file.tmp");

        // Create a test file
        fs::write(&test_file, "test content").unwrap();
        assert!(test_file.exists());

        let validator = StartupValidator::new();

        // Test write permission (should clean up after itself)
        let _ = validator.test_file_write_permission().await;

        // Verify temp file still exists (our test file, not the validator's temp file)
        assert!(test_file.exists());
    }

    #[test]
    async fn test_timeout_behavior() {
        let validator = StartupValidator::new();

        // Test command with timeout
        let start_time = std::time::Instant::now();
        let _result = validator.check_command_available("sleep").await;
        let elapsed = start_time.elapsed();

        // Should complete within reasonable time due to timeout
        assert!(elapsed.as_secs() < 10);
    }

    #[test]
    async fn test_cross_platform_compatibility() {
        let validator = StartupValidator::new();

        // Test OS-specific methods don't panic
        let _windows_version = validator.get_windows_version().await;
        let _linux_dist = validator.get_linux_distribution().await;
        let _elevated = validator.check_elevated_privileges().await;
        let _av_interference = validator.check_antivirus_interference().await;
        let _process_info = validator.can_access_process_info().await;

        // Should complete without panicking regardless of platform
    }

    #[test]
    async fn test_network_test_fallback() {
        let validator = StartupValidator::new();

        // Test network connection with fallback
        let result = validator.test_network_connection().await;

        // Should return a result (true/false) without error
        assert!(result.is_ok());
    }

    #[test]
    async fn test_comprehensive_edge_cases() {
        // Test with very restrictive requirements
        let requirements = SystemRequirements {
            min_memory_mb: u64::MAX,     // Impossible requirement
            min_disk_space_mb: u64::MAX, // Impossible requirement
            required_permissions: vec!["invalid_permission".to_string()],
            required_environment_vars: vec!["NONEXISTENT_VAR".to_string()],
            critical_dependencies: vec!["nonexistent_command".to_string()],
        };

        let mut validator = StartupValidator::with_requirements(requirements);
        let result = validator.run_all_checks().await;

        // Should complete even with impossible requirements
        assert!(result.is_ok());
        assert!(!validator.check_results.is_empty());

        // Should have some failures due to impossible requirements
        assert!(validator.has_failures());
    }
}
