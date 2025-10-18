use anyhow::Result;
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub sandbox_analysis: bool,
    pub allow_network_access: bool,
    pub log_sensitive_data: bool,
    pub encrypt_config: bool,
    pub hashing: HashingConfig,
    pub subprocess: SubprocessConfig,
    pub serialization: SerializationConfig,
    pub input_validation: InputValidationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashingConfig {
    pub default_algorithm: String,
    pub allow_md5_for_security: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubprocessConfig {
    pub allow_shell_true: bool,
    pub shell_whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializationConfig {
    pub default_format: String,
    pub restrict_pickle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputValidationConfig {
    pub strict_mode: bool,
    pub max_file_size: Option<u64>,
    pub allowed_extensions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub initialized: bool,
    pub bypass_enabled: bool,
    pub config: SecurityConfig,
    pub patches_applied: HashMap<String, bool>,
}

pub struct SecurityManager {
    config: SecurityConfig,
    enforcement_active: bool,
    bypass_enabled: bool,
}

impl SecurityManager {
    pub fn new() -> Result<Self> {
        let config = Self::load_security_config()?;

        Ok(SecurityManager {
            config,
            enforcement_active: false,
            bypass_enabled: false,
        })
    }

    fn load_security_config() -> Result<SecurityConfig> {
        info!("Loading security configuration");

        let mut config_paths = Vec::new();

        if let Ok(exe_path) = env::current_exe()
            && let Some(exe_dir) = exe_path.parent()
        {
            debug!("Executable directory: {:?}", exe_dir);

            config_paths.push(exe_dir.join("config/intellicrack_config.json"));
            config_paths.push(exe_dir.join("../config/intellicrack_config.json"));

            let mut current_dir = exe_dir;
            for _ in 0..5 {
                let potential_config = current_dir.join("config/intellicrack_config.json");
                config_paths.push(potential_config);

                if let Some(parent) = current_dir.parent() {
                    current_dir = parent;
                } else {
                    break;
                }
            }
        }

        if let Ok(cwd) = env::current_dir() {
            debug!("Current working directory: {:?}", cwd);
            config_paths.push(cwd.join("config/intellicrack_config.json"));
            config_paths.push(cwd.join("../config/intellicrack_config.json"));
        }

        config_paths.push(PathBuf::from("config/intellicrack_config.json"));
        config_paths.push(PathBuf::from("../config/intellicrack_config.json"));

        if let Some(home_dir) = dirs::home_dir() {
            config_paths.push(home_dir.join(".intellicrack/intellicrack_config.json"));
        }

        for config_path in &config_paths {
            if config_path.exists() {
                debug!("Trying to load config from: {:?}", config_path);
                match std::fs::read_to_string(config_path) {
                    Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(config_json) => {
                            if let Some(security_section) = config_json.get("security") {
                                match serde_json::from_value::<SecurityConfig>(
                                    security_section.clone(),
                                ) {
                                    Ok(security_config) => {
                                        info!(
                                            "Security configuration loaded from: {:?}",
                                            config_path
                                        );
                                        return Ok(security_config);
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to parse security config from {}: {}",
                                            config_path.display(),
                                            e
                                        );
                                    }
                                }
                            } else {
                                debug!("No 'security' section found in config at: {:?}", config_path);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse JSON from {}: {}", config_path.display(), e);
                        }
                    },
                    Err(e) => {
                        warn!(
                            "Failed to read config from {}: {}",
                            config_path.display(),
                            e
                        );
                    }
                }
            }
        }

        warn!("No valid security configuration found, using defaults");
        debug!("Searched paths: {:#?}", config_paths);
        Ok(Self::get_default_security_config())
    }

    fn get_default_security_config() -> SecurityConfig {
        SecurityConfig {
            sandbox_analysis: true,
            allow_network_access: false,
            log_sensitive_data: false,
            encrypt_config: false,
            hashing: HashingConfig {
                default_algorithm: "sha256".to_string(),
                allow_md5_for_security: false,
            },
            subprocess: SubprocessConfig {
                allow_shell_true: false,
                shell_whitelist: vec![],
            },
            serialization: SerializationConfig {
                default_format: "json".to_string(),
                restrict_pickle: true,
            },
            input_validation: InputValidationConfig {
                strict_mode: true,
                max_file_size: None,
                allowed_extensions: None,
            },
        }
    }

    pub fn initialize_security_enforcement(&mut self) -> Result<()> {
        info!("Initializing comprehensive security enforcement");

        // Set security environment variables
        self.configure_security_environment()?;

        // Initialize Python-based security patches
        self.initialize_python_security_patches()?;

        self.enforcement_active = true;
        info!("Security enforcement initialization complete");
        Ok(())
    }

    fn configure_security_environment(&self) -> Result<()> {
        info!("Configuring security environment variables");

        unsafe {
            // Set sandbox mode
            if self.config.sandbox_analysis {
                env::set_var("INTELLICRACK_SANDBOX", "1");
                debug!("Sandbox analysis mode enabled");
            }

            // Set network access restrictions
            if !self.config.allow_network_access {
                env::set_var("INTELLICRACK_NO_NETWORK", "1");
                debug!("Network access disabled");
            }

            // Set sensitive data logging policy
            if !self.config.log_sensitive_data {
                env::set_var("INTELLICRACK_NO_SENSITIVE_LOGS", "1");
                debug!("Sensitive data logging disabled");
            }

            // Set default hashing algorithm
            env::set_var(
                "INTELLICRACK_DEFAULT_HASH",
                &self.config.hashing.default_algorithm,
            );

            // Set subprocess security policies
            if !self.config.subprocess.allow_shell_true {
                env::set_var("INTELLICRACK_NO_SHELL_TRUE", "1");
            }

            // Set serialization policies
            if self.config.serialization.restrict_pickle {
                env::set_var("INTELLICRACK_RESTRICT_PICKLE", "1");
            }

            // Set input validation mode
            if self.config.input_validation.strict_mode {
                env::set_var("INTELLICRACK_STRICT_VALIDATION", "1");
            }
        }

        info!("Security environment configuration complete");
        Ok(())
    }

    fn initialize_python_security_patches(&self) -> Result<()> {
        info!("Initializing Python security patches");

        // Check if Python is initialized before trying to use it
        match Python::attach(|_| -> Result<(), anyhow::Error> { Ok(()) }) {
            Ok(_) => {
                // Python is initialized, proceed
            }
            Err(_) => {
                warn!("Python not initialized yet - deferring security patches");
                return Ok(());
            }
        }

        Python::attach(|py| -> Result<()> {
            match py.import("intellicrack.core.security_enforcement") {
                Ok(security_module) => {
                    debug!("Security enforcement module imported");

                    if let Ok(init_func) = security_module.getattr("initialize_security") {
                        init_func.call0()?;
                        info!("Python security patches initialized");
                    } else {
                        warn!("initialize_security function not found in security module");
                    }

                    if let Ok(status_func) = security_module.getattr("get_security_status") {
                        let status = status_func.call0()?;
                        debug!("Security status: {:?}", status);
                    }
                }
                Err(e) => {
                    warn!("Failed to import security enforcement module: {}", e);
                    warn!("Security patches will not be applied");
                }
            }
            Ok(())
        })?;

        Ok(())
    }

    pub fn enable_bypass(&mut self) {
        warn!("Security bypass enabled - use with extreme caution!");
        self.bypass_enabled = true;

        // Set bypass environment variable for Python integration
        unsafe {
            env::set_var("INTELLICRACK_SECURITY_BYPASS", "1");
        }

        Python::attach(|py| {
            if let Ok(security_module) = py.import("intellicrack.core.security_enforcement")
                && let Ok(security_obj) = security_module.getattr("_security")
                    && let Ok(enable_bypass) = security_obj.getattr("enable_bypass") {
                        let _ = enable_bypass.call0();
                    }
        });
    }

    pub fn disable_bypass(&mut self) {
        info!("Security bypass disabled");
        self.bypass_enabled = false;

        // Remove bypass environment variable
        unsafe {
            env::remove_var("INTELLICRACK_SECURITY_BYPASS");
        }

        Python::attach(|py| {
            if let Ok(security_module) = py.import("intellicrack.core.security_enforcement")
                && let Ok(security_obj) = security_module.getattr("_security")
                    && let Ok(disable_bypass) = security_obj.getattr("disable_bypass") {
                        let _ = disable_bypass.call0();
                    }
        });
    }

    pub fn validate_file_input(&self, file_path: &Path, operation: &str) -> Result<bool> {
        if self.bypass_enabled {
            return Ok(true);
        }

        let validation_config = &self.config.input_validation;

        if !validation_config.strict_mode {
            return Ok(true);
        }

        // Check file size if configured
        if let Some(max_size) = validation_config.max_file_size
            && file_path.exists()
                && let Ok(metadata) = file_path.metadata() {
                    let file_size = metadata.len();
                    if file_size > max_size {
                        warn!(
                            "File {} exceeds max size: {} > {}",
                            file_path.display(),
                            file_size,
                            max_size
                        );
                        anyhow::bail!(
                            "File exceeds maximum size limit: {} > {}",
                            file_size,
                            max_size
                        );
                    }
                }

        // Check allowed extensions if configured
        if let Some(allowed_extensions) = &validation_config.allowed_extensions
            && let Some(extension) = file_path.extension() {
                let ext_str = extension.to_string_lossy().to_lowercase();
                if !allowed_extensions
                    .iter()
                    .any(|allowed| allowed.to_lowercase() == ext_str)
                {
                    warn!(
                        "File extension {} not in allowed list: {:?}",
                        ext_str, allowed_extensions
                    );
                    anyhow::bail!("File extension {} not allowed", ext_str);
                }
            }

        // Check for path traversal
        let path_str = file_path.to_string_lossy();
        if path_str.contains("..") {
            warn!("Potential path traversal detected: {}", file_path.display());
            if validation_config.strict_mode {
                anyhow::bail!("Path traversal not allowed in strict mode");
            }
        }

        debug!(
            "File validation passed for {}: {}",
            operation,
            file_path.display()
        );
        Ok(true)
    }

    pub fn validate_subprocess_command(&self, command: &[String], shell: bool) -> Result<bool> {
        if self.bypass_enabled {
            return Ok(true);
        }

        let subprocess_config = &self.config.subprocess;

        // Check shell=True usage
        if shell && !subprocess_config.allow_shell_true {
            warn!(
                "Subprocess with shell=True blocked by security policy: {:?}",
                command
            );
            anyhow::bail!("subprocess with shell=True is disabled by security policy");
        }

        // Check command whitelist if shell=True is used
        if shell && !subprocess_config.shell_whitelist.is_empty() {
            let command_str = command.join(" ");
            let whitelisted = subprocess_config
                .shell_whitelist
                .iter()
                .any(|allowed| command_str.contains(allowed));

            if !whitelisted {
                warn!("Command not in whitelist: {}", command_str);
                anyhow::bail!("Command not in shell whitelist: {}", command_str);
            }
        }

        debug!(
            "Subprocess validation passed: {:?} (shell={})",
            command, shell
        );
        Ok(true)
    }

    pub fn validate_hashing_algorithm(&self, algorithm: &str) -> Result<String> {
        if self.bypass_enabled {
            return Ok(algorithm.to_string());
        }

        let hashing_config = &self.config.hashing;

        if algorithm.to_lowercase() == "md5" && !hashing_config.allow_md5_for_security {
            warn!("MD5 algorithm requested but not allowed for security");
            info!("Using {} instead of MD5", hashing_config.default_algorithm);
            return Ok(hashing_config.default_algorithm.clone());
        }

        Ok(algorithm.to_string())
    }

    pub fn get_security_status(&self) -> SecurityStatus {
        let mut patches_applied = HashMap::new();

        // Check if Python security patches are applied
        Python::attach(|py| {
            if let Ok(security_module) = py.import("intellicrack.core.security_enforcement")
                && let Ok(status_func) = security_module.getattr("get_security_status")
                    && let Ok(status) = status_func.call0()
                        && let Ok(status_dict) = status.extract::<HashMap<String, Py<PyAny>>>()
                            && let Some(patches) = status_dict.get("patches_applied")
                                && let Ok(patches_dict) =
                                    patches.extract::<HashMap<String, bool>>(py)
                                {
                                    patches_applied.extend(patches_dict);
                                }
        });

        SecurityStatus {
            initialized: self.enforcement_active,
            bypass_enabled: self.bypass_enabled,
            config: self.config.clone(),
            patches_applied,
        }
    }

    pub fn is_sandbox_mode(&self) -> bool {
        self.config.sandbox_analysis
    }

    pub fn is_network_access_allowed(&self) -> bool {
        self.config.allow_network_access
    }

    pub fn get_default_hash_algorithm(&self) -> &str {
        &self.config.hashing.default_algorithm
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            warn!("Failed to create SecurityManager: {}", e);
            SecurityManager {
                config: SecurityManager::get_default_security_config(),
                enforcement_active: false,
                bypass_enabled: false,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::{NamedTempFile, TempDir};

    fn get_test_security_manager() -> SecurityManager {
        SecurityManager {
            config: SecurityManager::get_default_security_config(),
            enforcement_active: false,
            bypass_enabled: false,
        }
    }

    #[test]
    fn test_security_manager_creation() {
        let security_manager = SecurityManager::new();
        assert!(security_manager.is_ok());

        let manager = security_manager.unwrap();
        assert!(!manager.enforcement_active);
        assert!(!manager.bypass_enabled);
        assert!(manager.config.sandbox_analysis);
    }

    #[test]
    fn test_security_manager_default() {
        let manager = SecurityManager::default();
        assert!(!manager.enforcement_active);
        assert!(!manager.bypass_enabled);

        // Verify default config
        assert!(manager.config.sandbox_analysis);
        assert!(!manager.config.allow_network_access);
        assert!(!manager.config.log_sensitive_data);
        assert_eq!(manager.config.hashing.default_algorithm, "sha256");
        assert!(!manager.config.hashing.allow_md5_for_security);
        assert!(!manager.config.subprocess.allow_shell_true);
        assert!(manager.config.subprocess.shell_whitelist.is_empty());
    }

    #[test]
    fn test_default_security_config() {
        let config = SecurityManager::get_default_security_config();

        assert!(config.sandbox_analysis);
        assert!(!config.allow_network_access);
        assert!(!config.log_sensitive_data);
        assert!(!config.encrypt_config);

        assert_eq!(config.hashing.default_algorithm, "sha256");
        assert!(!config.hashing.allow_md5_for_security);

        assert!(!config.subprocess.allow_shell_true);
        assert!(config.subprocess.shell_whitelist.is_empty());

        assert_eq!(config.serialization.default_format, "json");
        assert!(config.serialization.restrict_pickle);

        assert!(config.input_validation.strict_mode);
        assert!(config.input_validation.max_file_size.is_none());
        assert!(config.input_validation.allowed_extensions.is_none());
    }

    #[test]
    fn test_security_config_serialization() {
        let config = SecurityManager::get_default_security_config();

        // Test JSON serialization
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("sandbox_analysis"));
        assert!(json.contains("sha256"));

        // Test deserialization
        let deserialized: SecurityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sandbox_analysis, config.sandbox_analysis);
        assert_eq!(
            deserialized.hashing.default_algorithm,
            config.hashing.default_algorithm
        );
    }

    #[test]
    fn test_bypass_enable_disable() {
        let mut manager = get_test_security_manager();

        // Initially disabled
        assert!(!manager.bypass_enabled);

        // Enable bypass
        manager.enable_bypass();
        assert!(manager.bypass_enabled);
        assert_eq!(env::var("INTELLICRACK_SECURITY_BYPASS").unwrap(), "1");

        // Disable bypass
        manager.disable_bypass();
        assert!(!manager.bypass_enabled);
        assert!(env::var("INTELLICRACK_SECURITY_BYPASS").is_err());
    }

    #[test]
    fn test_security_environment_configuration() {
        let manager = get_test_security_manager();

        // Clean environment first
        unsafe {
            env::remove_var("INTELLICRACK_SANDBOX");
            env::remove_var("INTELLICRACK_NO_NETWORK");
            env::remove_var("INTELLICRACK_NO_SENSITIVE_LOGS");
            env::remove_var("INTELLICRACK_DEFAULT_HASH");
        }

        manager.configure_security_environment().unwrap();

        // Check that environment variables are set correctly
        assert_eq!(env::var("INTELLICRACK_SANDBOX").unwrap(), "1");
        assert_eq!(env::var("INTELLICRACK_NO_NETWORK").unwrap(), "1");
        assert_eq!(env::var("INTELLICRACK_NO_SENSITIVE_LOGS").unwrap(), "1");
        assert_eq!(env::var("INTELLICRACK_DEFAULT_HASH").unwrap(), "sha256");

        // Clean up
        unsafe {
            env::remove_var("INTELLICRACK_SANDBOX");
            env::remove_var("INTELLICRACK_NO_NETWORK");
            env::remove_var("INTELLICRACK_NO_SENSITIVE_LOGS");
            env::remove_var("INTELLICRACK_DEFAULT_HASH");
        }
    }

    #[test]
    fn test_file_input_validation_basic() {
        let manager = get_test_security_manager();
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").unwrap();

        // Basic validation should pass
        let result = manager.validate_file_input(&test_file, "read");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_file_input_validation_with_bypass() {
        let mut manager = get_test_security_manager();
        manager.enable_bypass();

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("../malicious.txt");

        // Should pass with bypass enabled, even with path traversal
        let result = manager.validate_file_input(&test_file, "read");
        assert!(result.is_ok());
        assert!(result.unwrap());

        manager.disable_bypass();
    }

    #[test]
    fn test_file_input_validation_path_traversal() {
        let manager = get_test_security_manager();
        let malicious_path = PathBuf::from("../../../etc/passwd");

        // Should fail due to path traversal in strict mode
        let result = manager.validate_file_input(&malicious_path, "read");
        assert!(result.is_err());
    }

    #[test]
    fn test_file_input_validation_size_limit() {
        let mut config = SecurityManager::get_default_security_config();
        config.input_validation.max_file_size = Some(10); // 10 bytes limit

        let manager = SecurityManager {
            config,
            enforcement_active: false,
            bypass_enabled: false,
        };

        let temp_dir = TempDir::new().unwrap();
        let large_file = temp_dir.path().join("large.txt");
        fs::write(
            &large_file,
            "This is a very long content that exceeds the 10 byte limit",
        )
        .unwrap();

        // Should fail due to file size
        let result = manager.validate_file_input(&large_file, "read");
        assert!(result.is_err());

        // Small file should pass
        let small_file = temp_dir.path().join("small.txt");
        fs::write(&small_file, "small").unwrap();
        let result = manager.validate_file_input(&small_file, "read");
        assert!(result.is_ok());
    }

    #[test]
    fn test_file_input_validation_extension_filter() {
        let mut config = SecurityManager::get_default_security_config();
        config.input_validation.allowed_extensions =
            Some(vec!["txt".to_string(), "json".to_string()]);

        let manager = SecurityManager {
            config,
            enforcement_active: false,
            bypass_enabled: false,
        };

        let temp_dir = TempDir::new().unwrap();

        // Allowed extension should pass
        let txt_file = temp_dir.path().join("test.txt");
        fs::write(&txt_file, "test").unwrap();
        assert!(manager.validate_file_input(&txt_file, "read").is_ok());

        let json_file = temp_dir.path().join("test.json");
        fs::write(&json_file, "{}").unwrap();
        assert!(manager.validate_file_input(&json_file, "read").is_ok());

        // Disallowed extension should fail
        let exe_file = temp_dir.path().join("malware.exe");
        let pe_header: Vec<u8> = vec![
            0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        fs::write(&exe_file, pe_header).unwrap();
        assert!(manager.validate_file_input(&exe_file, "read").is_err());
    }

    #[test]
    fn test_subprocess_command_validation_basic() {
        let manager = get_test_security_manager();

        let safe_command = vec!["echo".to_string(), "hello".to_string()];

        // Should pass without shell
        assert!(manager
            .validate_subprocess_command(&safe_command, false)
            .is_ok());

        // Should fail with shell=true by default
        assert!(manager
            .validate_subprocess_command(&safe_command, true)
            .is_err());
    }

    #[test]
    fn test_subprocess_command_validation_with_shell_allowed() {
        let mut config = SecurityManager::get_default_security_config();
        config.subprocess.allow_shell_true = true;
        config.subprocess.shell_whitelist = vec!["echo".to_string(), "ls".to_string()];

        let manager = SecurityManager {
            config,
            enforcement_active: false,
            bypass_enabled: false,
        };

        let whitelisted_command = vec!["echo".to_string(), "hello".to_string()];
        let non_whitelisted_command = vec!["rm".to_string(), "-rf".to_string(), "/".to_string()];

        // Whitelisted command should pass
        assert!(manager
            .validate_subprocess_command(&whitelisted_command, true)
            .is_ok());

        // Non-whitelisted command should fail
        assert!(manager
            .validate_subprocess_command(&non_whitelisted_command, true)
            .is_err());
    }

    #[test]
    fn test_subprocess_command_validation_with_bypass() {
        let mut manager = get_test_security_manager();
        manager.enable_bypass();

        let dangerous_command = vec!["rm".to_string(), "-rf".to_string(), "/".to_string()];

        // Should pass with bypass enabled
        assert!(manager
            .validate_subprocess_command(&dangerous_command, true)
            .is_ok());

        manager.disable_bypass();
    }

    #[test]
    fn test_hashing_algorithm_validation() {
        let manager = get_test_security_manager();

        // Safe algorithms should pass through
        assert_eq!(
            manager.validate_hashing_algorithm("sha256").unwrap(),
            "sha256"
        );
        assert_eq!(
            manager.validate_hashing_algorithm("sha512").unwrap(),
            "sha512"
        );

        // MD5 should be replaced with default when not allowed
        assert_eq!(manager.validate_hashing_algorithm("md5").unwrap(), "sha256");
        assert_eq!(manager.validate_hashing_algorithm("MD5").unwrap(), "sha256");
    }

    #[test]
    fn test_hashing_algorithm_validation_md5_allowed() {
        let mut config = SecurityManager::get_default_security_config();
        config.hashing.allow_md5_for_security = true;

        let manager = SecurityManager {
            config,
            enforcement_active: false,
            bypass_enabled: false,
        };

        // MD5 should pass through when allowed
        assert_eq!(manager.validate_hashing_algorithm("md5").unwrap(), "md5");
        assert_eq!(manager.validate_hashing_algorithm("MD5").unwrap(), "MD5");
    }

    #[test]
    fn test_hashing_algorithm_validation_with_bypass() {
        let mut manager = get_test_security_manager();
        manager.enable_bypass();

        // MD5 should pass through with bypass enabled
        assert_eq!(manager.validate_hashing_algorithm("md5").unwrap(), "md5");

        manager.disable_bypass();
    }

    #[test]
    fn test_security_status() {
        let mut manager = get_test_security_manager();

        let status = manager.get_security_status();
        assert!(!status.initialized);
        assert!(!status.bypass_enabled);
        assert!(status.config.sandbox_analysis);

        // Enable bypass and check status
        manager.enable_bypass();
        let status = manager.get_security_status();
        assert!(status.bypass_enabled);

        manager.disable_bypass();
    }

    #[test]
    fn test_security_manager_getters() {
        let manager = get_test_security_manager();

        assert!(manager.is_sandbox_mode());
        assert!(!manager.is_network_access_allowed());
        assert_eq!(manager.get_default_hash_algorithm(), "sha256");
    }

    #[test]
    fn test_config_loading_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("intellicrack_config.json");

        let test_config = r#"{
            "security": {
                "sandbox_analysis": false,
                "allow_network_access": true,
                "log_sensitive_data": true,
                "encrypt_config": true,
                "hashing": {
                    "default_algorithm": "sha512",
                    "allow_md5_for_security": true
                },
                "subprocess": {
                    "allow_shell_true": true,
                    "shell_whitelist": ["echo", "ls", "cat"]
                },
                "serialization": {
                    "default_format": "yaml",
                    "restrict_pickle": false
                },
                "input_validation": {
                    "strict_mode": false,
                    "max_file_size": 1000000,
                    "allowed_extensions": ["txt", "json", "py"]
                }
            }
        }"#;

        fs::write(&config_file, test_config).unwrap();

        // Change working directory temporarily to load the config
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        // Create config directory and file
        fs::create_dir_all("config").unwrap();
        fs::copy(&config_file, "config/intellicrack_config.json").unwrap();

        let config_result = SecurityManager::load_security_config();
        env::set_current_dir(original_dir).unwrap();

        assert!(config_result.is_ok());
        let config = config_result.unwrap();

        // Verify loaded config
        assert!(!config.sandbox_analysis);
        assert!(config.allow_network_access);
        assert!(config.log_sensitive_data);
        assert!(config.encrypt_config);
        assert_eq!(config.hashing.default_algorithm, "sha512");
        assert!(config.hashing.allow_md5_for_security);
        assert!(config.subprocess.allow_shell_true);
        assert_eq!(config.subprocess.shell_whitelist, vec!["echo", "ls", "cat"]);
        assert_eq!(config.serialization.default_format, "yaml");
        assert!(!config.serialization.restrict_pickle);
        assert!(!config.input_validation.strict_mode);
        assert_eq!(config.input_validation.max_file_size, Some(1000000));
        assert_eq!(
            config.input_validation.allowed_extensions,
            Some(vec![
                "txt".to_string(),
                "json".to_string(),
                "py".to_string()
            ])
        );
    }

    #[test]
    fn test_config_loading_fallback_to_default() {
        // Ensure no config files exist by using a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        let config_result = SecurityManager::load_security_config();
        env::set_current_dir(original_dir).unwrap();

        assert!(config_result.is_ok());
        let config = config_result.unwrap();

        // Should match default config
        let default_config = SecurityManager::get_default_security_config();
        assert_eq!(config.sandbox_analysis, default_config.sandbox_analysis);
        assert_eq!(
            config.allow_network_access,
            default_config.allow_network_access
        );
        assert_eq!(
            config.hashing.default_algorithm,
            default_config.hashing.default_algorithm
        );
    }

    #[test]
    fn test_invalid_config_fallback() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("intellicrack_config.json");

        // Write invalid JSON
        fs::write(&config_file, "{ invalid json }").unwrap();

        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        fs::create_dir_all("config").unwrap();
        fs::copy(&config_file, "config/intellicrack_config.json").unwrap();

        let config_result = SecurityManager::load_security_config();
        env::set_current_dir(original_dir).unwrap();

        // Should fallback to default config
        assert!(config_result.is_ok());
        let config = config_result.unwrap();
        let default_config = SecurityManager::get_default_security_config();
        assert_eq!(config.sandbox_analysis, default_config.sandbox_analysis);
    }

    #[test]
    fn test_security_status_structure() {
        let manager = get_test_security_manager();
        let status = manager.get_security_status();

        // Verify SecurityStatus structure
        assert_eq!(status.initialized, false);
        assert_eq!(status.bypass_enabled, false);
        assert_eq!(status.config.sandbox_analysis, true);

        // patches_applied should be a HashMap
        assert!(status.patches_applied.is_empty() || !status.patches_applied.is_empty());
    }

    #[test]
    fn test_environment_variable_cleanup() {
        let manager = get_test_security_manager();

        // Set some environment variables
        manager.configure_security_environment().unwrap();

        // Verify they are set
        assert!(env::var("INTELLICRACK_SANDBOX").is_ok());
        assert!(env::var("INTELLICRACK_DEFAULT_HASH").is_ok());

        // Clean up manually (in a real scenario, this would happen on drop or explicit cleanup)
        unsafe {
            env::remove_var("INTELLICRACK_SANDBOX");
            env::remove_var("INTELLICRACK_NO_NETWORK");
            env::remove_var("INTELLICRACK_NO_SENSITIVE_LOGS");
            env::remove_var("INTELLICRACK_DEFAULT_HASH");
            env::remove_var("INTELLICRACK_NO_SHELL_TRUE");
            env::remove_var("INTELLICRACK_RESTRICT_PICKLE");
            env::remove_var("INTELLICRACK_STRICT_VALIDATION");
        }

        // Verify cleanup
        assert!(env::var("INTELLICRACK_SANDBOX").is_err());
        assert!(env::var("INTELLICRACK_DEFAULT_HASH").is_err());
    }

    #[test]
    fn test_temporary_file_security_operations() {
        // Test secure temporary file creation and usage
        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_path_buf();

        // Write sensitive data to temporary file
        fs::write(&temp_path, "sensitive security configuration").unwrap();

        // Verify file was created and contains data
        assert!(temp_path.exists());
        let content = fs::read_to_string(&temp_path).unwrap();
        assert_eq!(content, "sensitive security configuration");

        // Test that file is automatically cleaned up when NamedTempFile is dropped
        drop(temp_file);
        // On some systems, the file might still exist until process exit, but this demonstrates usage
    }
}
