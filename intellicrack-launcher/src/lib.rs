/*!
# Intellicrack Launcher

A sophisticated Rust launcher that completely replaces the existing Python launch system
for Intellicrack binary analysis platform with enhanced performance, comprehensive error
handling, and advanced system integration.

## Features

- **Platform Detection**: Automatic Windows/WSL/Linux detection with appropriate configuration
- **Python Integration**: Native `PyO3` integration with GIL safety and threading configuration
- **Dependency Validation**: Comprehensive testing of Flask, TensorFlow, QEMU, and system dependencies
- **Security Integration**: Full integration with Intellicrack's security enforcement system
- **Process Management**: Sophisticated Python process lifecycle management with signal handling
- **Performance Monitoring**: Real-time diagnostics and performance metrics

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use anyhow::Result;
use std::sync::{Arc, Mutex};

// Public modules
pub mod dependencies;
pub mod diagnostics;
pub mod environment;
pub mod flask_validator;
pub mod gil_safety;
pub mod platform;
pub mod process_manager;
pub mod python_integration;
pub mod security;
pub mod startup_checks;
pub mod tensorflow_validator;

// Re-exports for convenience
pub use dependencies::{DependencyStatus, DependencyValidator, ValidationSummary};
pub use diagnostics::{DiagnosticsManager, PerformanceMetrics};
pub use environment::EnvironmentManager;
pub use gil_safety::GilSafetyManager;
pub use platform::{GpuVendor, OsType, PlatformInfo};
pub use process_manager::ProcessManager;
pub use python_integration::PythonIntegration;
pub use security::{SecurityManager, SecurityStatus};
pub use startup_checks::StartupValidator;

/// Main launcher structure that orchestrates all subsystems
pub struct IntellicrackLauncher {
    pub platform: PlatformInfo,
    pub environment: EnvironmentManager,
    pub python: Option<PythonIntegration>,
    pub security: Arc<Mutex<SecurityManager>>,
    pub dependencies: DependencyValidator,
    pub process_manager: ProcessManager,
    pub diagnostics: DiagnosticsManager,
}

impl IntellicrackLauncher {
    /// Initialize a new Intellicrack launcher instance
    pub async fn new() -> Result<Self> {
        // Detect platform and initialize components in parallel
        let (platform_result, security_result, diagnostics_result) = tokio::join!(
            tokio::spawn(async { PlatformInfo::detect() }),
            tokio::spawn(async { SecurityManager::new() }),
            tokio::spawn(async { DiagnosticsManager::new() })
        );

        let platform = platform_result??;
        let security = Arc::new(Mutex::new(security_result??));
        let diagnostics = diagnostics_result??;

        let process_manager = ProcessManager::new(&platform, Arc::clone(&security))?;
        let environment = EnvironmentManager::new(&platform);
        let dependencies = DependencyValidator::new();

        Ok(IntellicrackLauncher {
            platform,
            environment,
            python: None,
            security,
            dependencies,
            process_manager,
            diagnostics,
        })
    }

    /// Execute the complete launch sequence
    pub async fn launch(&mut self) -> Result<i32> {
        tracing::info!("Starting Intellicrack launcher");

        // CRITICAL: Configure environment BEFORE Python initialization
        self.environment.configure_complete_environment()?;
        tracing::info!(
            "Environment configured for platform: {:?}",
            self.platform.os_type
        );

        // Initialize GIL safety BEFORE Python initialization
        // This ensures all GIL-related environment variables are set before PyO3 starts
        GilSafetyManager::initialize_gil_safety()?;

        // NOW initialize Python with the correct environment and GIL safety
        tracing::info!("Initializing Python with configured environment and GIL safety");
        let mut python = PythonIntegration::initialize()?;

        // Configure PyBind11 compatibility
        python.configure_pybind11_compatibility()?;

        self.python = Some(python);

        // Initialize security enforcement
        {
            let mut security = self.security.lock().unwrap();
            security.initialize_security_enforcement()?;
        }

        // Skip comprehensive dependency validation for faster startup
        // Just do minimal Python validation

        // Create minimal validation results for compatibility
        let _validation_results = ValidationSummary {
            dependencies: std::collections::HashMap::new(),
            flask_validation: None,
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };

        // Display startup summary
        self.display_startup_summary(&_validation_results);

        // Check for test mode
        let exit_code = if std::env::var("RUST_LAUNCHER_TEST_MODE").is_ok() {
            tracing::info!("Test mode enabled - running environment verification");
            self.python
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Python not initialized"))?
                .run_environment_test()?
        } else {
            // Launch main application directly via Python integration
            // This eliminates the circular dependency of calling launch_intellicrack.py
            self.python
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Python not initialized"))?
                .run_intellicrack_main()?
        };

        tracing::info!(
            "Intellicrack launcher completed with exit code: {}",
            exit_code
        );
        Ok(exit_code)
    }

    /// Display comprehensive startup summary
    fn display_startup_summary(&self, results: &ValidationSummary) {
        println!("=== Intellicrack Launcher ===");
        println!(
            "Platform: {:?} (WSL: {})",
            self.platform.os_type, self.platform.is_wsl
        );
        println!("GPU Vendor: {:?}", self.platform.gpu_vendor);

        // Debug: Check what's in the dependencies HashMap
        tracing::debug!("Dependencies HashMap size: {}", results.dependencies.len());

        // Only show dependency status if we actually validated dependencies
        if !results.dependencies.is_empty() {
            println!("\nDependency Status:");
            for (name, status) in &results.dependencies {
                let status_symbol = if status.available { "OK" } else { "MISSING" };
                let version = status.version.as_deref().unwrap_or("unknown");
                println!("  [{}] {}: {}", status_symbol, name, version);
            }

            if results.all_critical_available() {
                println!("\nAll critical dependencies available - launching Intellicrack...\n");
            } else {
                println!("\nSome dependencies unavailable - functionality may be limited\n");
            }
        } else {
            // Fast launch mode - skipped dependency validation
            println!("\nFast launch mode - launching Intellicrack...\n");
        }
    }
}

/// Initialize the launcher's logging system
pub async fn initialize_logging() -> Result<()> {
    let guard = tokio::task::spawn_blocking(|| {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        let file_appender = tracing_appender::rolling::daily("logs", "intellicrack-launcher");
        let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "intellicrack_launcher=info".into()),
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_target(false),
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking_appender)
                    .with_ansi(false)
                    .json(),
            )
            .init();
        guard
    })
    .await?;

    std::mem::forget(guard);

    Ok(())
}
