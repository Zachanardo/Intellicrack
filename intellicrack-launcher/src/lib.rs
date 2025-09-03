/*!
# Intellicrack Launcher

A sophisticated Rust launcher that completely replaces the existing Python launch system
for Intellicrack binary analysis platform with enhanced performance, comprehensive error
handling, and advanced system integration.

## Features

- **Platform Detection**: Automatic Windows/WSL/Linux detection with appropriate configuration
- **Python Integration**: Native PyO3 integration with GIL safety and threading configuration
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
    pub python: PythonIntegration,
    pub security: Arc<Mutex<SecurityManager>>,
    pub dependencies: DependencyValidator,
    pub process_manager: ProcessManager,
    pub diagnostics: DiagnosticsManager,
}

impl IntellicrackLauncher {
    /// Initialize a new Intellicrack launcher instance
    pub async fn new() -> Result<Self> {
        // Detect platform and initialize components
        let platform = PlatformInfo::detect()?;
        let environment = EnvironmentManager::new(&platform);
        let python = PythonIntegration::initialize()?;
        let security = Arc::new(Mutex::new(SecurityManager::new()?));
        let dependencies = DependencyValidator::new();
        let process_manager = ProcessManager::new(&platform, Arc::clone(&security))?;
        let diagnostics = DiagnosticsManager::new()?;

        Ok(IntellicrackLauncher {
            platform,
            environment,
            python,
            security,
            dependencies,
            process_manager,
            diagnostics,
        })
    }

    /// Execute the complete launch sequence
    pub async fn launch(&mut self) -> Result<i32> {
        tracing::info!("Starting Intellicrack launcher v2.0.0");

        // Configure environment
        self.environment.configure_complete_environment()?;
        tracing::info!(
            "Environment configured for platform: {:?}",
            self.platform.os_type
        );

        // Initialize Python integration
        self.python.configure_pybind11_compatibility()?;

        // Initialize GIL safety
        GilSafetyManager::initialize_gil_safety()?;

        // Initialize security enforcement
        {
            let mut security = self.security.lock().unwrap();
            security.initialize_security_enforcement()?;
        }

        // Perform comprehensive startup checks
        let validation_results = self.dependencies.validate_all_dependencies().await?;
        self.diagnostics.log_validation_results(&validation_results);

        // Display startup summary
        self.display_startup_summary(&validation_results);

        // Launch main application
        let exit_code = self
            .process_manager
            .launch_intellicrack_application()
            .await?;

        tracing::info!(
            "Intellicrack launcher completed with exit code: {}",
            exit_code
        );
        Ok(exit_code)
    }

    /// Display comprehensive startup summary
    fn display_startup_summary(&self, results: &ValidationSummary) {
        println!("=== Intellicrack Launcher v2.0.0 ===");
        println!(
            "Platform: {:?} (WSL: {})",
            self.platform.os_type, self.platform.is_wsl
        );
        println!("GPU Vendor: {:?}", self.platform.gpu_vendor);
        println!("\nDependency Status:");

        for (name, status) in &results.dependencies {
            let status_symbol = if status.available { "✅" } else { "❌" };
            let version = status.version.as_deref().unwrap_or("unknown");
            println!("  {} {}: {}", status_symbol, name, version);
        }

        if results.all_critical_available() {
            println!("\n🚀 All critical dependencies available - launching Intellicrack...\n");
        } else {
            println!("\n⚠️  Some dependencies unavailable - functionality may be limited\n");
        }
    }
}

/// Initialize the launcher's logging system
pub fn initialize_logging() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let file_appender = tracing_appender::rolling::daily("logs", "intellicrack-launcher");
    let (non_blocking_appender, _guard) = tracing_appender::non_blocking(file_appender);

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

    Ok(())
}
