/*!
# Intellicrack Launcher - Main Entry Point

Sophisticated Rust launcher that completely replaces the existing Python launch system
for Intellicrack binary analysis platform.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use anyhow::Result;
use intellicrack_launcher::{initialize_logging, IntellicrackLauncher};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // CRITICAL: Configure pixi environment BEFORE any Python operations
    std::env::set_var("PYO3_PYTHON", r"C:\Intellicrack\.pixi\envs\default\python.exe");
    std::env::set_var("PYTHON_SYS_EXECUTABLE", r"C:\Intellicrack\.pixi\envs\default\python.exe");
    std::env::set_var("PIXI_PREFIX", r"C:\Intellicrack\.pixi\envs\default");
    std::env::set_var("PIXI_DEFAULT_ENV", "default");
    std::env::set_var("PYTHONPATH", r"C:\Intellicrack");
    std::env::set_var("PYTHONHOME", r"C:\Intellicrack\.pixi\envs\default");

    // Set launcher environment variables to suppress threading warnings
    std::env::set_var("RUST_LAUNCHER_MODE", "1");
    std::env::set_var("PYTHON_SUBPROCESS_MODE", "1");

    // Windows-specific optimizations
    #[cfg(target_os = "windows")]
    {
        // CRITICAL: Add pixi env to PATH FIRST so python312.dll and vcruntime140.dll are found
        let current_path = std::env::var("PATH").unwrap_or_default();
        let dll_path = format!(
            "{};{};{};{};{}",
            r"C:\Intellicrack\.pixi\envs\default",
            r"C:\Intellicrack\.pixi\envs\default\Library\bin",
            r"C:\Intellicrack\.pixi\envs\default\DLLs",
            r"C:\Intellicrack\.pixi\envs\default\Scripts",
            current_path
        );
        std::env::set_var("PATH", dll_path);

        // Also explicitly add the DLL directory for Windows DLL loading
        unsafe {
            use std::ffi::CString;

            let dll_dir = CString::new(r"C:\Intellicrack\.pixi\envs\default").unwrap();

            // Try to load kernel32.dll and call SetDllDirectoryA
            let kernel32 = libloading::Library::new("kernel32.dll");
            if let Ok(lib) = kernel32 {
                if let Ok(set_dll_dir) = lib.get::<unsafe extern "system" fn(*const i8) -> i32>(b"SetDllDirectoryA") {
                    set_dll_dir(dll_dir.as_ptr());
                }
            }
        }

        // Windows console UTF-8 support
        std::env::set_var("PYTHONIOENCODING", "utf-8");
        std::env::set_var("PYTHONUTF8", "1");
    }

    // Initialize logging system
    if let Err(e) = initialize_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    info!("Intellicrack Launcher starting...");

    // Set up panic hook for better error reporting
    std::panic::set_hook(Box::new(|panic_info| {
        error!("Panic occurred: {}", panic_info);
        eprintln!("Fatal error: {}", panic_info);
        eprintln!("Please check logs/intellicrack-launcher.* for details");
    }));

    // Set up Ctrl+C handler for graceful shutdown
    let shutdown_signal = tokio::signal::ctrl_c();
    let launcher_future = async {
        // Initialize and run launcher
        match IntellicrackLauncher::new().await {
            Ok(mut launcher) => match launcher.launch().await {
                Ok(exit_code) => std::process::exit(exit_code),
                Err(e) => {
                    error!("Launcher failed: {:?}", e);
                    eprintln!("Launch failed: {}", e);
                    std::process::exit(1);
                }
            },
            Err(e) => {
                error!("Failed to initialize launcher: {:?}", e);
                eprintln!("Initialization failed: {}", e);
                std::process::exit(1);
            }
        }
    };

    // Wait for either completion or Ctrl+C
    tokio::select! {
        _ = launcher_future => {
            // Launcher completed naturally
        }
        _ = shutdown_signal => {
            info!("Received shutdown signal, terminating...");
            println!("\nShutdown requested - terminating launcher...");
            std::process::exit(130); // Standard SIGINT exit code
        }
    }

    Ok(())
}
