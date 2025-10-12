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

use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    // CRITICAL: Configure pixi environment BEFORE any Python operations
let project_root = std::env::var("INTELLICRACK_ROOT").unwrap_or_else(|_| r"D:\Intellicrack".to_string());
    std::env::set_var("PYO3_PYTHON", format!("{}/.pixi/envs/default/python.exe", project_root));
    std::env::set_var("PYTHON_SYS_EXECUTABLE", format!("{}/.pixi/envs/default/python.exe", project_root));
    std::env::set_var("PIXI_PREFIX", format!("{}/.pixi/envs/default", project_root));
    std::env::set_var("PYTHONPATH", project_root.clone());
    std::env::set_var("PYTHONHOME", format!("{}/.pixi/envs/default", project_root));

    // Set launcher environment variables to suppress threading warnings
    std::env::set_var("RUST_LAUNCHER_MODE", "1");
    std::env::set_var("PYTHON_SUBPROCESS_MODE", "1");

    // Windows-specific optimizations
    #[cfg(target_os = "windows")]
    {
        // CRITICAL: Build PATH with launcher directory and pixi FIRST, system Intel oneAPI LAST
        // This prevents conflicts with system-installed Intel oneAPI MKL libraries
        let current_path = std::env::var("PATH").unwrap_or_default();

        // Get launcher directory
        let exe_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let exe_dir = exe_path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

        // Build new PATH with launcher and pixi directories FIRST
        let dll_path = format!(
            "{};{};{};{};{};{}",
            exe_dir,  // Launcher directory FIRST (contains copied MKL DLLs)
            format!("{}/.pixi/envs/default", project_root),
            format!("{}/.pixi/envs/default/Library/bin", project_root),
            format!("{}/.pixi/envs/default/DLLs", project_root),
            format!("{}/.pixi/envs/default/Scripts", project_root),
            current_path
        );
        std::env::set_var("PATH", dll_path);

        // Also explicitly add DLL directories using Windows API
        unsafe {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            // Add launcher directory
            let launcher_wide: Vec<u16> = OsStr::new(&exe_dir)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // Add pixi Library/bin directory
            let pixi_lib_bin = format!("{}/.pixi/envs/default/Library/bin", project_root);
            let pixi_wide: Vec<u16> = OsStr::new(&pixi_lib_bin)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            #[link(name = "kernel32")]
            extern "system" {
                fn AddDllDirectory(NewDirectory: *const u16) -> *mut std::ffi::c_void;
            }

            // Add both directories to DLL search path (takes priority over PATH)
            let result1 = AddDllDirectory(launcher_wide.as_ptr());
            if !result1.is_null() {
                eprintln!("Added launcher directory to DLL search path");
            }

            let result2 = AddDllDirectory(pixi_wide.as_ptr());
            if !result2.is_null() {
                eprintln!("Added pixi Library/bin to DLL search path");
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
