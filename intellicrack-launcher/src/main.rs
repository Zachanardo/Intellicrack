/*!
# Intellicrack Launcher - Main Entry Point

Sophisticated Rust launcher that completely replaces the existing Python launch system
for Intellicrack binary analysis platform.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
*/

use anyhow::Result;
use intellicrack_launcher::{
    IntellicrackLauncher, environment::PROJECT_ROOT, initialize_logging,
    optimize_process, discover_and_cache_tools, run_preflight_checks,
};
use tracing::{error, info, warn};

use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<()> {
    // CRITICAL: Prevent system-level error dialogs on DLL load failures.
    // This is the primary defense against the system crash described in the issue.
    // By handling the error in-process, we avoid a state that leads to system instability.
    #[cfg(target_os = "windows")]
    unsafe {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetErrorMode(uMode: u32) -> u32;
        }
        // SEM_FAILCRITICALERRORS (0x0001)
        SetErrorMode(0x0001);
    }

    // OPTIMIZATION: Boost process priority and CPU affinity for better performance
    let optimization_start = std::time::Instant::now();
    if let Err(e) = optimize_process() {
        // Non-fatal - log warning and continue with normal priority
        eprintln!("Process optimization failed: {:?}", e);
    }

    dotenv().ok();
    // CRITICAL: Configure pixi environment BEFORE any Python operations
    unsafe {
        rayon::scope(|s| {
            s.spawn(|_| {
                std::env::set_var(
                    "PYO3_PYTHON",
                    format!("{}/.pixi/envs/default/python.exe", &*PROJECT_ROOT),
                );
            });
            s.spawn(|_| {
                std::env::set_var(
                    "PYTHON_SYS_EXECUTABLE",
                    format!("{}/.pixi/envs/default/python.exe", &*PROJECT_ROOT),
                );
            });
            s.spawn(|_| {
                std::env::set_var(
                    "PIXI_PREFIX",
                    format!("{}/.pixi/envs/default", &*PROJECT_ROOT),
                );
            });
            s.spawn(|_| std::env::set_var("PYTHONPATH", PROJECT_ROOT.clone()));
            s.spawn(|_| {
                std::env::set_var(
                    "PYTHONHOME",
                    format!("{}/.pixi/envs/default", &*PROJECT_ROOT),
                );
            });
            s.spawn(|_| std::env::set_var("RUST_LAUNCHER_MODE", "1"));
            s.spawn(|_| std::env::set_var("PYTHON_SUBPROCESS_MODE", "1"));
        });
    }

    // Windows-specific optimizations
    #[cfg(target_os = "windows")]
    {
        // CRITICAL: Build PATH with launcher directory and pixi FIRST, system Intel oneAPI LAST
        // This prevents conflicts with system-installed Intel oneAPI MKL libraries
        let current_path = std::env::var("PATH").unwrap_or_default();

        // Get launcher directory
        let exe_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let exe_dir = exe_path
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Build new PATH with launcher and pixi directories FIRST
        let dll_path = format!(
            "{};{}/.pixi/envs/default;{}/.pixi/envs/default/Library/bin;{}/.pixi/envs/default/DLLs;{}/.pixi/envs/default/Scripts;{}",
            exe_dir, // Launcher directory FIRST (contains copied MKL DLLs)
            &*PROJECT_ROOT,
            &*PROJECT_ROOT,
            &*PROJECT_ROOT,
            &*PROJECT_ROOT,
            current_path
        );
        unsafe {
            std::env::set_var("PATH", dll_path);
        }

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
            let pixi_lib_bin = format!("{}/.pixi/envs/default/Library/bin", &*PROJECT_ROOT);
            let pixi_wide: Vec<u16> = OsStr::new(&pixi_lib_bin)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            #[link(name = "kernel32")]
            unsafe extern "system" {
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
        unsafe {
            std::env::set_var("PYTHONIOENCODING", "utf-8");
            std::env::set_var("PYTHONUTF8", "1");
        }
    }

    // CRITICAL: Validate environment before Python initialization
    if let Err(e) = run_preflight_checks() {
        eprintln!("Preflight checks failed:\n{}", e);
        std::process::exit(1);
    }

    // Initialize logging system
    if let Err(e) = initialize_logging().await {
        eprintln!("Failed to initialize logging: {e}");
        std::process::exit(1);
    }

    info!("Intellicrack Launcher starting...");

    // OPTIMIZATION: Discover and cache tool paths for Python
    if let Err(e) = discover_and_cache_tools() {
        warn!("Tool discovery failed: {:?}", e);
        // Continue anyway - Python will do its own discovery
    }

    let optimization_elapsed = optimization_start.elapsed();
    info!("Startup optimizations completed in {:?}", optimization_elapsed);

    // Set up panic hook for better error reporting
    std::panic::set_hook(Box::new(|panic_info| {
        error!("Panic occurred: {}", panic_info);
        eprintln!("Fatal error: {panic_info}");
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
                    eprintln!("Launch failed: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                error!("Failed to initialize launcher: {:?}", e);
                eprintln!("Initialization failed: {e}");
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
