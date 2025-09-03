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
    // Initialize logging system
    if let Err(e) = initialize_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    info!("Intellicrack Launcher v2.0.0 starting...");

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
