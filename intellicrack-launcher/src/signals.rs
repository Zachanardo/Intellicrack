use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

pub fn register_signal_handlers(shutdown_flag: Arc<AtomicBool>) -> Result<()> {
    let flag_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        let was_shutdown = flag_clone.swap(true, Ordering::SeqCst);
        if was_shutdown {
            warn!("Received repeated Ctrl+C signal - forcing immediate shutdown");
            std::process::exit(1);
        } else {
            info!("Received Ctrl+C signal - initiating graceful shutdown");
        }
    })?;

    Ok(())
}
