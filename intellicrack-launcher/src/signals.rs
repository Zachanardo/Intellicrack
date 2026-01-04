use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

pub fn register_signal_handlers(shutdown_flag: Arc<AtomicBool>) -> Result<()> {
    // Ctrl+C handler
    let flag_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        info!("Received Ctrl+C signal");
        flag_clone.store(true, Ordering::SeqCst);
    })?;

    Ok(())
}
