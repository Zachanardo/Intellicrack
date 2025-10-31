//! Process optimization module for improving Intellicrack launcher performance.
//!
//! This module provides Windows-specific optimizations to boost process priority and
//! pin the application to performance cores on hybrid CPUs (Intel 12th gen+, AMD with 3D V-Cache).
//!
//! # Features
//!
//! - **Process Priority Boosting**: Elevates process to ABOVE_NORMAL priority class on Windows
//! - **CPU Topology Detection**: Identifies P-cores (performance) and E-cores (efficiency) on hybrid CPUs
//! - **CPU Affinity Masking**: Pins the process to P-cores for better performance on hybrid architectures
//!
//! # Platform Support
//!
//! - **Windows**: Full functionality with process priority and CPU affinity control
//! - **Non-Windows**: Gracefully degrades to no-ops with debug logging
//!
//! # Error Handling
//!
//! All optimizations are non-fatal. If any optimization fails, a warning is logged and
//! execution continues normally. This ensures the launcher starts even if optimizations
//! cannot be applied.
//!
//! # Example
//!
//! ```no_run
//! use intellicrack_launcher::process_optimization;
//!
//! // Apply all process optimizations
//! if let Err(e) = process_optimization::optimize_process() {
//!     eprintln!("Warning: Process optimization failed: {}", e);
//! }
//! ```

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use winapi::shared::minwindef::DWORD;
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::{GetCurrentProcess, SetPriorityClass};
#[cfg(target_os = "windows")]
use winapi::um::sysinfoapi::GetLogicalProcessorInformationEx;
#[cfg(target_os = "windows")]
use winapi::um::winbase::{ABOVE_NORMAL_PRIORITY_CLASS, SetProcessAffinityMask};
#[cfg(target_os = "windows")]
use winapi::um::winnt::{RelationProcessorCore, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX};

/// Errors that can occur during process optimization operations.
///
/// These errors are informational and non-fatal. The launcher will continue
/// executing even if these errors occur.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProcessOptimizationError {
    #[error("Failed to get process handle")]
    ProcessHandleError,
    #[error("Failed to set process priority: {0}")]
    SetPriorityError(String),
    #[error("Failed to detect CPU topology: {0}")]
    CpuTopologyError(String),
    #[error("Failed to set CPU affinity: {0}")]
    SetAffinityError(String),
    #[error("Invalid CPU topology: {0}")]
    InvalidTopology(String),
}

/// Represents the CPU topology of the system, distinguishing between
/// performance cores (P-cores) and efficiency cores (E-cores).
///
/// # Fields
///
/// - `p_cores`: Indices of performance cores (high-performance, higher power)
/// - `e_cores`: Indices of efficiency cores (power-efficient, lower performance)
/// - `is_hybrid`: `true` if both P-cores and E-cores are present
///
/// # Platform Notes
///
/// - **Windows**: Detected via `GetLogicalProcessorInformationEx` API using `EfficiencyClass` field
/// - **Hybrid CPUs**: Intel 12th gen+ (Alder Lake, Raptor Lake), AMD Ryzen with 3D V-Cache
/// - **Non-hybrid CPUs**: All cores treated as P-cores, `is_hybrid` is `false`
#[derive(Debug, Clone)]
pub struct CpuTopology {
    pub p_cores: Vec<usize>,
    pub e_cores: Vec<usize>,
    pub is_hybrid: bool,
}

impl CpuTopology {
    /// Creates a new CPU topology descriptor.
    ///
    /// Automatically sets `is_hybrid` to `true` if both P-cores and E-cores are non-empty.
    ///
    /// # Arguments
    ///
    /// - `p_cores`: Vector of performance core indices
    /// - `e_cores`: Vector of efficiency core indices
    ///
    /// # Returns
    ///
    /// A new `CpuTopology` instance with computed `is_hybrid` flag.
    pub fn new(p_cores: Vec<usize>, e_cores: Vec<usize>) -> Self {
        let is_hybrid = !p_cores.is_empty() && !e_cores.is_empty();
        Self {
            p_cores,
            e_cores,
            is_hybrid,
        }
    }
}

/// Optimizes the process priority to improve responsiveness and performance.
///
/// # Platform Behavior
///
/// - **Windows**: Sets process priority to `ABOVE_NORMAL_PRIORITY_CLASS` using `SetPriorityClass`
/// - **Non-Windows**: No-op, logs debug message and returns immediately
///
/// # Error Handling
///
/// This function is non-fatal. If setting priority fails on Windows, a warning is logged
/// and `Ok(())` is returned. The launcher continues normally without elevated priority.
///
/// # Returns
///
/// Always returns `Ok(())`, even if the optimization fails.
///
/// # Example
///
/// ```no_run
/// # use intellicrack_launcher::process_optimization;
/// process_optimization::optimize_process_priority().unwrap();
/// ```
#[cfg(target_os = "windows")]
pub fn optimize_process_priority() -> Result<()> {
    info!("Optimizing process priority for better performance...");

    unsafe {
        let handle = GetCurrentProcess();
        let result = SetPriorityClass(handle, ABOVE_NORMAL_PRIORITY_CLASS);

        if result == 0 {
            let error = std::io::Error::last_os_error();
            warn!("Failed to set process priority: {}", error);
            return Ok(());
        }

        info!("Process priority set to ABOVE_NORMAL");
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn optimize_process_priority() -> Result<()> {
    debug!("Process priority optimization skipped (non-Windows platform)");
    Ok(())
}

#[cfg(target_os = "windows")]
fn detect_cpu_topology() -> Result<CpuTopology> {
    use std::alloc::{Layout, alloc, dealloc};
    use std::mem;

    debug!("Detecting CPU topology...");

    unsafe {
        let mut buffer_length: DWORD = 0;
        GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            std::ptr::null_mut(),
            &mut buffer_length,
        );

        if buffer_length == 0 {
            warn!("Failed to get buffer size for CPU topology, using fallback");
            return Ok(create_fallback_topology());
        }

        let layout = Layout::from_size_align_unchecked(
            buffer_length as usize,
            mem::align_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(),
        );
        let buffer = alloc(layout);

        if buffer.is_null() {
            warn!("Failed to allocate buffer for CPU topology, using fallback");
            return Ok(create_fallback_topology());
        }

        let result = GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            buffer as *mut _,
            &mut buffer_length,
        );

        if result == 0 {
            dealloc(buffer, layout);
            warn!("Failed to get CPU topology information, using fallback");
            return Ok(create_fallback_topology());
        }

        let mut p_cores = Vec::new();
        let mut e_cores = Vec::new();
        let mut offset = 0usize;

        while offset < buffer_length as usize {
            let info = &*(buffer.add(offset) as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX);

            if info.Relationship == RelationProcessorCore {
                let processor_info = &info.u.Processor();
                // EfficiencyClass: Higher values = higher performance (P-cores)
                // On hybrid CPUs: P-cores have EfficiencyClass >= 1, E-cores have EfficiencyClass = 0
                // On non-hybrid CPUs: All cores typically have EfficiencyClass = 0
                let efficiency_class = processor_info.EfficiencyClass;

                let group_mask = &processor_info.GroupMask[0];
                let mut mask = group_mask.Mask as usize;
                let mut core_index = 0;

                while mask != 0 {
                    if mask & 1 != 0 {
                        if efficiency_class >= 1 {
                            p_cores.push(core_index);
                        } else {
                            e_cores.push(core_index);
                        }
                    }
                    mask >>= 1;
                    core_index += 1;
                }
            }

            offset += info.Size as usize;
        }

        dealloc(buffer, layout);

        if p_cores.is_empty() && e_cores.is_empty() {
            debug!("Non-hybrid CPU detected, using all cores");
            return Ok(create_fallback_topology());
        }

        if e_cores.is_empty() {
            let total_cores = p_cores.len();
            debug!("Non-hybrid CPU detected with {} cores", total_cores);
            return Ok(CpuTopology::new(p_cores, e_cores));
        }

        debug!(
            "CPU topology: {} P-cores, {} E-cores",
            p_cores.len(),
            e_cores.len()
        );
        Ok(CpuTopology::new(p_cores, e_cores))
    }
}

#[cfg(target_os = "windows")]
fn create_fallback_topology() -> CpuTopology {
    let core_count = num_cpus::get();
    debug!("Creating fallback topology for {} cores", core_count);
    let p_cores: Vec<usize> = (0..core_count).collect();
    CpuTopology::new(p_cores, Vec::new())
}

#[cfg(not(target_os = "windows"))]
fn detect_cpu_topology() -> Result<CpuTopology> {
    let core_count = num_cpus::get();
    debug!("Non-Windows platform: using all {} cores", core_count);
    let p_cores: Vec<usize> = (0..core_count).collect();
    Ok(CpuTopology::new(p_cores, Vec::new()))
}

/// Sets CPU affinity to pin the process to P-cores only (on hybrid CPUs).
///
/// On hybrid CPUs, E-cores are slower and less suitable for latency-sensitive workloads.
/// This function pins the process to P-cores only for better performance.
///
/// On non-hybrid CPUs, this is a no-op.
///
/// # Arguments
///
/// * `topology` - CPU topology information from `detect_cpu_topology()`
///
/// # Limitations
///
/// Due to DWORD (u32) size constraints in the Windows API wrapper, CPU affinity is limited
/// to the first 32 logical processors. This is sufficient for all consumer CPUs as of 2025,
/// including high-end gaming and workstation processors (e.g., Intel i9-14900K has 32 threads,
/// AMD Ryzen 9 7950X3D has 32 threads). Systems with >32 cores are rare in consumer markets.
///
/// # Errors
///
/// Returns an error if setting affinity fails, but this is non-fatal.
#[cfg(target_os = "windows")]
fn set_cpu_affinity(topology: &CpuTopology) -> Result<()> {
    if !topology.is_hybrid {
        debug!("Non-hybrid CPU, skipping affinity masking");
        return Ok(());
    }

    if topology.p_cores.is_empty() {
        warn!("No P-cores found, skipping affinity masking");
        return Ok(());
    }

    let mut mask: usize = 0;
    for &core in &topology.p_cores {
        if core < std::mem::size_of::<usize>() * 8 {
            mask |= 1 << core;
        }
    }

    if mask == 0 {
        warn!("Invalid affinity mask, skipping");
        return Ok(());
    }

    unsafe {
        let handle = GetCurrentProcess();
        // SetProcessAffinityMask expects DWORD (u32) in winapi crate
        // This limits affinity to first 32 cores, which is sufficient for most consumer CPUs
        let result = SetProcessAffinityMask(handle, mask as u32);

        if result == 0 {
            let error = std::io::Error::last_os_error();
            warn!("Failed to set CPU affinity: {}", error);
            return Ok(());
        }

        info!("Pinned to P-cores: {:?}", topology.p_cores);
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_cpu_affinity(_topology: &CpuTopology) -> Result<()> {
    debug!("CPU affinity optimization skipped (non-Windows platform)");
    Ok(())
}

/// Applies all process optimizations: priority boosting and CPU affinity on hybrid CPUs.
///
/// This is the main entry point for process optimization. It orchestrates:
/// 1. Process priority elevation to ABOVE_NORMAL (Windows only)
/// 2. CPU topology detection (identifies P-cores and E-cores)
/// 3. CPU affinity masking to pin to P-cores on hybrid CPUs (Windows only)
///
/// # Platform Behavior
///
/// - **Windows with hybrid CPU**: All three optimizations applied
/// - **Windows with non-hybrid CPU**: Only priority boosting applied
/// - **Non-Windows**: All optimizations are no-ops with debug logging
///
/// # Performance Impact
///
/// Expected time saved: 10-50ms on process startup, with more consistent performance
/// under system load due to priority elevation and P-core pinning.
///
/// # Error Handling
///
/// All optimizations are non-fatal. Any failures are logged as warnings, and execution
/// continues. This ensures the launcher always starts, even if optimizations cannot be applied.
///
/// # Returns
///
/// Always returns `Ok(())`. Errors are logged but do not propagate.
///
/// # Example
///
/// ```no_run
/// # use intellicrack_launcher::process_optimization;
/// if let Err(e) = process_optimization::optimize_process() {
///     eprintln!("Process optimization warning: {}", e);
/// }
/// ```
pub fn optimize_process() -> Result<()> {
    let start = std::time::Instant::now();

    optimize_process_priority().context("Process priority optimization failed")?;

    let topology = detect_cpu_topology().context("CPU topology detection failed")?;
    set_cpu_affinity(&topology).context("CPU affinity setting failed")?;

    info!("Process optimization completed in {:?}", start.elapsed());
    Ok(())
}
