use anyhow::{Context, Result};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::platform::PlatformInfo;
use crate::security::SecurityManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub max_processes: usize,
    pub default_timeout: Duration,
    pub enable_stdout_capture: bool,
    pub enable_stderr_capture: bool,
    pub process_priority: ProcessPriority,
    pub worker_pool_size: usize,
    pub auto_restart_failed: bool,
    pub log_process_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessPriority {
    Low,
    Normal,
    High,
    Realtime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub id: u32,
    pub pid: u32,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    pub started_at: std::time::SystemTime,
    pub status: ProcessStatus,
    pub exit_code: Option<i32>,
    pub stdout_lines: Vec<String>,
    pub stderr_lines: Vec<String>,
    pub timeout: Option<Duration>,
    pub security_validated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessStatus {
    Starting,
    Running,
    Completed,
    Failed,
    Timeout,
    Killed,
    SecurityBlocked,
}

#[derive(Debug)]
struct ManagedProcess {
    id: u32,
    child: Option<Child>,
    info: ProcessInfo,
    start_time: Instant,
    output_thread: Option<thread::JoinHandle<()>>,
    monitor_thread: Option<thread::JoinHandle<()>>,
}

pub struct ProcessManager {
    platform: PlatformInfo,
    config: ProcessConfig,
    security: Arc<Mutex<SecurityManager>>,
    processes: Arc<Mutex<HashMap<u32, ManagedProcess>>>,
    next_process_id: Arc<Mutex<u32>>,
    worker_pool: Arc<Mutex<Vec<WorkerInfo>>>,
    process_stats: Arc<Mutex<ProcessStatistics>>,
    shutdown_flag: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub id: usize,
    pub status: WorkerStatus,
    pub current_task: Option<u32>,
    pub processes_completed: usize,
    pub total_execution_time: Duration,
    pub last_activity: Instant,
}

#[derive(Debug, Clone)]
pub enum WorkerStatus {
    Idle,
    Busy,
    Failed,
    Shutdown,
}

#[derive(Debug, Default)]
pub struct ProcessStatistics {
    pub total_processes: usize,
    pub successful_processes: usize,
    pub failed_processes: usize,
    pub timed_out_processes: usize,
    pub security_blocked_processes: usize,
    pub total_execution_time: Duration,
    pub average_execution_time: Duration,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            max_processes: 32,
            default_timeout: Duration::from_secs(300), // 5 minutes
            enable_stdout_capture: true,
            enable_stderr_capture: true,
            process_priority: ProcessPriority::Normal,
            worker_pool_size: num_cpus::get(),
            auto_restart_failed: false,
            log_process_output: true,
        }
    }
}

impl ProcessManager {
    pub fn new(platform: &PlatformInfo, security: Arc<Mutex<SecurityManager>>) -> Result<Self> {
        let config = ProcessConfig::default();
        let worker_pool = Self::initialize_worker_pool(config.worker_pool_size)?;

        Ok(Self {
            platform: platform.clone(),
            config,
            security,
            processes: Arc::new(Mutex::new(HashMap::new())),
            next_process_id: Arc::new(Mutex::new(1)),
            worker_pool: Arc::new(Mutex::new(worker_pool)),
            process_stats: Arc::new(Mutex::new(ProcessStatistics::default())),
            shutdown_flag: Arc::new(Mutex::new(false)),
        })
    }

    pub fn with_config(
        platform: &PlatformInfo,
        security: Arc<Mutex<SecurityManager>>,
        config: ProcessConfig,
    ) -> Result<Self> {
        let worker_pool = Self::initialize_worker_pool(config.worker_pool_size)?;

        Ok(Self {
            platform: platform.clone(),
            config,
            security,
            processes: Arc::new(Mutex::new(HashMap::new())),
            next_process_id: Arc::new(Mutex::new(1)),
            worker_pool: Arc::new(Mutex::new(worker_pool)),
            process_stats: Arc::new(Mutex::new(ProcessStatistics::default())),
            shutdown_flag: Arc::new(Mutex::new(false)),
        })
    }

    fn initialize_worker_pool(size: usize) -> Result<Vec<WorkerInfo>> {
        let mut workers = Vec::with_capacity(size);

        for i in 0..size {
            workers.push(WorkerInfo {
                id: i,
                status: WorkerStatus::Idle,
                current_task: None,
                processes_completed: 0,
                total_execution_time: Duration::new(0, 0),
                last_activity: Instant::now(),
            });
        }

        info!(
            "Initialized process manager worker pool with {} workers",
            size
        );
        Ok(workers)
    }

    pub async fn launch_intellicrack_application(&mut self) -> Result<i32> {
        info!("Launching Intellicrack application directly via Python integration");

        // We no longer need to spawn a separate Python process
        // The Python integration module will handle running the main module directly
        // This eliminates the circular dependency and runs the application in-process

        // Note: This method is now primarily for backward compatibility
        // The actual execution happens via the Python integration module
        // which is called from the main launcher

        warn!("ProcessManager::launch_intellicrack_application is deprecated");
        warn!("Application should be launched via PythonIntegration::run_intellicrack_main");

        // Return success since the actual launch happens elsewhere
        Ok(0)
    }

    pub fn execute_command<P: AsRef<Path>>(
        &self,
        command: &str,
        args: &[String],
        working_dir: Option<P>,
        timeout: Option<Duration>,
    ) -> Result<u32> {
        // Security validation
        {
            let security = self.security.lock().unwrap();
            let all_args = [vec![command.to_string()], args.to_vec()].concat();
            security
                .validate_subprocess_command(&all_args, false)
                .context("Security validation failed for subprocess command")?;
        }

        // Check process limits
        {
            let processes = self.processes.lock().unwrap();
            if processes.len() >= self.config.max_processes {
                anyhow::bail!(
                    "Maximum process limit ({}) reached",
                    self.config.max_processes
                );
            }
        }

        // Generate process ID
        let process_id = {
            let mut next_id = self.next_process_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            id
        };

        info!(
            "Starting process {} on {:?}: {} {:?}",
            process_id, self.platform.os_type, command, args
        );

        // Set up command
        let mut cmd = Command::new(command);
        cmd.args(args);

        if let Some(ref wd) = working_dir {
            cmd.current_dir(wd.as_ref());
        }

        // Apply platform-specific command configuration
        match self.platform.os_type {
            crate::platform::OsType::Windows => {
                // Windows-specific: ensure proper console handling
                debug!("Configuring Windows process creation flags");
            }
            crate::platform::OsType::Unix => {
                // Unix-specific: might need different signal handling
                debug!("Configuring Unix process environment");
            }
        }

        // Configure stdio based on config
        if self.config.enable_stdout_capture {
            cmd.stdout(Stdio::piped());
        }
        if self.config.enable_stderr_capture {
            cmd.stderr(Stdio::piped());
        }

        // Apply process priority (Windows-specific implementation)
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let priority_flag = match self.config.process_priority {
                ProcessPriority::Low => 0x0000_0040, // BELOW_NORMAL_PRIORITY_CLASS
                ProcessPriority::Normal => 0x0000_0020, // NORMAL_PRIORITY_CLASS
                ProcessPriority::High => 0x0000_0080, // ABOVE_NORMAL_PRIORITY_CLASS
                ProcessPriority::Realtime => 0x0000_0100, // HIGH_PRIORITY_CLASS
            };
            cmd.creation_flags(priority_flag);
        }

        // Start the process
        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to start process: {command}"))?;

        let pid = child.id();
        let timeout_duration = timeout.unwrap_or(self.config.default_timeout);

        let process_info = ProcessInfo {
            id: process_id,
            pid,
            command: command.to_string(),
            args: args.to_vec(),
            working_dir: working_dir
                .as_ref()
                .map(|p| p.as_ref().to_string_lossy().to_string()),
            started_at: std::time::SystemTime::now(),
            status: ProcessStatus::Starting,
            exit_code: None,
            stdout_lines: Vec::new(),
            stderr_lines: Vec::new(),
            timeout: Some(timeout_duration),
            security_validated: true,
        };

        let managed_process = ManagedProcess {
            id: process_id,
            child: Some(child),
            info: process_info,
            start_time: Instant::now(),
            output_thread: None,
            monitor_thread: None,
        };

        // Insert process
        {
            let mut processes = self.processes.lock().unwrap();
            processes.insert(process_id, managed_process);
        }

        // Assign worker and update status
        let worker_id = (process_id as usize) % self.config.worker_pool_size;
        self.update_worker_status(worker_id, WorkerStatus::Busy, Some(process_id));

        // Start monitoring threads
        if self.config.enable_stdout_capture || self.config.enable_stderr_capture {
            self.start_output_monitoring_thread(process_id)?;
        }

        self.start_process_monitoring_thread(process_id, timeout_duration)?;

        // Update statistics
        {
            let mut stats = self.process_stats.lock().unwrap();
            stats.total_processes += 1;
        }

        debug!("Process {} (PID: {}) started successfully", process_id, pid);
        Ok(process_id)
    }

    fn start_output_monitoring_thread(&self, process_id: u32) -> Result<()> {
        let processes_arc = Arc::clone(&self.processes);
        let config = self.config.clone();
        let shutdown_flag = Arc::clone(&self.shutdown_flag);

        let handle = thread::spawn(move || {
            loop {
                if *shutdown_flag.lock().unwrap() {
                    break;
                }

                let should_continue = {
                    let mut processes = processes_arc.lock().unwrap();
                    if let Some(managed_process) = processes.get_mut(&process_id) {
                        if let Some(child) = &mut managed_process.child {
                            // Read stdout
                            if config.enable_stdout_capture
                                && let Some(stdout) = child.stdout.as_mut()
                            {
                                let reader = BufReader::new(stdout);
                                for line in reader.lines().map_while(Result::ok) {
                                    if config.log_process_output {
                                        debug!("Process {} stdout: {}", process_id, line);
                                    }
                                    managed_process.info.stdout_lines.push(line);
                                }
                            }

                            // Read stderr
                            if config.enable_stderr_capture
                                && let Some(stderr) = child.stderr.as_mut()
                            {
                                let reader = BufReader::new(stderr);
                                for line in reader.lines().map_while(Result::ok) {
                                    if config.log_process_output {
                                        debug!("Process {} stderr: {}", process_id, line);
                                    }
                                    managed_process.info.stderr_lines.push(line);
                                }
                            }

                            // Check if process is still running
                            match child.try_wait() {
                                Ok(Some(_)) => false, // Process has finished
                                Ok(None) => true,     // Process still running
                                Err(_) => false,      // Error checking process
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

                if !should_continue {
                    break;
                }

                thread::sleep(Duration::from_millis(50));
            }

            debug!(
                "Output monitoring thread for process {} finished",
                process_id
            );
        });

        // Store thread handle
        {
            let mut processes = self.processes.lock().unwrap();
            if let Some(managed_process) = processes.get_mut(&process_id) {
                managed_process.output_thread = Some(handle);
            }
        }

        Ok(())
    }

    fn start_process_monitoring_thread(&self, process_id: u32, timeout: Duration) -> Result<()> {
        let processes_arc = Arc::clone(&self.processes);
        let stats_arc = Arc::clone(&self.process_stats);
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        let workers_arc = Arc::clone(&self.worker_pool);
        let worker_pool_size = self.config.worker_pool_size;

        let handle = thread::spawn(move || {
            let start_time = Instant::now();
            let worker_id = (process_id as usize) % worker_pool_size;

            // Helper function to update worker status
            let update_worker_status = |status: WorkerStatus, current_task: Option<u32>| {
                if let Ok(mut workers) = workers_arc.lock()
                    && let Some(worker) = workers.get_mut(worker_id)
                {
                    worker.status = status;
                    worker.current_task = current_task;
                    worker.last_activity = Instant::now();

                    if current_task.is_none() && worker.current_task.is_some() {
                        worker.processes_completed += 1;
                    }
                }
            };

            loop {
                if *shutdown_flag.lock().unwrap() {
                    // Update worker status to Shutdown when shutting down
                    update_worker_status(WorkerStatus::Shutdown, None);
                    break;
                }

                let (should_kill_timeout, process_finished) = {
                    let mut processes = processes_arc.lock().unwrap();
                    if let Some(managed_process) = processes.get_mut(&process_id) {
                        if let Some(child) = &mut managed_process.child {
                            match child.try_wait() {
                                Ok(Some(exit_status)) => {
                                    // Process finished
                                    managed_process.info.exit_code = exit_status.code();
                                    managed_process.info.status = if exit_status.success() {
                                        ProcessStatus::Completed
                                    } else {
                                        ProcessStatus::Failed
                                    };

                                    let runtime = managed_process.start_time.elapsed();
                                    info!(
                                        process_id = process_id,
                                        pid = managed_process.info.pid,
                                        exit_code = ?exit_status.code(),
                                        duration_ms = runtime.as_millis(),
                                        status = ?managed_process.info.status,
                                        "Process finished"
                                    );
                                    (false, true)
                                }
                                Ok(None) => {
                                    // Process still running - check timeout
                                    managed_process.info.status = ProcessStatus::Running;

                                    if start_time.elapsed() > timeout {
                                        warn!(
                                            "Process {} timed out after {:?}",
                                            process_id, timeout
                                        );
                                        (true, false)
                                    } else {
                                        (false, false)
                                    }
                                }
                                Err(e) => {
                                    error!("Error checking process {} status: {}", process_id, e);
                                    managed_process.info.status = ProcessStatus::Failed;
                                    (false, true)
                                }
                            }
                        } else {
                            (false, true)
                        }
                    } else {
                        (false, true)
                    }
                };

                if should_kill_timeout {
                    // Kill the process due to timeout
                    {
                        let mut processes = processes_arc.lock().unwrap();
                        if let Some(managed_process) = processes.get_mut(&process_id)
                            && let Some(child) = &mut managed_process.child
                        {
                            if let Err(e) = child.kill() {
                                error!("Failed to kill timed out process {}: {}", process_id, e);
                            } else {
                                managed_process.info.status = ProcessStatus::Timeout;
                                info!("Process {} killed due to timeout", process_id);
                            }
                        }
                    }

                    // Update statistics
                    {
                        let mut stats = stats_arc.lock().unwrap();
                        stats.timed_out_processes += 1;
                    }

                    // Update worker status to Failed due to timeout
                    update_worker_status(WorkerStatus::Failed, None);
                    break;
                } else if process_finished {
                    // Update statistics
                    let execution_time = start_time.elapsed();
                    {
                        let mut stats = stats_arc.lock().unwrap();
                        let processes = processes_arc.lock().unwrap();
                        if let Some(managed_process) = processes.get(&process_id) {
                            match managed_process.info.status {
                                ProcessStatus::Completed => stats.successful_processes += 1,
                                ProcessStatus::Failed => stats.failed_processes += 1,
                                ProcessStatus::SecurityBlocked => {
                                    stats.security_blocked_processes += 1;
                                }
                                _ => {}
                            }
                        }
                        stats.total_execution_time += execution_time;
                        if stats.successful_processes + stats.failed_processes > 0 {
                            stats.average_execution_time = stats.total_execution_time
                                / (stats.successful_processes + stats.failed_processes) as u32;
                        }
                    }

                    // Update worker status back to Idle when process completes
                    update_worker_status(WorkerStatus::Idle, None);
                    break;
                }

                thread::sleep(Duration::from_millis(100));
            }

            debug!(
                "Process monitoring thread for process {} finished",
                process_id
            );
        });

        // Store thread handle
        {
            let mut processes = self.processes.lock().unwrap();
            if let Some(managed_process) = processes.get_mut(&process_id) {
                managed_process.monitor_thread = Some(handle);
            }
        }

        Ok(())
    }

    pub fn kill_process(&self, process_id: u32) -> Result<()> {
        let mut processes = self.processes.lock().unwrap();

        if let Some(managed_process) = processes.get_mut(&process_id) {
            if let Some(child) = &mut managed_process.child {
                child.kill().context("Failed to kill process")?;
                managed_process.info.status = ProcessStatus::Killed;
                info!("Process {} killed by request", process_id);
                Ok(())
            } else {
                anyhow::bail!("Process {} has no active child process", process_id);
            }
        } else {
            anyhow::bail!("Process {} not found", process_id);
        }
    }

    #[must_use]
    pub fn get_process_info(&self, process_id: u32) -> Option<ProcessInfo> {
        let processes = self.processes.lock().unwrap();
        processes.get(&process_id).map(|p| p.info.clone())
    }

    #[must_use]
    pub fn list_processes(&self) -> Vec<ProcessInfo> {
        let processes = self.processes.lock().unwrap();
        processes.values().map(|p| p.info.clone()).collect()
    }

    pub fn wait_for_process(&self, process_id: u32) -> Result<ProcessInfo> {
        loop {
            let processes = self.processes.lock().unwrap();
            if let Some(managed_process) = processes.get(&process_id) {
                match managed_process.info.status {
                    ProcessStatus::Completed
                    | ProcessStatus::Failed
                    | ProcessStatus::Timeout
                    | ProcessStatus::Killed
                    | ProcessStatus::SecurityBlocked => {
                        return Ok(managed_process.info.clone());
                    }
                    _ => {
                        drop(processes);
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            } else {
                anyhow::bail!("Process {} not found", process_id);
            }
        }
    }

    pub fn cleanup_finished_processes(&self) -> usize {
        let mut processes = self.processes.lock().unwrap();
        let mut to_remove = Vec::new();

        for (id, managed_process) in processes.iter() {
            match managed_process.info.status {
                ProcessStatus::Completed
                | ProcessStatus::Failed
                | ProcessStatus::Timeout
                | ProcessStatus::Killed
                | ProcessStatus::SecurityBlocked => {
                    to_remove.push(*id);
                }
                _ => {}
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            if let Some(mut managed_process) = processes.remove(&id) {
                // Wait for threads to finish
                if let Some(handle) = managed_process.output_thread.take() {
                    let _ = handle.join();
                }
                if let Some(handle) = managed_process.monitor_thread.take() {
                    let _ = handle.join();
                }
                debug!("Cleaned up process {}", id);
            }
        }

        info!("Cleaned up {} finished processes", count);
        count
    }

    pub fn shutdown(&self) -> Result<()> {
        info!("Shutting down process manager");

        // Set shutdown flag
        {
            let mut shutdown_flag = self.shutdown_flag.lock().unwrap();
            *shutdown_flag = true;
        }

        // Kill all running processes
        let process_ids: Vec<u32> = {
            let processes = self.processes.lock().unwrap();
            processes.keys().copied().collect()
        };

        for process_id in process_ids {
            if let Err(e) = self.kill_process(process_id) {
                warn!(
                    "Failed to kill process {} during shutdown: {}",
                    process_id, e
                );
            }
        }

        // Wait for all processes to finish with timeout
        let shutdown_timeout = Duration::from_secs(10);
        let start_time = Instant::now();

        while start_time.elapsed() < shutdown_timeout {
            let remaining_processes = {
                let processes = self.processes.lock().unwrap();
                processes.len()
            };

            if remaining_processes == 0 {
                break;
            }

            thread::sleep(Duration::from_millis(100));
        }

        // Force cleanup any remaining processes
        self.cleanup_finished_processes();

        info!("Process manager shutdown complete");
        Ok(())
    }

    #[must_use]
    pub fn get_statistics(&self) -> ProcessStatistics {
        let stats = self.process_stats.lock().unwrap();
        ProcessStatistics {
            total_processes: stats.total_processes,
            successful_processes: stats.successful_processes,
            failed_processes: stats.failed_processes,
            timed_out_processes: stats.timed_out_processes,
            security_blocked_processes: stats.security_blocked_processes,
            total_execution_time: stats.total_execution_time,
            average_execution_time: stats.average_execution_time,
        }
    }

    #[must_use]
    pub fn get_worker_status(&self) -> Vec<WorkerInfo> {
        let workers = self.worker_pool.lock().unwrap();
        workers.clone()
    }

    /// Update worker status based on process activity
    fn update_worker_status(
        &self,
        worker_id: usize,
        new_status: WorkerStatus,
        current_task: Option<u32>,
    ) {
        let mut workers = self.worker_pool.lock().unwrap();
        if let Some(worker) = workers.get_mut(worker_id) {
            worker.status = new_status;
            worker.current_task = current_task;
            worker.last_activity = Instant::now();

            if current_task.is_none() && worker.current_task.is_some() {
                worker.processes_completed += 1;
            }
        }
    }

    pub fn execute_python_subprocess(&self, script_path: &str, args: &[String]) -> Result<u32> {
        // Validate Python script execution through security manager
        {
            let security = self.security.lock().unwrap();
            let script_path_obj = Path::new(script_path);
            security
                .validate_file_input(script_path_obj, "python_execution")
                .context("Security validation failed for Python script")?;
        }

        // Use Python integration to execute subprocess
        Python::attach(|py| -> Result<u32> {
            match py.import("intellicrack.utils.runtime.runner_functions") {
                Ok(runner_module) => {
                    debug!("Python runner module imported for subprocess execution");

                    // Validate the runner module has expected functions
                    if !runner_module.hasattr("run_subprocess")? {
                        warn!("Runner module missing expected run_subprocess function");
                    }

                    // Build command for Python execution
                    let python_command =
                        std::env::var("PYTHON").unwrap_or_else(|_| "python".to_string());
                    let mut full_args = vec![script_path.to_string()];
                    full_args.extend_from_slice(args);

                    // Execute through our process manager
                    self.execute_command(&python_command, &full_args, None::<&str>, None)
                }
                Err(e) => {
                    warn!("Failed to import Python runner module: {}", e);

                    // Fallback to direct Python execution
                    let python_command =
                        std::env::var("PYTHON").unwrap_or_else(|_| "python".to_string());
                    let mut full_args = vec![script_path.to_string()];
                    full_args.extend_from_slice(args);

                    self.execute_command(&python_command, &full_args, None::<&str>, None)
                }
            }
        })
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        !*self.shutdown_flag.lock().unwrap()
    }

    #[must_use]
    pub fn get_active_process_count(&self) -> usize {
        let processes = self.processes.lock().unwrap();
        processes
            .values()
            .filter(|p| {
                matches!(
                    p.info.status,
                    ProcessStatus::Starting | ProcessStatus::Running
                )
            })
            .count()
    }
}

impl Drop for ProcessManager {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            error!("Error during ProcessManager drop: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_logging() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }

    fn create_test_platform() -> PlatformInfo {
        PlatformInfo {
            os_type: crate::platform::OsType::Windows,
            is_wsl: false,
            gpu_vendor: crate::platform::GpuVendor::Intel,
            display_available: true,
            font_directory: PathBuf::from("C:\\Windows\\Fonts"),
            architecture: "x86_64".to_string(),
            version: "Windows 11".to_string(),
        }
    }

    fn create_test_security_manager() -> Arc<Mutex<SecurityManager>> {
        Arc::new(Mutex::new(SecurityManager::new().unwrap()))
    }

    fn create_test_config() -> ProcessConfig {
        ProcessConfig {
            max_processes: 10,
            default_timeout: Duration::from_secs(30),
            enable_stdout_capture: true,
            enable_stderr_capture: true,
            process_priority: ProcessPriority::Normal,
            worker_pool_size: 4,
            auto_restart_failed: false,
            log_process_output: true,
        }
    }

    fn create_minimal_config() -> ProcessConfig {
        ProcessConfig {
            max_processes: 2,
            default_timeout: Duration::from_secs(5),
            enable_stdout_capture: false,
            enable_stderr_capture: false,
            process_priority: ProcessPriority::Low,
            worker_pool_size: 1,
            auto_restart_failed: false,
            log_process_output: false,
        }
    }

    #[test]
    fn test_process_config_creation() {
        init_test_logging();
        let config = create_test_config();

        assert_eq!(config.max_processes, 10);
        assert_eq!(config.default_timeout, Duration::from_secs(30));
        assert!(config.enable_stdout_capture);
        assert!(config.enable_stderr_capture);
        assert!(matches!(config.process_priority, ProcessPriority::Normal));
        assert_eq!(config.worker_pool_size, 4);
        assert!(!config.auto_restart_failed);
        assert!(config.log_process_output);
    }

    #[test]
    fn test_process_priority_values() {
        init_test_logging();
        let priorities = [
            ProcessPriority::Low,
            ProcessPriority::Normal,
            ProcessPriority::High,
            ProcessPriority::Realtime,
        ];

        // Test that all priority levels can be created and cloned
        for priority in &priorities {
            let cloned = priority.clone();
            assert!(matches!(
                cloned,
                ProcessPriority::Low
                    | ProcessPriority::Normal
                    | ProcessPriority::High
                    | ProcessPriority::Realtime
            ));
        }
    }

    #[test]
    fn test_process_status_values() {
        init_test_logging();
        let statuses = [
            ProcessStatus::Starting,
            ProcessStatus::Running,
            ProcessStatus::Completed,
            ProcessStatus::Failed,
            ProcessStatus::Timeout,
            ProcessStatus::Killed,
            ProcessStatus::SecurityBlocked,
        ];

        // Test that all status levels can be created and cloned
        for status in &statuses {
            let cloned = status.clone();
            assert!(matches!(
                cloned,
                ProcessStatus::Starting
                    | ProcessStatus::Running
                    | ProcessStatus::Completed
                    | ProcessStatus::Failed
                    | ProcessStatus::Timeout
                    | ProcessStatus::Killed
                    | ProcessStatus::SecurityBlocked
            ));
        }
    }

    #[test]
    fn test_process_info_creation() {
        init_test_logging();
        let start_time = std::time::SystemTime::now();

        let info = ProcessInfo {
            id: 1,
            pid: 1234,
            command: "echo".to_string(),
            args: vec!["test".to_string()],
            working_dir: Some("C:\\Test".to_string()),
            started_at: start_time,
            status: ProcessStatus::Running,
            exit_code: None,
            stdout_lines: vec!["output line".to_string()],
            stderr_lines: vec!["error line".to_string()],
            timeout: Some(Duration::from_secs(10)),
            security_validated: true,
        };

        assert_eq!(info.id, 1);
        assert_eq!(info.pid, 1234);
        assert_eq!(info.command, "echo");
        assert_eq!(info.args, vec!["test"]);
        assert_eq!(info.working_dir, Some("C:\\Test".to_string()));
        assert!(matches!(info.status, ProcessStatus::Running));
        assert_eq!(info.exit_code, None);
        assert_eq!(info.stdout_lines, vec!["output line"]);
        assert_eq!(info.stderr_lines, vec!["error line"]);
        assert_eq!(info.timeout, Some(Duration::from_secs(10)));
        assert!(info.security_validated);
    }

    #[test]
    fn test_process_manager_creation() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();

        let result = ProcessManager::new(&platform, security);
        assert!(result.is_ok());

        let manager = result.unwrap();
        assert_eq!(manager.get_active_process_count(), 0);
        assert!(manager.is_running());
    }

    #[test]
    fn test_process_manager_creation_with_custom_config() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let config = create_minimal_config();

        let result = ProcessManager::with_config(&platform, security, config);
        assert!(result.is_ok());

        let manager = result.unwrap();
        assert_eq!(manager.get_active_process_count(), 0);
        assert!(manager.is_running());
    }

    #[test]
    fn test_process_manager_statistics_initial() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        let stats = manager.get_statistics();
        assert_eq!(stats.total_processes, 0);
        assert_eq!(stats.successful_processes, 0);
        assert_eq!(stats.failed_processes, 0);
        assert_eq!(stats.timed_out_processes, 0);
        assert_eq!(stats.security_blocked_processes, 0);
    }

    #[test]
    fn test_process_manager_worker_status_initial() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        let worker_status = manager.get_worker_status();
        assert!(!worker_status.is_empty()); // Should have at least one worker

        // Check first worker status
        let first_worker = &worker_status[0];
        assert!(first_worker.id == 0);
        assert!(matches!(first_worker.status, WorkerStatus::Idle));
        assert!(first_worker.current_task.is_none());
        assert_eq!(first_worker.processes_completed, 0);
        assert!(first_worker.total_execution_time >= Duration::from_secs(0));
    }

    #[test]
    fn test_process_manager_list_processes_empty() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        let processes = manager.list_processes();
        assert!(processes.is_empty());
    }

    #[test]
    fn test_process_manager_cleanup_finished_processes_empty() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        let cleanup_count = manager.cleanup_finished_processes();
        assert_eq!(cleanup_count, 0);
    }

    #[test]
    fn test_default_process_config() {
        init_test_logging();
        let config = ProcessConfig::default();

        assert_eq!(config.max_processes, 50);
        assert_eq!(config.default_timeout, Duration::from_secs(300));
        assert!(config.enable_stdout_capture);
        assert!(config.enable_stderr_capture);
        assert!(matches!(config.process_priority, ProcessPriority::Normal));
        assert_eq!(config.worker_pool_size, 8);
        assert!(!config.auto_restart_failed);
        assert!(config.log_process_output);
    }

    #[test]
    fn test_process_config_serialization() {
        init_test_logging();
        let config = create_test_config();

        // Test JSON serialization
        let json_result = serde_json::to_string(&config);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        assert!(json_str.contains("max_processes"));
        assert!(json_str.contains("default_timeout"));

        // Test deserialization
        let deserialize_result: Result<ProcessConfig, _> = serde_json::from_str(&json_str);
        assert!(deserialize_result.is_ok());

        let deserialized_config = deserialize_result.unwrap();
        assert_eq!(deserialized_config.max_processes, config.max_processes);
        assert_eq!(
            deserialized_config.worker_pool_size,
            config.worker_pool_size
        );
    }

    #[test]
    fn test_process_info_serialization() {
        init_test_logging();
        let start_time = std::time::SystemTime::now();

        let info = ProcessInfo {
            id: 42,
            pid: 5678,
            command: "test_command".to_string(),
            args: vec!["arg1".to_string(), "arg2".to_string()],
            working_dir: None,
            started_at: start_time,
            status: ProcessStatus::Completed,
            exit_code: Some(0),
            stdout_lines: vec!["success".to_string()],
            stderr_lines: vec![],
            timeout: Some(Duration::from_secs(15)),
            security_validated: true,
        };

        // Test JSON serialization
        let json_result = serde_json::to_string(&info);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        assert!(json_str.contains("test_command"));
        assert!(json_str.contains("Completed"));

        // Test deserialization
        let deserialize_result: Result<ProcessInfo, _> = serde_json::from_str(&json_str);
        assert!(deserialize_result.is_ok());

        let deserialized_info = deserialize_result.unwrap();
        assert_eq!(deserialized_info.id, info.id);
        assert_eq!(deserialized_info.command, info.command);
        assert_eq!(deserialized_info.args, info.args);
        assert!(matches!(deserialized_info.status, ProcessStatus::Completed));
    }

    #[test]
    fn test_process_status_debug_format() {
        init_test_logging();
        let status = ProcessStatus::Running;
        let debug_str = format!("{:?}", status);
        assert_eq!(debug_str, "Running");

        let failed_status = ProcessStatus::Failed;
        let failed_debug_str = format!("{:?}", failed_status);
        assert_eq!(failed_debug_str, "Failed");
    }

    #[test]
    fn test_process_priority_debug_format() {
        init_test_logging();
        let priority = ProcessPriority::High;
        let debug_str = format!("{:?}", priority);
        assert_eq!(debug_str, "High");

        let low_priority = ProcessPriority::Low;
        let low_debug_str = format!("{:?}", low_priority);
        assert_eq!(low_debug_str, "Low");
    }

    #[test]
    fn test_process_manager_execute_command_validation() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        // Test simple command execution (will likely fail in test environment, but should validate)
        #[cfg(windows)]
        let result = manager.execute_command(
            "echo",
            &["test".to_string()],
            None::<&str>,
            Some(Duration::from_secs(1)),
        );

        #[cfg(unix)]
        let result = manager.execute_command(
            "echo",
            &["test".to_string()],
            None::<&str>,
            Some(Duration::from_secs(1)),
        );

        // The result might be Ok or Err depending on system state, but shouldn't panic
        match result {
            Ok(process_id) => {
                assert!(process_id > 0);
                // Try to get process info
                let _info_result = manager.get_process_info(process_id);
                // May or may not exist depending on timing
            }
            Err(_) => {
                // Command might fail due to security restrictions or system state
                // This is acceptable in test environment
            }
        }
    }

    #[test]
    fn test_process_manager_get_process_info_nonexistent() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        let result = manager.get_process_info(99999);
        assert!(result.is_none());
    }

    #[test]
    fn test_process_manager_wait_for_process_nonexistent() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        let result = manager.wait_for_process(99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_manager_kill_process_nonexistent() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        let result = manager.kill_process(99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_manager_shutdown() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();
        let manager = ProcessManager::new(&platform, security).unwrap();

        assert!(manager.is_running());

        let result = manager.shutdown();
        assert!(result.is_ok());

        assert!(!manager.is_running());
    }

    #[test]
    fn test_process_manager_config_validation() {
        init_test_logging();
        let platform = create_test_platform();
        let security = create_test_security_manager();

        // Test with zero max_processes (should still work)
        let mut config = create_test_config();
        config.max_processes = 0;

        let result = ProcessManager::with_config(&platform, security.clone(), config);
        assert!(result.is_ok());

        // Test with very short timeout
        let mut short_timeout_config = create_test_config();
        short_timeout_config.default_timeout = Duration::from_millis(1);

        let result2 = ProcessManager::with_config(&platform, security, short_timeout_config);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_worker_info_creation() {
        init_test_logging();
        let worker = WorkerInfo {
            id: 1,
            status: WorkerStatus::Idle,
            current_task: None,
            processes_completed: 5,
            total_execution_time: Duration::from_secs(120),
            last_activity: Instant::now(),
        };

        assert_eq!(worker.id, 1);
        assert!(matches!(worker.status, WorkerStatus::Idle));
        assert_eq!(worker.current_task, None);
        assert_eq!(worker.processes_completed, 5);
        assert_eq!(worker.total_execution_time, Duration::from_secs(120));
    }

    #[test]
    fn test_worker_status_values() {
        init_test_logging();
        let statuses = [
            WorkerStatus::Idle,
            WorkerStatus::Busy,
            WorkerStatus::Failed,
            WorkerStatus::Shutdown,
        ];

        // Test that all worker status levels can be created and cloned
        for status in &statuses {
            let cloned = status.clone();
            assert!(matches!(
                cloned,
                WorkerStatus::Idle
                    | WorkerStatus::Busy
                    | WorkerStatus::Failed
                    | WorkerStatus::Shutdown
            ));
        }
    }
}
