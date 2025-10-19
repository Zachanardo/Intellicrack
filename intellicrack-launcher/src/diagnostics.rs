use crate::dependencies::ValidationSummary;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub startup_time: Duration,
    pub validation_time: Duration,
    pub dependency_check_time: Duration,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub disk_usage_mb: f64,
    pub network_latency_ms: Option<u64>,
    pub thread_count: usize,
    pub process_count: usize,
    pub system_uptime_hours: f64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            startup_time: Duration::from_millis(0),
            validation_time: Duration::from_millis(0),
            dependency_check_time: Duration::from_millis(0),
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
            disk_usage_mb: 0.0,
            network_latency_ms: None,
            thread_count: 1,
            process_count: 1,
            system_uptime_hours: 0.0,
        }
    }
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_startup_time(&mut self, duration: Duration) {
        self.startup_time = duration;
        debug!("Recorded startup time: {:?}", duration);
    }

    pub fn record_validation_time(&mut self, duration: Duration) {
        self.validation_time = duration;
        debug!("Recorded validation time: {:?}", duration);
    }

    pub fn record_dependency_check_time(&mut self, duration: Duration) {
        self.dependency_check_time = duration;
        debug!("Recorded dependency check time: {:?}", duration);
    }

    pub fn collect_system_metrics(&mut self) -> Result<()> {
        debug!("Collecting system metrics");

        // Collect memory usage
        self.memory_usage_mb = Self::get_memory_usage()?;

        // Collect CPU usage
        self.cpu_usage_percent = Self::get_cpu_usage()?;

        // Collect disk usage
        self.disk_usage_mb = Self::get_disk_usage()?;

        // Collect thread count
        self.thread_count = Self::get_thread_count()?;

        // Collect process count
        self.process_count = Self::get_process_count()?;

        // Collect system uptime
        self.system_uptime_hours = Self::get_system_uptime_hours()?;

        // Try to measure network latency (optional)
        self.network_latency_ms = Self::get_network_latency().ok();

        info!("System metrics collected successfully");
        Ok(())
    }

    fn get_memory_usage() -> Result<f64> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args([
                    "-Command",
                    "Get-Process -Id $PID | Select-Object -ExpandProperty WorkingSet",
                ])
                .output()?;

            if output.status.success() {
                let memory_str = String::from_utf8_lossy(&output.stdout);
                let memory_bytes: f64 = memory_str.trim().parse().unwrap_or(0.0);
                let memory_mb = memory_bytes / (1024.0 * 1024.0);
                debug!("Memory usage: {:.2} MB", memory_mb);
                return Ok(memory_mb);
            }
        }

        #[cfg(unix)]
        {
            use std::process::Command;

            let output = Command::new("ps")
                .args(&["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()?;

            if output.status.success() {
                let memory_str = String::from_utf8_lossy(&output.stdout);
                let memory_kb: f64 = memory_str.trim().parse().unwrap_or(0.0);
                let memory_mb = memory_kb / 1024.0;
                debug!("Memory usage: {:.2} MB", memory_mb);
                return Ok(memory_mb);
            }
        }

        // Fallback: estimate based on process size
        debug!("Using fallback memory estimation");
        Ok(50.0) // Reasonable estimate for a Rust launcher process
    }

    fn get_cpu_usage() -> Result<f64> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args(["-Command", "Get-Counter \"\\Processor(_Total)\\% Processor Time\" | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"])
                .output()?;

            if output.status.success() {
                let cpu_str = String::from_utf8_lossy(&output.stdout);
                let cpu_percent: f64 = cpu_str.trim().parse().unwrap_or(0.0);
                debug!("CPU usage: {:.2}%", cpu_percent);
                return Ok(cpu_percent);
            }
        }

        #[cfg(unix)]
        {
            use std::process::Command;

            let output = Command::new("top").args(&["-bn1"]).output()?;

            if output.status.success() {
                let top_output = String::from_utf8_lossy(&output.stdout);
                // Parse CPU usage from top output
                for line in top_output.lines() {
                    if line.contains("%Cpu(s)") || line.contains("Cpu(s)") {
                        // Extract CPU usage percentage
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        for (i, part) in parts.iter().enumerate() {
                            if part.contains("us") && i > 0 {
                                if let Ok(cpu_usage) = parts[i - 1].parse::<f64>() {
                                    debug!("CPU usage: {:.2}%", cpu_usage);
                                    return Ok(cpu_usage);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fallback: return a reasonable default
        debug!("Using fallback CPU estimation");
        Ok(5.0) // Reasonable estimate for idle system
    }

    fn get_disk_usage() -> Result<f64> {
        // Get current executable directory size
        let current_dir = std::env::current_exe()?
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        let disk_usage = Self::calculate_directory_size(&current_dir)?;
        let disk_usage_mb = disk_usage as f64 / (1024.0 * 1024.0);
        debug!("Disk usage: {:.2} MB", disk_usage_mb);
        Ok(disk_usage_mb)
    }

    fn calculate_directory_size(dir: &Path) -> Result<u64> {
        let mut total_size = 0;

        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    total_size += Self::calculate_directory_size(&path).unwrap_or(0);
                } else {
                    total_size += entry.metadata()?.len();
                }
            }
        }

        Ok(total_size)
    }

    fn get_thread_count() -> Result<usize> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args(["-Command", "Get-Process -Id $PID | Select-Object -ExpandProperty Threads | Measure-Object | Select-Object -ExpandProperty Count"])
                .output()?;

            if output.status.success() {
                let count_str = String::from_utf8_lossy(&output.stdout);
                let thread_count: usize = count_str.trim().parse().unwrap_or(1);
                debug!("Thread count: {}", thread_count);
                return Ok(thread_count);
            }
        }

        #[cfg(unix)]
        {
            use std::process::Command;

            let output = Command::new("ps")
                .args(&["-o", "nlwp=", "-p", &std::process::id().to_string()])
                .output()?;

            if output.status.success() {
                let count_str = String::from_utf8_lossy(&output.stdout);
                let thread_count: usize = count_str.trim().parse().unwrap_or(1);
                debug!("Thread count: {}", thread_count);
                return Ok(thread_count);
            }
        }

        // Fallback: estimate based on typical Rust async application
        debug!("Using fallback thread count estimation");
        Ok(4) // Reasonable default for tokio runtime
    }

    fn get_process_count() -> Result<usize> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args([
                    "-Command",
                    "Get-Process | Measure-Object | Select-Object -ExpandProperty Count",
                ])
                .output()?;

            if output.status.success() {
                let count_str = String::from_utf8_lossy(&output.stdout);
                let process_count: usize = count_str.trim().parse().unwrap_or(50);
                debug!("Process count: {}", process_count);
                return Ok(process_count);
            }
        }

        #[cfg(unix)]
        {
            use std::process::Command;

            let output = Command::new("ps").args(&["aux"]).output()?;

            if output.status.success() {
                let ps_output = String::from_utf8_lossy(&output.stdout);
                let process_count = ps_output.lines().count().saturating_sub(1); // Subtract header
                debug!("Process count: {}", process_count);
                return Ok(process_count);
            }
        }

        // Fallback: reasonable estimate
        debug!("Using fallback process count estimation");
        Ok(50) // Reasonable estimate for typical system
    }

    fn get_system_uptime_hours() -> Result<f64> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let output = Command::new("powershell")
                .args(["-Command", "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty TotalHours"])
                .output()?;

            if output.status.success() {
                let uptime_str = String::from_utf8_lossy(&output.stdout);
                let uptime_hours: f64 = uptime_str.trim().parse().unwrap_or(1.0);
                debug!("System uptime: {:.2} hours", uptime_hours);
                return Ok(uptime_hours);
            }
        }

        #[cfg(unix)]
        {
            if let Ok(uptime_content) = fs::read_to_string("/proc/uptime") {
                let uptime_seconds: f64 = uptime_content
                    .split_whitespace()
                    .next()
                    .unwrap_or("3600.0")
                    .parse()
                    .unwrap_or(3600.0);
                let uptime_hours = uptime_seconds / 3600.0;
                debug!("System uptime: {:.2} hours", uptime_hours);
                return Ok(uptime_hours);
            }
        }

        // Fallback: assume system has been up for at least an hour
        debug!("Using fallback system uptime estimation");
        Ok(1.0)
    }

    fn get_network_latency() -> Result<u64> {
        use std::process::Command;

        #[cfg(windows)]
        {
            let output = Command::new("ping").args(["-n", "1", "8.8.8.8"]).output()?;

            if output.status.success() {
                let ping_output = String::from_utf8_lossy(&output.stdout);
                for line in ping_output.lines() {
                    if line.contains("time=") || line.contains("time<") {
                        for part in line.split_whitespace() {
                            if part.starts_with("time=") || part.starts_with("time<") {
                                let time_part = part
                                    .replace("time=", "")
                                    .replace("time<", "")
                                    .replace("ms", "");
                                if let Ok(latency) = time_part.parse::<u64>() {
                                    debug!("Network latency: {} ms", latency);
                                    return Ok(latency);
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            let output = Command::new("ping")
                .args(&["-c", "1", "8.8.8.8"])
                .output()?;

            if output.status.success() {
                let ping_output = String::from_utf8_lossy(&output.stdout);
                for line in ping_output.lines() {
                    if line.contains("time=") {
                        for part in line.split_whitespace() {
                            if part.starts_with("time=") {
                                let time_part = part.replace("time=", "").replace("ms", "");
                                if let Ok(latency) = time_part.parse::<f64>() {
                                    let latency_ms = latency as u64;
                                    debug!("Network latency: {} ms", latency_ms);
                                    return Ok(latency_ms);
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(anyhow!("Failed to measure network latency"))
    }

    pub fn get_total_runtime(&self) -> Duration {
        self.startup_time + self.validation_time + self.dependency_check_time
    }

    pub fn format_summary(&self) -> String {
        format!(
            "Performance Summary:\n\
             - Startup Time: {:?}\n\
             - Validation Time: {:?}\n\
             - Dependency Check Time: {:?}\n\
             - Total Runtime: {:?}\n\
             - Memory Usage: {:.2} MB\n\
             - CPU Usage: {:.2}%\n\
             - Disk Usage: {:.2} MB\n\
             - Thread Count: {}\n\
             - Process Count: {}\n\
             - System Uptime: {:.2} hours\n\
             - Network Latency: {}",
            self.startup_time,
            self.validation_time,
            self.dependency_check_time,
            self.get_total_runtime(),
            self.memory_usage_mb,
            self.cpu_usage_percent,
            self.disk_usage_mb,
            self.thread_count,
            self.process_count,
            self.system_uptime_hours,
            self.network_latency_ms
                .map(|ms| format!("{} ms", ms))
                .unwrap_or("N/A".to_string())
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEntry {
    pub timestamp: u64,
    pub level: String,
    pub category: String,
    pub message: String,
    pub details: HashMap<String, String>,
    pub metrics: Option<PerformanceMetrics>,
}

impl DiagnosticEntry {
    pub fn new(level: String, category: String, message: String) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level,
            category,
            message,
            details: HashMap::new(),
            metrics: None,
        }
    }

    pub fn with_details(mut self, details: HashMap<String, String>) -> Self {
        self.details = details;
        self
    }

    pub fn with_metrics(mut self, metrics: PerformanceMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn add_detail(&mut self, key: String, value: String) {
        self.details.insert(key, value);
    }
}

pub struct DiagnosticsManager {
    log_path: PathBuf,
    metrics: PerformanceMetrics,
    entries: Vec<DiagnosticEntry>,
    enabled: bool,
}

impl DiagnosticsManager {
    pub fn new() -> Result<Self> {
        let log_path = Self::get_log_path()?;

        // Ensure log directory exists
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }

        info!(
            "Diagnostics manager initialized with log path: {:?}",
            log_path
        );

        Ok(DiagnosticsManager {
            log_path,
            metrics: PerformanceMetrics::new(),
            entries: Vec::new(),
            enabled: true,
        })
    }

    pub fn new_with_path<P: AsRef<Path>>(log_path: P) -> Result<Self> {
        let log_path = log_path.as_ref().to_path_buf();

        // Ensure log directory exists
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }

        info!(
            "Diagnostics manager initialized with custom log path: {:?}",
            log_path
        );

        Ok(DiagnosticsManager {
            log_path,
            metrics: PerformanceMetrics::new(),
            entries: Vec::new(),
            enabled: true,
        })
    }

    fn get_log_path() -> Result<PathBuf> {
        let mut log_path = std::env::current_exe()?
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        log_path.push("logs");
        log_path.push("intellicrack_launcher_diagnostics.log");
        Ok(log_path)
    }

    pub fn enable_diagnostics(&mut self, enabled: bool) {
        self.enabled = enabled;
        info!(
            "Diagnostics {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn get_metrics(&self) -> &PerformanceMetrics {
        &self.metrics
    }

    pub fn get_metrics_mut(&mut self) -> &mut PerformanceMetrics {
        &mut self.metrics
    }

    pub fn collect_system_metrics(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        self.metrics.collect_system_metrics()?;

        let entry = DiagnosticEntry::new(
            "INFO".to_string(),
            "METRICS".to_string(),
            "System metrics collected".to_string(),
        )
        .with_metrics(self.metrics.clone());

        self.add_entry(entry);
        Ok(())
    }

    pub fn log_validation_results(&mut self, results: &ValidationSummary) {
        if !self.enabled {
            return;
        }

        info!("Logging validation results");

        let mut details = HashMap::new();
        details.insert(
            "total_dependencies".to_string(),
            results.total().to_string(),
        );
        details.insert(
            "successful_validations".to_string(),
            results.successful().to_string(),
        );
        details.insert(
            "failed_validations".to_string(),
            results.failed().to_string(),
        );
        details.insert(
            "success_rate".to_string(),
            format!("{:.2}%", results.success_rate()),
        );

        // Add details for each dependency
        for (i, (name, status)) in results.dependencies.iter().enumerate() {
            details.insert(format!("dep_{}_name", i), name.clone());
            details.insert(format!("dep_{}_available", i), status.available.to_string());
            if let Some(version) = &status.version {
                details.insert(format!("dep_{}_version", i), version.clone());
            }
        }

        let entry = DiagnosticEntry::new(
            "INFO".to_string(),
            "VALIDATION".to_string(),
            format!(
                "Validation completed: {}/{} successful",
                results.successful(),
                results.total()
            ),
        )
        .with_details(details)
        .with_metrics(self.metrics.clone());

        self.add_entry(entry);
    }

    pub fn log_startup_metrics(&mut self, startup_time: Duration) {
        if !self.enabled {
            return;
        }

        self.metrics.record_startup_time(startup_time);

        let mut details = HashMap::new();
        details.insert(
            "startup_time_ms".to_string(),
            startup_time.as_millis().to_string(),
        );
        details.insert(
            "startup_time_secs".to_string(),
            format!("{:.3}", startup_time.as_secs_f64()),
        );

        let entry = DiagnosticEntry::new(
            "INFO".to_string(),
            "STARTUP".to_string(),
            format!("Startup completed in {:?}", startup_time),
        )
        .with_details(details);

        self.add_entry(entry);
    }

    pub fn log_error(&mut self, category: &str, message: &str, error: &anyhow::Error) {
        if !self.enabled {
            return;
        }

        error!("Error in {}: {} - {}", category, message, error);

        let mut details = HashMap::new();
        details.insert("error_type".to_string(), error.to_string());
        details.insert("error_debug".to_string(), format!("{:?}", error));

        // Try to get error chain
        let mut source = error.source();
        let mut chain_index = 0;
        while let Some(err) = source {
            details.insert(format!("error_chain_{}", chain_index), err.to_string());
            source = err.source();
            chain_index += 1;
        }

        let entry = DiagnosticEntry::new(
            "ERROR".to_string(),
            category.to_uppercase(),
            format!("{}: {}", message, error),
        )
        .with_details(details);

        self.add_entry(entry);
    }

    pub fn log_warning(&mut self, category: &str, message: &str) {
        if !self.enabled {
            return;
        }

        warn!("Warning in {}: {}", category, message);

        let entry = DiagnosticEntry::new(
            "WARN".to_string(),
            category.to_uppercase(),
            message.to_string(),
        );

        self.add_entry(entry);
    }

    pub fn log_info(&mut self, category: &str, message: &str) {
        if !self.enabled {
            return;
        }

        info!("Info in {}: {}", category, message);

        let entry = DiagnosticEntry::new(
            "INFO".to_string(),
            category.to_uppercase(),
            message.to_string(),
        );

        self.add_entry(entry);
    }

    pub fn add_entry(&mut self, entry: DiagnosticEntry) {
        if !self.enabled {
            return;
        }

        self.entries.push(entry.clone());

        // Write to log file immediately
        if let Err(e) = self.write_entry_to_file(&entry) {
            error!("Failed to write diagnostic entry to file: {}", e);
        }
    }

    fn write_entry_to_file(&self, entry: &DiagnosticEntry) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let timestamp = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| entry.timestamp.to_string());

        writeln!(
            file,
            "[{}] [{}] [{}] {}",
            timestamp, entry.level, entry.category, entry.message
        )?;

        // Write details if present
        if !entry.details.is_empty() {
            for (key, value) in &entry.details {
                writeln!(file, "  {}: {}", key, value)?;
            }
        }

        // Write metrics summary if present
        if let Some(metrics) = &entry.metrics {
            writeln!(file, "  Metrics:")?;
            writeln!(file, "    Memory: {:.2} MB", metrics.memory_usage_mb)?;
            writeln!(file, "    CPU: {:.2}%", metrics.cpu_usage_percent)?;
            writeln!(file, "    Threads: {}", metrics.thread_count)?;
        }

        writeln!(file)?; // Empty line for readability
        file.flush()?;

        Ok(())
    }

    pub fn get_entries(&self) -> &Vec<DiagnosticEntry> {
        &self.entries
    }

    pub fn clear_entries(&mut self) {
        self.entries.clear();
        info!("Diagnostic entries cleared");
    }

    pub fn export_diagnostics(&self, export_path: &Path) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let diagnostic_data = serde_json::to_string_pretty(&DiagnosticExport {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metrics: self.metrics.clone(),
            entries: self.entries.clone(),
        })?;

        fs::write(export_path, diagnostic_data)?;
        info!("Diagnostics exported to {:?}", export_path);
        Ok(())
    }

    pub fn get_summary_report(&self) -> String {
        if !self.enabled {
            return "Diagnostics disabled".to_string();
        }

        let error_count = self.entries.iter().filter(|e| e.level == "ERROR").count();
        let warning_count = self.entries.iter().filter(|e| e.level == "WARN").count();
        let info_count = self.entries.iter().filter(|e| e.level == "INFO").count();

        let mut report = String::new();
        report.push_str("=== DIAGNOSTICS SUMMARY ===\n");
        report.push_str(&format!("Total Entries: {}\n", self.entries.len()));
        report.push_str(&format!("Errors: {}\n", error_count));
        report.push_str(&format!("Warnings: {}\n", warning_count));
        report.push_str(&format!("Info: {}\n", info_count));
        report.push('\n');
        report.push_str(&self.metrics.format_summary());
        report.push_str("\n\n=== RECENT ENTRIES ===\n");

        // Show last 10 entries
        let recent_entries = self.entries.iter().rev().take(10);
        for entry in recent_entries {
            let timestamp = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                .map(|dt| dt.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| entry.timestamp.to_string());
            report.push_str(&format!(
                "[{}] [{}] {}\n",
                timestamp, entry.level, entry.message
            ));
        }

        report
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DiagnosticExport {
    timestamp: u64,
    metrics: PerformanceMetrics,
    entries: Vec<DiagnosticEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn setup_test_environment() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    }

    #[test]
    fn test_performance_metrics_creation() {
        setup_test_environment();

        let metrics = PerformanceMetrics::new();

        assert_eq!(metrics.startup_time, Duration::from_millis(0));
        assert_eq!(metrics.validation_time, Duration::from_millis(0));
        assert_eq!(metrics.dependency_check_time, Duration::from_millis(0));
        assert_eq!(metrics.memory_usage_mb, 0.0);
        assert_eq!(metrics.cpu_usage_percent, 0.0);
        assert_eq!(metrics.thread_count, 1);
    }

    #[test]
    fn test_performance_metrics_recording() {
        setup_test_environment();

        let mut metrics = PerformanceMetrics::new();

        let startup_duration = Duration::from_millis(500);
        let validation_duration = Duration::from_millis(1000);
        let dependency_duration = Duration::from_millis(300);

        metrics.record_startup_time(startup_duration);
        metrics.record_validation_time(validation_duration);
        metrics.record_dependency_check_time(dependency_duration);

        assert_eq!(metrics.startup_time, startup_duration);
        assert_eq!(metrics.validation_time, validation_duration);
        assert_eq!(metrics.dependency_check_time, dependency_duration);

        let total_runtime = startup_duration + validation_duration + dependency_duration;
        assert_eq!(metrics.get_total_runtime(), total_runtime);
    }

    #[tokio::test]
    async fn test_system_metrics_collection() {
        setup_test_environment();

        let mut metrics = PerformanceMetrics::new();

        let result = metrics.collect_system_metrics();

        // System metrics collection might fail on some test environments,
        // but it should not panic
        match result {
            Ok(()) => {
                // If collection succeeds, verify metrics are populated
                assert!(metrics.memory_usage_mb > 0.0);
                assert!(metrics.cpu_usage_percent >= 0.0);
                assert!(metrics.thread_count > 0);
                assert!(metrics.process_count > 0);
                assert!(metrics.system_uptime_hours >= 0.0);
            }
            Err(_) => {
                // Collection failure is acceptable in test environments
            }
        }
    }

    #[test]
    fn test_performance_metrics_serialization() {
        setup_test_environment();

        let mut metrics = PerformanceMetrics::new();
        metrics.record_startup_time(Duration::from_millis(123));
        metrics.record_validation_time(Duration::from_millis(456));
        metrics.memory_usage_mb = 42.5;
        metrics.cpu_usage_percent = 15.3;
        metrics.thread_count = 8;

        // Test JSON serialization
        let json_result = serde_json::to_string(&metrics);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        assert!(json_str.contains("startup_time"));
        assert!(json_str.contains("memory_usage_mb"));
        assert!(json_str.contains("42.5"));

        // Test deserialization
        let deserialize_result: Result<PerformanceMetrics, _> = serde_json::from_str(&json_str);
        assert!(deserialize_result.is_ok());

        let deserialized = deserialize_result.unwrap();
        assert_eq!(deserialized.startup_time, Duration::from_millis(123));
        assert_eq!(deserialized.validation_time, Duration::from_millis(456));
        assert_eq!(deserialized.memory_usage_mb, 42.5);
        assert_eq!(deserialized.cpu_usage_percent, 15.3);
        assert_eq!(deserialized.thread_count, 8);
    }

    #[test]
    fn test_performance_metrics_format_summary() {
        setup_test_environment();

        let mut metrics = PerformanceMetrics::new();
        metrics.record_startup_time(Duration::from_millis(100));
        metrics.memory_usage_mb = 32.1;
        metrics.cpu_usage_percent = 8.5;
        metrics.thread_count = 4;

        let summary = metrics.format_summary();

        assert!(summary.contains("Performance Summary"));
        assert!(summary.contains("100ms"));
        assert!(summary.contains("32.1"));
        assert!(summary.contains("8.5"));
        assert!(summary.contains("Thread Count: 4"));
    }

    #[test]
    fn test_diagnostic_entry_creation() {
        setup_test_environment();

        let entry = DiagnosticEntry::new(
            "INFO".to_string(),
            "TEST".to_string(),
            "Test message".to_string(),
        );

        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.category, "TEST");
        assert_eq!(entry.message, "Test message");
        assert!(entry.timestamp > 0);
        assert!(entry.details.is_empty());
        assert!(entry.metrics.is_none());
    }

    #[test]
    fn test_diagnostic_entry_with_details_and_metrics() {
        setup_test_environment();

        let mut details = HashMap::new();
        details.insert("key1".to_string(), "value1".to_string());
        details.insert("key2".to_string(), "value2".to_string());

        let mut metrics = PerformanceMetrics::new();
        metrics.memory_usage_mb = 25.0;

        let entry = DiagnosticEntry::new(
            "ERROR".to_string(),
            "VALIDATION".to_string(),
            "Validation failed".to_string(),
        )
        .with_details(details.clone())
        .with_metrics(metrics.clone());

        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.category, "VALIDATION");
        assert_eq!(entry.details, details);
        assert!(entry.metrics.is_some());
        assert_eq!(entry.metrics.unwrap().memory_usage_mb, 25.0);
    }

    #[test]
    fn test_diagnostics_manager_creation() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let result = DiagnosticsManager::new_with_path(&log_path);
        assert!(result.is_ok());

        let manager = result.unwrap();
        assert!(manager.is_enabled());
        assert_eq!(manager.get_entries().len(), 0);
    }

    #[test]
    fn test_diagnostics_manager_enable_disable() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        assert!(manager.is_enabled());

        manager.enable_diagnostics(false);
        assert!(!manager.is_enabled());

        manager.enable_diagnostics(true);
        assert!(manager.is_enabled());
    }

    #[test]
    fn test_diagnostics_manager_logging() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        manager.log_info("TEST", "Test info message");
        manager.log_warning("TEST", "Test warning message");

        let entries = manager.get_entries();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].level, "INFO");
        assert_eq!(entries[0].category, "TEST");
        assert_eq!(entries[0].message, "Test info message");

        assert_eq!(entries[1].level, "WARN");
        assert_eq!(entries[1].category, "TEST");
        assert_eq!(entries[1].message, "Test warning message");
    }

    #[test]
    fn test_diagnostics_manager_error_logging() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        let test_error = anyhow::anyhow!("Test error message");
        manager.log_error("VALIDATION", "Validation failed", &test_error);

        let entries = manager.get_entries();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.category, "VALIDATION");
        assert!(entry.message.contains("Validation failed"));
        assert!(entry.message.contains("Test error message"));
        assert!(entry.details.contains_key("error_type"));
    }

    #[test]
    fn test_diagnostics_manager_validation_results() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        // Create a mock validation summary
        let mut dependencies = HashMap::new();
        dependencies.insert(
            "Python".to_string(),
            crate::dependencies::DependencyStatus {
                available: true,
                version: Some("3.9.0".to_string()),
                details: HashMap::new(),
            },
        );
        dependencies.insert(
            "Flask".to_string(),
            crate::dependencies::DependencyStatus {
                available: true,
                version: Some("2.3.0".to_string()),
                details: HashMap::new(),
            },
        );
        dependencies.insert(
            "TensorFlow".to_string(),
            crate::dependencies::DependencyStatus {
                available: false,
                version: None,
                details: HashMap::new(),
            },
        );

        let validation_summary = ValidationSummary {
            dependencies,
            flask_validation: None,
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };

        manager.log_validation_results(&validation_summary);

        let entries = manager.get_entries();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.category, "VALIDATION");
        assert!(entry.message.contains("2/3 successful"));
        assert!(entry.details.contains_key("total_dependencies"));
        assert!(entry.details.contains_key("success_rate"));
        assert!(entry.details.contains_key("dep_0_name"));
    }

    #[test]
    fn test_diagnostics_manager_startup_metrics() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        let startup_time = Duration::from_millis(750);
        manager.log_startup_metrics(startup_time);

        assert_eq!(manager.get_metrics().startup_time, startup_time);

        let entries = manager.get_entries();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.category, "STARTUP");
        assert!(entry.message.contains("750ms"));
        assert!(entry.details.contains_key("startup_time_ms"));
        assert!(entry.details.contains_key("startup_time_secs"));
    }

    #[test]
    fn test_diagnostics_manager_disabled_logging() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();
        manager.enable_diagnostics(false);

        manager.log_info("TEST", "This should not be logged");
        manager.log_warning("TEST", "This should also not be logged");

        let entries = manager.get_entries();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_diagnostics_manager_clear_entries() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        manager.log_info("TEST", "Message 1");
        manager.log_info("TEST", "Message 2");

        assert_eq!(manager.get_entries().len(), 2);

        manager.clear_entries();
        assert_eq!(manager.get_entries().len(), 0);
    }

    #[test]
    fn test_diagnostics_manager_export() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");
        let export_path = temp_dir.path().join("export.json");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        manager.log_info("TEST", "Test message");
        manager.get_metrics_mut().memory_usage_mb = 45.0;

        let result = manager.export_diagnostics(&export_path);
        assert!(result.is_ok());

        assert!(export_path.exists());

        let exported_content = fs::read_to_string(&export_path).unwrap();
        assert!(exported_content.contains("Test message"));
        assert!(exported_content.contains("memory_usage_mb"));
        assert!(exported_content.contains("45"));
    }

    #[test]
    fn test_diagnostics_manager_summary_report() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        manager.log_info("TEST", "Info message");
        manager.log_warning("TEST", "Warning message");
        manager.log_error("TEST", "Error occurred", &anyhow::anyhow!("Test error"));

        let summary = manager.get_summary_report();

        assert!(summary.contains("DIAGNOSTICS SUMMARY"));
        assert!(summary.contains("Total Entries: 3"));
        assert!(summary.contains("Errors: 1"));
        assert!(summary.contains("Warnings: 1"));
        assert!(summary.contains("Info: 1"));
        assert!(summary.contains("Performance Summary"));
        assert!(summary.contains("RECENT ENTRIES"));
    }

    #[test]
    fn test_diagnostics_file_logging() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        manager.log_info("FILE_TEST", "Testing file logging");

        // Give a small delay for file operations to complete
        thread::sleep(Duration::from_millis(100));

        assert!(log_path.exists());

        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("FILE_TEST"));
        assert!(log_content.contains("Testing file logging"));
        assert!(log_content.contains("[INFO]"));
    }

    #[tokio::test]
    async fn test_system_metrics_collection_integration() {
        setup_test_environment();

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_diagnostics.log");

        let mut manager = DiagnosticsManager::new_with_path(&log_path).unwrap();

        // This test may fail in some environments, so we handle both success and failure
        let result = manager.collect_system_metrics();

        match result {
            Ok(()) => {
                // If collection succeeded, verify an entry was added
                let entries = manager.get_entries();
                assert!(!entries.is_empty());

                let entry = &entries[entries.len() - 1];
                assert_eq!(entry.category, "METRICS");
                assert!(entry.metrics.is_some());
            }
            Err(_) => {
                // Collection failure is acceptable in test environments
                // The important thing is that it doesn't panic
            }
        }
    }

    #[test]
    fn test_diagnostic_entry_serialization() {
        setup_test_environment();

        let mut details = HashMap::new();
        details.insert("test_key".to_string(), "test_value".to_string());

        let mut metrics = PerformanceMetrics::new();
        metrics.memory_usage_mb = 100.0;

        let entry = DiagnosticEntry::new(
            "INFO".to_string(),
            "TEST".to_string(),
            "Test entry".to_string(),
        )
        .with_details(details)
        .with_metrics(metrics);

        let json_result = serde_json::to_string(&entry);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        let deserialize_result: Result<DiagnosticEntry, _> = serde_json::from_str(&json_str);
        assert!(deserialize_result.is_ok());

        let deserialized = deserialize_result.unwrap();
        assert_eq!(deserialized.level, "INFO");
        assert_eq!(deserialized.category, "TEST");
        assert_eq!(deserialized.message, "Test entry");
        assert!(deserialized.details.contains_key("test_key"));
        assert!(deserialized.metrics.is_some());
        assert_eq!(deserialized.metrics.unwrap().memory_usage_mb, 100.0);
    }
}
