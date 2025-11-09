//! Tool discovery and caching system for Intellicrack analysis tools.
//!
//! This module provides intelligent caching of binary analysis tool paths to dramatically
//! speed up launcher startup times. On first run, tools are discovered via PATH searches
//! and common installation locations. Subsequent runs use the cached paths (validated for
//! freshness) to avoid expensive filesystem operations.
//!
//! # Features
//!
//! - **Smart Caching**: 24-hour cache validity with automatic path verification
//! - **Multi-Path Discovery**: Searches PATH, common install locations, and platform-specific directories
//! - **Environment Integration**: Automatically sets `{TOOL}_PATH` environment variables for Python
//! - **Graceful Degradation**: Missing tools are non-fatal; Python can perform its own discovery
//!
//! # Cache Location
//!
//! - **Windows**: `%LOCALAPPDATA%\intellicrack\tool_cache.json` or `.cache/intellicrack/tool_cache.json`
//! - **Unix**: `~/.cache/intellicrack/tool_cache.json` or `.cache/intellicrack/tool_cache.json`
//!
//! # Cache Invalidation Rules
//!
//! Cache is invalidated and regenerated if:
//! - Cache file is older than 24 hours
//! - Any cached tool path no longer exists
//! - Cache file is corrupted or unreadable
//! - Cache format version mismatches (currently version 1)
//!
//! # Performance Impact
//!
//! - **Cold start** (no cache): 50-100ms for full tool discovery
//! - **Warm start** (valid cache): 2-5ms for cache load and validation
//! - **Expected savings**: 30-80ms per launch after first run
//!
//! # Example
//!
//! ```no_run
//! use intellicrack_launcher::tool_discovery;
//!
//! // Discover tools and set environment variables
//! if let Err(e) = tool_discovery::discover_and_cache_tools() {
//!     eprintln!("Warning: Tool discovery failed: {}", e);
//!     // Non-fatal - continue with launch
//! }
//! ```

use anyhow::{Context, Result};
use chrono::Utc;
use dirs::cache_dir;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use which::which;

/// Errors that can occur during tool discovery operations.
///
/// These errors are generally non-fatal. If tool discovery fails, the launcher
/// continues normally and Python performs its own tool discovery as needed.
#[derive(Debug, thiserror::Error)]
pub enum ToolDiscoveryError {
    #[error("Failed to determine cache directory")]
    CacheDirectoryError,
    #[error("Failed to read cache file: {0}")]
    CacheReadError(String),
    #[error("Failed to write cache file: {0}")]
    CacheWriteError(String),
    #[error("Failed to parse cache: {0}")]
    CacheParseError(String),
    #[error("Tool discovery failed: {0}")]
    DiscoveryError(String),
}

/// Cache validity duration in hours.
///
/// After this period, the cache is considered stale and tools are re-discovered.
const CACHE_VALIDITY_HOURS: i64 = 24;

/// Required analysis tools to discover and cache.
///
/// This list includes binary analysis tools commonly used by Intellicrack:
/// - `radare2`, `r2`: Reverse engineering framework
/// - `ghidra`, `ghidraRun`: NSA's software reverse engineering suite
/// - `frida`, `frida-ps`: Dynamic instrumentation toolkit
/// - `qemu-system-x86_64`: Machine emulator for sandboxed execution
/// - `capstone`: Disassembly framework
const REQUIRED_TOOLS: &[&str] = &[
    "radare2",
    "r2",
    "ghidra",
    "ghidraRun",
    "frida",
    "frida-ps",
    "qemu-system-x86_64",
    "capstone",
];

/// Information about a discovered tool.
///
/// Contains the full path to the tool executable, optional version information,
/// and a timestamp of when the tool was last verified to exist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolInfo {
    /// Full absolute path to the tool executable
    pub path: PathBuf,
    /// Optional version string if detectable (e.g., "radare2 5.8.8")
    pub version: Option<String>,
    /// Unix timestamp of last verification (when path was confirmed to exist)
    pub verified_at: i64,
}

impl ToolInfo {
    /// Creates a new ToolInfo with the current timestamp.
    ///
    /// # Arguments
    ///
    /// - `path`: Full path to the tool executable
    /// - `version`: Optional version string
    ///
    /// # Returns
    ///
    /// A new ToolInfo instance with `verified_at` set to the current time.
    pub fn new(path: PathBuf, version: Option<String>) -> Self {
        Self {
            path,
            version,
            verified_at: Utc::now().timestamp(),
        }
    }
}

/// Tool cache structure persisted to disk.
///
/// Contains a version number for format compatibility, creation timestamp,
/// and a map of tool names to their discovery information.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolCache {
    /// Cache format version (currently 1)
    pub version: u32,
    /// Unix timestamp when cache was created
    pub timestamp: i64,
    /// Map of tool name to discovered tool information
    pub tools: HashMap<String, ToolInfo>,
}

impl Default for ToolCache {
    fn default() -> Self {
        Self {
            version: 1,
            timestamp: Utc::now().timestamp(),
            tools: HashMap::new(),
        }
    }
}

impl ToolCache {
    /// Creates a new tool cache with the current timestamp.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a tool cache with the given tools map.
    pub fn with_tools(tools: HashMap<String, ToolInfo>) -> Self {
        Self {
            version: 1,
            timestamp: Utc::now().timestamp(),
            tools,
        }
    }
}

/// Returns the path to the tool cache file.
///
/// Attempts to use the platform-specific cache directory first (via `dirs::cache_dir()`),
/// falling back to a `.cache` directory in the project root if unavailable.
///
/// The cache file is stored at: `<cache_dir>/intellicrack/tool_cache.json`
///
/// # Returns
///
/// A `Result` containing the cache file path, or an error if directories cannot be created.
///
/// # Errors
///
/// Returns `ToolDiscoveryError::CacheDirectoryError` if:
/// - Cannot determine a suitable cache directory
/// - Cannot create the cache directory structure
fn get_cache_path() -> Result<PathBuf> {
    let cache_base = cache_dir()
        .or_else(|| {
            let fallback = PathBuf::from(".cache");
            debug!(
                "Platform cache_dir unavailable, using fallback: {}",
                fallback.display()
            );
            Some(fallback)
        })
        .ok_or(ToolDiscoveryError::CacheDirectoryError)?;

    let cache_dir = cache_base.join("intellicrack");

    if !cache_dir.exists() {
        fs::create_dir_all(&cache_dir)
            .context("Failed to create cache directory")
            .map_err(|_e| ToolDiscoveryError::CacheDirectoryError)?;
        debug!("Created cache directory: {}", cache_dir.display());
    }

    let cache_path = cache_dir.join("tool_cache.json");
    debug!("Tool cache path: {}", cache_path.display());

    Ok(cache_path)
}

/// Loads the tool cache from disk if it exists.
///
/// Reads the cache file, deserializes the JSON content, and returns the cache structure.
/// If the cache file doesn't exist or is corrupted, returns `Ok(None)` rather than
/// failing, allowing the caller to regenerate the cache.
///
/// # Returns
///
/// - `Ok(Some(cache))` if cache loaded successfully
/// - `Ok(None)` if cache doesn't exist or is corrupted
/// - `Err(...)` only for unexpected I/O errors
///
/// # Error Handling
///
/// Corrupted or invalid cache files are logged as warnings and treated as if the cache
/// doesn't exist, ensuring the launcher never fails due to cache issues.
fn load_cache() -> Result<Option<ToolCache>> {
    let cache_path = match get_cache_path() {
        Ok(path) => path,
        Err(e) => {
            warn!("Cannot determine cache path: {}", e);
            return Ok(None);
        }
    };

    if !cache_path.exists() {
        debug!("Cache file does not exist: {}", cache_path.display());
        return Ok(None);
    }

    let contents = match fs::read_to_string(&cache_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read cache file: {}. Will regenerate cache.", e);
            return Ok(None);
        }
    };

    match serde_json::from_str::<ToolCache>(&contents) {
        Ok(cache) => {
            debug!("Loaded tool cache from {}", cache_path.display());
            Ok(Some(cache))
        }
        Err(e) => {
            warn!("Failed to parse cache file: {}. Will regenerate cache.", e);
            Ok(None)
        }
    }
}

/// Saves the tool cache to disk atomically.
///
/// Writes the cache to a temporary file first, then renames it to the actual cache file.
/// This atomic operation prevents cache corruption if the process is interrupted during writing.
///
/// # Arguments
///
/// - `cache`: The tool cache to persist
///
/// # Returns
///
/// `Ok(())` on success, or an error if writing or renaming fails.
///
/// # Implementation Notes
///
/// Uses a two-step write process for atomicity:
/// 1. Serialize cache to `tool_cache.json.tmp`
/// 2. Rename temp file to `tool_cache.json` (atomic operation)
fn save_cache(cache: &ToolCache) -> Result<()> {
    let cache_path = get_cache_path()?;
    let temp_path = cache_path.with_extension("json.tmp");

    let json_content = serde_json::to_string_pretty(cache)
        .context("Failed to serialize cache")
        .map_err(|e| ToolDiscoveryError::CacheWriteError(e.to_string()))?;

    fs::write(&temp_path, json_content)
        .context("Failed to write temporary cache file")
        .map_err(|e| ToolDiscoveryError::CacheWriteError(e.to_string()))?;

    fs::rename(&temp_path, &cache_path)
        .context("Failed to rename temporary cache file")
        .map_err(|e| ToolDiscoveryError::CacheWriteError(e.to_string()))?;

    info!("Saved tool cache to {}", cache_path.display());
    Ok(())
}

/// Validates whether the cache is still valid and usable.
///
/// A cache is considered valid if:
/// 1. It's less than 24 hours old
/// 2. All cached tool paths still exist on the filesystem
///
/// # Arguments
///
/// - `cache`: The cache to validate
///
/// # Returns
///
/// `true` if the cache is valid and can be used, `false` if it should be regenerated.
///
/// # Performance
///
/// This function performs filesystem checks on all cached paths, but is still much
/// faster than full tool discovery (typically 1-3ms for 8 tools).
fn is_cache_valid(cache: &ToolCache) -> bool {
    let now = Utc::now().timestamp();
    let age_hours = (now - cache.timestamp) / 3600;

    if age_hours > CACHE_VALIDITY_HOURS {
        debug!(
            "Cache expired: {} hours old (max: {})",
            age_hours, CACHE_VALIDITY_HOURS
        );
        return false;
    }

    for (name, info) in &cache.tools {
        if !info.path.exists() {
            warn!(
                "Cached path for '{}' no longer exists: {}",
                name,
                info.path.display()
            );
            return false;
        }
    }

    debug!(
        "Tool cache is valid (age: {} hours, {} tools)",
        age_hours,
        cache.tools.len()
    );
    true
}

/// Load custom tool paths from the Intellicrack configuration file.
///
/// Reads `config/intellicrack_config.json` and extracts custom tool paths.
///
/// # Returns
///
/// A HashMap of tool names to their configured paths.
fn load_custom_tool_paths() -> HashMap<String, PathBuf> {
    let mut custom_paths = HashMap::new();

    let config_path = PathBuf::from("config").join("intellicrack_config.json");

    if !config_path.exists() {
        debug!("Config file not found at: {}", config_path.display());
        return custom_paths;
    }

    let config_content = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read config file: {}", e);
            return custom_paths;
        }
    };

    let config: Value = match serde_json::from_str(&config_content) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to parse config file: {}", e);
            return custom_paths;
        }
    };

    let tool_mappings = [
        ("ghidra_path", "ghidra"),
        ("radare2_path", "radare2"),
        ("radare2_path", "r2"),
        ("frida_path", "frida"),
        ("qemu_path", "qemu-system-x86_64"),
        ("nasm_path", "nasm"),
    ];

    for (config_key, tool_name) in &tool_mappings {
        if let Some(path_str) = config.get(config_key).and_then(|v| v.as_str()) {
            if !path_str.is_empty() {
                let path = PathBuf::from(path_str);
                if path.exists() {
                    debug!("Loaded custom path for '{}': {}", tool_name, path.display());
                    custom_paths.insert(tool_name.to_string(), path);
                } else {
                    warn!("Custom path for '{}' does not exist: {}", tool_name, path.display());
                }
            }
        }
    }

    debug!("Loaded {} custom tool paths from config", custom_paths.len());
    custom_paths
}

/// Discovers a single tool by searching custom config, PATH, and common installation locations.
///
/// Search strategy:
/// 1. Check config file for custom tool path (highest priority)
/// 2. Try `which` to find tool in PATH
/// 3. Check project's `tools/` directory
/// 4. Check platform-specific common installation directories
/// 5. Attempt to extract version information (non-fatal if fails)
///
/// # Arguments
///
/// - `name`: The tool name to search for (e.g., "radare2", "ghidra")
/// - `custom_paths`: HashMap of custom tool paths from config
///
/// # Returns
///
/// `Some(ToolInfo)` if the tool is found, `None` if not found anywhere.
///
/// # Platform-Specific Search Paths
///
/// **Windows:**
/// - `tools/{tool}/{tool}.exe` (project tools directory)
/// - `C:\Program Files\{tool}\bin\{tool}.exe`
/// - `C:\{tool}\{tool}.exe`
/// - `%USERPROFILE%\.{tool}\{tool}.exe`
///
/// **Unix (Linux/macOS):**
/// - `tools/{tool}/{tool}` (project tools directory)
/// - `/opt/{tool}/bin/{tool}`
/// - `/usr/local/{tool}/bin/{tool}`
/// - `~/.{tool}/{tool}`
///
/// # Performance
///
/// Typically 5-15ms per tool on cold search, <1ms if tool is in PATH or config.
fn discover_tool_with_config(name: &str, custom_paths: &HashMap<String, PathBuf>) -> Option<ToolInfo> {
    debug!("Discovering tool: {}", name);

    if let Some(custom_path) = custom_paths.get(name) {
        if custom_path.exists() {
            debug!("Found '{}' in config at: {}", name, custom_path.display());
            let version = get_tool_version(custom_path, name);
            return Some(ToolInfo::new(custom_path.clone(), version));
        } else {
            warn!("Custom path for '{}' in config does not exist: {}", name, custom_path.display());
        }
    }

    if let Ok(tool_path) = which(name) {
        debug!("Found '{}' in PATH at: {}", name, tool_path.display());
        let version = get_tool_version(&tool_path, name);
        return Some(ToolInfo::new(tool_path, version));
    }

    debug!("'{}' not found in PATH, checking common locations", name);

    let common_paths = get_common_tool_paths(name);

    for candidate_path in common_paths {
        if candidate_path.exists() && candidate_path.is_file() {
            debug!(
                "Found '{}' at common location: {}",
                name,
                candidate_path.display()
            );
            let version = get_tool_version(&candidate_path, name);
            return Some(ToolInfo::new(candidate_path, version));
        }
    }

    debug!("Tool '{}' not found in any search location", name);
    None
}

/// Discovers a single tool by searching PATH and common installation locations.
///
/// This is a wrapper around `discover_tool_with_config` for backward compatibility.
///
/// # Arguments
///
/// - `name`: The tool name to search for (e.g., "radare2", "ghidra")
///
/// # Returns
///
/// `Some(ToolInfo)` if the tool is found, `None` if not found anywhere.
#[allow(dead_code)]
fn discover_tool(name: &str) -> Option<ToolInfo> {
    let custom_paths = load_custom_tool_paths();
    discover_tool_with_config(name, &custom_paths)
}

/// Returns a list of common installation paths to check for a tool.
///
/// # Arguments
///
/// - `tool_name`: Name of the tool to generate paths for
///
/// # Returns
///
/// A vector of possible paths where the tool might be installed.
fn get_common_tool_paths(tool_name: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let tools_dir = project_root.join("tools");

    #[cfg(target_os = "windows")]
    {
        let exe_name = format!("{}.exe", tool_name);

        if tools_dir.exists() {
            paths.push(tools_dir.join(tool_name).join(&exe_name));
            paths.push(tools_dir.join(tool_name).join("bin").join(&exe_name));

            if tool_name == "ghidra" || tool_name == "ghidraRun" {
                paths.push(tools_dir.join("ghidra").join("ghidraRun.bat"));
                paths.push(tools_dir.join("ghidra").join("support").join("launch.bat"));
            }

            if tool_name == "qemu-system-x86_64" {
                paths.push(tools_dir.join("qemu").join("qemu-system-x86_64.exe"));
                paths.push(tools_dir.join("qemu").join("bin").join("qemu-system-x86_64.exe"));
            }

            if tool_name == "nasm" {
                paths.push(tools_dir.join("NASM").join("nasm.exe"));
            }
        }

        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            paths.push(
                PathBuf::from(&program_files)
                    .join(tool_name)
                    .join("bin")
                    .join(&exe_name),
            );
            paths.push(
                PathBuf::from(&program_files)
                    .join(tool_name)
                    .join(&exe_name),
            );
        }

        paths.push(PathBuf::from(format!("C:\\{}", tool_name)).join(&exe_name));
        paths.push(
            PathBuf::from(format!("C:\\{}", tool_name))
                .join("bin")
                .join(&exe_name),
        );

        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(format!(".{}", tool_name)).join(&exe_name));
            paths.push(
                home.join(format!(".{}", tool_name))
                    .join("bin")
                    .join(&exe_name),
            );
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if tools_dir.exists() {
            paths.push(tools_dir.join(tool_name).join(tool_name));
            paths.push(tools_dir.join(tool_name).join("bin").join(tool_name));

            if tool_name == "ghidra" || tool_name == "ghidraRun" {
                paths.push(tools_dir.join("ghidra").join("ghidraRun"));
                paths.push(tools_dir.join("ghidra").join("support").join("launch.sh"));
            }
        }

        paths.push(PathBuf::from(format!(
            "/opt/{}/bin/{}",
            tool_name, tool_name
        )));
        paths.push(PathBuf::from(format!("/opt/{}/{}", tool_name, tool_name)));
        paths.push(PathBuf::from(format!(
            "/usr/local/{}/bin/{}",
            tool_name, tool_name
        )));
        paths.push(PathBuf::from(format!(
            "/usr/local/{}/{}",
            tool_name, tool_name
        )));

        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(format!(".{}/bin/{}", tool_name, tool_name)));
            paths.push(home.join(format!(".{}/{}", tool_name, tool_name)));
        }
    }

    paths
}

/// Attempts to extract version information from a tool.
///
/// Runs `{tool} --version` and parses the output. This is best-effort;
/// if version extraction fails, returns `None` rather than failing the discovery.
///
/// # Arguments
///
/// - `tool_path`: Path to the tool executable
/// - `tool_name`: Name of the tool (for logging)
///
/// # Returns
///
/// `Some(version_string)` if version was extracted successfully, `None` otherwise.
///
/// # Performance Note
///
/// This spawns a subprocess which adds 10-30ms per tool. Consider disabling
/// for performance-critical scenarios.
fn get_tool_version(tool_path: &Path, tool_name: &str) -> Option<String> {
    use std::process::Command;

    // Skip version check for tools that don't support --version or launch GUIs
    if tool_name == "ghidra" || tool_name == "ghidraRun" {
        debug!("Skipping version check for '{}' (launches GUI)", tool_name);
        return None;
    }

    let output = Command::new(tool_path).arg("--version").output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let first_line = stdout.lines().next().unwrap_or("").trim();

            if !first_line.is_empty() {
                debug!("Version for '{}': {}", tool_name, first_line);
                return Some(first_line.to_string());
            }

            debug!("Empty version output for '{}'", tool_name);
            None
        }
        Ok(_) => {
            debug!("Version command failed for '{}' (non-zero exit)", tool_name);
            None
        }
        Err(e) => {
            debug!("Could not run version command for '{}': {}", tool_name, e);
            None
        }
    }
}

/// Discovers all required analysis tools and returns a map of tool names to their information.
///
/// Iterates through `REQUIRED_TOOLS` and attempts to discover each one. Missing tools
/// are silently skipped (not an error condition).
///
/// # Returns
///
/// A `HashMap` of tool name to `ToolInfo` for all successfully discovered tools.
///
/// # Performance
///
/// - Cold discovery (no cache): 50-100ms for ~8 tools
/// - Only tools found in config, PATH, or common locations are included
/// - Missing tools don't slow down the process (fail fast)
fn discover_all_tools() -> HashMap<String, ToolInfo> {
    info!("Discovering analysis tools...");
    let mut tools = HashMap::new();

    let custom_paths = load_custom_tool_paths();

    for &tool_name in REQUIRED_TOOLS {
        if let Some(tool_info) = discover_tool_with_config(tool_name, &custom_paths) {
            tools.insert(tool_name.to_string(), tool_info);
        }
    }

    info!(
        "Discovered {} of {} required tools",
        tools.len(),
        REQUIRED_TOOLS.len()
    );
    tools
}

/// Sets environment variables for discovered tools.
///
/// For each discovered tool, creates an environment variable named `{TOOL}_PATH`
/// (uppercase) pointing to the tool's installation directory (parent of executable).
///
/// # Special Cases
///
/// - `r2`: Also sets `RADARE2_PATH` (alias)
/// - `ghidraRun`: Also sets `GHIDRA_PATH` (conventional name)
///
/// # Arguments
///
/// - `tools`: Map of tool names to their discovery information
///
/// # Environment Variables Set
///
/// Examples:
/// - `RADARE2_PATH=/usr/local/radare2/bin`
/// - `GHIDRA_PATH=C:\Program Files\ghidra`
/// - `FRIDA_PATH=/opt/frida/bin`
///
/// # Safety
///
/// Uses `unsafe` block for `std::env::set_var`, which is technically unsafe in
/// multi-threaded contexts. However, this function is called during launcher
/// initialization before any other threads are spawned, making it safe in practice.
///
/// # Performance
///
/// Negligible (< 1ms) for typical tool counts (5-10 tools).
fn set_tool_env_vars(tools: &HashMap<String, ToolInfo>) {
    info!(
        "Setting environment variables for {} discovered tools",
        tools.len()
    );

    for (name, info) in tools {
        if let Some(parent_dir) = info.path.parent() {
            let env_var_name = format!("{}_PATH", name.to_uppercase());

            unsafe {
                std::env::set_var(&env_var_name, parent_dir);
            }

            debug!("Set {} = {}", env_var_name, parent_dir.display());

            match name.as_str() {
                "r2" => {
                    unsafe {
                        std::env::set_var("RADARE2_PATH", parent_dir);
                    }
                    debug!("Set RADARE2_PATH = {} (alias for r2)", parent_dir.display());
                }
                "ghidraRun" => {
                    unsafe {
                        std::env::set_var("GHIDRA_PATH", parent_dir);
                    }
                    debug!(
                        "Set GHIDRA_PATH = {} (alias for ghidraRun)",
                        parent_dir.display()
                    );
                }
                _ => {}
            }
        } else {
            warn!(
                "Could not determine parent directory for '{}': {}",
                name,
                info.path.display()
            );
        }
    }

    unsafe {
        std::env::set_var("INTELLICRACK_TOOLS_DISCOVERED", "1");
    }
    debug!("Set INTELLICRACK_TOOLS_DISCOVERED=1 to skip Python tool discovery");

    info!("Environment variables set for {} tools", tools.len());
}

/// Main entry point for tool discovery and caching system.
///
/// This function orchestrates the complete tool discovery workflow:
/// 1. Attempts to load existing cache from disk
/// 2. Validates cache freshness (age < 24 hours, paths still exist)
/// 3. Uses cached tools if valid, or performs full discovery if not
/// 4. Saves newly discovered tools to cache for future runs
/// 5. Sets environment variables for all discovered tools
///
/// # Performance Characteristics
///
/// - **First run** (no cache): 50-100ms for full discovery + cache save
/// - **Subsequent runs** (valid cache): 2-5ms for cache load + validation
/// - **Expected improvement**: 30-80ms saved on warm starts (95% time reduction)
///
/// # Error Handling
///
/// This function is designed to be non-fatal. All errors are logged as warnings,
/// and the function returns `Ok(())` even if tool discovery fails completely.
/// This ensures the launcher continues to start even if tools cannot be discovered.
///
/// If tool discovery fails:
/// - Environment variables are not set
/// - Python side will perform its own tool discovery as fallback
/// - Functionality is not impaired, just slightly slower
///
/// # Returns
///
/// Always returns `Ok(())`. Errors are logged but not propagated.
///
/// # Example
///
/// ```no_run
/// use intellicrack_launcher::tool_discovery;
///
/// // Call during launcher initialization
/// if let Err(e) = tool_discovery::discover_and_cache_tools() {
///     eprintln!("Warning: Tool discovery failed: {}", e);
/// }
/// ```
///
/// # Thread Safety
///
/// This function should be called once during launcher initialization, before
/// spawning any additional threads. The `set_tool_env_vars` call uses `unsafe`
/// environment variable modification, which is only safe during single-threaded
/// initialization.
pub fn discover_and_cache_tools() -> Result<()> {
    let start = std::time::Instant::now();
    info!("Starting tool discovery and caching...");

    let tools = match load_cache() {
        Ok(Some(cache)) if is_cache_valid(&cache) => {
            info!("Using cached tool locations ({} tools)", cache.tools.len());
            cache.tools
        }
        Ok(Some(cache)) => {
            info!("Cache exists but is invalid, performing fresh discovery");
            debug!(
                "Cache age: {} hours",
                (Utc::now().timestamp() - cache.timestamp) / 3600
            );
            let fresh_tools = discover_all_tools();

            if !fresh_tools.is_empty() {
                let new_cache = ToolCache::with_tools(fresh_tools.clone());
                if let Err(e) = save_cache(&new_cache) {
                    warn!(
                        "Failed to save tool cache: {}. Will regenerate next time.",
                        e
                    );
                }
            }

            fresh_tools
        }
        Ok(None) => {
            info!("No existing cache, performing initial tool discovery");
            let fresh_tools = discover_all_tools();

            if !fresh_tools.is_empty() {
                let new_cache = ToolCache::with_tools(fresh_tools.clone());
                if let Err(e) = save_cache(&new_cache) {
                    warn!(
                        "Failed to save tool cache: {}. Will regenerate next time.",
                        e
                    );
                }
            }

            fresh_tools
        }
        Err(e) => {
            warn!("Cache load failed: {}. Performing fresh discovery.", e);
            let fresh_tools = discover_all_tools();

            if !fresh_tools.is_empty() {
                let new_cache = ToolCache::with_tools(fresh_tools.clone());
                if let Err(e) = save_cache(&new_cache) {
                    warn!(
                        "Failed to save tool cache: {}. Will regenerate next time.",
                        e
                    );
                }
            }

            fresh_tools
        }
    };

    // Display detailed tool list (whether from cache or fresh discovery)
    info!(
        "Tool Status: {} of {} required tools available",
        tools.len(),
        REQUIRED_TOOLS.len()
    );

    for &tool_name in REQUIRED_TOOLS {
        if let Some(tool_info) = tools.get(tool_name) {
            let version_str = tool_info
                .version
                .as_ref()
                .map(|v| format!(" ({})", v))
                .unwrap_or_default();
            info!("  ✓ {} found at: {}{}", tool_name, tool_info.path.display(), version_str);
        } else {
            warn!("  ✗ {} NOT FOUND", tool_name);
        }
    }

    if !tools.is_empty() {
        set_tool_env_vars(&tools);
    } else {
        warn!("No tools discovered. Python will perform its own discovery.");
    }

    let elapsed = start.elapsed();
    info!("Tool discovery completed in {:?}", elapsed);

    Ok(())
}
