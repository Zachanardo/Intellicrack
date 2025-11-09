use std::env;
use std::path::PathBuf;
use std::process::Command;

#[allow(clippy::cognitive_complexity)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::option_if_let_else)]
fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=intellicrack.rc");
        println!("cargo:rerun-if-changed=Intellicrack.exe.manifest");

        unsafe {
            std::env::set_var("RC_NOLOGO", "1");
            std::env::set_var("VSLANG", "1033");
        }

        let output_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
        unsafe {
            std::env::set_var("TMP", &output_dir);
            std::env::set_var("TEMP", &output_dir);
        }

        // Detect target toolchain (MSVC vs GNU)
        let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
        let is_gnu = target.contains("gnu");

        if is_gnu {
            // Use windres for GNU toolchain
            if Command::new("windres").arg("--version").output().is_ok() {
                let output_dir = std::env::var("OUT_DIR").unwrap();
                let o_file = PathBuf::from(&output_dir).join("intellicrack.o");

                let windres_result = Command::new("windres")
                    .args([
                        "intellicrack.rc",
                        "-O",
                        "coff",
                        "-o",
                        o_file.to_str().unwrap(),
                    ])
                    .output();

                if windres_result.is_ok() {
                    let o_file_str = o_file.to_str().unwrap();
                    println!("cargo:rustc-link-arg={o_file_str}");
                    println!("cargo:warning=Windows manifest embedded (windres)");
                } else {
                    println!("cargo:warning=windres failed, skipping resource compilation");
                }
            } else {
                println!(
                    "cargo:warning=windres not found, skipping resource compilation for GNU target"
                );
            }
        } else {
            // MSVC toolchain - use llvm-rc or embed-resource
            let rc_compiled = if Command::new("llvm-rc").arg("/?").output().is_ok() {
                let output_dir = std::env::var("OUT_DIR").unwrap();
                let res_file = PathBuf::from(&output_dir).join("intellicrack.res");

                let llvm_rc_result = Command::new("llvm-rc")
                    .args(["/FO", res_file.to_str().unwrap(), "intellicrack.rc"])
                    .output();

                if llvm_rc_result.is_ok() {
                    let res_file_str = res_file.to_str().unwrap();
                    println!("cargo:rustc-link-arg={res_file_str}");
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !rc_compiled {
                let empty_macros: &[&str] = &[];
                use embed_resource::CompilationResult;

                match embed_resource::compile("intellicrack.rc", empty_macros) {
                    CompilationResult::Ok => {
                        println!("cargo:warning=Successfully compiled Windows resource file with embed-resource");
                    }
                    CompilationResult::NotWindows => {
                        println!("cargo:warning=Not building for Windows, skipping resource compilation");
                    }
                    CompilationResult::NotAttempted(reason) => {
                        println!("cargo:warning=Resource compilation not attempted: {}", reason);
                        println!("cargo:warning=Continuing without Windows manifest (non-critical)");
                    }
                    CompilationResult::Failed(reason) => {
                        eprintln!("cargo:warning=CRITICAL: Failed to compile Windows resource file: {}", reason);
                        eprintln!("cargo:warning=Windows manifest will be missing from executable");
                        panic!("Resource compilation failed: {}. This may cause runtime issues on Windows.", reason);
                    }
                }
            }
            println!("cargo:warning=Windows manifest embedded");
        }
        println!("cargo:warning=Windows manifest embedded");

        let nul_path = std::path::Path::new("NUL");
        if nul_path.exists() {
            let _ = std::fs::remove_file(nul_path);
            println!("cargo:warning=Cleaned up NUL file created by rc.exe");
        }
    }

    // Determine project root for all scenarios
    let project_root =
        env::var("INTELLICRACK_ROOT").unwrap_or_else(|_| r"D:\Intellicrack".to_string());

    // Detect CI environment or use PYO3_PYTHON if set
    let python_exe = if let Ok(pyo3_python) = env::var("PYO3_PYTHON") {
        // CI or custom Python path
        println!("cargo:warning=Using PYO3_PYTHON from environment: {pyo3_python}");
        PathBuf::from(pyo3_python)
    } else if env::var("CI").is_ok() || env::var("GITHUB_ACTIONS").is_ok() {
        // Running in CI, try to find Python
        let python_candidates = vec![
            env::var("pythonLocation")
                .ok()
                .map(|p| PathBuf::from(p).join("python.exe")),
            env::var("Python_ROOT_DIR")
                .ok()
                .map(|p| PathBuf::from(p).join("python.exe")),
            Some(PathBuf::from("python.exe")),
            Some(PathBuf::from("python3.exe")),
        ];

        let mut found_python = None;
        for candidate in python_candidates.into_iter().flatten() {
            if candidate.exists() || Command::new(&candidate).arg("--version").output().is_ok() {
                found_python = Some(candidate);
                break;
            }
        }

        #[allow(non_snake_case)]
        found_python.map_or_else(
            || {
                panic!(
                    "CI environment detected but Python not found. Set PYO3_PYTHON environment variable."
                )
            },
            |p| {
                let p_display = p.display();
                println!("cargo:warning=CI environment detected, using Python: {p_display}");
                p
            },
        )
    } else {
        // Local development with Pixi
        let pixi_python = PathBuf::from(&project_root).join(".pixi/envs/default/python.exe");
        assert!(
            pixi_python.exists(),
            "Local development: Pixi Python not found at: {}. For CI, set PYO3_PYTHON.",
            pixi_python.display()
        );
        let pixi_python_str = pixi_python.display();
        println!("cargo:warning=Using local Pixi Python: {pixi_python_str}");
        pixi_python
    };

    // Verify Python executable works
    let output = Command::new(&python_exe)
        .arg("--version")
        .output()
        .expect("Failed to run Python");

    let version_str = String::from_utf8_lossy(&output.stdout);
    let version_trimmed = version_str.trim();
    println!("cargo:warning=Detected Python version: {version_trimmed}");

    // Ensure we're using Python 3.12
    if !version_str.contains("3.12") {
        let version_trimmed = version_str.trim();
        println!("cargo:warning=Warning: Expected Python 3.12.x, got: {version_trimmed}");
    }

    // Only set environment variables if not already set (allows CI to override)
    unsafe {
        if env::var("PYO3_PYTHON").is_err() {
            env::set_var("PYO3_PYTHON", python_exe.to_str().unwrap());
        }
        if env::var("PYTHON_SYS_EXECUTABLE").is_err() {
            env::set_var("PYTHON_SYS_EXECUTABLE", python_exe.to_str().unwrap());
        }
    }

    // Print diagnostics
    let python_exe_display = python_exe.display();
    println!("cargo:warning=Configuring PyO3 for Python at: {python_exe_display}");

    // Configure PyO3 build
    // The correct function for pyo3-build-config 0.20 is just to use environment variables
    // PyO3 will automatically use PYO3_PYTHON environment variable we set above

    // Additional configuration for linking
    // Only add pixi-specific paths in local development
    if env::var("CI").is_err() && env::var("GITHUB_ACTIONS").is_err() {
        // Local development paths
        println!(
            "cargo:rustc-link-search=native={}/.pixi/envs/default/libs",
            &project_root
        );
        println!(
            "cargo:rustc-link-search=native={}/.pixi/envs/default/DLLs",
            &project_root
        );
        println!(
            "cargo:rustc-link-search=native={}/.pixi/envs/default",
            &project_root
        );
    }

    // Link against Python 3.12 DLL
    println!("cargo:rustc-link-lib=python312");

    // Force rerun if environment changes
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-env-changed=PYTHONHOME");
    println!("cargo:rerun-if-env-changed=PYTHON_SYS_EXECUTABLE");
    println!("cargo:rerun-if-changed=build.rs");

    // Copy critical DLLs to output directory for runtime access (local development only)
    if env::var("CI").is_err() && env::var("GITHUB_ACTIONS").is_err() {
        let target_dir = env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
        let target_dir = PathBuf::from(target_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let project_root_path = PathBuf::from(&project_root);
        let pixi_env_path = project_root_path.join(".pixi/envs/default");

        // Define search paths within the pixi environment
        let search_paths = vec![
            pixi_env_path.clone(),
            pixi_env_path.join("Library/bin"),
            pixi_env_path.join("DLLs"),
        ];

        // --- Critical DLLs that MUST exist, otherwise the build fails ---
        let critical_dlls = [
            // Core Python
            "python312.dll",
            "python3.dll",
            // Core VC Runtimes
            "vcruntime140.dll",
            "vcruntime140_1.dll",
        ];

        // --- Standard DLLs, warn if not found ---
        let standard_dlls = [
            "msvcp140.dll",
            "ucrtbase.dll",
            "zlib.dll",
            "sqlite3.dll",
            "libssl-3-x64.dll",
            "libcrypto-3-x64.dll",
            "libbz2.dll",
            "ffi-8.dll",
            "libexpat.dll",
            "freetype.dll",
            "libpng16.dll",
            "libblas.dll",
            "libcblas.dll",
            "liblapack.dll",
            "liblapacke.dll",
            "tbb12.dll",
            "tbbmalloc.dll",
            // Intel MKL - optional for enhanced performance
            "mkl_rt.2.dll",
            "mkl_core.2.dll",
            "mkl_intel_thread.2.dll",
            "libiomp5md.dll",
            "mkl_sycl_blas.5.dll",
        ];

        // --- Standard PYDs, warn if not found ---
        let standard_pyds = [
            "_ctypes.pyd",
            "_sqlite3.pyd",
            "_bz2.pyd",
            "_ssl.pyd",
            "_hashlib.pyd",
            "select.pyd",
            "_socket.pyd",
            "unicodedata.pyd",
            "_lzma.pyd",
            "pyexpat.pyd",
            "_elementtree.pyd",
            "_asyncio.pyd",
            "_decimal.pyd",
            "_multiprocessing.pyd",
            "_overlapped.pyd",
            "_queue.pyd",
            "_uuid.pyd",
            "_zoneinfo.pyd",
            "winsound.pyd",
            "_tkinter.pyd",
        ];

        // --- Tcl/Tk libraries ---
        let tcl_tk_libs = ["tcl86t.dll", "tk86t.dll"];

        // --- Copy functions ---
        let copy_file = |file_name: &str, is_critical: bool| {
            let mut source_path: Option<PathBuf> = None;
            for path in &search_paths {
                let potential_path = path.join(file_name);
                if potential_path.exists() {
                    source_path = Some(potential_path);
                    break;
                }
            }

            if let Some(src) = source_path {
                let dst = target_dir.join(file_name);

                let should_copy = if dst.exists() {
                    match (std::fs::metadata(&src), std::fs::metadata(&dst)) {
                        (Ok(src_meta), Ok(dst_meta)) => {
                            src_meta.len() != dst_meta.len()
                                || src_meta.modified().ok() != dst_meta.modified().ok()
                        }
                        _ => true,
                    }
                } else {
                    true
                };

                if should_copy {
                    match std::fs::copy(&src, &dst) {
                        Ok(_) => {
                            let src_display = src.display();
                            println!("cargo:warning=Copied {src_display} to target directory");
                        }
                        Err(e) if e.raw_os_error() == Some(32) => {
                            println!(
                                "cargo:warning={file_name} is in use, skipping copy (file already exists)"
                            );
                        }
                        Err(e) => {
                            let msg = format!("Failed to copy {file_name}: {e}");
                            if is_critical && !dst.exists() {
                                panic!("{msg}");
                            } else {
                                println!("cargo:warning={msg}");
                            }
                        }
                    }
                } else {
                    println!("cargo:warning={file_name} already up-to-date");
                }
            } else {
                let msg = format!(
                    "Could not find required DLL '{file_name}' in any of the search paths: {search_paths:?}"
                );
                if is_critical {
                    panic!("{msg}");
                } else {
                    println!("cargo:warning={msg}");
                }
            }
        };

        // Process all DLLs and PYDs
        for dll in &critical_dlls {
            copy_file(dll, true);
        }
        for dll in &standard_dlls {
            copy_file(dll, false);
        }
        for pyd in &standard_pyds {
            copy_file(pyd, false);
        }
        for lib in &tcl_tk_libs {
            copy_file(lib, false);
        }

        // Copy Tcl/Tk library directories for _tkinter functionality
        let tcl_tk_dirs = [
            ("tcl8.6", pixi_env_path.join("Library/lib/tcl8.6")),
            ("tk8.6", pixi_env_path.join("Library/lib/tk8.6")),
        ];

        for (dir_name, src_path) in &tcl_tk_dirs {
            let dst = target_dir.join(dir_name);
            if src_path.exists() && src_path.is_dir() {
                if let Err(e) = copy_dir_all(src_path, &dst) {
                    println!("cargo:warning=Failed to copy directory {dir_name}: {e}");
                } else {
                    println!("cargo:warning=Copied {dir_name} directory to target");
                }
            } else {
                let src_path_str = src_path.display();
                println!("cargo:warning=Directory {dir_name} not found at {src_path_str}");
            }
        }
    }
}

// Helper function to recursively copy directories
fn copy_dir_all(src: &PathBuf, dst: &PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}
