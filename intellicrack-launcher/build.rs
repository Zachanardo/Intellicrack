use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=intellicrack.rc");
        println!("cargo:rerun-if-changed=Intellicrack.exe.manifest");
        
        std::env::set_var("RC_NOLOGO", "1");
        std::env::set_var("VSLANG", "1033");
        
        let output_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
        std::env::set_var("TMP", &output_dir);
        std::env::set_var("TEMP", &output_dir);
        
        let empty_macros: &[&str] = &[];
        embed_resource::compile("intellicrack.rc", empty_macros);
        println!("cargo:warning=Windows manifest embedded");
        
        let nul_path = std::path::Path::new("NUL");
        if nul_path.exists() {
            let _ = std::fs::remove_file(nul_path);
            println!("cargo:warning=Cleaned up NUL file created by rc.exe");
        }
    }
    
    let mamba_python = PathBuf::from(r"C:\Intellicrack\mamba_env\python.exe");
    
    // Verify the Python executable exists
    if !mamba_python.exists() {
        panic!("Mamba Python not found at expected location: {}", mamba_python.display());
    }
    
    // Ensure Python 3.12 DLL is accessible
    let python312_dll = PathBuf::from(r"C:\Intellicrack\mamba_env\python312.dll");
    if !python312_dll.exists() {
        panic!("Python 3.12 DLL not found at: {}", python312_dll.display());
    }
    
    // Set environment variables for PyO3 build configuration
    env::set_var("PYO3_PYTHON", mamba_python.to_str().unwrap());
    env::set_var("PYTHONHOME", r"C:\Intellicrack\mamba_env");
    env::set_var("PYTHON_SYS_EXECUTABLE", mamba_python.to_str().unwrap());
    
    // Verify Python version
    let output = Command::new(&mamba_python)
        .arg("--version")
        .output()
        .expect("Failed to run Python");
    
    let version_str = String::from_utf8_lossy(&output.stdout);
    println!("cargo:warning=Detected Python version: {}", version_str.trim());
    
    // Ensure we're using Python 3.12
    if !version_str.contains("3.12") {
        panic!(
            "Wrong Python version detected! Expected Python 3.12.x from mamba, got: {}",
            version_str.trim()
        );
    }
    
    // Print diagnostics
    println!("cargo:warning=Configuring PyO3 for mamba Python 3.12 at: {}", mamba_python.display());
    
    // Configure PyO3 build
    // The correct function for pyo3-build-config 0.20 is just to use environment variables
    // PyO3 will automatically use PYO3_PYTHON environment variable we set above
    
    // Additional configuration for Windows linking with GNU toolchain
    // Link against Python 3.12 DLL using proper GNU linker syntax
    println!("cargo:rustc-link-search=native=C:/Intellicrack/mamba_env/libs");
    println!("cargo:rustc-link-search=native=C:/Intellicrack/mamba_env/DLLs");
    println!("cargo:rustc-link-search=native=C:/Intellicrack/mamba_env");
    
    // Link against Python 3.12 DLL
    println!("cargo:rustc-link-lib=python312");
    
    // Force rerun if environment changes
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-env-changed=PYTHONHOME");
    println!("cargo:rerun-if-env-changed=PYTHON_SYS_EXECUTABLE");
    println!("cargo:rerun-if-changed=build.rs");
    
    // Copy critical DLLs to output directory for runtime access
    let target_dir = env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
    let target_dir = PathBuf::from(target_dir).parent().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
    
    // Copy critical Python and runtime DLLs to target directory
    let dlls_to_copy = [
        // Core Python DLLs
        ("python312.dll", r"C:\Intellicrack\mamba_env\python312.dll"),
        ("python3.dll", r"C:\Intellicrack\mamba_env\python3.dll"),
        
        // Runtime DLLs
        ("vcruntime140.dll", r"C:\Intellicrack\mamba_env\vcruntime140.dll"),
        ("vcruntime140_1.dll", r"C:\Intellicrack\mamba_env\vcruntime140_1.dll"),
        ("msvcp140.dll", r"C:\Intellicrack\mamba_env\msvcp140.dll"),
        ("ucrtbase.dll", r"C:\Intellicrack\mamba_env\ucrtbase.dll"),
        ("zlib.dll", r"C:\Intellicrack\mamba_env\zlib.dll"),
        
        // Critical supporting libraries
        ("sqlite3.dll", r"C:\Intellicrack\mamba_env\Library\bin\sqlite3.dll"),
        ("libssl-3-x64.dll", r"C:\Intellicrack\mamba_env\Library\bin\libssl-3-x64.dll"),
        ("libcrypto-3-x64.dll", r"C:\Intellicrack\mamba_env\Library\bin\libcrypto-3-x64.dll"),
        ("libbz2.dll", r"C:\Intellicrack\mamba_env\Library\bin\libbz2.dll"),
        ("ffi-8.dll", r"C:\Intellicrack\mamba_env\Library\bin\ffi-8.dll"),
        ("tcl86t.dll", r"C:\Intellicrack\mamba_env\Library\bin\tcl86t.dll"),
        ("tk86t.dll", r"C:\Intellicrack\mamba_env\Library\bin\tk86t.dll"),
        
        // XML parsing libraries (critical for pyexpat functionality)
        ("libexpat.dll", r"C:\Intellicrack\mamba_env\Library\bin\libexpat.dll"),
        
        // Font and graphics libraries for matplotlib
        ("freetype.dll", r"C:\Intellicrack\mamba_env\Library\bin\freetype.dll"),
        ("fontconfig-1.dll", r"C:\Intellicrack\mamba_env\Library\bin\fontconfig-1.dll"),
        ("libpng16.dll", r"C:\Intellicrack\mamba_env\Library\bin\libpng16.dll"),
        
        // Math libraries for scipy and numpy
        ("libblas.dll", r"C:\Intellicrack\mamba_env\Library\bin\libblas.dll"),
        ("libcblas.dll", r"C:\Intellicrack\mamba_env\Library\bin\libcblas.dll"),
        ("liblapack.dll", r"C:\Intellicrack\mamba_env\Library\bin\liblapack.dll"),
        ("liblapacke.dll", r"C:\Intellicrack\mamba_env\Library\bin\liblapacke.dll"),
        
        // Intel MKL libraries for high-performance math
        ("mkl_core.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_core.2.dll"),
        ("mkl_rt.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_rt.2.dll"),
        ("mkl_avx2.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_avx2.2.dll"),
        ("mkl_avx512.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_avx512.2.dll"),
        ("mkl_sequential.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_sequential.2.dll"),
        ("mkl_intel_thread.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_intel_thread.2.dll"),
        ("mkl_tbb_thread.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_tbb_thread.2.dll"),
        ("mkl_def.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_def.2.dll"),
        ("mkl_vml_avx2.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_vml_avx2.2.dll"),
        ("mkl_vml_avx512.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_vml_avx512.2.dll"),
        ("mkl_vml_def.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_vml_def.2.dll"),
        ("mkl_vml_cmpt.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_vml_cmpt.2.dll"),
        ("mkl_mc3.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_mc3.2.dll"),
        ("mkl_vml_mc3.2.dll", r"C:\Intellicrack\mamba_env\Library\bin\mkl_vml_mc3.2.dll"),
        
        // Intel threading libraries
        ("libiomp5md.dll", r"C:\Intellicrack\mamba_env\Library\bin\libiomp5md.dll"),
        ("tbb12.dll", r"C:\Intellicrack\mamba_env\Library\bin\tbb12.dll"),
        ("tbbmalloc.dll", r"C:\Intellicrack\mamba_env\Library\bin\tbbmalloc.dll"),
        ("tbbmalloc_proxy.dll", r"C:\Intellicrack\mamba_env\Library\bin\tbbmalloc_proxy.dll"),
        
        // Tcl/Tk DLLs for _tkinter module
        ("tcl86t.dll", r"C:\Intellicrack\mamba_env\Library\bin\tcl86t.dll"),
        ("tk86t.dll", r"C:\Intellicrack\mamba_env\Library\bin\tk86t.dll"),
    ];

    // Copy Python extension modules (.pyd files)
    let pyds_to_copy = [
        ("_ctypes.pyd", r"C:\Intellicrack\mamba_env\DLLs\_ctypes.pyd"),
        ("_sqlite3.pyd", r"C:\Intellicrack\mamba_env\DLLs\_sqlite3.pyd"),
        ("_bz2.pyd", r"C:\Intellicrack\mamba_env\DLLs\_bz2.pyd"),
        ("_ssl.pyd", r"C:\Intellicrack\mamba_env\DLLs\_ssl.pyd"),
        ("_tkinter.pyd", r"C:\Intellicrack\mamba_env\DLLs\_tkinter.pyd"),
        ("_hashlib.pyd", r"C:\Intellicrack\mamba_env\DLLs\_hashlib.pyd"),
        ("select.pyd", r"C:\Intellicrack\mamba_env\DLLs\select.pyd"),
        ("_socket.pyd", r"C:\Intellicrack\mamba_env\DLLs\_socket.pyd"),
        ("unicodedata.pyd", r"C:\Intellicrack\mamba_env\DLLs\unicodedata.pyd"),
        ("_lzma.pyd", r"C:\Intellicrack\mamba_env\DLLs\_lzma.pyd"),
        
        // Critical XML parsing modules
        ("pyexpat.pyd", r"C:\Intellicrack\mamba_env\DLLs\pyexpat.pyd"),
        ("_elementtree.pyd", r"C:\Intellicrack\mamba_env\DLLs\_elementtree.pyd"),
        
        // Additional critical modules for full functionality
        ("_asyncio.pyd", r"C:\Intellicrack\mamba_env\DLLs\_asyncio.pyd"),
        ("_decimal.pyd", r"C:\Intellicrack\mamba_env\DLLs\_decimal.pyd"),
        ("_multiprocessing.pyd", r"C:\Intellicrack\mamba_env\DLLs\_multiprocessing.pyd"),
        ("_overlapped.pyd", r"C:\Intellicrack\mamba_env\DLLs\_overlapped.pyd"),
        ("_queue.pyd", r"C:\Intellicrack\mamba_env\DLLs\_queue.pyd"),
        ("_uuid.pyd", r"C:\Intellicrack\mamba_env\DLLs\_uuid.pyd"),
        ("_zoneinfo.pyd", r"C:\Intellicrack\mamba_env\DLLs\_zoneinfo.pyd"),
        ("winsound.pyd", r"C:\Intellicrack\mamba_env\DLLs\winsound.pyd"),
    ];
    
    // Copy DLL files
    for (dll_name, src_path) in &dlls_to_copy {
        let src = PathBuf::from(src_path);
        let dst = target_dir.join(dll_name);
        
        if src.exists() {
            if let Err(e) = std::fs::copy(&src, &dst) {
                println!("cargo:warning=Failed to copy {}: {}", dll_name, e);
            } else {
                println!("cargo:warning=Copied {} to target directory", dll_name);
            }
        } else {
            println!("cargo:warning={} not found at {}", dll_name, src.display());
        }
    }
    
    // Copy Python extension modules (.pyd files)
    for (pyd_name, src_path) in &pyds_to_copy {
        let src = PathBuf::from(src_path);
        let dst = target_dir.join(pyd_name);
        
        if src.exists() {
            if let Err(e) = std::fs::copy(&src, &dst) {
                println!("cargo:warning=Failed to copy {}: {}", pyd_name, e);
            } else {
                println!("cargo:warning=Copied {} to target directory", pyd_name);
            }
        } else {
            println!("cargo:warning={} not found at {}", pyd_name, src.display());
        }
    }
    
    // Copy Tcl/Tk library directories for _tkinter functionality
    let tcl_tk_dirs = [
        ("tcl8.6", r"C:\Intellicrack\mamba_env\Library\lib\tcl8.6"),
        ("tk8.6", r"C:\Intellicrack\mamba_env\Library\lib\tk8.6"),
    ];
    
    for (dir_name, src_path) in &tcl_tk_dirs {
        let src = PathBuf::from(src_path);
        let dst = target_dir.join(dir_name);
        
        if src.exists() && src.is_dir() {
            if let Err(e) = copy_dir_all(&src, &dst) {
                println!("cargo:warning=Failed to copy directory {}: {}", dir_name, e);
            } else {
                println!("cargo:warning=Copied {} directory to target", dir_name);
            }
        } else {
            println!("cargo:warning=Directory {} not found at {}", dir_name, src.display());
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