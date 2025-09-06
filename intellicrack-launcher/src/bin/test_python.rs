use pyo3::prelude::*;
use std::env;

fn main() {
    println!("Test Python embedding");
    
    // Set environment variables
    env::set_var("PYO3_PYTHON", r"C:\Intellicrack\mamba_env\python.exe");
    env::set_var("PYTHONHOME", r"C:\Intellicrack\mamba_env");
    env::set_var("PYTHONPATH", r"C:\Intellicrack");
    
    println!("Environment variables set");
    println!("PYO3_PYTHON = {:?}", env::var("PYO3_PYTHON"));
    println!("PYTHONHOME = {:?}", env::var("PYTHONHOME"));
    
    println!("About to call Python::with_gil()...");
    
    // Try to initialize Python
    match Python::with_gil(|py| -> Result<(), PyErr> {
        println!("Successfully acquired GIL!");
        
        // Get Python version
        let version = py.version();
        println!("Python version: {}", version);
        
        // Test simple evaluation
        let result: i32 = py.eval("2 + 2", None, None)?.extract()?;
        println!("2 + 2 = {}", result);
        
        Ok(())
    }) {
        Ok(()) => println!("Test successful!"),
        Err(e) => eprintln!("Test failed: {}", e),
    }
}