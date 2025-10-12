use pyo3::prelude::*;
use std::env;

fn main() {
    println!("Test Python embedding");

    // Set environment variables
    env::set_var("PYO3_PYTHON", r"D:\\Intellicrack\.pixi\envs\default\python.exe");
    env::set_var("PYTHONHOME", r"D:\\Intellicrack\.pixi\envs\default");
    env::set_var("PYTHONPATH", r"D:\\Intellicrack");

    println!("Environment variables set");
    println!("PYO3_PYTHON = {:?}", env::var("PYO3_PYTHON"));
    println!("PYTHONHOME = {:?}", env::var("PYTHONHOME"));

    println!("About to attach to Python...");

    // Try to initialize Python
    match Python::attach(|py| -> Result<(), PyErr> {
        println!("Successfully attached to the GIL!");

        // Get Python version
        let version = py.version();
        println!("Python version: {}", version);

        // Test simple evaluation
        let code = std::ffi::CString::new("2 + 2").unwrap();
        let result: i32 = py.eval(code.as_c_str(), None, None)?.extract()?;
        println!("2 + 2 = {}", result);

        Ok(())
    }) {
        Ok(()) => println!("Test successful!"),
        Err(e) => eprintln!("Test failed: {}", e),
    }
}
