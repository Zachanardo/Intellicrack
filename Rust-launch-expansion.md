# Rust Launch Expansion Plan (Granular)

This document outlines the detailed, granular plan to completely convert the Intellicrack launch process from a hybrid Rust-Python model to a pure Rust implementation.

## 1. Eliminate `launch_intellicrack.py`

The primary goal is to eliminate the need for the `launch_intellicrack.py` script. This will be achieved by replicating its functionality in the `intellicrack-launcher` Rust crate.

### 1.1. Replicate Environment Variable Configuration

**File:** `intellicrack-launcher/src/environment.rs`

-   [x] Create a new public function `set_threading_environment_variables()`.
-   [x] Inside this function, use `std::env::set_var` to set the following environment variables to "1":
    -   [x] `OMP_NUM_THREADS`
    -   [x] `MKL_NUM_THREADS`
    -   [x] `NUMEXPR_NUM_THREADS`
    -   [x] `OPENBLAS_NUM_THREADS`
    -   [x] `VECLIB_MAXIMUM_THREADS`
    -   [x] `BLIS_NUM_THREADS`
-   [x] Create a new public function `set_pytorch_environment_variables()`.
-   [x] Inside this function, use `std::env::set_var` to set the following environment variables:
    -   [x] `PYTORCH_DISABLE_CUDNN_BATCH_NORM` to "1"
    -   [x] `CUDA_LAUNCH_BLOCKING` to "1"
-   [x] In `intellicrack-launcher/src/lib.rs`, within the `IntellicrackLauncher::launch` function, call these new functions before initializing Python.

### 1.2. Replicate PyBind11 GIL Safety

**File:** `intellicrack-launcher/src/python_integration.rs`

-   [x] In the `PythonIntegration::initialize` function, before `Python::attach`, set the `PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF` environment variable to "1". This is already present, but verify it is correctly placed before any other pyo3 calls.

### 1.3. Replicate Warning Suppression

**File:** `intellicrack-launcher/src/python_integration.rs`

-   [x] Create a new private function `suppress_pkg_resources_warnings(py: Python) -> Result<()>`.
-   [x] Inside this function, use `py.import("warnings")` to get the warnings module.
-   [x] Call `warnings.call_method1("filterwarnings", ("ignore",), Some(&[("category", py.import("builtins")?.getattr("UserWarning")?), ("module", "pkg_resources")].into_py_dict(py)))?`.
-   [x] Call `warnings.call_method1("filterwarnings", ("ignore",), Some(&[("message", ".*pkg_resources is deprecated.*")].into_py_dict(py)))?`.
-   [x] In the `PythonIntegration::initialize` function, within the `Python::attach` block, call `suppress_pkg_resources_warnings`.

### 1.4. Replicate TCL/TK Configuration and Tkinter Test

**File:** `intellicrack-launcher/src/python_integration.rs`

-   [x] Create a new private function `verify_tkinter(py: Python) -> Result<()>`.
-   [x] Inside `verify_tkinter`:
    -   [x] Use `py.import("importlib.util")` to get the `importlib.util` module.
    -   [x] Call `importlib.util.find_spec("_tkinter")` to check if the `_tkinter` module is available.
    -   [x] If the spec is `None`, return an `anyhow::Error` indicating that `_tkinter` is not available.
    -   [x] If the spec is not `None`, import `tkinter` as `tk`.
    -   [x] Create a `tk.Tk()` instance.
    -   [x] Call `root.withdraw()`.
    -   [x] Call `root.destroy()`.
    -   [x] Log a success message if all steps complete without error.
    -   [x] Handle any exceptions and return an informative `anyhow::Error`.
-   [x] In the `PythonIntegration::initialize` function, within the `Python::attach` block, call `verify_tkinter`.

-   [x] QUALITY-GATE: Run /verify and do a full review of your implementations and edits. You must read every line of code written in this phase and fix every issue that you find before moving on.

## 2. Directly Launch `intellicrack.main`

Instead of using a subprocess to call `launch_intellicrack.py`, the Rust launcher will directly call the `main` function in `intellicrack.main` using `pyo3`.

### 2.1. Implement `run_intellicrack_main_embedded`

**File:** `intellicrack-launcher/src/python_integration.rs`

-   [x] Create a new public function `run_intellicrack_main_embedded(&self) -> Result<i32>`.
-   [x] Inside this function, use `Python::with_gil` to acquire the GIL.
-   [x] Within the GIL closure:
    -   [x] Import the `intellicrack.main` module using `py.import("intellicrack.main")`.
    -   [x] Call the `main` function using `main_module.call_method0("main")`.
    -   [x] Extract the integer exit code from the result.
    -   [x] Handle any `PyErr` exceptions, logging them and returning an appropriate `anyhow::Error`.
    -   [x] Return the exit code.

### 2.2. Update `IntellicrackLauncher::launch`

**File:** `intellicrack-launcher/src/lib.rs`

-   [x] In the `IntellicrackLauncher::launch` method, replace the call to `self.python.as_ref().ok_or_else(...)?.run_intellicrack_main()?` with a call to `self.python.as_ref().ok_or_else(...)?.run_intellicrack_main_embedded()?`.

-   [x] QUALITY-GATE: Run /verify and do a full review of your implementations and edits. You must read every line of code written in this phase and fix every issue that you find before moving on.

## 3. Code Cleanup and Refactoring

Once the functionality of `launch_intellicrack.py` has been migrated to Rust, the following cleanup tasks should be performed:

### 3.1. Delete `launch_intellicrack.py`

-   [x] Delete the file `D:\Intellicrack\launch_intellicrack.py` from the project.

### 3.2. Remove `run_via_subprocess`

**File:** `intellicrack-launcher/src/python_integration.rs`

-   [x] Delete the `run_via_subprocess` function.
-   [x] Delete the `run_intellicrack_main` function that calls `run_via_subprocess`.

### 3.3. Update Documentation

-   [x] Review and update `README.md` in the root directory to remove any mention of `launch_intellicrack.py`.
-   [x] Review and update `intellicrack-launcher/README.md` to reflect the new pure-Rust launch process.
-   [x] Search the entire codebase for any other references to `launch_intellicrack.py` and update them accordingly.

-   [x] QUALITY-GATE: Run /verify and do a full review of your implementations and edits. You must read every line of code written in this phase and fix every issue that you find before moving on.

## 4. Final Verification

-   [ ] Run the integration test to ensure the full Rust launch implementation was successful:
    ```bash
    pixi run pytest tests/test_full_rust_launch.py
    ```
    Note: Integration test requires release build (`cargo build --release`). All code has been implemented, verified, and passes debug builds.
