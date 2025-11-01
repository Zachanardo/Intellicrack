import os
import sys
import subprocess
import pytest

@pytest.fixture
def setup_test_environment():
    # Read the original content of intellicrack/main.py
    main_py_path = os.path.join(os.path.dirname(__file__), '..', 'intellicrack', 'main.py')
    with open(main_py_path, 'r') as f:
        original_main_py_content = f.read()

    # Overwrite intellicrack/main.py with the test script
    test_main_py_content = r"""
import os
import sys
import time

def main():
    print("[Python Script] Starting execution.", file=sys.stderr)
    results = []

    print("[Python Script] Checking environment variables...", file=sys.stderr)
    expected_env_vars = {
        "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF": "1",
        "OMP_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
        "BLIS_NUM_THREADS": "1",
        "PYTORCH_DISABLE_CUDNN_BATCH_NORM": "1",
        "CUDA_LAUNCH_BLOCKING": "1",
    }

    for var, expected_value in expected_env_vars.items():
        if os.getenv(var) == expected_value:
            results.append(f"SUCCESS: {var} is set correctly.")
        else:
            results.append(f"FAILURE: {var} is not set or has the wrong value.")
    print("[Python Script] Finished checking environment variables.", file=sys.stderr)

    # Check for _tkinter initialization
    # print("[Python Script] Checking tkinter initialization...", file=sys.stderr)
    # try:
    #     import tkinter
    #     root = tkinter.Tk()
    #     root.withdraw()
    #     root.destroy()
    #     results.append("SUCCESS: _tkinter initialized successfully.")
    # except Exception as e:
    #     results.append(f"FAILURE: _tkinter initialization failed: {e}")
    # print("[Python Script] Finished checking tkinter.", file=sys.stderr)

    print("[Python Script] Writing output file...", file=sys.stderr)
    with open("rust_launch_test_output.txt", "w") as f:
        f.write("
".join(results))
    print("[Python Script] Finished writing output file.", file=sys.stderr)

    # If any failures, return 1
    if any("FAILURE" in result for result in results):
        print("[Python Script] Failures detected. Exiting with code 1.", file=sys.stderr)
        return 1
    else:
        print("[Python Script] All checks passed. Exiting with code 0.", file=sys.stderr)
        return 0

if __name__ == "__main__":
    print("[Python Script] __main__ block started.", file=sys.stderr)
    sys.exit(main())
"""
    with open(main_py_path, 'w') as f:
        f.write(test_main_py_content)

    yield

    # Restore original main.py content
    with open(main_py_path, 'w') as f:
        f.write(original_main_py_content)

    # Clean up the output file
    if os.path.exists("rust_launch_test_output.txt"):
        os.remove("rust_launch_test_output.txt")

def test_full_rust_launch(setup_test_environment):
    # 1. Check for the absence of launch_intellicrack.py
    launch_script_path = os.path.join(os.path.dirname(__file__), '..', 'launch_intellicrack.py')
    assert not os.path.exists(launch_script_path), "launch_intellicrack.py should not exist in a full Rust launch implementation."

    # 2. Set the environment variable for the test itself
    env = os.environ.copy()
    env["FULL_RUST_LAUNCH_TEST"] = "1"

    # 3. Run the launcher
    launcher_path = os.path.join(os.path.dirname(__file__), '..', 'intellicrack-launcher', 'target', 'release', 'Intellicrack.exe')
    print(f"\n[PyTest] Running launcher: {launcher_path}")
    try:
        result = subprocess.run([launcher_path], env=env, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as e:
        pytest.fail(f"Launcher process timed out after 60 seconds. stdout:\n{e.stdout}\nstderr:\n{e.stderr}")
    
    print("[PyTest] Launcher process finished.")
    print(f"[PyTest] stdout:\n{result.stdout}")
    print(f"[PyTest] stderr:\n{result.stderr}")


    # 4. Check the result of the launch
    assert result.returncode == 0, f"Launcher returned a non-zero exit code: {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"

    # 5. Read the output file and assert its contents
    assert os.path.exists("rust_launch_test_output.txt"), "Output file was not created."
    with open("rust_launch_test_output.txt", 'r') as f:
        output_content = f.read()
    
    print(f"Test output file content:\n{output_content}")
    assert "FAILURE" not in output_content, f"One or more validation checks failed.\n{output_content}"