
import os
import sys

def main():
    results = []

    # Check for environment variables
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

    # Check for _tkinter initialization
    try:
        import tkinter
        root = tkinter.Tk()
        root.withdraw()
        root.destroy()
        results.append("_tkinter initialized successfully.")
    except Exception as e:
        results.append(f"_tkinter initialization failed: {e}")

    with open("rust_launch_test_output.txt", "w") as f:
        f.write("\n".join(results))

    # If any failures, return 1
    if any("FAILURE" in result for result in results):
        return 1
    else:
        return 0

if __name__ == "__main__":
    sys.exit(main())
