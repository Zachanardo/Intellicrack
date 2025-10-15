import os
import sys


def clean_nul_files():
    """Recursively finds and deletes files named 'nul' in the current working directory.
    This is necessary because some Windows build tools can erroneously create these files,
    and standard command-line tools fail to delete them due to 'nul' being a reserved name.
    """
    print("--- Python NUL File Cleaner ---")
    # The batch script ensures this script is run from the project root.
    root_dir = os.getcwd()
    print(f"Starting recursive search in: {root_dir}")
    files_deleted = 0

    try:
        for dirpath, _, filenames in os.walk(root_dir):
            if "nul" in filenames:
                nul_path = os.path.join(dirpath, "nul")
                # On Windows, prepend \\?\ to the path to handle reserved names.
                prefixed_path = "\\\\?\\" + nul_path

                try:
                    os.remove(prefixed_path)
                    print(f"  [OK] Deleted: {nul_path}")
                    files_deleted += 1
                except OSError as e:
                    print(f"  [!!!] FAILED to delete: {nul_path}. Reason: {e}")
    except Exception as e:
        print(f"[!!!] The script failed with an unexpected error: {e}")
        sys.exit(1)

    print(f"\nScan complete. {files_deleted} file(s) deleted.")
    sys.exit(0)


if __name__ == "__main__":
    clean_nul_files()
