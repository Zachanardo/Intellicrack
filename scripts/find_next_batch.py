"""Find the next 10 largest untested Python files for Batch 7."""

import os
from pathlib import Path
from typing import List, Tuple

# Known tested files from Batches 1-6
TESTED_FILES = {
    # Batch 6 (files 45-54)
    "intellicrack/ui/hexview/hex_widget.py",
    "intellicrack/core/analysis/radare2_vulnerability_engine.py",
    "intellicrack/plugins/plugin_system.py",
    "intellicrack/core/vulnerability_research/research_manager.py",
    "intellicrack/core/hardware_spoofer.py",
    "intellicrack/core/offline_activation_emulator.py",
    "intellicrack/core/analysis/concolic_executor.py",
    "intellicrack/protection/icp_backend.py",
    "intellicrack/core/network/protocols/hasp_parser.py",
    "intellicrack/ui/distributed_processing.py",
    # Batch 5 (files 35-44)
    "intellicrack/core/debugging_engine.py",
    "intellicrack/ai/protection_aware_script_gen.py",
    "intellicrack/utils/exploitation/exploitation.py",
    "intellicrack/core/frida_manager.py",
    "intellicrack/ui/dialogs/ai_coding_assistant_dialog.py",
    "intellicrack/core/analysis/symbolic_executor.py",
    "intellicrack/ai/multi_agent_system.py",
    "intellicrack/ui/dialogs/model_finetuning_dialog.py",
    "intellicrack/ui/tabs/analysis_tab.py",
    "intellicrack/plugins/custom_modules/intellicrack_core_engine.py",
    # Batch 4 (files 25-34)
    "intellicrack/utils/core/internal_helpers.py",
    "intellicrack/core/process_manipulation.py",
    "intellicrack/utils/runtime/runner_functions.py",
    "intellicrack/ai/model_manager_module.py",
    "intellicrack/ai/script_generation_agent.py",
    "intellicrack/core/vulnerability_research/fuzzing_engine.py",
    "intellicrack/plugins/custom_modules/anti_anti_debug_suite.py",
    "intellicrack/ui/dialogs/frida_manager_dialog.py",
    "intellicrack/core/patching/license_check_remover.py",
    "intellicrack/utils/tools/tool_wrappers.py",
    # Batch 3 (files 11-20)
    "intellicrack/utils/runtime/additional_runners.py",
    "intellicrack/ai/llm_backends.py",
    "intellicrack/core/exploitation/crypto_key_extractor.py",
    "intellicrack/core/processing/qemu_emulator.py",
    "intellicrack/cli/cli.py",
    "intellicrack/ui/tabs/exploitation_tab.py",
    "intellicrack/utils/core/final_utilities.py",
    "intellicrack/ui/dialogs/plugin_manager_dialog.py",
    "intellicrack/ui/tabs/tools_tab.py",
    "intellicrack/ai/enhanced_training_interface.py",
}


def find_python_files(root_dir: Path) -> List[Tuple[Path, int]]:
    """Find all Python files with their sizes."""
    python_files = []

    for py_file in root_dir.rglob("*.py"):
        # Skip test files
        if "/tests/" in str(py_file) or "\\tests\\" in str(py_file):
            continue
        # Skip __init__.py files
        if py_file.name == "__init__.py":
            continue
        # Skip __pycache__
        if "__pycache__" in str(py_file):
            continue
        # Skip .pixi directory
        if "/.pixi/" in str(py_file) or "\\.pixi\\" in str(py_file):
            continue
        # Skip .venv directory
        if "/.venv/" in str(py_file) or "\\.venv\\" in str(py_file):
            continue
        # Skip node_modules
        if "/node_modules/" in str(py_file) or "\\node_modules\\" in str(py_file):
            continue

        try:
            size = py_file.stat().st_size
            python_files.append((py_file, size))
        except Exception:
            continue

    return python_files


def main() -> None:
    """Find next 10 largest untested files."""
    root = Path("D:/Intellicrack")

    # Find all Python files
    all_files = find_python_files(root)

    # Sort by size (largest first)
    all_files.sort(key=lambda x: x[1], reverse=True)

    # Filter out tested files and non-intellicrack files
    untested_files = []
    for file_path, size in all_files:
        rel_path = str(file_path.relative_to(root)).replace("\\", "/")
        # Only include files in the intellicrack/ directory
        if not rel_path.startswith("intellicrack/"):
            continue
        if rel_path not in TESTED_FILES:
            untested_files.append((rel_path, size))

    # Get next 10
    print("=" * 80)
    print("BATCH 7 - Next 10 Largest Untested Files (Files 55-64)")
    print("=" * 80)
    print()

    for i, (file_path, size) in enumerate(untested_files[:10], start=55):
        lines = count_lines(Path("D:/Intellicrack") / file_path)
        print(f"{i}. {file_path}")
        print(f"   Size: {size:,} bytes ({lines:,} lines)")
        print()


def count_lines(file_path: Path) -> int:
    """Count lines in a file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


if __name__ == "__main__":
    main()
