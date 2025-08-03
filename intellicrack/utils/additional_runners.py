"""Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

# Import all functions from the runtime additional_runners module
from .runtime.additional_runners import (
    check_adobe_licensex_status,
    compute_file_hash,
    create_sample_plugins,
    detect_hardware_dongles,
    detect_local_tpm_protection,
    get_target_process_pid,
    load_ai_model,
    run_adobe_licensex_manually,
    run_analysis,
    run_autonomous_crack,
    run_cfg_analysis,
    run_comprehensive_analysis,
    run_deep_cfg_analysis,
    run_deep_license_analysis,
    run_detect_packing,
    run_external_command,
    run_external_tool,
    run_full_autonomous_mode,
    run_generate_patch_suggestions,
    run_ghidra_analysis_gui,
    run_import_export_analysis,
    run_incremental_analysis_ui,
    run_local_protection_scan,
    run_ml_similarity_search,
    run_ml_vulnerability_prediction,
    run_multi_format_analysis,
    run_rop_gadget_finder,
    run_section_analysis,
    run_vulnerability_scan,
    run_weak_crypto_detection,
    run_windows_activator,
    validate_dataset,
    verify_hash,
)

__all__ = [
    "check_adobe_licensex_status",
    "compute_file_hash",
    "create_sample_plugins",
    "detect_hardware_dongles",
    "detect_local_tpm_protection",
    "get_target_process_pid",
    "load_ai_model",
    "run_adobe_licensex_manually",
    "run_analysis",
    "run_autonomous_crack",
    "run_cfg_analysis",
    "run_comprehensive_analysis",
    "run_deep_cfg_analysis",
    "run_deep_license_analysis",
    "run_detect_packing",
    "run_external_command",
    "run_external_tool",
    "run_full_autonomous_mode",
    "run_generate_patch_suggestions",
    "run_ghidra_analysis_gui",
    "run_import_export_analysis",
    "run_incremental_analysis_ui",
    "run_local_protection_scan",
    "run_ml_similarity_search",
    "run_ml_vulnerability_prediction",
    "run_multi_format_analysis",
    "run_rop_gadget_finder",
    "run_section_analysis",
    "run_vulnerability_scan",
    "run_weak_crypto_detection",
    "run_windows_activator",
    "validate_dataset",
    "verify_hash",
]
