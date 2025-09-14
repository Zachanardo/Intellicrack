"""Enhanced Protection Scanner.

This module provides functionality to scan for various software protections
like packers, anti-debugging techniques, and virtualization detection.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os
from threading import Thread

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine


def run_scan_thread(main_app, binary_path):
    """The actual scanning logic that runs in a separate thread."""
    try:
        main_app.update_output.emit(f"[Protection Scanner] Starting enhanced scan on {os.path.basename(binary_path)}...")

        results = {"packers": [], "anti_debug": [], "virtualization": [], "other_detections": []}

        # 1. Use Yara Engine for signature-based detection
        try:
            yara_engine = YaraPatternEngine()
            # A real implementation would ensure rules are loaded. Assuming they are for now.
            yara_results = yara_engine.scan_file(binary_path)
            if yara_results and yara_results.matches:
                main_app.update_output.emit(f"[Protection Scanner] Yara found {len(yara_results.matches)} potential matches.")
                for match in yara_results.matches:
                    results["other_detections"].append(f"Yara rule match: {match.rule_name}")
        except Exception as e:
            main_app.update_output.emit(f"[Protection Scanner] Yara analysis failed: {e}")

        # 2. Use Binary Analyzer to inspect sections and imports
        try:
            binary_analyzer = BinaryAnalyzer()
            analysis = binary_analyzer.analyze(binary_path)

            # Check for common packer section names
            packer_sections = [".upx", ".aspack", ".themida", ".vmp", ".petite", ".neolite"]
            if "sections" in analysis:
                for section in analysis["sections"]:
                    section_name = section.get("name", "").lower()
                    for packer_section in packer_sections:
                        if packer_section in section_name:
                            results["packers"].append(f"Suspicious section name found: {section.get('name')}")

            # Check for common anti-debug imports
            anti_debug_imports = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString", "NtQueryInformationProcess"]
            if "imports" in analysis:
                for imp in analysis["imports"]:
                    if imp in anti_debug_imports:
                        results["anti_debug"].append(f"Potential anti-debug API found: {imp}")
        except Exception as e:
            main_app.update_output.emit(f"[Protection Scanner] Binary analysis failed: {e}")

        # Report findings
        main_app.update_output.emit("[Protection Scanner] Scan complete.")
        main_app.update_analysis_results.emit(json.dumps(results, indent=2))

    except Exception as e:
        main_app.update_output.emit(f"[Protection Scanner] A critical error occurred: {e}")
    finally:
        if hasattr(main_app, "analysis_completed"):
            main_app.analysis_completed.emit("Enhanced Protection Scan")


def run_enhanced_protection_scan(main_app):
    """Runs an enhanced scan for software protections on the target binary."""
    if not main_app.current_binary:
        main_app.update_output.emit("[Protection Scanner] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary

    thread = Thread(target=run_scan_thread, args=(main_app, binary_path), daemon=True)
    thread.start()
    main_app.update_output.emit("[Protection Scanner] Protection scan task submitted.")
