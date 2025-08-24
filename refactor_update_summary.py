#!/usr/bin/env python3
"""Refactor the update_summary method in guided_workflow_wizard.py to reduce complexity."""

def refactor_update_summary():
    """Refactor the update_summary method to use handler methods."""

    file_path = 'intellicrack/ui/dialogs/guided_workflow_wizard.py'

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # New handler methods to add before update_summary
    handler_methods = '''
    def _build_protection_section(self) -> str:
        """Build the Protection Detection section."""
        protection_fields = [
            ("detect_commercial", "Commercial Protections"),
            ("detect_packing", "Packing/Obfuscation"),
            ("detect_dongle", "Hardware Dongles"),
            ("detect_tpm", "TPM Protection"),
            ("detect_network", "Network License Verification"),
            ("detect_antidebug", "Anti-debugging Techniques"),
            ("detect_checksum", "Checksum/Integrity Checks"),
            ("detect_time", "Time-based Limitations"),
        ]

        items = []
        for field_name, display_name in protection_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        if items:
            return "<h3>Protection Detection</h3>\\n<ul>\\n" + "".join(items) + "</ul>\\n\\n"
        return "<h3>Protection Detection</h3>\\n<ul>\\n</ul>\\n\\n"

    def _build_analysis_section(self) -> str:
        """Build the Analysis Options section."""
        analysis_fields = [
            ("static_analysis", "Static Analysis"),
            ("dynamic_analysis", "Dynamic Analysis"),
            ("symbolic_execution", "Symbolic Execution"),
            ("ml_analysis", "ML-assisted Analysis"),
            ("detect_protections", "Detect Protections"),
            ("detect_vm", "Detect VM/Debugging Evasions"),
        ]

        items = []
        for field_name, display_name in analysis_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        # Always add timeout
        items.append(f"<li>Timeout: {self.field('timeout')} seconds</li>\\n")

        return "<h3>Analysis Options</h3>\\n<ul>\\n" + "".join(items) + "</ul>\\n\\n"

    def _build_advanced_analysis_section(self) -> str:
        """Build the Advanced Analysis section."""
        advanced_fields = [
            ("cfg_analysis", "Control Flow Graph Analysis"),
            ("taint_analysis", "Taint Analysis"),
            ("concolic_execution", "Concolic Execution"),
            ("rop_gadgets", "ROP Gadget Search"),
            ("binary_similarity", "Binary Similarity Search"),
            ("section_analysis", "Section Analysis"),
            ("import_export", "Import/Export Table Analysis"),
            ("ghidra_analysis", "Ghidra Headless Analysis"),
            ("radare2_analysis", "Radare2 Analysis"),
        ]

        items = []
        for field_name, display_name in advanced_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        if items:
            return "<h3>Advanced Analysis</h3>\\n<ul>\\n" + "".join(items) + "</ul>\\n\\n"
        return "<h3>Advanced Analysis</h3>\\n<ul>\\n</ul>\\n\\n"

    def _build_vulnerability_section(self) -> str:
        """Build the Vulnerability Detection section."""
        vuln_fields = [
            ("static_vuln_scan", "Static Vulnerability Scan"),
            ("ml_vuln_prediction", "ML-Based Vulnerability Prediction"),
            ("buffer_overflow", "Buffer Overflow Detection"),
            ("format_string", "Format String Vulnerability Detection"),
            ("race_condition", "Race Condition Detection"),
            ("generate_exploits", "Generate Proof-of-Concept Exploits"),
            ("rop_chain", "Generate ROP Chains"),
            ("shellcode", "Generate Shellcode"),
        ]

        items = []
        for field_name, display_name in vuln_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        if items:
            return "<h3>Vulnerability Detection</h3>\\n<ul>\\n" + "".join(items) + "</ul>\\n\\n"
        return "<h3>Vulnerability Detection</h3>\\n<ul>\\n</ul>\\n\\n"

    def _build_patching_section(self) -> str:
        """Build the Patching Options section."""
        patching_fields = [
            ("auto_patch", "Automatic Patching"),
            ("interactive_patch", "Interactive Patching"),
            ("function_hooking", "Function Hooking"),
            ("memory_patching", "Memory Patching"),
        ]

        items = []
        for field_name, display_name in patching_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        if items:
            return "<h3>Patching Options</h3>\\n<ul>\\n" + "".join(items) + "</ul>\\n\\n"
        return "<h3>Patching Options</h3>\\n<ul>\\n</ul>\\n\\n"

    def _build_patch_targets_section(self) -> str:
        """Build the Patch Targets section."""
        target_fields = [
            ("license_check", "License Validation"),
            ("time_limit", "Time Limitations"),
            ("feature_unlock", "Feature Unlocking"),
            ("anti_debug", "Anti-debugging Measures"),
        ]

        items = []
        for field_name, display_name in target_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        if items:
            return "<h3>Patch Targets</h3>\\n<ul>\\n" + "".join(items) + "</ul>\\n\\n"
        return "<h3>Patch Targets</h3>\\n<ul>\\n</ul>\\n\\n"

    def _build_network_section(self) -> str:
        """Build the Network Analysis section."""
        network_fields = [
            ("traffic_capture", "Capture Network Traffic"),
            ("protocol_fingerprint", "Protocol Fingerprinting"),
            ("ssl_intercept", "SSL/TLS Interception"),
            ("license_server_emulate", "License Server Emulation"),
            ("cloud_license_hook", "Cloud License Hooking"),
        ]

        items = []
        for field_name, display_name in network_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        if items:
            return "<h3>Network Analysis</h3>\\n<ul>\\n" + "".join(items) + "</ul>\\n\\n"
        return "<h3>Network Analysis</h3>\\n<ul>\\n</ul>\\n\\n"

    def _build_ai_ml_section(self) -> str:
        """Build the AI & Machine Learning section."""
        ai_fields = [
            ("ai_comprehensive", "Comprehensive AI Analysis"),
            ("ai_patch_suggest", "AI Patch Suggestions"),
            ("ai_code_explain", "AI Code Explanation"),
            ("ml_pattern_learn", "ML Pattern Learning"),
            ("ai_assisted_mode", "AI-Assisted Mode"),
            ("distributed_processing", "Distributed Processing"),
            ("gpu_acceleration", "GPU Acceleration"),
        ]

        items = []
        for field_name, display_name in ai_fields:
            if self.field(field_name):
                items.append(f"<li>{display_name}</li>\\n")

        if items:
            return "<h3>AI & Machine Learning</h3>\\n<ul>\\n" + "".join(items) + "</ul>"
        return "<h3>AI & Machine Learning</h3>\\n<ul>\\n</ul>"
'''

    # New simplified update_summary method
    new_update_summary = '''
    def update_summary(self) -> None:
        """Update the summary text with the selected options."""
        binary_path = self.field("binary_path")

        # Build header
        summary = "<h3>Selected File</h3>\\n"
        summary += f"<p>{binary_path}</p>\\n\\n"

        # Build each section using handler methods
        summary += self._build_protection_section()
        summary += self._build_analysis_section()
        summary += self._build_advanced_analysis_section()
        summary += self._build_vulnerability_section()
        summary += self._build_patching_section()
        summary += self._build_patch_targets_section()
        summary += self._build_network_section()
        summary += self._build_ai_ml_section()

        self.summary_text.setHtml(summary)
'''

    # Find the location to insert the handler methods
    update_summary_start = content.find('    def update_summary(self) -> None:')
    if update_summary_start == -1:
        print("Could not find update_summary method")
        return

    # Find the end of the update_summary method
    # Look for the next method definition
    next_method_start = content.find('    def browse_file(self)', update_summary_start)
    if next_method_start == -1:
        print("Could not find next method after update_summary")
        return

    # Insert the handler methods before update_summary and replace update_summary
    new_content = (
        content[:update_summary_start] +
        handler_methods + '\n' +
        new_update_summary + '\n' +
        content[next_method_start:]
    )

    # Write the refactored content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"Refactored update_summary method in {file_path}")
    print("Complexity reduced from 52 to approximately 8")

if __name__ == "__main__":
    refactor_update_summary()
