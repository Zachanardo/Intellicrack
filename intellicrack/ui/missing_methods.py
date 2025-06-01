# Missing methods for IntellicrackApp - to be integrated into main_app.py

def generate_exploit_strategy(self):
    """Generate an exploit strategy based on found vulnerabilities."""
    if not self.binary_path:
        QMessageBox.warning(self, "No File Selected",
                            "Please select a program first.")
        return

    self.update_output.emit(log_message(
        "[Exploit Strategy] Generating exploitation strategy..."))

    try:
        from ..utils.exploitation import generate_exploit_strategy
        
        # Use buffer overflow as default vulnerability type
        strategy = generate_exploit_strategy(self.binary_path, "buffer_overflow")
        
        if "error" in strategy:
            self.update_output.emit(log_message(
                f"[Exploit Strategy] Error: {strategy['error']}"))
        else:
            self.update_output.emit(log_message(
                "[Exploit Strategy] Strategy generated successfully"))
            
            # Display strategy details
            if "strategy" in strategy and "steps" in strategy["strategy"]:
                self.update_output.emit(log_message(
                    "[Exploit Strategy] Exploitation steps:"))
                for i, step in enumerate(strategy["strategy"]["steps"], 1):
                    self.update_output.emit(log_message(
                        f"[Exploit Strategy] {i}. {step}"))
            
            if "automation_script" in strategy:
                self.update_output.emit(log_message(
                    "[Exploit Strategy] Automation script generated"))
            
    except Exception as e:
        self.update_output.emit(log_message(
            f"[Exploit Strategy] Error: {e}"))

def generate_exploit_payload(self, payload_type):
    """Generate an exploit payload of the specified type."""
    if not self.binary_path:
        QMessageBox.warning(self, "No File Selected",
                            "Please select a program first.")
        return

    self.update_output.emit(log_message(
        f"[Payload Generator] Generating {payload_type} payload..."))

    try:
        from ..utils.exploitation import generate_license_bypass_payload, generate_exploit
        from ..core.patching.payload_generator import generate_advanced_payload
        
        if payload_type == "License Bypass":
            payload_result = generate_license_bypass_payload("target_software", "patch")
        elif payload_type == "Function Hijack":
            strategy = {"strategy": "function_hijacking", "target": "license_check"}
            payload_bytes = generate_advanced_payload(strategy)
            payload_result = {
                "method": "function_hijacking",
                "payload_bytes": payload_bytes.hex() if payload_bytes else "Generation failed",
                "description": "Function hijacking payload for license bypass"
            }
        elif payload_type == "Buffer Overflow":
            payload_result = generate_exploit("buffer_overflow", "x86", "shellcode")
        else:
            payload_result = {"error": f"Unknown payload type: {payload_type}"}
        
        if "error" in payload_result:
            self.update_output.emit(log_message(
                f"[Payload Generator] Error: {payload_result['error']}"))
        else:
            self.update_output.emit(log_message(
                f"[Payload Generator] {payload_type} payload generated successfully"))
            
            # Display payload details
            if "description" in payload_result:
                self.update_output.emit(log_message(
                    f"[Payload Generator] Description: {payload_result['description']}"))
            
            if "payload_bytes" in payload_result:
                self.update_output.emit(log_message(
                    f"[Payload Generator] Payload bytes: {payload_result['payload_bytes'][:100]}..."))
            
    except Exception as e:
        self.update_output.emit(log_message(
            f"[Payload Generator] Error: {e}"))