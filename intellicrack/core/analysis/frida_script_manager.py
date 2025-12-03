"""Frida Script Manager - Production Implementation.

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import frida


logger = logging.getLogger(__name__)


class ScriptCategory(Enum):
    """Categories for Frida scripts."""

    PROTECTION_BYPASS = "protection_bypass"
    MEMORY_ANALYSIS = "memory_analysis"
    NETWORK_INTERCEPTION = "network_interception"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    REGISTRY_MONITORING = "registry_monitoring"
    CRYPTO_DETECTION = "crypto_detection"
    LICENSE_BYPASS = "license_bypass"
    ANTI_DEBUG = "anti_debug"
    UNPACKING = "unpacking"
    PATCHING = "patching"


@dataclass
class FridaScriptConfig:
    """Configuration for a Frida script."""

    name: str
    path: Path
    category: ScriptCategory
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    requires_admin: bool = False
    supports_spawn: bool = True
    supports_attach: bool = True
    output_handlers: dict[str, Callable[[dict[str, Any]], None]] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)


@dataclass
class ScriptResult:
    """Result from Frida script execution."""

    script_name: str
    success: bool
    start_time: float
    end_time: float
    messages: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    memory_dumps: list[bytes] = field(default_factory=list)
    patches: list[dict[str, Any]] = field(default_factory=list)


class FridaScriptManager:
    """Manages Frida script execution and results."""

    def __init__(self, scripts_dir: Path) -> None:
        """Initialize the FridaScriptManager with a directory containing scripts.

        Args:
            scripts_dir: Path to the directory containing Frida scripts.

        """
        self.scripts_dir = scripts_dir
        self.scripts: dict[str, FridaScriptConfig] = {}
        self.active_sessions: dict[str, frida.core.Session] = {}
        self.results: dict[str, ScriptResult] = {}
        self._load_script_configs()

    def _generate_mac_address(self) -> str:
        """Generate a realistic MAC address for hardware ID spoofing.

        Returns:
            A valid MAC address string in standard format (XX:XX:XX:XX:XX:XX)
            with real OUI prefixes from known vendors.

        """
        oui_prefixes = [
            "00:1B:44",  # Cisco
            "00:50:56",  # VMware
            "08:00:27",  # VirtualBox
            "00:15:5D",  # Hyper-V
            "52:54:00",  # QEMU
            "00:0C:29",  # VMware
            "00:25:90",  # Dell
            "00:1C:42",  # Parallels
        ]
        prefix = secrets.choice(oui_prefixes)
        suffix = ":".join([f"{secrets.randbelow(256):02X}" for _ in range(3)])
        return f"{prefix}:{suffix}"

    def _generate_disk_serial(self) -> str:
        """Generate a realistic disk serial number for hardware ID spoofing.

        Returns:
            A formatted disk serial string mimicking real disk manufacturer formats
            (e.g., WD-1234-ABCDEF12).

        """
        prefixes = ["WD", "ST", "HGST", "TOSHIBA", "SAMSUNG", "INTEL"]
        prefix = secrets.choice(prefixes)
        serial_parts = [
            prefix,
            f"{secrets.randbelow(9000) + 1000}",
            "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(8)),
        ]
        return "-".join(serial_parts)

    def _generate_motherboard_id(self) -> str:
        """Generate a realistic motherboard ID for hardware ID spoofing.

        Returns:
            A formatted motherboard identifier string combining manufacturer,
            model series, chipset, and serial (e.g., ASUS-PRIME-Z790-A1B2C3D4E5F6).

        """
        manufacturers = ["ASUS", "MSI", "GIGABYTE", "ASROCK", "BIOSTAR", "EVGA"]
        models = ["PRIME", "ROG", "TUF", "GAMING", "PRO", "MASTER"]
        chipsets = ["Z790", "B760", "H610", "X670", "B650", "A620"]

        manufacturer = secrets.choice(manufacturers)
        model = secrets.choice(models)
        chipset = secrets.choice(chipsets)
        serial = "".join(secrets.choice("0123456789ABCDEF") for _ in range(12))

        return f"{manufacturer}-{model}-{chipset}-{serial}"

    def _generate_cpu_id(self) -> str:
        """Generate a realistic CPU ID for hardware ID spoofing.

        Returns:
            A formatted CPU identifier string combining brand, family, model,
            and a hash-based serial (e.g., Intel-Core-i9-13900K-A1B2C3D4E5F6G7H8).

        """
        cpu_families = [
            ("Intel", "Core-i9", "13900K"),
            ("Intel", "Core-i7", "13700K"),
            ("Intel", "Core-i5", "13600K"),
            ("AMD", "Ryzen-9", "7950X"),
            ("AMD", "Ryzen-7", "7700X"),
            ("AMD", "Ryzen-5", "7600X"),
        ]

        brand, family, model = secrets.choice(cpu_families)
        cpuid_hash = hashlib.sha256(f"{brand}{family}{model}{secrets.token_hex(8)}".encode()).hexdigest()[:16].upper()

        return f"{brand}-{family}-{model}-{cpuid_hash}"

    def _load_script_configs(self) -> None:
        """Load all script configurations."""
        # Define production script configurations
        script_configs = {
            "memory_dumper.js": FridaScriptConfig(
                name="Memory Dumper",
                path=self.scripts_dir / "memory_dumper.js",
                category=ScriptCategory.MEMORY_ANALYSIS,
                description="Dumps process memory regions for analysis",
                parameters={
                    "dump_executable": True,
                    "dump_heap": True,
                    "dump_stack": False,
                    "output_format": "binary",
                    "compress": True,
                },
            ),
            "anti_debugger.js": FridaScriptConfig(
                name="Anti-Debug Bypass",
                path=self.scripts_dir / "anti_debugger.js",
                category=ScriptCategory.ANTI_DEBUG,
                description="Bypasses common anti-debugging techniques",
                parameters={
                    "bypass_isdebuggerpresent": True,
                    "bypass_checkremotedebuggerpresent": True,
                    "bypass_ntqueryinformationprocess": True,
                    "bypass_peb_checks": True,
                    "bypass_timing_checks": True,
                },
            ),
            "certificate_pinning_bypass.js": FridaScriptConfig(
                name="Certificate Pinning Bypass",
                path=self.scripts_dir / "certificate_pinning_bypass.js",
                category=ScriptCategory.NETWORK_INTERCEPTION,
                description="Bypasses SSL certificate pinning",
                parameters={
                    "bypass_android": True,
                    "bypass_ios": True,
                    "bypass_okhttp": True,
                    "bypass_trustmanager": True,
                    "log_certificates": True,
                },
            ),
            "hwid_spoofer.js": FridaScriptConfig(
                name="Hardware ID Spoofer",
                path=self.scripts_dir / "hwid_spoofer.js",
                category=ScriptCategory.LICENSE_BYPASS,
                description="Spoofs hardware identifiers",
                parameters={
                    "spoof_mac": self._generate_mac_address(),
                    "spoof_disk_serial": self._generate_disk_serial(),
                    "spoof_motherboard": self._generate_motherboard_id(),
                    "spoof_cpu_id": self._generate_cpu_id(),
                    "randomize": True,
                },
            ),
            "registry_monitor.js": FridaScriptConfig(
                name="Registry Monitor",
                path=self.scripts_dir / "registry_monitor.js",
                category=ScriptCategory.REGISTRY_MONITORING,
                description="Monitors Windows registry operations",
                parameters={
                    "monitor_reads": True,
                    "monitor_writes": True,
                    "monitor_deletes": True,
                    "filter_keys": [],
                    "log_values": True,
                },
            ),
            "telemetry_blocker.js": FridaScriptConfig(
                name="Telemetry Blocker",
                path=self.scripts_dir / "telemetry_blocker.js",
                category=ScriptCategory.NETWORK_INTERCEPTION,
                description="Blocks telemetry and analytics",
                parameters={
                    "block_domains": [],
                    "block_ips": [],
                    "block_user_agents": [],
                    "generate_spoofed_responses": True,
                },
            ),
            "time_bomb_defuser.js": FridaScriptConfig(
                name="Time Bomb Defuser",
                path=self.scripts_dir / "time_bomb_defuser.js",
                category=ScriptCategory.LICENSE_BYPASS,
                description="Bypasses time-based protection",
                parameters={
                    "freeze_time": None,
                    "accelerate_time": 1.0,
                    "bypass_expiry_checks": True,
                    "spoof_system_time": None,
                },
            ),
            "behavioral_pattern_analyzer.js": FridaScriptConfig(
                name="Behavioral Pattern Analyzer",
                path=self.scripts_dir / "behavioral_pattern_analyzer.js",
                category=ScriptCategory.BEHAVIORAL_ANALYSIS,
                description="Analyzes program behavior patterns",
                parameters={
                    "track_api_calls": True,
                    "track_file_operations": True,
                    "track_network": True,
                    "pattern_detection": True,
                    "ml_analysis": False,
                },
            ),
            "universal_unpacker.js": FridaScriptConfig(
                name="Universal Unpacker",
                path=self.scripts_dir / "universal_unpacker.js",
                category=ScriptCategory.UNPACKING,
                description="Unpacks protected executables",
                parameters={
                    "detect_packer": True,
                    "dump_at_oep": True,
                    "fix_imports": True,
                    "rebuild_iat": True,
                    "remove_overlays": False,
                },
            ),
            "keygen_generator.js": FridaScriptConfig(
                name="Keygen Generator",
                path=self.scripts_dir / "keygen_generator.js",
                category=ScriptCategory.LICENSE_BYPASS,
                description="Generates valid license keys",
                parameters={
                    "analyze_validation": True,
                    "extract_algorithm": True,
                    "generate_keys": 10,
                    "test_keys": True,
                    "export_keygen": True,
                },
            ),
        }

        # Load configurations
        for script_name, config in script_configs.items():
            if config.path.exists():
                self.scripts[script_name] = config
                logger.info(f"Loaded script: {script_name}")

        # Load custom script configurations from metadata
        self._load_custom_scripts()

    def _load_custom_scripts(self) -> None:
        """Load custom scripts not in the predefined list."""
        for script_file in self.scripts_dir.glob("*.js"):
            if script_file.name not in self.scripts:
                if metadata := self._parse_script_metadata(script_file):
                    config = FridaScriptConfig(
                        name=metadata.get("name", script_file.stem),
                        path=script_file,
                        category=ScriptCategory(metadata.get("category", "behavioral_analysis")),
                        description=metadata.get("description", "Custom script"),
                        parameters=metadata.get("parameters", {}),
                    )
                    self.scripts[script_file.name] = config

    def _parse_script_metadata(self, script_path: Path) -> dict[str, Any] | None:
        """Parse metadata from script header."""
        try:
            with open(script_path, encoding="utf-8") as f:
                content = f.read()

            # Look for metadata in comments
            import re

            if metadata_match := re.search(r"/\*\*\s*@metadata(.*?)@end\s*\*/", content, re.DOTALL):
                metadata_text = metadata_match.group(1)
                if json_match := re.search(r"\{.*\}", metadata_text, re.DOTALL):
                    parsed: dict[str, Any] = json.loads(json_match.group())
                    return parsed

            return None

        except Exception as e:
            logger.warning(f"Failed to parse metadata from {script_path}: {e}")
            return None

    def execute_script(
        self,
        script_name: str,
        target: str,
        mode: str = "spawn",
        parameters: dict[str, Any] | None = None,
        output_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> ScriptResult:
        """Execute a Frida script.

        Args:
            script_name: Name of the script to execute
            target: Target process (path for spawn, pid/name for attach)
            mode: "spawn" or "attach"
            parameters: Script parameters to override defaults
            output_callback: Callback for real-time output

        Returns:
            ScriptResult with execution details

        """
        if script_name not in self.scripts:
            raise ValueError(f"Unknown script: {script_name}")

        config = self.scripts[script_name]
        result = ScriptResult(script_name=script_name, success=False, start_time=time.time(), end_time=0)

        try:
            # Load script content
            with open(config.path, encoding="utf-8") as f:
                script_content = f.read()

            # Inject parameters
            if parameters:
                merged_params = {**config.parameters, **parameters}
            else:
                merged_params = config.parameters

            # Create parameter injection code
            param_injection = self._create_parameter_injection(merged_params)
            script_content = param_injection + "\n" + script_content

            # Get Frida device
            device = frida.get_local_device()

            # Create session based on mode
            if mode == "spawn":
                if not config.supports_spawn:
                    raise ValueError(f"Script {script_name} does not support spawn mode")

                pid = device.spawn([target])
                session = device.attach(pid)
                device.resume(pid)

            else:  # attach mode
                if not config.supports_attach:
                    raise ValueError(f"Script {script_name} does not support attach mode")

                # Try to attach by PID or name
                try:
                    pid = int(target)
                    session = device.attach(pid)
                except ValueError:
                    session = device.attach(target)

            # Store session
            session_id = f"{script_name}_{target}_{time.time()}"
            self.active_sessions[session_id] = session

            # Create and load script
            script = session.create_script(script_content)

            # Set up message handler
            def on_message(message: dict[str, Any], data: bytes | None) -> None:
                self._handle_message(result, message, data, output_callback)

            script.on("message", on_message)
            script.load()

            # Wait for script to complete or timeout
            timeout = merged_params.get("timeout", 60)
            start = time.time()

            while not session.is_detached and (time.time() - start) < timeout:
                time.sleep(0.1)

            result.success = True
            result.end_time = time.time()

            # Clean up session
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]

            # Store result
            self.results[session_id] = result

            return result

        except Exception as e:
            logger.error(f"Failed to execute script {script_name}: {e}")
            result.errors.append(str(e))
            result.end_time = time.time()
            return result

    def _create_parameter_injection(self, parameters: dict[str, Any]) -> str:
        """Create JavaScript code to inject parameters."""
        js_params = []

        for key, value in parameters.items():
            if isinstance(value, str):
                js_value = f'"{value}"'
            elif isinstance(value, bool):
                js_value = "true" if value else "false"
            elif value is None:
                js_value = "null"
            elif isinstance(value, (list, dict)):
                js_value = json.dumps(value)
            else:
                js_value = str(value)

            js_params.append(f"var {key} = {js_value};")

        return "\n".join(js_params)

    def _handle_message(
        self,
        result: ScriptResult,
        message: dict[str, Any],
        data: bytes | None,
        callback: Callable[[dict[str, Any]], None] | None,
    ) -> None:
        """Handle messages from Frida script.

        Args:
            result: ScriptResult object to accumulate execution results
            message: Message dictionary from Frida containing type and payload
            data: Optional binary data attached to the message (e.g., memory dumps)
            callback: Optional callback function for real-time output handling

        """
        try:
            msg_type = message.get("type")

            if msg_type == "send":
                payload = message.get("payload", {})
                result.messages.append(payload)

                # Handle specific message types
                if isinstance(payload, dict):
                    if "memory_dump" in payload:
                        if data is not None:
                            result.memory_dumps.append(data)
                    elif "patch" in payload:
                        result.patches.append(payload["patch"])
                    elif "data" in payload:
                        result.data.update(payload["data"])

                # Call output callback
                if callback:
                    callback(payload)

            elif msg_type == "error":
                error = message.get("description", "Unknown error")
                result.errors.append(error)
                logger.error(f"Script error: {error}")

        except Exception as e:
            logger.error(f"Failed to handle message: {e}")

    def stop_script(self, session_id: str) -> None:
        """Stop a running script."""
        if session_id in self.active_sessions:
            try:
                session = self.active_sessions[session_id]
                session.detach()
                del self.active_sessions[session_id]
                logger.info(f"Stopped script session: {session_id}")
            except Exception as e:
                logger.error(f"Failed to stop script: {e}")

    def get_script_categories(self) -> list[ScriptCategory]:
        """Get all available script categories."""
        categories = {config.category for config in self.scripts.values()}
        return list(categories)

    def get_scripts_by_category(self, category: ScriptCategory) -> list[str]:
        """Get scripts in a specific category."""
        return [name for name, config in self.scripts.items() if config.category == category]

    def get_script_config(self, script_name: str) -> FridaScriptConfig | None:
        """Get configuration for a script."""
        return self.scripts.get(script_name)

    def export_results(self, session_id: str, output_path: Path) -> None:
        """Export script results to file."""
        if session_id not in self.results:
            raise ValueError(f"No results for session: {session_id}")

        result = self.results[session_id]

        export_data = {
            "script_name": result.script_name,
            "success": result.success,
            "duration": result.end_time - result.start_time,
            "messages": result.messages,
            "errors": result.errors,
            "data": result.data,
            "patches": result.patches,
            "memory_dumps_count": len(result.memory_dumps),
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        # Export memory dumps
        if result.memory_dumps:
            dump_dir = output_path.parent / f"{output_path.stem}_dumps"
            dump_dir.mkdir(exist_ok=True)

            for i, dump in enumerate(result.memory_dumps):
                dump_file = dump_dir / f"dump_{i:04d}.bin"
                dump_file.write_bytes(dump)

    def create_custom_script(
        self,
        name: str,
        code: str,
        category: ScriptCategory,
        parameters: dict[str, Any] | None = None,
    ) -> FridaScriptConfig:
        """Create a custom Frida script."""
        script_path = self.scripts_dir / f"custom_{name}.js"

        # Add metadata header
        metadata = {
            "name": name,
            "category": category.value,
            "parameters": parameters or {},
            "description": f"Custom script: {name}",
        }

        header = f"""/**
 * @metadata
 * {json.dumps(metadata, indent=2)}
 * @end
 */

"""

        # Write script
        with open(script_path, "w") as f:
            f.write(header)
            f.write(code)

        # Create configuration
        config = FridaScriptConfig(
            name=name,
            path=script_path,
            category=category,
            description=f"Custom script: {name}",
            parameters=parameters or {},
        )

        # Register script
        self.scripts[script_path.name] = config

        return config
