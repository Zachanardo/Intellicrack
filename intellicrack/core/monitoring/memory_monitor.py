"""Memory Monitor for license pattern scanning.

Scans process memory for license-related patterns: serial keys, HWIDs,
activation codes, and other licensing data.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import threading
import time
from typing import Any

import frida

from intellicrack.core.monitoring.base_monitor import BaseMonitor, EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.frida_types import parse_frida_message


class MemoryMonitor(BaseMonitor):
    """Memory pattern scanning for license detection.

    Periodically scans process memory for patterns indicating license data.
    """

    def __init__(self, pid: int, process_info: ProcessInfo | None = None, scan_interval: float = 5.0) -> None:
        """Initialize memory monitor.

        Args:
            pid: Process ID to monitor.
            process_info: Process information.
            scan_interval: Seconds between scans.

        """
        super().__init__("MemoryMonitor", process_info)
        self.pid = pid
        self.scan_interval = scan_interval
        self.session: frida.core.Session | None = None
        self.script: frida.core.Script | None = None
        self._scan_thread: threading.Thread | None = None
        self._found_patterns: set[str] = set()

        self.patterns = {
            "serial_key": [
                r"[A-Z0-9]{4,5}-[A-Z0-9]{4,5}-[A-Z0-9]{4,5}-[A-Z0-9]{4,5}",
                r"[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}",
            ],
            "email": [
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            ],
            "hwid": [
                r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            ],
            "activation": [
                r"activation[_-]?code[:\s]+([A-Z0-9-]+)",
                r"license[_-]?key[:\s]+([A-Z0-9-]+)",
            ],
        }

    def _start_monitoring(self) -> bool:
        """Start memory monitoring.

        Returns:
            True if started successfully.

        """
        try:
            self.session = frida.attach(self.pid)

            script_source = self._build_frida_script()
            self.script = self.session.create_script(script_source)
            self.script.on("message", self._on_frida_message)
            self.script.load()

            self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
            self._scan_thread.start()

            return True

        except Exception as e:
            return not self._handle_error(e)

    def _stop_monitoring(self) -> None:
        """Stop memory monitoring."""
        if self.script:
            try:
                self.script.unload()
            except Exception as e:
                print(f"[MemoryMonitor] Error unloading script: {e}")
            self.script = None

        if self.session:
            try:
                self.session.detach()
            except Exception as e:
                print(f"[MemoryMonitor] Error detaching session: {e}")
            self.session = None

        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=2.0)

    def _scan_loop(self) -> None:
        """Periodic scanning loop (runs in thread)."""
        while self._running:
            try:
                if self.script:
                    self._trigger_scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                if not self._handle_error(e):
                    break

    def _trigger_scan(self) -> None:
        """Trigger memory scan via Frida script."""
        try:
            if self.script:
                self.script.exports.scan_memory()
        except Exception as e:
            self._handle_error(e)

    def _on_frida_message(self, message: frida.core.ScriptPayloadMessage | frida.core.ScriptErrorMessage, data: bytes | None) -> None:
        """Handle messages from Frida script.

        Args:
            message: Message from Frida.
            data: Additional data payload.

        """
        msg_type, payload = parse_frida_message(message)
        if msg_type != "send":
            return

        event_type = payload.get("event_type")

        if event_type == "pattern_found":
            self._handle_pattern_found(payload)
        elif event_type == "scan_complete":
            pass
        elif event_type == "error":
            error_msg = payload.get("message")
            self._handle_error(Exception(error_msg if isinstance(error_msg, str) else "Unknown error"))

    def _handle_pattern_found(self, payload: dict[str, Any]) -> None:
        """Handle pattern found in memory.

        Args:
            payload: Pattern information.

        """
        pattern_type = payload.get("pattern_type", "unknown")
        pattern_value = payload.get("value", "")
        address = payload.get("address", 0)

        pattern_key = f"{pattern_type}:{pattern_value}"
        if pattern_key in self._found_patterns:
            return

        self._found_patterns.add(pattern_key)

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.MEMORY,
            event_type=EventType.SCAN,
            severity=EventSeverity.CRITICAL,
            details={
                "pattern_type": pattern_type,
                "value": pattern_value,
                "address": hex(address) if address else "unknown",
                "context": payload.get("context", ""),
            },
            process_info=self.process_info,
        )

        self._emit_event(event)

    def _build_frida_script(self) -> str:
        """Build Frida JavaScript for memory scanning.

        Returns:
            Frida script source code.

        """
        return """
// Memory Pattern Scanning Script

const SCAN_PATTERNS = {
    serial_key: [
        /[A-Z0-9]{4,5}-[A-Z0-9]{4,5}-[A-Z0-9]{4,5}-[A-Z0-9]{4,5}/g,
        /[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}/g
    ],
    email: [
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g
    ],
    hwid: [
        /[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/gi
    ]
};

const LICENSE_KEYWORDS = [
    'license', 'licence', 'serial', 'key', 'activation',
    'register', 'trial', 'crack', 'hwid', 'machine'
];

function scanMemory() {
    try {
        const ranges = Process.enumerateRanges('r--');
        let scannedRanges = 0;

        for (const range of ranges) {
            if (!range.protection.includes('r')) continue;

            scannedRanges++;

            if (scannedRanges > 100) break;

            try {
                const data = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                if (!data) continue;

                const text = bufferToString(data);
                if (!text) continue;

                scanForPatterns(text, range.base.toInt32());
                scanForKeywords(text, range.base.toInt32());

            } catch (e) {
                continue;
            }
        }

        send({event_type: 'scan_complete', ranges_scanned: scannedRanges});

    } catch (e) {
        send({event_type: 'error', message: 'Memory scan failed: ' + e.message});
    }
}

function bufferToString(buffer) {
    try {
        const decoder = new TextDecoder('utf-8', {fatal: false});
        const uint8Array = new Uint8Array(buffer);
        return decoder.decode(uint8Array);
    } catch (e) {
        return null;
    }
}

function scanForPatterns(text, baseAddress) {
    for (const [patternType, patterns] of Object.entries(SCAN_PATTERNS)) {
        for (const pattern of patterns) {
            const matches = text.matchAll(pattern);

            for (const match of matches) {
                send({
                    event_type: 'pattern_found',
                    pattern_type: patternType,
                    value: match[0],
                    address: baseAddress + match.index,
                    context: getContext(text, match.index)
                });
            }
        }
    }
}

function scanForKeywords(text, baseAddress) {
    const lowerText = text.toLowerCase();

    for (const keyword of LICENSE_KEYWORDS) {
        let index = lowerText.indexOf(keyword);

        while (index !== -1) {
            const context = getContext(text, index);

            const hasSerial = /[A-Z0-9]{4,5}-[A-Z0-9]{4,5}/.test(context);
            if (hasSerial) {
                send({
                    event_type: 'pattern_found',
                    pattern_type: 'license_keyword',
                    value: keyword,
                    address: baseAddress + index,
                    context: context
                });
            }

            index = lowerText.indexOf(keyword, index + 1);
        }
    }
}

function getContext(text, index, contextSize = 64) {
    const start = Math.max(0, index - contextSize);
    const end = Math.min(text.length, index + contextSize);
    return text.substring(start, end).replace(/[\\x00-\\x1F\\x7F-\\x9F]/g, '.');
}

rpc.exports = {
    scanMemory: scanMemory
};

send({event_type: 'ready', message: 'Memory scanner initialized'});
"""
