"""Windows API Monitor using Frida instrumentation.

Hooks critical Windows APIs for registry, file, network, crypto, and time
operations to detect license-related activity.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import time
from typing import Any

import frida

from intellicrack.core.monitoring.base_monitor import BaseMonitor, EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.frida_types import parse_frida_message


class APIMonitor(BaseMonitor):
    """Windows API monitoring via Frida hooking.

    Hooks licensing-critical APIs: registry, file I/O, network, crypto, time checks.
    """

    def __init__(self, pid: int, process_info: ProcessInfo | None = None) -> None:
        """Initialize API monitor.

        Args:
            pid: Process ID to monitor.
            process_info: Process information.

        """
        super().__init__("APIMonitor", process_info)
        self.pid: int = pid
        self.session: frida.core.Session | None = None
        self.script: frida.core.Script | None = None

    def _start_monitoring(self) -> bool:
        """Start API monitoring.

        Returns:
            True if started successfully.

        """
        try:
            self.session = frida.attach(self.pid)

            script_source = self._build_frida_script()
            self.script = self.session.create_script(script_source)
            self.script.on("message", self._on_frida_message)
            self.script.load()

            return True

        except Exception as e:
            self._handle_error(e)
            return False

    def _stop_monitoring(self) -> None:
        """Stop API monitoring.

        Unloads the Frida script and detaches from the target process.

        """
        if self.script:
            try:
                self.script.unload()
            except Exception as e:
                print(f"[APIMonitor] Error unloading script: {e}")
            self.script = None

        if self.session:
            try:
                self.session.detach()
            except Exception as e:
                print(f"[APIMonitor] Error detaching session: {e}")
            self.session = None

    def _on_frida_message(self, message: frida.core.ScriptPayloadMessage | frida.core.ScriptErrorMessage, data: bytes | None) -> None:
        """Handle messages from Frida script.

        Processes incoming Frida messages to detect and emit API call events
        or handle script errors.

        Args:
            message: Message from Frida.
            data: Additional data payload.

        """
        msg_type, payload = parse_frida_message(message)
        if msg_type != "send":
            return

        event_type = payload.get("event_type")

        if event_type == "api_call":
            self._handle_api_call(payload)
        elif event_type == "error":
            error_msg = payload.get("message")
            self._handle_error(Exception(error_msg if isinstance(error_msg, str) else "Unknown error"))

    def _handle_api_call(self, payload: dict[str, Any]) -> None:
        """Handle API call event from Frida.

        Extracts API call details, determines event severity based on
        licensing-related keywords, and emits a monitor event.

        Args:
            payload: API call information.

        """
        api_name = payload.get("api", "Unknown")
        args = payload.get("args", [])
        result = payload.get("result")
        category = payload.get("category", "unknown")

        event_type_map = {
            "registry_read": EventType.READ,
            "registry_write": EventType.WRITE,
            "file_read": EventType.READ,
            "file_write": EventType.WRITE,
            "network_connect": EventType.CONNECT,
            "network_send": EventType.SEND,
            "network_receive": EventType.RECEIVE,
            "crypto": EventType.ACCESS,
            "time": EventType.ACCESS,
        }

        event_type = event_type_map.get(category, EventType.ACCESS)

        severity = EventSeverity.INFO
        if any(keyword in str(args).lower() for keyword in ["license", "serial", "key", "activation", "trial"]):
            severity = EventSeverity.CRITICAL
        elif category in ["registry_write", "file_write"]:
            severity = EventSeverity.WARNING

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=event_type,
            severity=severity,
            details={
                "api": api_name,
                "category": category,
                "args": args,
                "result": result,
            },
            process_info=self.process_info,
            call_stack=payload.get("call_stack", []),
        )

        self._emit_event(event)

    def _build_frida_script(self) -> str:
        """Build Frida JavaScript for API hooking.

        Generates Frida instrumentation code that hooks Windows APIs for
        registry, file, network, crypto, and time operations to detect
        licensing-related activity.

        Returns:
            JavaScript source code for Frida script execution.

        """
        return """
// Windows API Monitoring Script
// Hooks licensing-critical APIs

const hooks = [];
const MAX_STRING_LEN = 256;

// Helper function to read wide string
function readWideString(ptr, maxLen) {
    if (!ptr || ptr.isNull()) return null;
    try {
        return ptr.readUtf16String(maxLen || MAX_STRING_LEN);
    } catch (e) {
        return null;
    }
}

// Helper function to read ANSI string
function readAnsiString(ptr, maxLen) {
    if (!ptr || ptr.isNull()) return null;
    try {
        return ptr.readAnsiString(maxLen || MAX_STRING_LEN);
    } catch (e) {
        return null;
    }
}

// Helper to get call stack
function getCallStack() {
    try {
        return Thread.backtrace(this.context, Backtracer.ACCURATE)
            .slice(0, 5)
            .map(addr => DebugSymbol.fromAddress(addr))
            .map(sym => sym.toString());
    } catch (e) {
        return [];
    }
}

// Registry API Hooks
function hookRegistryAPIs() {
    const advapi32 = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
    if (advapi32) {
        Interceptor.attach(advapi32, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.lpSubKey = readWideString(args[1]);
            },
            onLeave: function(retval) {
                if (this.lpSubKey) {
                    send({
                        event_type: 'api_call',
                        category: 'registry_read',
                        api: 'RegOpenKeyExW',
                        args: [this.hKey.toString(), this.lpSubKey],
                        result: retval.toInt32(),
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const regQuery = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
    if (regQuery) {
        Interceptor.attach(regQuery, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.lpValueName = readWideString(args[1]);
                this.lpData = args[4];
                this.lpcbData = args[5];
            },
            onLeave: function(retval) {
                if (this.lpValueName && retval.toInt32() === 0) {
                    let value = null;
                    if (this.lpData && !this.lpData.isNull() && this.lpcbData) {
                        try {
                            const size = this.lpcbData.readU32();
                            if (size > 0 && size < 1024) {
                                value = readWideString(this.lpData, size / 2);
                            }
                        } catch (e) {}
                    }
                    send({
                        event_type: 'api_call',
                        category: 'registry_read',
                        api: 'RegQueryValueExW',
                        args: [this.hKey.toString(), this.lpValueName],
                        result: value,
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const regSet = Module.findExportByName('advapi32.dll', 'RegSetValueExW');
    if (regSet) {
        Interceptor.attach(regSet, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.lpValueName = readWideString(args[1]);
                this.dwType = args[2].toInt32();
                this.lpData = args[3];
                let value = null;
                if (this.dwType === 1 && this.lpData) {
                    value = readWideString(this.lpData);
                }
                this.value = value;
            },
            onLeave: function(retval) {
                if (this.lpValueName) {
                    send({
                        event_type: 'api_call',
                        category: 'registry_write',
                        api: 'RegSetValueExW',
                        args: [this.hKey.toString(), this.lpValueName, this.value],
                        result: retval.toInt32(),
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const regDelete = Module.findExportByName('advapi32.dll', 'RegDeleteKeyW');
    if (regDelete) {
        Interceptor.attach(regDelete, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.lpSubKey = readWideString(args[1]);
            },
            onLeave: function(retval) {
                if (this.lpSubKey) {
                    send({
                        event_type: 'api_call',
                        category: 'registry_write',
                        api: 'RegDeleteKeyW',
                        args: [this.hKey.toString(), this.lpSubKey],
                        result: retval.toInt32(),
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }
}

// File API Hooks
function hookFileAPIs() {
    const createFile = Module.findExportByName('kernel32.dll', 'CreateFileW');
    if (createFile) {
        Interceptor.attach(createFile, {
            onEnter: function(args) {
                this.lpFileName = readWideString(args[0]);
                this.dwDesiredAccess = args[1].toInt32();
            },
            onLeave: function(retval) {
                if (this.lpFileName && retval.toInt32() !== -1) {
                    const access = (this.dwDesiredAccess & 0x80000000) ? 'write' : 'read';
                    send({
                        event_type: 'api_call',
                        category: 'file_' + access,
                        api: 'CreateFileW',
                        args: [this.lpFileName, access],
                        result: retval.toString(),
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const readFile = Module.findExportByName('kernel32.dll', 'ReadFile');
    if (readFile) {
        Interceptor.attach(readFile, {
            onEnter: function(args) {
                this.hFile = args[0];
                this.nNumberOfBytesToRead = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    send({
                        event_type: 'api_call',
                        category: 'file_read',
                        api: 'ReadFile',
                        args: [this.hFile.toString(), this.nNumberOfBytesToRead + ' bytes'],
                        result: 'success',
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const writeFile = Module.findExportByName('kernel32.dll', 'WriteFile');
    if (writeFile) {
        Interceptor.attach(writeFile, {
            onEnter: function(args) {
                this.hFile = args[0];
                this.nNumberOfBytesToWrite = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    send({
                        event_type: 'api_call',
                        category: 'file_write',
                        api: 'WriteFile',
                        args: [this.hFile.toString(), this.nNumberOfBytesToWrite + ' bytes'],
                        result: 'success',
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const deleteFile = Module.findExportByName('kernel32.dll', 'DeleteFileW');
    if (deleteFile) {
        Interceptor.attach(deleteFile, {
            onEnter: function(args) {
                this.lpFileName = readWideString(args[0]);
            },
            onLeave: function(retval) {
                if (this.lpFileName) {
                    send({
                        event_type: 'api_call',
                        category: 'file_write',
                        api: 'DeleteFileW',
                        args: [this.lpFileName],
                        result: retval.toInt32(),
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }
}

// Network API Hooks
function hookNetworkAPIs() {
    const wsConnect = Module.findExportByName('ws2_32.dll', 'connect');
    if (wsConnect) {
        Interceptor.attach(wsConnect, {
            onEnter: function(args) {
                this.socket = args[0];
                const sockaddr = args[1];
                try {
                    const family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        const ip = sockaddr.add(4).readU8() + '.' +
                                   sockaddr.add(5).readU8() + '.' +
                                   sockaddr.add(6).readU8() + '.' +
                                   sockaddr.add(7).readU8();
                        this.addr = ip + ':' + port;
                    }
                } catch (e) {
                    this.addr = 'unknown';
                }
            },
            onLeave: function(retval) {
                if (this.addr) {
                    send({
                        event_type: 'api_call',
                        category: 'network_connect',
                        api: 'connect',
                        args: [this.socket.toString(), this.addr],
                        result: retval.toInt32(),
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const send = Module.findExportByName('ws2_32.dll', 'send');
    if (send) {
        Interceptor.attach(send, {
            onEnter: function(args) {
                this.socket = args[0];
                this.len = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (retval.toInt32() > 0) {
                    send({
                        event_type: 'api_call',
                        category: 'network_send',
                        api: 'send',
                        args: [this.socket.toString(), retval.toInt32() + ' bytes'],
                        result: 'success',
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const recv = Module.findExportByName('ws2_32.dll', 'recv');
    if (recv) {
        Interceptor.attach(recv, {
            onEnter: function(args) {
                this.socket = args[0];
            },
            onLeave: function(retval) {
                if (retval.toInt32() > 0) {
                    send({
                        event_type: 'api_call',
                        category: 'network_receive',
                        api: 'recv',
                        args: [this.socket.toString(), retval.toInt32() + ' bytes'],
                        result: 'success',
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }

    const internetOpen = Module.findExportByName('wininet.dll', 'InternetOpenW');
    if (internetOpen) {
        Interceptor.attach(internetOpen, {
            onEnter: function(args) {
                this.lpszAgent = readWideString(args[0]);
            },
            onLeave: function(retval) {
                if (!retval.isNull() && this.lpszAgent) {
                    send({
                        event_type: 'api_call',
                        category: 'network_connect',
                        api: 'InternetOpenW',
                        args: [this.lpszAgent],
                        result: retval.toString(),
                        call_stack: getCallStack.call(this)
                    });
                }
            }
        });
    }
}

// Crypto API Hooks
function hookCryptoAPIs() {
    const cryptDecrypt = Module.findExportByName('advapi32.dll', 'CryptDecrypt');
    if (cryptDecrypt) {
        Interceptor.attach(cryptDecrypt, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.pdwDataLen = args[4];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.pdwDataLen) {
                    try {
                        const len = this.pdwDataLen.readU32();
                        send({
                            event_type: 'api_call',
                            category: 'crypto',
                            api: 'CryptDecrypt',
                            args: [this.hKey.toString(), len + ' bytes'],
                            result: 'success',
                            call_stack: getCallStack.call(this)
                        });
                    } catch (e) {}
                }
            }
        });
    }

    const cryptEncrypt = Module.findExportByName('advapi32.dll', 'CryptEncrypt');
    if (cryptEncrypt) {
        Interceptor.attach(cryptEncrypt, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.pdwDataLen = args[4];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.pdwDataLen) {
                    try {
                        const len = this.pdwDataLen.readU32();
                        send({
                            event_type: 'api_call',
                            category: 'crypto',
                            api: 'CryptEncrypt',
                            args: [this.hKey.toString(), len + ' bytes'],
                            result: 'success',
                            call_stack: getCallStack.call(this)
                        });
                    } catch (e) {}
                }
            }
        });
    }
}

// Time API Hooks
function hookTimeAPIs() {
    const getSystemTime = Module.findExportByName('kernel32.dll', 'GetSystemTime');
    if (getSystemTime) {
        Interceptor.attach(getSystemTime, {
            onLeave: function(retval) {
                send({
                    event_type: 'api_call',
                    category: 'time',
                    api: 'GetSystemTime',
                    args: [],
                    result: 'queried',
                    call_stack: getCallStack.call(this)
                });
            }
        });
    }

    const getTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
    if (getTickCount) {
        Interceptor.attach(getTickCount, {
            onLeave: function(retval) {
                send({
                    event_type: 'api_call',
                    category: 'time',
                    api: 'GetTickCount',
                    args: [],
                    result: retval.toInt32(),
                    call_stack: getCallStack.call(this)
                });
            }
        });
    }
}

// Initialize all hooks
try {
    hookRegistryAPIs();
    hookFileAPIs();
    hookNetworkAPIs();
    hookCryptoAPIs();
    hookTimeAPIs();
    send({event_type: 'ready', message: 'API hooks initialized'});
} catch (e) {
    send({event_type: 'error', message: 'Hook initialization failed: ' + e.message});
}
"""
