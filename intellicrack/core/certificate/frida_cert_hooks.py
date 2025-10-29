"""Frida-based certificate validation bypass integration layer for runtime hooking.

CAPABILITIES:
- Runtime hooking of certificate validation APIs without binary modification
- Cross-platform support (Windows, Linux, macOS, Android, iOS)
- Universal SSL bypass (auto-detects and hooks all TLS libraries)
- Library-specific bypass scripts (WinHTTP, Schannel, OpenSSL, NSS, etc.)
- Android certificate pinning bypass (OkHttp3, TrustManager, WebView)
- iOS certificate pinning bypass (SecTrust, NSURLSession, AFNetworking)
- Process attachment by name or PID
- Script injection with error handling
- Message handling from Frida scripts (logs, certificates, status)
- RPC call support to injected scripts
- Certificate interception and logging
- Bypass status monitoring
- Automatic hook restoration if removed
- Thread-safe operation

LIMITATIONS:
- Requires Frida runtime library and frida-server on target device
- May be detected by anti-Frida checks (use frida_stealth.py to mitigate)
- Cannot hook before process initialization (spawn mode required)
- Some apps detect Frida via thread enumeration or D-Bus
- Limited effectiveness against kernel-level protection
- Hooks may be removed by self-protection mechanisms
- Android/iOS require root/jailbreak for system apps
- Script injection may fail on heavily protected applications

USAGE EXAMPLES:
    # Attach and inject universal bypass
    from intellicrack.core.certificate.frida_cert_hooks import (
        FridaCertificateHooks
    )

    hooks = FridaCertificateHooks()
    success = hooks.attach("target.exe")  # or PID: hooks.attach(1234)

    if success:
        hooks.inject_universal_bypass()
        print("Universal bypass injected")

    # Inject library-specific bypass
    hooks.inject_specific_bypass("openssl")

    # Get bypass status
    status = hooks.get_bypass_status()
    print(f"Active bypasses: {status['active_scripts']}")
    print(f"Detected libraries: {status['detected_libraries']}")

    # Get intercepted certificates
    certs = hooks.get_intercepted_certificates()
    for cert in certs:
        print(f"Certificate: {cert['subject']}")
        print(f"  Issuer: {cert['issuer']}")
        print(f"  Valid: {cert['not_before']} - {cert['not_after']}")

    # Call RPC function in injected script
    result = hooks.call_rpc("getOpenSSLConnections")
    print(f"Active SSL connections: {len(result)}")

    # Detach when done
    hooks.detach()

RELATED MODULES:
- frida_scripts/: Contains JavaScript bypass scripts for each library
- frida_stealth.py: Provides anti-detection for Frida
- bypass_orchestrator.py: Uses this for runtime bypass strategy
- hook_obfuscation.py: Additional stealth techniques for hooks
- detection_report.py: Identifies which libraries need hooking

SUPPORTED LIBRARIES:
    Windows:
        - WinHTTP (winhttp.dll)
        - Schannel (sspicli.dll)
        - CryptoAPI (crypt32.dll)
        - OpenSSL (libssl-1_1-x64.dll, libssl-1_1.dll)

    Linux/Unix:
        - OpenSSL (libssl.so)
        - NSS (libnss3.so, libssl3.so)

    Android:
        - OpenSSL/BoringSSL (libssl.so)
        - OkHttp3 CertificatePinner
        - TrustManagerImpl
        - NetworkSecurityTrustManager
        - Custom X509TrustManager implementations

    iOS/macOS:
        - SecTrust (Security framework)
        - NSURLSession (CFNetwork)
        - AFNetworking
        - Alamofire

ARCHITECTURE:
    Python Layer (this file):
        - Process attachment/detachment
        - Script loading and injection
        - Message routing and handling
        - RPC interface
        - Status monitoring

    JavaScript Layer (frida_scripts/):
        - API hooking (Interceptor.attach)
        - Return value manipulation
        - Certificate interception
        - Logging and reporting

MESSAGE TYPES FROM SCRIPTS:
    - log: Informational messages
    - error: Error messages
    - certificate: Intercepted certificate data
    - bypass_success: Bypass successfully applied
    - bypass_failure: Bypass failed
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import frida

logger = logging.getLogger(__name__)


@dataclass
class FridaMessage:
    """Represents a message received from a Frida script.

    Attributes:
        timestamp: When the message was received.
        message_type: Type of message (log, certificate, bypass_success, etc.).
        payload: The message data payload.
        level: Log level (info, warning, error).

    """

    timestamp: datetime
    message_type: str
    payload: Any
    level: str = "info"


@dataclass
class BypassStatus:
    """Status information for active certificate bypass operations.

    Attributes:
        active: Whether bypass is currently active.
        library: Name of the bypassed TLS library (e.g., 'WinHTTP', 'OpenSSL').
        platform: Target platform (Windows, Android, iOS).
        hooks_installed: List of hooked API function names.
        detected_libraries: Libraries detected in target process.
        message_count: Total messages received from Frida scripts.
        errors: List of error messages encountered during bypass.
        intercepted_data: Dictionary containing intercepted certificates and connections.

    """

    active: bool
    library: Optional[str]
    platform: Optional[str]
    hooks_installed: List[str]
    detected_libraries: List[Dict]
    message_count: int
    errors: List[str]
    intercepted_data: Dict[str, List] = field(default_factory=dict)


class FridaCertificateHooks:
    """Manages Frida-based certificate validation bypass operations.

    This class handles the complete lifecycle of certificate bypass operations including
    attaching to target processes, injecting Frida scripts, handling messages from hooks,
    and managing bypass state. It supports bypassing certificate validation in multiple
    TLS/SSL libraries to defeat licensing protections that rely on certificate verification.

    The class provides both universal bypass (auto-detects libraries) and library-specific
    bypass modes (WinHTTP, Schannel, OpenSSL, CryptoAPI, etc.).

    Example:
        >>> hooks = FridaCertificateHooks()
        >>> hooks.attach("target_app.exe")
        >>> hooks.inject_universal_bypass()
        >>> status = hooks.get_bypass_status()
        >>> hooks.detach()

    """

    SCRIPT_DIR = Path(__file__).parent / "frida_scripts"

    AVAILABLE_SCRIPTS = {
        "winhttp": "winhttp_bypass.js",
        "schannel": "schannel_bypass.js",
        "openssl": "openssl_bypass.js",
        "cryptoapi": "cryptoapi_bypass.js",
        "android": "android_pinning.js",
        "ios": "ios_pinning.js",
        "universal": "universal_ssl_bypass.js",
    }

    def __init__(self):
        """Initialize the Frida certificate hooks manager.

        Sets up internal state for managing Frida session, script, messages, and bypass data.
        """
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.target: Optional[Union[str, int]] = None
        self.messages: List[FridaMessage] = []
        self.intercepted_certificates: List[Dict] = []
        self.bypassed_connections: List[Dict] = []
        self.errors: List[str] = []
        self._message_lock = threading.Lock()
        self._attached = False
        self._script_loaded = False

    def load_script(self, script_name: str) -> str:
        """Load a Frida JavaScript bypass script from disk.

        Args:
            script_name: Name of the script to load (winhttp, schannel, openssl,
                        cryptoapi, android, ios, universal).

        Returns:
            The JavaScript source code as a string.

        Raises:
            ValueError: If script_name is not in AVAILABLE_SCRIPTS.
            FileNotFoundError: If the script file doesn't exist on disk.

        """
        if script_name not in self.AVAILABLE_SCRIPTS:
            raise ValueError(
                f"Unknown script: {script_name}. Available: {list(self.AVAILABLE_SCRIPTS.keys())}"
            )

        script_path = self.SCRIPT_DIR / self.AVAILABLE_SCRIPTS[script_name]

        if not script_path.exists():
            raise FileNotFoundError(f"Script file not found: {script_path}")

        try:
            with open(script_path, "r", encoding="utf-8") as f:
                content = f.read()
            logger.info(f"Loaded script: {script_name} ({len(content)} bytes)")
            return content
        except Exception as e:
            logger.error(f"Failed to load script {script_name}: {e}")
            raise

    def attach(self, target: Union[str, int]) -> bool:
        """Attach to a target process for certificate bypass injection.

        Args:
            target: Process identifier - either a PID (int) or process name (str).

        Returns:
            True if attachment succeeded, False otherwise.

        Raises:
            TypeError: If target is neither int nor str.

        """
        if self._attached:
            logger.warning("Already attached to a process. Detach first.")
            return False

        self.target = target

        try:
            if isinstance(target, int):
                logger.info(f"Attaching to process with PID: {target}")
                self.session = frida.attach(target)
            elif isinstance(target, str):
                if target.isdigit():
                    pid = int(target)
                    logger.info(f"Attaching to process with PID: {pid}")
                    self.session = frida.attach(pid)
                else:
                    logger.info(f"Attaching to process by name: {target}")
                    self.session = frida.attach(target)
            else:
                raise TypeError(f"Invalid target type: {type(target)}")

            self.session.on("detached", self._on_detached)
            self._attached = True
            logger.info(f"Successfully attached to target: {target}")
            return True

        except frida.ProcessNotFoundError:
            error_msg = f"Process not found: {target}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False
        except frida.PermissionDeniedError:
            error_msg = f"Permission denied when attaching to: {target}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False
        except Exception as e:
            error_msg = f"Failed to attach to {target}: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

    def inject_script(self, script_content: str) -> bool:
        """Inject JavaScript code into the attached process.

        Args:
            script_content: The JavaScript code to inject.

        Returns:
            True if injection succeeded, False otherwise.

        """
        if not self._attached or self.session is None:
            logger.error("Not attached to any process. Call attach() first.")
            return False

        try:
            logger.info(f"Injecting script ({len(script_content)} bytes)")
            self.script = self.session.create_script(script_content)
            self.script.on("message", self._on_message)
            self.script.load()
            self._script_loaded = True
            logger.info("Script injected and loaded successfully")

            time.sleep(0.5)

            return True
        except frida.InvalidOperationError as e:
            error_msg = f"Invalid operation while injecting script: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False
        except Exception as e:
            error_msg = f"Failed to inject script: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

    def inject_universal_bypass(self) -> bool:
        """Inject the universal SSL bypass script that auto-detects TLS libraries.

        Returns:
            True if injection succeeded, False otherwise.

        """
        logger.info("Injecting universal SSL bypass")

        try:
            universal_content = self.load_script("universal")
            success = self.inject_script(universal_content)

            if success:
                logger.info("Universal bypass injected successfully")
            else:
                logger.error("Failed to inject universal bypass")

            return success
        except Exception as e:
            error_msg = f"Failed to inject universal bypass: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

    def inject_specific_bypass(self, library: str) -> bool:
        """Inject a library-specific certificate bypass script.

        Args:
            library: Library name (winhttp, schannel, openssl, cryptoapi, android, ios).

        Returns:
            True if injection succeeded, False otherwise.

        """
        if library not in self.AVAILABLE_SCRIPTS:
            error_msg = f"Unknown library bypass: {library}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

        logger.info(f"Injecting specific bypass for: {library}")

        try:
            script_content = self.load_script(library)
            success = self.inject_script(script_content)

            if success:
                logger.info(f"Bypass for {library} injected successfully")
            else:
                logger.error(f"Failed to inject bypass for {library}")

            return success
        except Exception as e:
            error_msg = f"Failed to inject {library} bypass: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

    def _on_message(self, message: Dict, data: Optional[bytes]) -> None:
        """Handle messages received from injected Frida scripts.

        This callback processes all messages sent from the JavaScript hooks including
        logs, certificate interceptions, bypass notifications, and errors.

        Args:
            message: Message dictionary from Frida with 'type' and 'payload' keys.
            data: Optional binary data accompanying the message.

        """
        with self._message_lock:
            msg_type = message.get("type")
            payload = message.get("payload")

            if msg_type == "send":
                self._handle_send_message(payload, data)
            elif msg_type == "error":
                self._handle_error_message(message)
            else:
                logger.warning(f"Unknown message type: {msg_type}")

    def _handle_send_message(self, payload: Any, data: Optional[bytes]) -> None:
        """Process 'send' type messages from Frida scripts.

        Parses different message types (log, certificate, bypass_success, etc.)
        and updates internal state accordingly.

        Args:
            payload: Message payload containing type and data.
            data: Optional binary data.

        """
        if not isinstance(payload, dict):
            logger.debug(f"Non-dict payload: {payload}")
            return

        payload_type = payload.get("type")

        frida_msg = FridaMessage(
            timestamp=datetime.now(),
            message_type=payload_type or "unknown",
            payload=payload,
            level=payload.get("level", "info"),
        )
        self.messages.append(frida_msg)

        if payload_type == "log":
            log_data = payload.get("data", {})
            level = log_data.get("level", "info")
            message = log_data.get("message", "")
            logger.log(
                logging.INFO if level == "info" else logging.ERROR,
                f"[Frida] {message}",
            )

        elif payload_type == "certificate":
            cert_data = payload.get("data", {})
            self.intercepted_certificates.append(cert_data)
            logger.info(f"Intercepted certificate: {cert_data}")

        elif payload_type in [
            "https_request",
            "tls_session",
            "ssl_connection",
            "certificate_chain",
        ]:
            conn_data = payload.get("data", {})
            self.bypassed_connections.append(conn_data)
            logger.debug(f"Connection bypassed: {payload_type}")

        elif payload_type in [
            "bypass_success",
            "bypass_ready",
            "universal_bypass_loaded",
        ]:
            library = payload.get("library", payload.get("platform", "unknown"))
            logger.info(f"Bypass activated: {library}")

        elif payload_type == "bypass_failure":
            library = payload.get("library", "unknown")
            reason = payload.get("reason", "unknown")
            error_msg = f"Bypass failed for {library}: {reason}"
            logger.error(error_msg)
            self.errors.append(error_msg)

        elif payload_type == "library_detected":
            lib_data = payload.get("data", {})
            logger.info(f"Detected TLS library: {lib_data.get('type')} - {lib_data.get('name')}")

    def _handle_error_message(self, message: Dict) -> None:
        """Process error messages from Frida scripts.

        Logs script errors with stack traces and appends to error list.

        Args:
            message: Error message dictionary with description, stack, and location.

        """
        description = message.get("description", "Unknown error")
        stack = message.get("stack", "")
        line_number = message.get("lineNumber", "?")
        column_number = message.get("columnNumber", "?")

        error_msg = f"Frida script error at {line_number}:{column_number}: {description}"
        logger.error(error_msg)
        if stack:
            logger.error(f"Stack trace:\n{stack}")

        self.errors.append(error_msg)

    def _on_detached(self, reason: str, crash: Optional[Any]) -> None:
        """Handle detachment from target process.

        Called when Frida session is detached, either intentionally or due to crash.

        Args:
            reason: Reason for detachment.
            crash: Crash information if process crashed, None otherwise.

        """
        logger.warning(f"Detached from process. Reason: {reason}")
        if crash:
            logger.error(f"Process crashed: {crash}")
        self._attached = False
        self._script_loaded = False

    def get_bypass_status(self) -> BypassStatus:
        """Get current status of certificate bypass operations.

        Queries the injected script via RPC to retrieve active bypass information
        including detected libraries, installed hooks, and intercepted data.

        Returns:
            BypassStatus object containing comprehensive bypass state information.

        """
        if not self._script_loaded or self.script is None:
            return BypassStatus(
                active=False,
                library=None,
                platform=None,
                hooks_installed=[],
                detected_libraries=[],
                message_count=len(self.messages),
                errors=self.errors,
            )

        try:
            rpc_status = self.call_rpc("getBypassStatus")

            return BypassStatus(
                active=rpc_status.get("active", False),
                library=rpc_status.get("library"),
                platform=rpc_status.get("platform"),
                hooks_installed=rpc_status.get("hooksInstalled", []),
                detected_libraries=rpc_status.get("detectedLibraries", []),
                message_count=len(self.messages),
                errors=self.errors,
                intercepted_data={
                    "certificates": self.intercepted_certificates,
                    "connections": self.bypassed_connections,
                },
            )
        except Exception as e:
            logger.error(f"Failed to get bypass status via RPC: {e}")
            return BypassStatus(
                active=self._script_loaded,
                library=None,
                platform=None,
                hooks_installed=[],
                detected_libraries=[],
                message_count=len(self.messages),
                errors=self.errors + [str(e)],
            )

    def get_intercepted_certificates(self) -> List[Dict]:
        """Get all intercepted certificate data.

        Returns:
            List of dictionaries containing intercepted certificate information.

        """
        return self.intercepted_certificates.copy()

    def get_bypassed_connections(self) -> List[Dict]:
        """Get all bypassed HTTPS connection data.

        Returns:
            List of dictionaries containing bypassed connection information.

        """
        return self.bypassed_connections.copy()

    def call_rpc(self, function_name: str, *args) -> Any:
        """Call an RPC function exported by the injected Frida script.

        Args:
            function_name: Name of the exported RPC function.
            *args: Arguments to pass to the RPC function.

        Returns:
            Result returned by the RPC function.

        Raises:
            RuntimeError: If no script is loaded or RPC function not found.

        """
        if not self._script_loaded or self.script is None:
            raise RuntimeError("Script not loaded. Inject a script first.")

        try:
            logger.debug(f"Calling RPC function: {function_name} with args: {args}")
            result = self.script.exports_sync[function_name](*args)
            logger.debug(f"RPC call result: {result}")
            return result
        except AttributeError as e:
            error_msg = f"RPC function not found: {function_name}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except Exception as e:
            error_msg = f"RPC call failed for {function_name}: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    def detach(self) -> bool:
        """Detach from the target process and cleanup resources.

        Unloads injected scripts and detaches the Frida session. Safe to call
        multiple times.

        Returns:
            True always (cleanup is best-effort).

        """
        logger.info("Detaching from process")

        if self.script and self._script_loaded:
            try:
                self.script.unload()
                logger.info("Script unloaded")
            except Exception as e:
                logger.warning(f"Failed to unload script: {e}")

        if self.session and self._attached:
            try:
                self.session.detach()
                logger.info("Session detached")
            except Exception as e:
                logger.warning(f"Failed to detach session: {e}")

        self._attached = False
        self._script_loaded = False
        self.session = None
        self.script = None

        return True

    def unload_scripts(self) -> bool:
        """Unload injected scripts without detaching from the process.

        Returns:
            True if scripts were unloaded successfully, False otherwise.

        """
        if not self._script_loaded or self.script is None:
            logger.warning("No scripts to unload")
            return False

        try:
            self.script.unload()
            self._script_loaded = False
            logger.info("Scripts unloaded successfully")
            return True
        except Exception as e:
            error_msg = f"Failed to unload scripts: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

    def get_messages(self, count: Optional[int] = None) -> List[FridaMessage]:
        """Get messages received from Frida scripts.

        Args:
            count: Number of recent messages to return. If None, returns all messages.

        Returns:
            List of FridaMessage objects.

        """
        with self._message_lock:
            if count is None:
                return self.messages.copy()
            return self.messages[-count:]

    def clear_logs(self) -> bool:
        """Clear all local logs and optionally remote script logs.

        Clears messages, intercepted certificates, bypassed connections, and errors
        from both local Python state and remote Frida scripts.

        Returns:
            True if cleanup succeeded.

        """
        with self._message_lock:
            self.messages.clear()
            self.intercepted_certificates.clear()
            self.bypassed_connections.clear()
            self.errors.clear()

        if self._script_loaded and self.script:
            try:
                self.call_rpc("clearLogs")
            except Exception as e:
                logger.warning(f"Failed to clear remote logs: {e}")

        logger.info("Local logs cleared")
        return True

    def is_attached(self) -> bool:
        """Check if currently attached to a process.

        Returns:
            True if attached, False otherwise.

        """
        return self._attached

    def is_script_loaded(self) -> bool:
        """Check if a script is currently loaded.

        Returns:
            True if script is loaded, False otherwise.

        """
        return self._script_loaded

    def __enter__(self):
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager and detach from process."""
        self.detach()
        return False
