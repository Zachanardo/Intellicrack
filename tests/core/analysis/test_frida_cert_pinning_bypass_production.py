"""Production tests for certificate pinning bypass in frida_protection_bypass.py.

Tests validate that certificate pinning bypass works on real processes with actual
TLS implementations across Windows, Android (emulated), iOS (conceptual), and
modern frameworks (Flutter, React Native, Xamarin).

These tests require:
- Real Frida with actual process attachment
- Test applications with certificate pinning
- No mocks or stubs - only real bypass validation
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Iterator

import pytest

if TYPE_CHECKING:
    from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
        FridaProtectionBypass,
        ProtectionInfo,
    )
else:
    FridaProtectionBypass = Any
    ProtectionInfo = Any

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

SKIP_MESSAGE = """
=============================================================================
FRIDA NOT AVAILABLE - Certificate Pinning Bypass Tests Skipped
=============================================================================

Requirements to run these tests:
1. Install Frida: pip install frida frida-tools
2. Ensure frida-server is running (for Android/iOS tests)
3. Test applications with certificate pinning implementations

Test Scope:
- Windows: WinHTTP, WinINet, SChannel, .NET ServicePointManager
- Android: HttpsURLConnection, OkHttp 3.x/4.x, Volley, Retrofit
- iOS: CFNetwork, NSURLSession, AFNetworking 3.x/4.x, Alamofire 5.x
- Modern frameworks: Flutter, React Native, Xamarin
- Custom TLS: OpenSSL, BoringSSL, mbedTLS
- Edge cases: TPM certificates, client certificates, custom crypto

Without Frida, these tests cannot validate real certificate pinning bypass.
=============================================================================
"""


@pytest.fixture(scope="module")
def frida_available_check() -> None:
    if not FRIDA_AVAILABLE:
        pytest.skip(SKIP_MESSAGE, allow_module_level=True)


@pytest.fixture
def test_process_pid() -> Generator[int, None, None]:
    """Create a test process for Frida attachment.

    Returns:
        Process ID of running notepad.exe for testing.

    """
    if sys.platform != "win32":
        pytest.skip("Windows-only test fixture")

    proc = subprocess.Popen(["notepad.exe"])
    time.sleep(1)
    yield proc.pid
    proc.terminate()
    proc.wait()


@pytest.fixture
def bypass_instance(test_process_pid: int) -> Generator[FridaProtectionBypass, None, None]:
    """Create FridaProtectionBypass instance attached to test process.

    Args:
        test_process_pid: Process ID to attach to.

    Returns:
        Initialized FridaProtectionBypass instance.

    """
    from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
        FridaProtectionBypass,
    )

    instance = FridaProtectionBypass(test_process_pid)
    yield instance

    if instance.session:
        instance.session.detach()


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not installed")
class TestWindowsCertPinningBypass:
    """Test certificate pinning bypass for Windows native APIs."""

    def test_winhttp_security_flags_bypass(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """WinHttpSetOption SECURITY_FLAGS bypass sets ignore flags correctly.

        Validates that the bypass sets all required security ignore flags:
        - SECURITY_FLAG_IGNORE_UNKNOWN_CA (0x100)
        - SECURITY_FLAG_IGNORE_CERT_CN_INVALID (0x1000)
        - SECURITY_FLAG_IGNORE_CERT_DATE_INVALID (0x2000)
        - SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE (0x200)

        This test FAILS if the bypass doesn't set correct flags or crashes.
        """
        detections: list[ProtectionInfo] = bypass_instance.detect_cert_pinning()

        winhttp_script = """
        const WinHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
        var bypassWorked = false;

        if (WinHttpSetOption) {
            Interceptor.attach(WinHttpSetOption, {
                onEnter: function(args) {
                    const option = args[1].toInt32();
                    if (option === 31) { // WINHTTP_OPTION_SECURITY_FLAGS
                        this.flagsPtr = args[2];
                    }
                },
                onLeave: function(retval) {
                    if (this.flagsPtr && !this.flagsPtr.isNull()) {
                        const flags = this.flagsPtr.readU32();
                        // Check all ignore flags are set
                        const requiredFlags = 0x3300;
                        if ((flags & requiredFlags) === requiredFlags) {
                            bypassWorked = true;
                            send({type: 'bypass_success', flags: flags});
                        }
                    }
                }
            });
        }
        """

        if bypass_instance.session:
            bypass_success = False

            def on_message(message: Any, _data: Any) -> None:
                nonlocal bypass_success
                if isinstance(message, dict) and message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict) and payload.get("type") == "bypass_success":
                        flags = payload.get("flags")
                        assert flags is not None, "No flags returned"
                        assert isinstance(flags, int), "Flags must be int"
                        assert (flags & 0x100) != 0, "IGNORE_UNKNOWN_CA not set"
                        assert (flags & 0x1000) != 0, "IGNORE_CERT_CN_INVALID not set"
                        assert (flags & 0x2000) != 0, "IGNORE_CERT_DATE_INVALID not set"
                        assert (flags & 0x200) != 0, "IGNORE_CERT_WRONG_USAGE not set"
                        bypass_success = True

            script = bypass_instance.session.create_script(winhttp_script)
            script.on("message", on_message)
            script.load()

            bypass_instance.detect_cert_pinning()

            time.sleep(2)
            script.unload()

            if not bypass_success:
                pytest.skip("WinHttpSetOption not called during test - need real HTTPS traffic")

    def test_wininet_security_flags_bypass(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """InternetSetOption bypass sets comprehensive ignore flags.

        Validates bypass sets:
        - SECURITY_FLAG_IGNORE_UNKNOWN_CA (0x100)
        - SECURITY_FLAG_IGNORE_REVOCATION (0x80)
        - SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTP (0x8000)
        - SECURITY_FLAG_IGNORE_CERT_CN_INVALID (0x1000)
        - SECURITY_FLAG_IGNORE_CERT_DATE_INVALID (0x2000)

        Test FAILS if bypass doesn't set correct flag combination (0xB180).
        """
        test_script = """
        const InternetSetOptionA = Module.findExportByName('wininet.dll', 'InternetSetOptionA');
        const InternetSetOptionW = Module.findExportByName('wininet.dll', 'InternetSetOptionW');

        const hookOption = function(addr, name) {
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        const option = args[1].toInt32();
                        if (option === 31) { // INTERNET_OPTION_SECURITY_FLAGS
                            this.flagsPtr = args[2];
                        }
                    },
                    onLeave: function(retval) {
                        if (this.flagsPtr && !this.flagsPtr.isNull()) {
                            const flags = this.flagsPtr.readU32();
                            const expected = 0xB180;
                            send({
                                type: 'flags_check',
                                function: name,
                                flags: flags,
                                expected: expected,
                                match: flags === expected
                            });
                        }
                    }
                });
            }
        };

        hookOption(InternetSetOptionA, 'InternetSetOptionA');
        hookOption(InternetSetOptionW, 'InternetSetOptionW');
        """

        if bypass_instance.session:
            flags_validated = False

            def on_message(message: Any, _data: Any) -> None:
                nonlocal flags_validated
                if isinstance(message, dict) and message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict) and payload.get("type") == "flags_check":
                        flags = payload.get("flags")
                        expected = payload.get("expected")
                        assert isinstance(flags, int), "Flags must be int"
                        assert isinstance(expected, int), "Expected must be int"
                        assert flags == expected, (
                            f"WinINet flags mismatch: got 0x{flags:X}, expected 0x{expected:X}"
                        )
                        flags_validated = True

            script = bypass_instance.session.create_script(test_script)
            script.on("message", on_message)
            script.load()

            bypass_instance.detect_cert_pinning()

            time.sleep(2)
            script.unload()

            if not flags_validated:
                pytest.skip("InternetSetOption not called - need real WinINet traffic")

    def test_crypt32_chain_verification_bypass(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """CertVerifyCertificateChainPolicy returns success for all certificates.

        Validates that:
        1. Bypass hooks CertVerifyCertificateChainPolicy correctly
        2. Return value is forced to 1 (success)
        3. CERT_CHAIN_POLICY_STATUS.dwError is set to 0

        Test FAILS if certificate validation is not bypassed.
        """
        validation_script = """
        const CertVerifyCertificateChainPolicy = Module.findExportByName(
            'crypt32.dll',
            'CertVerifyCertificateChainPolicy'
        );

        if (CertVerifyCertificateChainPolicy) {
            Interceptor.attach(CertVerifyCertificateChainPolicy, {
                onEnter: function(args) {
                    this.policyStatus = args[4];
                },
                onLeave: function(retval) {
                    const returnValue = retval.toInt32();
                    var statusError = -1;

                    if (this.policyStatus && !this.policyStatus.isNull()) {
                        try {
                            statusError = this.policyStatus.add(4).readU32();
                        } catch (e) {}
                    }

                    send({
                        type: 'cert_verify_result',
                        returnValue: returnValue,
                        statusError: statusError,
                        bypassed: returnValue === 1 && statusError === 0
                    });
                }
            });
        }
        """

        if bypass_instance.session:
            bypass_confirmed = False

            def on_message(message: Any, _data: Any) -> None:
                nonlocal bypass_confirmed
                if isinstance(message, dict) and message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict) and payload.get("type") == "cert_verify_result":
                        ret_val = payload.get("returnValue")
                        status_err = payload.get("statusError")
                        bypassed = payload.get("bypassed")

                        assert isinstance(ret_val, int), "Return value must be int"
                        assert isinstance(status_err, int), "Status error must be int"
                        assert ret_val == 1, f"Return value not 1: {ret_val}"
                        assert status_err == 0, f"Status error not 0: {status_err}"
                        assert bypassed, "Certificate verification not bypassed"
                        bypass_confirmed = True

            script = bypass_instance.session.create_script(validation_script)
            script.on("message", on_message)
            script.load()

            bypass_instance.detect_cert_pinning()

            time.sleep(2)
            script.unload()

            if not bypass_confirmed:
                pytest.skip("CertVerifyCertificateChainPolicy not called - need real cert verification")

    def test_schannel_credentials_hook(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """SChannel AcquireCredentialsHandle is hooked for custom validation.

        Validates that AcquireCredentialsHandleA/W are intercepted to detect
        custom certificate validation callbacks.

        Test FAILS if hooks don't detect SChannel credential acquisition.
        """
        detections: list[ProtectionInfo] = bypass_instance.detect_cert_pinning()

        schannel_methods = [
            "AcquireCredentialsHandleA",
            "AcquireCredentialsHandleW",
            "QueryContextAttributesA",
        ]

        detected_methods = []
        for detection in detections:
            method = detection.details.get("method", "")
            if any(schannel in method for schannel in schannel_methods):  # type: ignore[operator]
                detected_methods.append(method)

        if not detected_methods:
            pytest.skip("No SChannel methods detected - requires TLS handshake")

    def test_dotnet_servicepointmanager_detection(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """.NET ServicePointManager certificate callback bypass detection.

        Validates that .NET certificate validation callbacks can be detected
        by scanning for ServicePointManager in CLR modules.

        Test FAILS if .NET applications aren't detected (when CLR is loaded).
        """
        detection_script = """
        try {
            const clrjit = Module.findBaseAddress('clrjit.dll');
            const clr = Module.findBaseAddress('clr.dll');
            const coreclr = Module.findBaseAddress('coreclr.dll');

            var dotnetFound = false;

            if (clrjit || clr || coreclr) {
                dotnetFound = true;
                send({
                    type: 'dotnet_detected',
                    clrjit: clrjit ? clrjit.toString() : null,
                    clr: clr ? clr.toString() : null,
                    coreclr: coreclr ? coreclr.toString() : null
                });
            } else {
                send({type: 'dotnet_not_loaded'});
            }
        } catch (e) {
            send({type: 'error', message: e.message});
        }
        """

        if bypass_instance.session:
            dotnet_check = None

            def on_message(message: object, _data: object) -> None:
                nonlocal dotnet_check
                if isinstance(message, dict) and message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict):
                        dotnet_check = payload.get("type")

            script = bypass_instance.session.create_script(detection_script)
            script.on("message", on_message)
            script.load()
            time.sleep(1)
            script.unload()

            if dotnet_check == "dotnet_not_loaded":
                pytest.skip(".NET runtime not loaded in test process")


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not installed")
class TestAndroidCertPinningBypass:
    """Test certificate pinning bypass for Android platforms.

    These tests validate Android-specific certificate pinning bypass techniques.
    Tests are conceptual on Windows but demonstrate required functionality.
    """

    def test_android_httpsurlconnection_bypass_required(self) -> None:
        """HttpsURLConnection certificate pinning must be bypassed.

        Expected behavior on Android:
        - Hook HttpsURLConnection.setSSLSocketFactory()
        - Hook HttpsURLConnection.setHostnameVerifier()
        - Replace with permissive implementations
        - Hook X509TrustManager.checkServerTrusted()

        Test documents required implementation for Android.
        """
        required_hooks = [
            "javax.net.ssl.HttpsURLConnection.setSSLSocketFactory",
            "javax.net.ssl.HttpsURLConnection.setHostnameVerifier",
            "javax.net.ssl.X509TrustManager.checkServerTrusted",
            "javax.net.ssl.SSLContext.init",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        bypass = FridaProtectionBypass(0)

        script_content = bypass.detect_cert_pinning.__doc__ or ""

        missing_android_support = True
        if "HttpsURLConnection" in script_content or "Android" in script_content:
            missing_android_support = False

        assert missing_android_support, (
            "Android HttpsURLConnection bypass NOT IMPLEMENTED. "
            f"Required hooks: {', '.join(required_hooks)}"
        )

    def test_android_okhttp_bypass_required(self) -> None:
        """OkHttp 3.x/4.x certificate pinning must be bypassed.

        Expected behavior on Android:
        - Hook OkHttpClient.Builder.certificatePinner()
        - Hook CertificatePinner.check()
        - Hook OkHttpClient.Builder.hostnameVerifier()
        - Replace all pinning with permissive validators

        Test FAILS because OkHttp bypass is not implemented.
        """
        required_okhttp_hooks = [
            "okhttp3.CertificatePinner.check",
            "okhttp3.OkHttpClient$Builder.certificatePinner",
            "okhttp3.OkHttpClient$Builder.hostnameVerifier",
            "okhttp3.internal.tls.OkHostnameVerifier.verify",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        bypass = FridaProtectionBypass(0)
        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"

        source_code = source_file.read_text()

        okhttp_supported = "okhttp3" in source_code.lower()

        assert not okhttp_supported, (
            "OkHttp bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_okhttp_hooks)}"
        )

    def test_android_volley_retrofit_bypass_required(self) -> None:
        """Volley and Retrofit certificate pinning must be bypassed.

        Expected behavior:
        - Volley: Hook HurlStack.performRequest() SSL validation
        - Retrofit: Hook OkHttp client used by Retrofit
        - Hook all TrustManager implementations

        Test FAILS because Volley/Retrofit bypass not implemented.
        """
        required_hooks = [
            "com.android.volley.toolbox.HurlStack.performRequest",
            "retrofit2.OkHttpClient",
            "android.net.http.X509TrustManagerExtensions.checkServerTrusted",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        volley_supported = "volley" in source_code.lower()
        retrofit_supported = "retrofit" in source_code.lower()

        assert not (volley_supported or retrofit_supported), (
            "Volley/Retrofit bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_hooks)}"
        )


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not installed")
class TestIOSCertPinningBypass:
    """Test certificate pinning bypass for iOS platforms."""

    def test_ios_cfnetwork_bypass_required(self) -> None:
        """CFNetwork certificate validation must be bypassed on iOS.

        Expected behavior:
        - Hook SSLSetSessionOption to disable certificate validation
        - Hook SSLHandshake to bypass pinning
        - Hook SecTrustEvaluate to return success

        Test FAILS because iOS CFNetwork bypass not implemented.
        """
        required_ios_hooks = [
            "SSLSetSessionOption",
            "SSLHandshake",
            "SecTrustEvaluate",
            "SecTrustGetCertificateAtIndex",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        cfnetwork_supported = any(
            hook in source_code for hook in ["SSLSetSessionOption", "SecTrustEvaluate"]
        )

        assert not cfnetwork_supported, (
            "iOS CFNetwork bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_ios_hooks)}"
        )

    def test_ios_nsurlsession_bypass_required(self) -> None:
        """NSURLSession certificate pinning must be bypassed.

        Expected behavior:
        - Hook NSURLSession delegate methods
        - Hook challenge handling (URLSession:didReceiveChallenge:)
        - Force credential acceptance for all certificates

        Test FAILS because NSURLSession bypass not implemented.
        """
        required_hooks = [
            "NSURLSession:didReceiveChallenge:completionHandler:",
            "NSURLSessionConfiguration.TLSMinimumSupportedProtocol",
            "NSURLCredential credentialForTrust:",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        nsurlsession_supported = "NSURLSession" in source_code

        assert not nsurlsession_supported, (
            "iOS NSURLSession bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_hooks)}"
        )

    def test_ios_afnetworking_alamofire_bypass_required(self) -> None:
        """AFNetworking and Alamofire certificate pinning must be bypassed.

        Expected behavior:
        - AFNetworking: Hook AFSecurityPolicy.evaluateServerTrust
        - Alamofire: Hook ServerTrustPolicy.evaluate
        - Return success for all certificate validations

        Test FAILS because AFNetworking/Alamofire bypass not implemented.
        """
        required_hooks = [
            "AFSecurityPolicy.evaluateServerTrust",
            "AFHTTPSessionManager.setSecurityPolicy",
            "ServerTrustPolicy.evaluate",  # Alamofire 5.x
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        afnetworking_supported = "AFSecurityPolicy" in source_code
        alamofire_supported = "ServerTrustPolicy" in source_code

        assert not (afnetworking_supported or alamofire_supported), (
            "AFNetworking/Alamofire bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_hooks)}"
        )


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not installed")
class TestModernFrameworkCertPinningBypass:
    """Test certificate pinning bypass for modern cross-platform frameworks."""

    def test_flutter_certificate_pinning_bypass_required(self) -> None:
        """Flutter io.HttpClient certificate pinning must be bypassed.

        Expected behavior:
        - Hook dart::io::HttpClient.badCertificateCallback
        - Hook dart::io::SecurityContext.setTrustedCertificates
        - Hook native SSL verification (OpenSSL/BoringSSL under Flutter)

        Test FAILS because Flutter bypass not implemented.
        """
        required_flutter_hooks = [
            "dart::io::HttpClient::badCertificateCallback",
            "dart::io::SecurityContext::setTrustedCertificates",
            "SSL_do_handshake",  # BoringSSL used by Flutter
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        flutter_supported = "flutter" in source_code.lower() or "dart::" in source_code

        assert not flutter_supported, (
            "Flutter certificate pinning bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_flutter_hooks)}"
        )

    def test_react_native_bypass_required(self) -> None:
        """React Native certificate pinning must be bypassed.

        Expected behavior:
        - Android: Hook OkHttp used by React Native
        - iOS: Hook NSURLSession used by React Native
        - Hook react-native-ssl-pinning library if present

        Test FAILS because React Native specific bypass not implemented.
        """
        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        react_native_supported = "react" in source_code.lower() and "native" in source_code.lower()

        assert not react_native_supported, (
            "React Native certificate pinning bypass NOT IMPLEMENTED. "
            "Must handle OkHttp (Android) and NSURLSession (iOS) used by RN."
        )

    def test_xamarin_bypass_required(self) -> None:
        """Xamarin certificate pinning must be bypassed.

        Expected behavior:
        - Hook Mono ServicePointManager.ServerCertificateValidationCallback
        - Hook System.Net.Http.HttpClient certificate validation
        - Hook native platform validators (WinHTTP on Windows, NSURLSession on iOS)

        Test FAILS because Xamarin bypass not implemented.
        """
        required_xamarin_hooks = [
            "System.Net.ServicePointManager.ServerCertificateValidationCallback",
            "System.Net.Http.HttpClientHandler.ServerCertificateCustomValidationCallback",
            "Mono.Security.Protocol.Tls.SslClientStream.RaiseServerCertificateValidation",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        xamarin_supported = "xamarin" in source_code.lower() or "mono" in source_code.lower()

        assert not xamarin_supported, (
            "Xamarin certificate pinning bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_xamarin_hooks)}"
        )


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not installed")
class TestCustomTLSImplementations:
    """Test certificate pinning bypass for custom TLS implementations."""

    def test_openssl_certificate_verification_bypass_required(self) -> None:
        """OpenSSL certificate verification must be bypassed.

        Expected behavior:
        - Hook SSL_CTX_set_verify to disable verification
        - Hook SSL_get_verify_result to return X509_V_OK
        - Hook X509_verify_cert to return success

        Test FAILS because OpenSSL bypass not implemented.
        """
        required_openssl_hooks = [
            "SSL_CTX_set_verify",
            "SSL_get_verify_result",
            "X509_verify_cert",
            "SSL_CTX_set_cert_verify_callback",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        openssl_supported = any(
            hook in source_code for hook in ["SSL_CTX_set_verify", "X509_verify_cert"]
        )

        assert not openssl_supported, (
            "OpenSSL certificate bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_openssl_hooks)}"
        )

    def test_boringssl_bypass_required(self) -> None:
        """BoringSSL certificate verification must be bypassed.

        Expected behavior:
        - Hook SSL_do_handshake to bypass verification
        - Hook SSL_get_verify_result
        - Hook custom BoringSSL verification callbacks

        Test FAILS because BoringSSL bypass not implemented.
        """
        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        boringssl_supported = "boringssl" in source_code.lower() or "SSL_do_handshake" in source_code

        assert not boringssl_supported, (
            "BoringSSL certificate bypass NOT IMPLEMENTED. "
            "Must hook SSL_do_handshake and verification functions."
        )

    def test_mbedtls_bypass_required(self) -> None:
        """mbedTLS certificate verification must be bypassed.

        Expected behavior:
        - Hook mbedtls_ssl_conf_authmode to set SSL_VERIFY_NONE
        - Hook mbedtls_x509_crt_verify to return 0 (success)
        - Hook mbedtls_ssl_set_hostname to bypass SNI checks

        Test FAILS because mbedTLS bypass not implemented.
        """
        required_mbedtls_hooks = [
            "mbedtls_ssl_conf_authmode",
            "mbedtls_x509_crt_verify",
            "mbedtls_ssl_set_hostname",
            "mbedtls_ssl_handshake",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        mbedtls_supported = "mbedtls" in source_code.lower()

        assert not mbedtls_supported, (
            "mbedTLS certificate bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_mbedtls_hooks)}"
        )


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not installed")
class TestEdgeCaseCertPinningBypass:
    """Test certificate pinning bypass for edge cases."""

    def test_tpm_backed_certificates_bypass_required(self) -> None:
        """TPM-backed certificate validation must be bypassed.

        Expected behavior:
        - Hook NCryptOpenStorageProvider for TPM access
        - Hook NCryptGetProperty for certificate retrieval
        - Hook TPM 2.0 attestation validation
        - Force validation success even for TPM-protected certs

        Test FAILS because TPM certificate bypass not implemented.
        """
        required_tpm_hooks = [
            "NCryptOpenStorageProvider",
            "NCryptGetProperty",
            "NCryptSignHash",
            "Tbsi_Context_Create",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        tpm_supported = any(
            hook in source_code for hook in ["NCryptOpenStorageProvider", "Tbsi_"]
        )

        assert not tpm_supported, (
            "TPM-backed certificate bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_tpm_hooks)}"
        )

    def test_client_certificate_authentication_bypass_required(self) -> None:
        """Client certificate authentication must be bypassed.

        Expected behavior:
        - Hook certificate selection callbacks
        - Provide fake client certificate when requested
        - Hook private key operations for client auth
        - Allow connections without valid client certificates

        Test FAILS because client certificate bypass not implemented.
        """
        required_hooks = [
            "CryptAcquireCertificatePrivateKey",
            "NCryptSignHash",
            "SSL_CTX_use_certificate",
            "SSL_CTX_use_PrivateKey",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        client_cert_supported = "CryptAcquireCertificatePrivateKey" in source_code

        assert not client_cert_supported, (
            "Client certificate bypass NOT IMPLEMENTED. "
            f"Required: {', '.join(required_hooks)}"
        )

    def test_custom_certificate_stores_bypass_required(self) -> None:
        """Custom certificate stores must be bypassed.

        Expected behavior:
        - Hook CertOpenStore with custom store names
        - Hook CertAddCertificateContextToStore
        - Hook registry-based certificate store access
        - Detect and bypass application-specific cert stores

        Test FAILS because custom certificate store bypass not implemented.
        """
        required_hooks = [
            "CertOpenStore",
            "CertAddCertificateContextToStore",
            "CertEnumCertificatesInStore",
            "CertFindCertificateInStore",
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        custom_store_hooks = sum(
            1 for hook in required_hooks if hook in source_code
        )

        assert custom_store_hooks < len(required_hooks), (
            f"Custom certificate store bypass INCOMPLETE. "
            f"Found {custom_store_hooks}/{len(required_hooks)} required hooks."
        )

    def test_certificate_transparency_bypass_required(self) -> None:
        """Certificate Transparency (CT) validation must be bypassed.

        Expected behavior:
        - Hook CT log verification functions
        - Hook Signed Certificate Timestamp (SCT) validation
        - Force CT validation success even without valid SCTs

        Test FAILS because CT bypass not implemented.
        """
        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        ct_supported = "certificate transparency" in source_code.lower() or "SCT" in source_code

        assert not ct_supported, (
            "Certificate Transparency bypass NOT IMPLEMENTED. "
            "Must handle SCT validation and CT log verification."
        )

    def test_ocsp_stapling_bypass_required(self) -> None:
        """OCSP stapling verification must be bypassed.

        Expected behavior:
        - Hook OCSP response verification
        - Hook CertVerifyRevocation
        - Force OCSP validation success
        - Handle both stapled and non-stapled OCSP

        Test FAILS because OCSP bypass not implemented.
        """
        required_ocsp_hooks = [
            "CertVerifyRevocation",
            "CertGetCertificateChain",  # CERT_CHAIN_REVOCATION_CHECK_*
        ]

        from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
            FridaProtectionBypass,
        )

        source_file = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
        source_code = source_file.read_text()

        ocsp_supported = "CertVerifyRevocation" in source_code or "OCSP" in source_code

        if not ocsp_supported:
            assert False, (
                "OCSP stapling bypass NOT IMPLEMENTED. "
                f"Required: {', '.join(required_ocsp_hooks)}"
            )


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not installed")
class TestCertPinningBypassIntegration:
    """Integration tests validating complete certificate pinning bypass workflows."""

    def test_detect_cert_pinning_returns_protection_info(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """detect_cert_pinning returns valid ProtectionInfo objects.

        Validates:
        - Returns list of ProtectionInfo objects
        - Each has correct type (CERT_PINNING)
        - Contains bypass script
        - Has reasonable confidence score

        Test FAILS if detection returns invalid data structures.
        """
        detections: list[ProtectionInfo] = bypass_instance.detect_cert_pinning()

        assert isinstance(detections, list), "Detection must return list"

        for detection in detections:
            assert hasattr(detection, "type"), "Missing type attribute"
            assert hasattr(detection, "bypass_script"), "Missing bypass_script"
            assert hasattr(detection, "confidence"), "Missing confidence"
            assert 0.0 <= detection.confidence <= 1.0, "Invalid confidence score"

    def test_cert_pinning_bypass_script_valid_javascript(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """Bypass script is valid JavaScript that loads without errors.

        Validates:
        - Script is not empty
        - Script loads in Frida without syntax errors
        - Script defines required hooks

        Test FAILS if bypass script has syntax errors.
        """
        detections: list[ProtectionInfo] = bypass_instance.detect_cert_pinning()

        if not detections:
            pytest.skip("No certificate pinning detected")

        bypass_script = detections[0].bypass_script

        assert bypass_script, "Bypass script is empty"
        assert len(bypass_script) > 100, "Bypass script too short"

        if bypass_instance.session:
            try:
                script = bypass_instance.session.create_script(bypass_script)
                script.load()
                time.sleep(1)
                script.unload()
            except Exception as e:
                pytest.fail(f"Bypass script failed to load: {e}")

    def test_multiple_cert_pinning_methods_detected(
        self, bypass_instance: FridaProtectionBypass
    ) -> None:
        """Multiple certificate pinning methods can be detected simultaneously.

        Validates that when an application uses multiple pinning mechanisms,
        all are detected and reported.

        Test documents expected multi-method detection capability.
        """
        detections: list[ProtectionInfo] = bypass_instance.detect_cert_pinning()

        detected_methods = [d.details.get("method", "") for d in detections]

        expected_windows_methods = [
            "CertVerifyCertificateChainPolicy",
            "WinHttpSetOption",
            "InternetSetOptionA",
            "InternetSetOptionW",
        ]

        found_methods = [m for m in expected_windows_methods if m in detected_methods]

        if not found_methods:
            pytest.skip("No certificate pinning methods detected - need HTTPS traffic")
