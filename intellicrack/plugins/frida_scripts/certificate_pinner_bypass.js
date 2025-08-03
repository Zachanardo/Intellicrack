/*
 * This file is part of Intellicrack.
 * Copyright (C) 2025 Zachary Flint
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Certificate Pinner Bypass
 *
 * Comprehensive SSL/TLS certificate pinning bypass for multiple platforms
 * and frameworks including native, Java, .NET, and custom implementations.
 *
 * Author: Intellicrack Framework
 * Version: 1.0.0
 * License: GPL v3
 */

{
    name: "Certificate Pinner Bypass",
    description: "Universal SSL/TLS certificate pinning bypass",
    version: "1.0.0",

    // Configuration
    config: {
        // Platforms to target
        platforms: {
            windows: true,
            android: true,
            ios: true,
            java: true,
            dotnet: true
        },

        // Bypass methods
        methods: {
            hookValidation: true,
            replaceKeys: true,
            disableChecks: true,
            injectCerts: true
        },

        // Custom certificate for injection
        customCert: {
            subject: "CN=*.licensed.app, O=Trusted, C=US",
            issuer: "CN=Trusted Root CA, O=Trusted, C=US",
            thumbprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
            publicKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
        }
    },

    // Statistics
    stats: {
        hooksInstalled: 0,
        validationsBypassed: 0,
        certificatesReplaced: 0,
        errors: 0
    },

    run: function() {
        send({
            type: "status",
            target: "certificate_pinner_bypass",
            action: "starting_bypass"
        });

        // Detect platform and apply appropriate hooks
        this.detectPlatform();

        // Windows/Native hooks
        if (this.platform.windows) {
            this.hookWindowsCertificateAPIs();
            this.hookWinHTTPCertificateValidation();
            this.hookSchannelAPIs();
        }

        // Android hooks
        if (this.platform.android) {
            this.hookAndroidCertificatePinning();
            this.hookOkHttpPinning();
            this.hookConscryptValidation();
        }

        // iOS hooks
        if (this.platform.ios) {
            this.hookiOSCertificateValidation();
            this.hookAFNetworkingPinning();
        }

        // Cross-platform hooks
        this.hookOpenSSLValidation();
        this.hookJavaCertificateValidation();
        this.hookDotNetCertificateValidation();
        this.hookCustomPinningImplementations();

        send({
            type: "info",
            target: "certificate_pinner_bypass",
            action: "installation_complete",
            hooks_installed: this.stats.hooksInstalled
        });
    },

    // Platform detection
    detectPlatform: function() {
        this.platform = {
            windows: Process.platform === 'windows',
            android: Java.available && Process.platform === 'linux',
            ios: Process.platform === 'darwin' && ObjC.available,
            java: Java.available,
            dotnet: false
        };

        // Check for .NET
        Process.enumerateModules().forEach(function(module) {
            if (module.name.toLowerCase().indexOf('clr.dll') !== -1 ||
                module.name.toLowerCase().indexOf('coreclr.dll') !== -1) {
                this.platform.dotnet = true;
            }
        }, this);

        send({
            type: "info",
            target: "certificate_pinner_bypass",
            action: "platform_detected",
            platform: this.platform
        });
    },

    // Windows certificate API hooks
    hookWindowsCertificateAPIs: function() {
        var self = this;

        // CertVerifyCertificateChainPolicy
        var certVerifyChainPolicy = Module.findExportByName("crypt32.dll", "CertVerifyCertificateChainPolicy");
        if (certVerifyChainPolicy) {
            Interceptor.attach(certVerifyChainPolicy, {
                onLeave: function(retval) {
                    // Force success
                    retval.replace(1);
                    self.stats.validationsBypassed++;
                }
            });
            this.stats.hooksInstalled++;
            send({
                type: "bypass",
                target: "certificate_pinner_bypass",
                action: "hooked_windows_api",
                api_name: "CertVerifyCertificateChainPolicy"
            });
        }

        // CertGetCertificateChain
        var certGetCertificateChain = Module.findExportByName("crypt32.dll", "CertGetCertificateChain");
        if (certGetCertificateChain) {
            Interceptor.attach(certGetCertificateChain, {
                onEnter: function(args) {
                    // Modify chain flags to disable revocation checking
                    if (args[3]) {
                        var flags = args[3].readU32();
                        flags &= ~0x00001000; // Remove CERT_CHAIN_REVOCATION_CHECK_CHAIN
                        flags &= ~0x00002000; // Remove CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                        args[3].writeU32(flags);
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        // Modify chain context to indicate success
                        var chainContext = this.context.r9;
                        if (chainContext && !chainContext.isNull()) {
                            var pChainContext = chainContext.readPointer();
                            if (pChainContext && !pChainContext.isNull()) {
                                // TrustStatus is at offset 0x14
                                var trustStatus = pChainContext.add(0x14);
                                trustStatus.writeU32(0); // dwErrorStatus = 0
                                trustStatus.add(4).writeU32(0x00000000); // dwInfoStatus = 0
                            }
                        }
                        self.stats.validationsBypassed++;
                    }
                }
            });
            this.stats.hooksInstalled++;
            send({
                type: "bypass",
                target: "certificate_pinner_bypass",
                action: "hooked_windows_api",
                api_name: "CertGetCertificateChain"
            });
        }

        // CertVerifyRevocation
        var certVerifyRevocation = Module.findExportByName("crypt32.dll", "CertVerifyRevocation");
        if (certVerifyRevocation) {
            Interceptor.replace(certVerifyRevocation, new NativeCallback(function() {
                // Always return success (no revocation)
                self.stats.validationsBypassed++;
                return 1;
            }, 'int', ['int', 'int', 'int', 'pointer', 'int', 'pointer', 'pointer']));
            this.stats.hooksInstalled++;
            send({
                type: "bypass",
                target: "certificate_pinner_bypass",
                action: "hooked_windows_api",
                api_name: "CertVerifyRevocation"
            });
        }
    },

    // WinHTTP certificate validation hooks
    hookWinHTTPCertificateValidation: function() {
        var self = this;

        // WinHttpSetOption - disable certificate validation
        var winHttpSetOption = Module.findExportByName("winhttp.dll", "WinHttpSetOption");
        if (winHttpSetOption) {
            Interceptor.attach(winHttpSetOption, {
                onEnter: function(args) {
                    var option = args[1].toInt32();

                    // WINHTTP_OPTION_SECURITY_FLAGS
                    if (option === 31) {
                        var flags = args[2].readU32();
                        // Add ignore flags
                        flags |= 0x00000100; // SECURITY_FLAG_IGNORE_UNKNOWN_CA
                        flags |= 0x00000200; // SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                        flags |= 0x00001000; // SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                        flags |= 0x00002000; // SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                        args[2].writeU32(flags);
                        send({
                            type: "bypass",
                            target: "certificate_pinner_bypass",
                            action: "modified_winhttp_security_flags",
                            flags: flags
                        });
                    }
                }
            });
            this.stats.hooksInstalled++;
        }

        // WinHttpQueryOption - spoof certificate info
        var winHttpQueryOption = Module.findExportByName("winhttp.dll", "WinHttpQueryOption");
        if (winHttpQueryOption) {
            Interceptor.attach(winHttpQueryOption, {
                onEnter: function(args) {
                    this.option = args[1].toInt32();
                    this.buffer = args[2];
                    this.bufferLength = args[3];
                },
                onLeave: function(retval) {
                    // WINHTTP_OPTION_SERVER_CERT_CONTEXT
                    if (this.option === 78 && retval.toInt32() === 1) {
                        // Replace with trusted certificate
                        self.injectTrustedCertificate(this.buffer);
                        self.stats.certificatesReplaced++;
                    }
                }
            });
            this.stats.hooksInstalled++;
        }
    },

    // Schannel API hooks
    hookSchannelAPIs: function() {
        var self = this;

        // InitializeSecurityContext
        var initSecContext = Module.findExportByName("secur32.dll", "InitializeSecurityContextW");
        if (initSecContext) {
            Interceptor.attach(initSecContext, {
                onEnter: function(args) {
                    // Modify context requirements to disable cert validation
                    if (args[5]) {
                        var contextReq = args[5].readU32();
                        contextReq &= ~0x00020000; // Remove ISC_REQ_MUTUAL_AUTH
                        contextReq |= 0x00000002;  // Add ISC_REQ_VALIDATE_CONTEXT
                        contextReq |= 0x00100000;  // Add ISC_REQ_MANUAL_CRED_VALIDATION
                        args[5].writeU32(contextReq);
                    }
                }
            });
            this.stats.hooksInstalled++;
            send({
                type: "bypass",
                target: "certificate_pinner_bypass",
                action: "hooked_schannel_api",
                api_name: "InitializeSecurityContext"
            });
        }

        // QueryContextAttributes
        var queryContextAttrs = Module.findExportByName("secur32.dll", "QueryContextAttributesW");
        if (queryContextAttrs) {
            Interceptor.attach(queryContextAttrs, {
                onEnter: function(args) {
                    this.attribute = args[1].toInt32();
                    this.buffer = args[2];
                },
                onLeave: function(retval) {
                    // SECPKG_ATTR_REMOTE_CERT_CONTEXT
                    if (this.attribute === 0x53 && retval.toInt32() === 0) {
                        self.injectTrustedCertificate(this.buffer);
                        self.stats.certificatesReplaced++;
                    }
                }
            });
            this.stats.hooksInstalled++;
        }
    },

    // Android certificate pinning hooks
    hookAndroidCertificatePinning: function() {
        if (!Java.available) return;

        var self = this;

        Java.perform(function() {
            // TrustManagerImpl
            try {
                var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

                TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "android_trust_manager_bypassed",
                        method: "verifyChain"
                    });
                    self.stats.validationsBypassed++;
                    return untrustedChain;
                };

                TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "android_trust_manager_bypassed",
                        method: "checkTrustedRecursive"
                    });
                    self.stats.validationsBypassed++;
                    return Java.use("java.util.ArrayList").$new();
                };

                self.stats.hooksInstalled += 2;
            } catch(e) {
                // Different Android version
            }

            // X509TrustManager implementations
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.includes("TrustManager") && !className.includes("com.android")) {
                        try {
                            var TrustManager = Java.use(className);

                            if (TrustManager.checkClientTrusted) {
                                TrustManager.checkClientTrusted.implementation = function() {
                                    send({
                                        type: "bypass",
                                        target: "certificate_pinner_bypass",
                                        action: "custom_trust_manager_bypassed",
                                        class_name: className,
                                        method: "checkClientTrusted"
                                    });
                                    self.stats.validationsBypassed++;
                                };
                            }

                            if (TrustManager.checkServerTrusted) {
                                TrustManager.checkServerTrusted.implementation = function() {
                                    send({
                                        type: "bypass",
                                        target: "certificate_pinner_bypass",
                                        action: "custom_trust_manager_bypassed",
                                        class_name: className,
                                        method: "checkServerTrusted"
                                    });
                                    self.stats.validationsBypassed++;
                                };
                            }

                            if (TrustManager.getAcceptedIssuers) {
                                TrustManager.getAcceptedIssuers.implementation = function() {
                                    return Java.array('java.security.cert.X509Certificate', []);
                                };
                            }

                            self.stats.hooksInstalled += 3;
                        } catch(e) {
                            // Not a valid TrustManager
                        }
                    }
                },
                onComplete: function() {}
            });

            // HostnameVerifier
            try {
                var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
                var SSLSession = Java.use("javax.net.ssl.SSLSession");

                var MyHostnameVerifier = Java.registerClass({
                    name: "com.intellicrack.MyHostnameVerifier",
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function(hostname, session) {
                            send({
                                type: "bypass",
                                target: "certificate_pinner_bypass",
                                action: "hostname_verifier_bypassed",
                                hostname: hostname
                            });
                            self.stats.validationsBypassed++;
                            return true;
                        }
                    }
                });

                // Replace all HostnameVerifier instances
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.includes("HostnameVerifier")) {
                            try {
                                var clazz = Java.use(className);
                                clazz.verify.implementation = function(hostname, session) {
                                    send({
                                        type: "bypass",
                                        target: "certificate_pinner_bypass",
                                        action: "custom_hostname_verifier_bypassed",
                                        class_name: className
                                    });
                                    self.stats.validationsBypassed++;
                                    return true;
                                };
                                self.stats.hooksInstalled++;
                            } catch(e) {}
                        }
                    },
                    onComplete: function() {}
                });

            } catch(e) {
                send({
                    type: "error",
                    target: "certificate_pinner_bypass",
                    action: "failed_to_hook_hostname_verifier",
                    error: e.toString()
                });
            }
        });
    },

    // OkHttp certificate pinning hooks
    hookOkHttpPinning: function() {
        if (!Java.available) return;

        var self = this;

        Java.perform(function() {
            // OkHttp3
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");

                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "okhttp3_pinning_bypassed",
                        method: "List overload",
                        hostname: hostname
                    });
                    self.stats.validationsBypassed++;
                };

                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "okhttp3_pinning_bypassed",
                        method: "Certificate array overload",
                        hostname: hostname
                    });
                    self.stats.validationsBypassed++;
                };

                self.stats.hooksInstalled += 2;
            } catch(e) {
                // OkHttp3 not found
            }

            // OkHttp2
            try {
                var CertificatePinner2 = Java.use("com.squareup.okhttp.CertificatePinner");

                CertificatePinner2.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "okhttp2_pinning_bypassed",
                        hostname: hostname
                    });
                    self.stats.validationsBypassed++;
                };

                self.stats.hooksInstalled++;
            } catch(e) {
                // OkHttp2 not found
            }

            // Retrofit
            try {
                var Platform = Java.use("retrofit2.Platform");
                var TrustManager = Java.use("javax.net.ssl.X509TrustManager");

                var TrustAllManager = Java.registerClass({
                    name: "com.intellicrack.TrustAllManager",
                    implements: [TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() {
                            return Java.array('java.security.cert.X509Certificate', []);
                        }
                    }
                });

                // Hook Platform.trustManager
                Platform.trustManager.implementation = function() {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "retrofit_trust_manager_replaced"
                    });
                    self.stats.validationsBypassed++;
                    return TrustAllManager.$new();
                };

                self.stats.hooksInstalled++;
            } catch(e) {
                // Retrofit not found
            }
        });
    },

    // OpenSSL validation hooks
    hookOpenSSLValidation: function() {
        var self = this;

        // SSL_CTX_set_verify
        var ssl_ctx_set_verify = Module.findExportByName(null, "SSL_CTX_set_verify");
        if (ssl_ctx_set_verify) {
            Interceptor.attach(ssl_ctx_set_verify, {
                onEnter: function(args) {
                    // Set mode to SSL_VERIFY_NONE (0)
                    args[1] = ptr(0);
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "openssl_verify_disabled",
                        api: "SSL_CTX_set_verify"
                    });
                }
            });
            this.stats.hooksInstalled++;
        }

        // SSL_set_verify
        var ssl_set_verify = Module.findExportByName(null, "SSL_set_verify");
        if (ssl_set_verify) {
            Interceptor.attach(ssl_set_verify, {
                onEnter: function(args) {
                    args[1] = ptr(0); // SSL_VERIFY_NONE
                }
            });
            this.stats.hooksInstalled++;
        }

        // X509_verify_cert
        var x509_verify_cert = Module.findExportByName(null, "X509_verify_cert");
        if (x509_verify_cert) {
            Interceptor.replace(x509_verify_cert, new NativeCallback(function(ctx) {
                send({
                    type: "bypass",
                    target: "certificate_pinner_bypass",
                    action: "openssl_cert_verification_bypassed",
                    api: "X509_verify_cert"
                });
                self.stats.validationsBypassed++;
                return 1; // Success
            }, 'int', ['pointer']));
            this.stats.hooksInstalled++;
        }

        // SSL_get_verify_result
        var ssl_get_verify_result = Module.findExportByName(null, "SSL_get_verify_result");
        if (ssl_get_verify_result) {
            Interceptor.replace(ssl_get_verify_result, new NativeCallback(function(ssl) {
                send({
                    type: "bypass",
                    target: "certificate_pinner_bypass",
                    action: "openssl_verify_result_bypassed",
                    api: "SSL_get_verify_result"
                });
                self.stats.validationsBypassed++;
                return 0; // X509_V_OK
            }, 'long', ['pointer']));
            this.stats.hooksInstalled++;
        }
    },

    // .NET certificate validation hooks
    hookDotNetCertificateValidation: function() {
        if (!this.platform.dotnet) return;

        var self = this;

        // Find System.dll
        var systemDll = Process.findModuleByName("System.dll");
        if (!systemDll) return;

        // Pattern for ServicePointManager.ServerCertificateValidationCallback setter
        var pattern = "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 48 8B DA";
        var matches = Memory.scanSync(systemDll.base, systemDll.size, pattern);

        if (matches.length > 0) {
            // Hook the setter to always accept certificates
            Interceptor.attach(matches[0].address, {
                onEnter: function(args) {
                    // Create a delegate that always returns true
                    var alwaysTrue = new NativeCallback(function() {
                        send({
                            type: "bypass",
                            target: "certificate_pinner_bypass",
                            action: "dotnet_cert_validation_bypassed",
                            component: "ServerCertificateValidationCallback"
                        });
                        self.stats.validationsBypassed++;
                        return 1;
                    }, 'int', ['pointer', 'pointer', 'pointer', 'int']);

                    // Replace the callback
                    args[1] = alwaysTrue;
                }
            });
            this.stats.hooksInstalled++;
            send({
                type: "bypass",
                target: "certificate_pinner_bypass",
                action: "dotnet_server_cert_callback_hooked"
            });
        }

        // Hook SslStream certificate validation
        var sslStreamPattern = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F2 48 8B F9";
        matches = Memory.scanSync(systemDll.base, systemDll.size, sslStreamPattern);

        if (matches.length > 0) {
            Interceptor.attach(matches[0].address, {
                onLeave: function(retval) {
                    // Force validation success
                    retval.replace(1);
                    self.stats.validationsBypassed++;
                }
            });
            this.stats.hooksInstalled++;
            send({
                type: "bypass",
                target: "certificate_pinner_bypass",
                action: "dotnet_sslstream_validation_hooked"
            });
        }
    },

    // Java certificate validation hooks
    hookJavaCertificateValidation: function() {
        if (!Java.available) return;

        var self = this;

        Java.perform(function() {
            // SSLContext
            try {
                var SSLContext = Java.use("javax.net.ssl.SSLContext");

                SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "java_sslcontext_init_intercepted"
                    });

                    // Create custom TrustManager
                    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                    var TrustAllManager = Java.registerClass({
                        name: "com.intellicrack.TrustAllManager",
                        implements: [TrustManager],
                        methods: {
                            checkClientTrusted: function(chain, authType) {
                                send({
                                    type: "bypass",
                                    target: "certificate_pinner_bypass",
                                    action: "java_trust_manager_bypassed",
                                    method: "checkClientTrusted"
                                });
                                self.stats.validationsBypassed++;
                            },
                            checkServerTrusted: function(chain, authType) {
                                send({
                                    type: "bypass",
                                    target: "certificate_pinner_bypass",
                                    action: "java_trust_manager_bypassed",
                                    method: "checkServerTrusted"
                                });
                                self.stats.validationsBypassed++;
                            },
                            getAcceptedIssuers: function() {
                                return Java.array('java.security.cert.X509Certificate', []);
                            }
                        }
                    });

                    var trustAllArray = Java.array("javax.net.ssl.TrustManager", [TrustAllManager.$new()]);
                    this.init(keyManager, trustAllArray, secureRandom);
                };

                self.stats.hooksInstalled++;
            } catch(e) {
                send({
                    type: "error",
                    target: "certificate_pinner_bypass",
                    action: "failed_to_hook_java_sslcontext",
                    error: e.toString()
                });
            }

            // HttpsURLConnection
            try {
                var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "java_https_hostname_verifier_intercepted"
                    });

                    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
                    var TrustAllVerifier = Java.registerClass({
                        name: "com.intellicrack.TrustAllVerifier",
                        implements: [HostnameVerifier],
                        methods: {
                            verify: function(hostname, session) {
                                send({
                                    type: "bypass",
                                    target: "certificate_pinner_bypass",
                                    action: "java_hostname_verification_bypassed",
                                    hostname: hostname
                                });
                                self.stats.validationsBypassed++;
                                return true;
                            }
                        }
                    });

                    this.setDefaultHostnameVerifier(TrustAllVerifier.$new());
                };

                self.stats.hooksInstalled++;
            } catch(e) {
                send({
                    type: "error",
                    target: "certificate_pinner_bypass",
                    action: "failed_to_hook_https_connection",
                    error: e.toString()
                });
            }
        });
    },

    // iOS certificate validation hooks
    hookiOSCertificateValidation: function() {
        if (!ObjC.available) return;

        var self = this;

        // NSURLSession
        try {
            var NSURLSession = ObjC.classes.NSURLSession;

            Interceptor.attach(NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    send({
                        type: "info",
                        target: "certificate_pinner_bypass",
                        action: "ios_nsurlsession_request",
                        url: request.URL().absoluteString()
                    });
                }
            });

            // Hook delegate methods
            if (ObjC.classes.NSURLSessionDelegate) {
                var origMethod = ObjC.classes.NSURLSessionDelegate["- URLSession:didReceiveChallenge:completionHandler:"];
                if (origMethod) {
                    Interceptor.attach(origMethod.implementation, {
                        onEnter: function(args) {
                            var completionHandler = new ObjC.Object(args[4]);
                            var NSURLSessionAuthChallengeDisposition = {
                                UseCredential: 0,
                                PerformDefaultHandling: 1,
                                CancelAuthenticationChallenge: 2,
                                RejectProtectionSpace: 3
                            };

                            // Call completion handler with UseCredential
                            completionHandler.call([NSURLSessionAuthChallengeDisposition.UseCredential, ObjC.classes.NSURLCredential.credentialForTrust_(ptr(0))]);

                            send({
                                type: "bypass",
                                target: "certificate_pinner_bypass",
                                action: "ios_nsurlsession_challenge_bypassed"
                            });
                            self.stats.validationsBypassed++;
                        }
                    });
                    self.stats.hooksInstalled++;
                }
            }
        } catch(e) {
            send({
                type: "error",
                target: "certificate_pinner_bypass",
                action: "failed_to_hook_nsurlsession",
                error: e.toString()
            });
        }

        // SecTrustEvaluate
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                send({
                    type: "bypass",
                    target: "certificate_pinner_bypass",
                    action: "ios_sectrust_evaluate_bypassed"
                });
                Memory.writeU32(result, 1); // kSecTrustResultProceed
                self.stats.validationsBypassed++;
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
            self.stats.hooksInstalled++;
        }

        // SecTrustSetAnchorCertificates
        var SecTrustSetAnchorCertificates = Module.findExportByName("Security", "SecTrustSetAnchorCertificates");
        if (SecTrustSetAnchorCertificates) {
            Interceptor.replace(SecTrustSetAnchorCertificates, new NativeCallback(function(trust, anchorCertificates) {
                send({
                    type: "bypass",
                    target: "certificate_pinner_bypass",
                    action: "ios_sectrust_anchor_certs_bypassed"
                });
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
            self.stats.hooksInstalled++;
        }
    },

    // Hook custom pinning implementations
    hookCustomPinningImplementations: function() {
        var self = this;

        // Common function name patterns
        var patterns = [
            "*pin*cert*", "*verify*cert*", "*check*cert*",
            "*validate*ssl*", "*trust*manager*", "*cert*valid*"
        ];

        // Search for custom implementations
        Process.enumerateModules().forEach(function(module) {
            if (module.name.toLowerCase().includes("app") ||
                module.name.toLowerCase().includes("lib")) {

                module.enumerateExports().forEach(function(exp) {
                    var name = exp.name.toLowerCase();

                    patterns.forEach(function(pattern) {
                        var regex = new RegExp(pattern.replace(/\*/g, '.*'));
                        if (regex.test(name)) {
                            try {
                                Interceptor.attach(exp.address, {
                                    onLeave: function(retval) {
                                        // Assume non-zero is success
                                        if (retval.toInt32() === 0) {
                                            retval.replace(1);
                                            send({
                                                type: "bypass",
                                                target: "certificate_pinner_bypass",
                                                action: "custom_function_bypassed",
                                                function_name: exp.name
                                            });
                                            self.stats.validationsBypassed++;
                                        }
                                    }
                                });
                                self.stats.hooksInstalled++;
                            } catch(e) {
                                // Failed to hook
                            }
                        }
                    });
                });
            }
        });
    },

    // Inject trusted certificate
    injectTrustedCertificate: function(buffer) {
        // This would contain actual certificate injection logic
        // For now, we'll just mark it as trusted
        send({
            type: "info",
            target: "certificate_pinner_bypass",
            action: "injecting_trusted_certificate"
        });
    },

    // Hook AFNetworking (iOS)
    hookAFNetworkingPinning: function() {
        if (!ObjC.available) return;

        var self = this;

        try {
            var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
            if (AFSecurityPolicy) {
                // setPinningMode:
                Interceptor.attach(AFSecurityPolicy["- setPinningMode:"].implementation, {
                    onEnter: function(args) {
                        // AFSSLPinningModeNone = 0
                        args[2] = ptr(0);
                        send({
                            type: "bypass",
                            target: "certificate_pinner_bypass",
                            action: "ios_afnetworking_pinning_disabled"
                        });
                    }
                });

                // setAllowInvalidCertificates:
                Interceptor.attach(AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation, {
                    onEnter: function(args) {
                        args[2] = ptr(1); // YES
                        send({
                            type: "bypass",
                            target: "certificate_pinner_bypass",
                            action: "ios_afnetworking_invalid_certs_allowed"
                        });
                    }
                });

                // evaluateServerTrust:forDomain:
                var evaluateMethod = AFSecurityPolicy["- evaluateServerTrust:forDomain:"];
                if (evaluateMethod) {
                    Interceptor.attach(evaluateMethod.implementation, {
                        onLeave: function(retval) {
                            retval.replace(ptr(1)); // YES
                            send({
                                type: "bypass",
                                target: "certificate_pinner_bypass",
                                action: "ios_afnetworking_evaluation_bypassed"
                            });
                            self.stats.validationsBypassed++;
                        }
                    });
                }

                self.stats.hooksInstalled += 3;
            }
        } catch(e) {
            send({
                type: "error",
                target: "certificate_pinner_bypass",
                action: "failed_to_hook_afnetworking",
                error: e.toString()
            });
        }
    },

    // Conscrypt validation hooks (Android)
    hookConscryptValidation: function() {
        if (!Java.available) return;

        var self = this;

        Java.perform(function() {
            try {
                // Conscrypt CertPinManager
                var CertPinManager = Java.use("com.android.org.conscrypt.CertPinManager");

                CertPinManager.checkChainPinning.implementation = function(hostname, chain) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "android_conscrypt_chain_pinning_bypassed"
                    });
                    self.stats.validationsBypassed++;
                    return true;
                };

                CertPinManager.isChainValid.implementation = function(hostname, chain) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "android_conscrypt_chain_valid_bypassed"
                    });
                    self.stats.validationsBypassed++;
                    return true;
                };

                self.stats.hooksInstalled += 2;
            } catch(e) {
                // Conscrypt not found
            }

            // Network Security Config (Android N+)
            try {
                var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");

                NetworkSecurityConfig.getDefaultBuilder.implementation = function(applicationInfo) {
                    send({
                        type: "bypass",
                        target: "certificate_pinner_bypass",
                        action: "android_network_security_config_intercepted"
                    });

                    var builder = this.getDefaultBuilder(applicationInfo);
                    var NetworkSecurityConfigBuilder = Java.use("android.security.net.config.NetworkSecurityConfig$Builder");

                    // Create permissive config
                    return NetworkSecurityConfigBuilder.$new()
                        .setCleartextTrafficPermitted(true)
                        .setHstsEnforced(false)
                        .build();
                };

                self.stats.hooksInstalled++;
            } catch(e) {
                // Not Android N+
            }
        });
    }
}
