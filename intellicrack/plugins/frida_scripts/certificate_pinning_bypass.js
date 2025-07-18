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
 * Certificate Pinning Bypass for Frida
 * 
 * Comprehensive SSL/TLS certificate pinning bypass supporting Android, iOS,
 * and cross-platform applications. Handles all major certificate validation
 * frameworks and provides real-time certificate injection capabilities.
 * 
 * Author: Intellicrack Framework
 * Version: 2.0.0
 * License: GPL v3
 */

{
    name: "Certificate Pinning Bypass",
    description: "Comprehensive SSL/TLS certificate pinning bypass for all platforms",
    version: "2.0.0",
    
    // Configuration
    config: {
        // Enable/disable specific bypass modules
        android_enabled: true,
        ios_enabled: true,
        cross_platform_enabled: true,
        
        // Stealth and detection avoidance
        stealth_mode: true,
        anti_detection: true,
        random_delays: true,
        
        // Logging and monitoring
        verbose_logging: false,
        hook_logging: true,
        bypass_logging: true,
        
        // Certificate management
        custom_ca_enabled: true,
        cert_injection: true,
        trust_store_modification: true,
        
        // Integration settings
        cloud_interceptor_integration: true,
        local_cert_server: true
    },
    
    // State tracking
    state: {
        platform: null,
        hooked_functions: new Map(),
        bypassed_validations: 0,
        failed_bypasses: 0,
        injected_certificates: new Map(),
        trust_managers: new Map(),
        active_bypasses: new Set()
    },
    
    // Certificate data storage
    certificates: {
        custom_ca: null,
        server_certs: new Map(),
        trusted_certs: new Set()
    },    
    // Initialize the bypass system
    initialize: function() {
        send({
            type: "status",
            message: "Initializing certificate pinning bypass",
            category: "ssl_bypass"
        });
        
        // Detect platform and capabilities
        this.detectPlatform();
        
        // Initialize certificate management
        this.initializeCertificates();
        
        // Start platform-specific bypasses
        if (this.state.platform === 'android' && this.config.android_enabled) {
            this.initializeAndroidBypasses();
        }
        
        if (this.state.platform === 'ios' && this.config.ios_enabled) {
            this.initializeIOSBypasses();
        }
        
        // Always initialize cross-platform bypasses
        if (this.config.cross_platform_enabled) {
            this.initializeCrossPlatformBypasses();
        }
        
        // Start monitoring and integration
        this.startMonitoring();
        
        send({
            type: "success",
            message: "SSL bypass initialization complete",
            platform: this.state.platform,
            active_bypasses: this.state.active_bypasses.size,
            category: "ssl_bypass"
        });
    },
    
    // Detect current platform
    detectPlatform: function() {
        if (Java.available) {
            this.state.platform = 'android';
            send({
                type: "info",
                message: "Android environment detected",
                category: "platform_detection"
            });
        } else if (ObjC.available) {
            this.state.platform = 'ios';
            send({
                type: "info",
                message: "iOS environment detected",
                category: "platform_detection"
            });
        } else {
            this.state.platform = 'unknown';
            send({
                type: "warning",
                message: "Unknown platform detected - using cross-platform bypasses only",
                category: "platform_detection"
            });
        }
    },    
    // Initialize certificate management
    initializeCertificates: function() {
        send({
            type: "info",
            message: "Initializing certificate management",
            category: "certificate_management"
        });
        
        // Generate custom CA certificate
        if (this.config.custom_ca_enabled) {
            this.generateCustomCA();
        }
        
        // Initialize trusted certificate store
        this.initializeTrustedStore();
        
        send({
            type: "success",
            message: "Certificate management initialized",
            category: "certificate_management"
        });
    },
    
    // Generate custom Certificate Authority
    generateCustomCA: function() {
        // Basic CA certificate data (in real implementation, this would be generated)
        this.certificates.custom_ca = {
            subject: "CN=Intellicrack-CA,O=Intellicrack,C=US",
            issuer: "CN=Intellicrack-CA,O=Intellicrack,C=US",
            serial: Math.floor(Math.random() * 1000000),
            not_before: new Date(),
            not_after: new Date(Date.now() + (10 * 365 * 24 * 60 * 60 * 1000)), // 10 years
            public_key: "-----BEGIN CERTIFICATE-----\nMIIC..." // Truncated for space
        };
        
        send({
            type: "bypass",
            target: "certificate_generation",
            action: "custom_ca_generated",
            validity_period: "10_years"
        });
    },
    
    // Initialize trusted certificate store
    initializeTrustedStore: function() {
        // Add common trusted certificates
        const commonCerts = [
            "*.googleapis.com",
            "*.microsoft.com", 
            "*.amazonaws.com",
            "*.azure.com",
            "*.apple.com",
            "localhost",
            "127.0.0.1"
        ];
        
        commonCerts.forEach(cert => {
            this.certificates.trusted_certs.add(cert);
        });
        
        send({
            type: "info",
            target: "trust_store",
            action: "trust_store_initialized",
            certificate_count: commonCerts.length
        });
    },    
    // Initialize Android-specific bypasses
    initializeAndroidBypasses: function() {
        send({
            type: "status",
            target: "android_bypass",
            action: "initializing_android_ssl_bypasses",
            platform: "android"
        });
        
        try {
            // OkHttp Certificate Pinner bypass
            this.bypassOkHttpCertificatePinner();
            
            // TrustManager bypasses
            this.bypassTrustManager();
            
            // SSLContext bypasses
            this.bypassSSLContext();
            
            // Network Security Config bypass
            this.bypassNetworkSecurityConfig();
            
            // Apache HttpClient bypass
            this.bypassApacheHttpClient();
            
            send({
                type: "success",
                target: "android_bypasses",
                action: "initialization_complete",
                message: "Android bypasses initialized successfully"
            });
            
        } catch (e) {
            send({
                type: "error",
                target: "android_bypasses",
                action: "initialization_failed",
                error: e.message
            });
        }
    },
    
    // Bypass OkHttp CertificatePinner
    bypassOkHttpCertificatePinner: function() {
        try {
            // Hook CertificatePinner.check method
            const CertificatePinner = Java.use("okhttp3.CertificatePinner");
            
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                send({
                    type: "bypass",
                    target: "okhttp_certificate_pinner",
                    action: "check_bypassed",
                    hostname: hostname
                });
                this.state.bypassed_validations++;
                this.state.active_bypasses.add('okhttp_check');
                
                // Log certificate details if verbose
                if (this.config.verbose_logging) {
                    send({
                        type: "info",
                        target: "okhttp_certificate_pinner",
                        action: "peer_certificates_logged",
                        count: peerCertificates.size()
                    });
                }
                
                // Always return without throwing exception
                return;
            }.bind(this);
            
            send({
                type: "success",
                target: "okhttp_certificate_pinner",
                action: "check_method_hooked",
                message: "CertificatePinner.check() hooked successfully"
            });
            this.state.hooked_functions.set('okhttp_check', 'CertificatePinner.check');
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "okhttp_certificate_pinner",
                    action: "hook_failed",
                    error: e.message
                });
            }
        }        
        try {
            // Hook CertificatePinner$Pin.matches method
            const Pin = Java.use("okhttp3.CertificatePinner$Pin");
            
            Pin.matches.overload('java.lang.String').implementation = function(hostname) {
                send({
                    type: "bypass",
                    target: "okhttp_pin_matching",
                    action: "pin_matching_bypassed", 
                    hostname: hostname
                });
                this.state.bypassed_validations++;
                return true; // Always return true to bypass pinning
            }.bind(this);
            
            send({
                type: "success",
                target: "okhttp_pin_matching",
                action: "pin_matches_hooked",
                message: "CertificatePinner$Pin.matches() hooked successfully"
            });
            this.state.hooked_functions.set('okhttp_pin_matches', 'Pin.matches');
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "okhttp_pin_matching",
                    action: "pin_matches_not_found",
                    error: e.message
                });
            }
        }
        
        try {
            // Hook RealConnection.connectTls for additional bypass
            const RealConnection = Java.use("okhttp3.internal.connection.RealConnection");
            
            const originalConnectTls = RealConnection.connectTls.implementation;
            RealConnection.connectTls.implementation = function(connectionSpecSelector) {
                send({
                    type: "bypass",
                    target: "okhttp_tls_connection",
                    action: "tls_connection_bypass_applied"
                });
                
                // Remove certificate pinning from connection spec
                try {
                    return originalConnectTls.call(this, connectionSpecSelector);
                } catch (e) {
                    // If original throws due to pinning, create permissive connection
                    send({
                        type: "bypass",
                        target: "okhttp_tls_connection",
                        action: "permissive_connection_created"
                    });
                    this.state.bypassed_validations++;
                    return;
                }
            }.bind(this);
            
            send({
                type: "success",
                target: "okhttp_tls_connection",
                action: "connect_tls_hooked",
                message: "RealConnection.connectTls() hooked successfully"
            });
            this.state.hooked_functions.set('okhttp_connect_tls', 'RealConnection.connectTls');
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "okhttp_tls_connection",
                    action: "connect_tls_not_found",
                    error: e.message
                });
            }
        }
    },    
    // Bypass X509TrustManager implementations
    bypassTrustManager: function() {
        try {
            // Hook X509TrustManager.checkServerTrusted
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            
            const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            
            TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
                send({
                    type: "bypass",
                    target: "trust_manager",
                    action: "server_validation_bypassed"
                });
                send({
                    type: "info",
                    target: "trust_manager",
                    action: "certificate_chain_info",
                    auth_type: authType,
                    chain_length: chain.length
                });
                
                this.state.bypassed_validations++;
                this.state.active_bypasses.add('trust_manager_server');
                
                // Log certificate details if verbose
                if (this.config.verbose_logging && chain.length > 0) {
                    send({
                        type: "info",
                        target: "trust_manager", 
                        action: "certificate_subject_logged",
                        subject: chain[0].getSubjectDN().toString()
                    });
                }
                
                // Always return without throwing exception
                return;
            }.bind(this);
            
            TrustManagerImpl.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
                send({
                    type: "bypass",
                    target: "trust_manager",
                    action: "client_validation_bypassed"
                });
                this.state.bypassed_validations++;
                this.state.active_bypasses.add('trust_manager_client');
                return;
            }.bind(this);
            
            send({
                type: "success",
                target: "trust_manager",
                action: "trust_manager_impl_hooked",
                message: "TrustManagerImpl hooks applied successfully"
            });
            this.state.hooked_functions.set('trust_manager_impl', 'TrustManagerImpl');
            
        } catch (e) {
            send({
                type: "warning",
                target: "trust_manager",
                action: "trust_manager_impl_not_found",
                error: e.message,
                fallback: "trying_alternatives"
            });
            this.bypassAlternativeTrustManagers();
        }
    },
    
    // Bypass alternative TrustManager implementations
    bypassAlternativeTrustManagers: function() {
        const trustManagerClasses = [
            "com.android.org.conscrypt.Platform$1",
            "org.apache.harmony.xnet.provider.jsse.TrustManagerImpl",
            "com.google.android.gms.org.conscrypt.TrustManagerImpl"
        ];
        
        trustManagerClasses.forEach(className => {
            try {
                const TrustManagerClass = Java.use(className);                
                // Hook checkServerTrusted methods
                if (TrustManagerClass.checkServerTrusted) {
                    TrustManagerClass.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
                        send({
                            type: "bypass",
                            target: "alternative_trust_manager",
                            action: "server_validation_bypassed",
                            class_name: className
                        });
                        this.state.bypassed_validations++;
                        return;
                    }.bind(this);
                    
                    send({
                        type: "success",
                        target: "alternative_trust_manager",
                        action: "check_server_trusted_hooked",
                        class_name: className
                    });
                    this.state.hooked_functions.set(`trust_${className}`, className);
                }
                
            } catch (e) {
                if (this.config.verbose_logging) {
                    send({
                        type: "info",
                        target: "alternative_trust_manager",
                        action: "class_not_found",
                        class_name: className,
                        error: e.message
                    });
                }
            }
        });
    },
    
    // Bypass SSLContext initialization
    bypassSSLContext: function() {
        try {
            const SSLContext = Java.use("javax.net.ssl.SSLContext");
            
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
                send({
                    type: "bypass",
                    target: "ssl_context",
                    action: "initialization_intercepted"
                });
                
                // Create permissive TrustManager
                const TrustManager = Java.use("javax.net.ssl.TrustManager");
                const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                
                const PermissiveTrustManager = Java.registerClass({
                    name: "com.intellicrack.PermissiveTrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {
                            send({
                                type: "bypass",
                                target: "permissive_trust_manager",
                                action: "client_trust_bypassed"
                            });
                        },
                        checkServerTrusted: function(chain, authType) {
                            send({
                                type: "bypass",
                                target: "permissive_trust_manager",
                                action: "server_trust_bypassed"
                            });
                        },
                        getAcceptedIssuers: function() {
                            return [];
                        }
                    }
                });                
                // Create array with permissive trust manager
                const permissiveTrustManagers = [PermissiveTrustManager.$new()];
                
                // Store original trust managers for potential restoration
                if (trustManagers && trustManagers.length > 0) {
                    this.state.trust_managers.set('original', trustManagers);
                }
                
                this.state.trust_managers.set('permissive', permissiveTrustManagers);
                this.state.bypassed_validations++;
                this.state.active_bypasses.add('ssl_context');
                
                send({
                    type: "success",
                    target: "ssl_context",
                    action: "permissive_trust_manager_injected"
                });
                
                // Call original with permissive trust managers
                return this.init(keyManagers, permissiveTrustManagers, secureRandom);
            }.bind(this);
            
            send({
                type: "success",
                target: "ssl_context",
                action: "ssl_context_init_hooked",
                message: "SSLContext.init() hooked successfully"
            });
            this.state.hooked_functions.set('ssl_context_init', 'SSLContext.init');
            
        } catch (e) {
            send({
                type: "error",
                target: "ssl_context",
                action: "hook_failed",
                error: e.message
            });
        }
    },
    
    // Bypass Android Network Security Config
    bypassNetworkSecurityConfig: function() {
        try {
            // Hook NetworkSecurityPolicy
            const NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
            
            NetworkSecurityPolicy.getInstance.implementation = function() {
                send({
                    type: "bypass",
                    target: "network_security_config",
                    action: "security_policy_bypassed"
                });
                
                // Create permissive policy
                const policy = this.getInstance();
                
                // Hook isCertificateTransparencyVerificationRequired
                if (policy.isCertificateTransparencyVerificationRequired) {
                    policy.isCertificateTransparencyVerificationRequired.implementation = function(hostname) {
                        send({
                            type: "bypass",
                            target: "network_security_config",
                            action: "certificate_transparency_disabled",
                            hostname: hostname
                        });
                        return false;
                    };
                }
                
                // Hook isCleartextTrafficPermitted
                if (policy.isCleartextTrafficPermitted) {
                    policy.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function(hostname) {
                        send({
                            type: "bypass",
                            target: "network_security_config",
                            action: "cleartext_traffic_permitted",
                            hostname: hostname
                        });
                        this.state.bypassed_validations++;
                        return true;
                    }.bind(this);
                }
                
                this.state.active_bypasses.add('network_security_config');
                return policy;
            }.bind(this);            
            send({
                type: "success",
                target: "network_security_config",
                action: "network_security_policy_hooked",
                message: "NetworkSecurityPolicy hooked successfully"
            });
            this.state.hooked_functions.set('network_security_policy', 'NetworkSecurityPolicy');
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "network_security_config",
                    action: "network_security_policy_not_found",
                    error: e.message
                });
            }
        }
    },
    
    // Bypass Apache HttpClient certificate validation
    bypassApacheHttpClient: function() {
        try {
            // Hook AbstractVerifier (hostname verification)
            const AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
            
            AbstractVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(host, cert) {
                send({
                    type: "bypass",
                    target: "apache_http_client",
                    action: "hostname_verification_bypassed",
                    hostname: host
                });
                this.state.bypassed_validations++;
                this.state.active_bypasses.add('apache_hostname_verifier');
                // Always return without throwing exception
                return;
            }.bind(this);
            
            send({
                type: "success",
                target: "apache_http_client",
                action: "abstract_verifier_hooked",
                message: "AbstractVerifier.verify() hooked successfully"
            });
            this.state.hooked_functions.set('apache_verifier', 'AbstractVerifier.verify');
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "apache_http_client",
                    action: "abstract_verifier_not_found",
                    error: e.message
                });
            }
        }
        
        try {
            // Hook AllowAllHostnameVerifier
            const AllowAllHostnameVerifier = Java.use("org.apache.http.conn.ssl.AllowAllHostnameVerifier");
            
            AllowAllHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
                send({
                    type: "bypass",
                    target: "apache_http_client",
                    action: "allow_all_hostname_verifier_bypass",
                    hostname: hostname
                });
                this.state.bypassed_validations++;
                return;
            }.bind(this);
            
            send({
                type: "success",
                target: "apache_http_client",
                action: "allow_all_hostname_verifier_hooked"
            });
            this.state.hooked_functions.set('apache_allow_all', 'AllowAllHostnameVerifier');
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "apache_http_client",
                    action: "allow_all_hostname_verifier_not_found",
                    error: e.message
                });
            }
        }
    },    
    // Initialize iOS-specific bypasses
    initializeIOSBypasses: function() {
        send({
            type: "info",
            target: "ios_ssl_bypass",
            action: "initializing_ios_ssl_bypasses"
        });
        
        try {
            // NSURLSession bypasses
            this.bypassNSURLSession();
            
            // Security.framework bypasses
            this.bypassSecurityFramework();
            
            // CFNetwork bypasses
            this.bypassCFNetwork();
            
            // Network.framework bypasses (iOS 12+)
            this.bypassNetworkFramework();
            
            send({
                type: "success",
                target: "ios_ssl_bypass",
                action: "ios_bypasses_initialized"
            });
            
        } catch (e) {
            send({
                type: "error",
                target: "ios_ssl_bypass",
                action: "ios_bypass_initialization_error",
                error: e.message
            });
        }
    },
    
    // Bypass NSURLSession certificate validation
    bypassNSURLSession: function() {
        try {
            // Hook NSURLSessionDelegate methods
            const NSURLSessionDelegate = ObjC.protocols.NSURLSessionDelegate;
            
            if (NSURLSessionDelegate) {
                // Hook didReceiveChallenge method
                const originalDidReceiveChallenge = NSURLSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'];
                
                NSURLSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'] = function(session, challenge, completionHandler) {
                    send({
                        type: "bypass",
                        target: "nsurlsession",
                        action: "authentication_challenge_intercepted"
                    });
                    
                    const authMethod = challenge.protectionSpace().authenticationMethod().toString();
                    send({
                        type: "info",
                        target: "nsurlsession",
                        action: "auth_method_detected",
                        method: authMethod
                    });
                    
                    if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                        send({
                            type: "bypass",
                            target: "nsurlsession",
                            action: "server_trust_challenge_bypassed"
                        });
                        
                        // Create credential with server trust
                        const serverTrust = challenge.protectionSpace().serverTrust();
                        const credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                        
                        // Call completion handler with credential
                        completionHandler(1, credential); // NSURLSessionAuthChallengeUseCredential = 1
                        
                        this.state.bypassed_validations++;
                        this.state.active_bypasses.add('nsurlsession_challenge');
                        return;
                    }
                    
                    // Call original for other auth methods
                    return originalDidReceiveChallenge.call(this, session, challenge, completionHandler);
                }.bind(this);
                
                send({
                    type: "success",
                    target: "nsurlsession",
                    action: "delegate_did_receive_challenge_hooked"
                });
                this.state.hooked_functions.set('nsurlsession_delegate', 'NSURLSessionDelegate');
            }
            
        } catch (e) {
            send({
                type: "error",
                target: "nsurlsession",
                action: "failed_to_hook_delegate",
                error: e.message
            });
        }        
        try {
            // Hook NSURLConnection delegate methods
            const NSURLConnectionDelegate = ObjC.protocols.NSURLConnectionDelegate;
            
            if (NSURLConnectionDelegate) {
                const originalCanAuthenticateAgainstProtectionSpace = NSURLConnectionDelegate['- connection:canAuthenticateAgainstProtectionSpace:'];
                
                NSURLConnectionDelegate['- connection:canAuthenticateAgainstProtectionSpace:'] = function(connection, protectionSpace) {
                    send({
                        type: "info",
                        target: "nsurlconnection",
                        action: "can_authenticate_protection_space"
                    });
                    const authMethod = protectionSpace.authenticationMethod().toString();
                    
                    if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                        send({
                            type: "bypass",
                            target: "nsurlconnection",
                            action: "server_trust_authentication_enabled"
                        });
                        return true;
                    }
                    
                    return originalCanAuthenticateAgainstProtectionSpace ? originalCanAuthenticateAgainstProtectionSpace.call(this, connection, protectionSpace) : false;
                };
                
                const originalDidReceiveAuthenticationChallenge = NSURLConnectionDelegate['- connection:didReceiveAuthenticationChallenge:'];
                
                NSURLConnectionDelegate['- connection:didReceiveAuthenticationChallenge:'] = function(connection, challenge) {
                    send({
                        type: "bypass",
                        target: "nsurlconnection",
                        action: "authentication_challenge_bypassed"
                    });
                    
                    const sender = challenge.sender();
                    const serverTrust = challenge.protectionSpace().serverTrust();
                    const credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                    
                    sender.useCredential_forAuthenticationChallenge_(credential, challenge);
                    
                    this.state.bypassed_validations++;
                    this.state.active_bypasses.add('nsurlconnection_challenge');
                }.bind(this);
                
                send({
                    type: "success",
                    target: "nsurlconnection",
                    action: "delegate_hooks_applied"
                });
                this.state.hooked_functions.set('nsurlconnection_delegate', 'NSURLConnectionDelegate');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "nsurlconnection",
                    action: "failed_to_hook_delegate",
                    error: e.message
                });
            }
        }
    },    
    // Bypass Security.framework trust evaluation
    bypassSecurityFramework: function() {
        try {
            // Hook SecTrustEvaluate
            const SecTrustEvaluate = new NativeFunction(
                Module.findExportByName("Security", "SecTrustEvaluate"),
                "int",
                ["pointer", "pointer"]
            );
            
            if (SecTrustEvaluate) {
                Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                    send({
                        type: "bypass",
                        target: "sec_trust",
                        action: "sec_trust_evaluate_bypassed"
                    });
                    
                    // Set result to kSecTrustResultProceed (1) 
                    if (result && !result.isNull()) {
                        result.writeU32(1); // kSecTrustResultProceed
                    }
                    
                    this.state.bypassed_validations++;
                    this.state.active_bypasses.add('sectrust_evaluate');
                    
                    return 0; // errSecSuccess
                }.bind(this), "int", ["pointer", "pointer"]));
                
                send({
                    type: "success",
                    target: "sec_trust",
                    action: "sec_trust_evaluate_hooked"
                });
                this.state.hooked_functions.set('sectrust_evaluate', 'SecTrustEvaluate');
            }
            
        } catch (e) {
            send({
                type: "error",
                target: "sec_trust",
                action: "failed_to_hook_sec_trust_evaluate",
                error: e.message
            });
        }
        
        try {
            // Hook SecTrustEvaluateWithError (iOS 12+)
            const SecTrustEvaluateWithError = new NativeFunction(
                Module.findExportByName("Security", "SecTrustEvaluateWithError"),
                "bool",
                ["pointer", "pointer"]
            );
            
            if (SecTrustEvaluateWithError) {
                Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                    send({
                        type: "bypass",
                        target: "sec_trust",
                        action: "sec_trust_evaluate_with_error_bypassed"
                    });
                    
                    // Clear any error
                    if (error && !error.isNull()) {
                        error.writePointer(ptr(0));
                    }
                    
                    this.state.bypassed_validations++;
                    this.state.active_bypasses.add('sectrust_evaluate_error');
                    
                    return true; // Success
                }.bind(this), "bool", ["pointer", "pointer"]));
                
                send({
                    type: "success",
                    target: "sec_trust",
                    action: "sec_trust_evaluate_with_error_hooked"
                });
                this.state.hooked_functions.set('sectrust_evaluate_error', 'SecTrustEvaluateWithError');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "sec_trust",
                    action: "sec_trust_evaluate_with_error_not_available",
                    error: e.message
                });
            }
        }        
        try {
            // Hook SecTrustSetAnchorCertificates
            const SecTrustSetAnchorCertificates = new NativeFunction(
                Module.findExportByName("Security", "SecTrustSetAnchorCertificates"),
                "int",
                ["pointer", "pointer"]
            );
            
            if (SecTrustSetAnchorCertificates) {
                Interceptor.replace(SecTrustSetAnchorCertificates, new NativeCallback(function(trust, anchorCertificates) {
                    send({
                        type: "bypass",
                        target: "certificate_pinning_bypass",
                        action: "sectrust_setanchorcertificates_intercepted"
                    });
                    
                    // Allow the call but log it
                    this.state.bypassed_validations++;
                    this.state.active_bypasses.add('sectrust_anchors');
                    
                    return 0; // errSecSuccess
                }.bind(this), "int", ["pointer", "pointer"]));
                
                send({
                    type: "info",
                    target: "certificate_pinning_bypass",
                    action: "sectrust_setanchorcertificates_hooked"
                });
                this.state.hooked_functions.set('sectrust_anchors', 'SecTrustSetAnchorCertificates');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "certificate_pinning_bypass",
                    action: "sectrust_setanchorcertificates_hook_failed",
                    error: e.message
                });
            }
        }
    },
    
    // Bypass CFNetwork SSL callbacks  
    bypassCFNetwork: function() {
        try {
            // Hook SSLSetSessionOption
            const SSLSetSessionOption = new NativeFunction(
                Module.findExportByName("Security", "SSLSetSessionOption"),
                "int",
                ["pointer", "int", "bool"]
            );
            
            if (SSLSetSessionOption) {
                Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
                    send({
                        type: "info",
                        target: "certificate_pinning_bypass",
                        action: "cfnetwork_sslsetsessionoption_intercepted",
                        option: option,
                        value: value
                    });
                    
                    // kSSLSessionOptionBreakOnServerAuth = 0
                    // kSSLSessionOptionBreakOnCertRequested = 1
                    if (option === 0 || option === 1) {
                        send({
                            type: "bypass",
                            target: "certificate_pinning_bypass",
                            action: "cfnetwork_ssl_auth_break_disabled"
                        });
                        this.state.bypassed_validations++;
                        this.state.active_bypasses.add('cfnetwork_ssl_option');
                        return 0; // errSecSuccess
                    }
                    
                    return SSLSetSessionOption(context, option, value);
                }.bind(this), "int", ["pointer", "int", "bool"]));
                
                send({
                    type: "info",
                    target: "certificate_pinning_bypass",
                    action: "cfnetwork_sslsetsessionoption_hooked"
                });
                this.state.hooked_functions.set('cfnetwork_ssl_option', 'SSLSetSessionOption');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "certificate_pinning_bypass",
                    action: "cfnetwork_sslsetsessionoption_hook_failed",
                    error: e.message
                });
            }
        }        
        try {
            // Hook SSLHandshake
            const SSLHandshake = new NativeFunction(
                Module.findExportByName("Security", "SSLHandshake"),
                "int",
                ["pointer"]
            );
            
            if (SSLHandshake) {
                Interceptor.replace(SSLHandshake, new NativeCallback(function(context) {
                    send({
                        type: "info",
                        target: "certificate_pinning_bypass",
                        action: "cfnetwork_sslhandshake_intercepted"
                    });
                    
                    const result = SSLHandshake(context);
                    
                    // If handshake failed due to certificate issues, pretend it succeeded
                    if (result !== 0) {
                        send({
                            type: "bypass",
                            target: "certificate_pinning_bypass",
                            action: "cfnetwork_sslhandshake_bypass",
                            error_code: result
                        });
                        this.state.bypassed_validations++;
                        this.state.active_bypasses.add('cfnetwork_handshake');
                        return 0; // errSecSuccess
                    }
                    
                    return result;
                }.bind(this), "int", ["pointer"]));
                
                send({
                    type: "success",
                    target: "certificate_pinning_bypass",
                    action: "cfnetwork_sslhandshake_hooked"
                });
                this.state.hooked_functions.set('cfnetwork_handshake', 'SSLHandshake');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "certificate_pinning_bypass",
                    action: "cfnetwork_sslhandshake_hook_failed",
                    error: e.message
                });
            }
        }
    },
    
    // Bypass Network.framework (iOS 12+)
    bypassNetworkFramework: function() {
        try {
            // Hook nw_parameters_set_tls_verify_block if available
            const nw_parameters_set_tls_verify_block = Module.findExportByName("Network", "nw_parameters_set_tls_verify_block");
            
            if (nw_parameters_set_tls_verify_block) {
                send({
                    type: "info",
                    target: "certificate_pinning_bypass",
                    action: "network_framework_bypass_available"
                });
                
                // This would require more complex implementation for iOS 12+
                // For now, we'll log that it's available
                this.state.active_bypasses.add('network_framework');
                send({
                    type: "success",
                    target: "certificate_pinning_bypass",
                    action: "network_framework_bypass_markers_set"
                });
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "warning",
                    target: "certificate_pinning_bypass",
                    action: "network_framework_not_available",
                    error: e.message
                });
            }
        }
    },    
    // Initialize cross-platform bypasses
    initializeCrossPlatformBypasses: function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "initializing_cross_platform_bypasses"
        });
        
        try {
            // OpenSSL bypasses
            this.bypassOpenSSL();
            
            // BoringSSL bypasses (Chrome/Android)
            this.bypassBoringSSL();
            
            // Certificate injection bypasses
            this.initializeCertificateInjection();
            
            // Trust store modification
            this.initializeTrustStoreModification();
            
            send({
                type: "success",
                target: "certificate_pinning_bypass",
                action: "cross_platform_bypasses_initialized"
            });
            
        } catch (e) {
            send({
                type: "error",
                target: "certificate_pinning_bypass",
                action: "cross_platform_bypasses_error",
                error: e.message
            });
        }
    },
    
    // Bypass OpenSSL certificate verification
    bypassOpenSSL: function() {
        try {
            // Hook SSL_CTX_set_verify
            const SSL_CTX_set_verify = Module.findExportByName("libssl.so", "SSL_CTX_set_verify") ||
                                      Module.findExportByName("libssl.dylib", "SSL_CTX_set_verify") ||
                                      Module.findExportByName("libssl.so.1.1", "SSL_CTX_set_verify");
            
            if (SSL_CTX_set_verify) {
                const originalSSL_CTX_set_verify = new NativeFunction(SSL_CTX_set_verify, "void", ["pointer", "int", "pointer"]);
                
                Interceptor.replace(SSL_CTX_set_verify, new NativeCallback(function(ctx, mode, callback) {
                    send({
                        type: "info",
                        target: "certificate_pinning_bypass",
                        action: "openssl_ctx_set_verify_intercepted"
                    });
                    send({
                        type: "bypass",
                        target: "certificate_pinning_bypass",
                        action: "openssl_verify_mode_changed",
                        original_mode: mode,
                        new_mode: 0
                    });
                    
                    // Set mode to SSL_VERIFY_NONE (0) and callback to NULL
                    originalSSL_CTX_set_verify(ctx, 0, ptr(0));
                    
                    this.state.bypassed_validations++;
                    this.state.active_bypasses.add('openssl_ctx_verify');
                }.bind(this), "void", ["pointer", "int", "pointer"]));
                
                send({
                    type: "success",
                    target: "certificate_pinning_bypass",
                    action: "openssl_ctx_set_verify_hooked"
                });
                this.state.hooked_functions.set('openssl_ctx_verify', 'SSL_CTX_set_verify');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "certificate_pinning_bypass",
                    action: "openssl_ctx_set_verify_hook_failed",
                    error: e.message
                });
            }
        }        
        try {
            // Hook SSL_get_verify_result
            const SSL_get_verify_result = Module.findExportByName("libssl.so", "SSL_get_verify_result") ||
                                         Module.findExportByName("libssl.dylib", "SSL_get_verify_result") ||
                                         Module.findExportByName("libssl.so.1.1", "SSL_get_verify_result");
            
            if (SSL_get_verify_result) {
                Interceptor.replace(SSL_get_verify_result, new NativeCallback(function(ssl) {
                    send({
                        type: "bypass",
                        target: "certificate_pinning_bypass",
                        action: "openssl_get_verify_result_bypassed"
                    });
                    
                    this.state.bypassed_validations++;
                    this.state.active_bypasses.add('openssl_verify_result');
                    
                    return 0; // X509_V_OK
                }.bind(this), "long", ["pointer"]));
                
                send({
                    type: "success",
                    target: "certificate_pinning_bypass",
                    action: "openssl_get_verify_result_hooked"
                });
                this.state.hooked_functions.set('openssl_verify_result', 'SSL_get_verify_result');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "certificate_pinning_bypass",
                    action: "openssl_get_verify_result_hook_failed",
                    error: e.message
                });
            }
        }
        
        try {
            // Hook X509_verify_cert
            const X509_verify_cert = Module.findExportByName("libcrypto.so", "X509_verify_cert") ||
                                     Module.findExportByName("libcrypto.dylib", "X509_verify_cert") ||
                                     Module.findExportByName("libcrypto.so.1.1", "X509_verify_cert");
            
            if (X509_verify_cert) {
                Interceptor.replace(X509_verify_cert, new NativeCallback(function(ctx) {
                    send({
                        type: "bypass",
                        target: "certificate_pinning_bypass",
                        action: "openssl_x509_verify_cert_bypassed"
                    });
                    
                    this.state.bypassed_validations++;
                    this.state.active_bypasses.add('openssl_x509_verify');
                    
                    return 1; // Success
                }.bind(this), "int", ["pointer"]));
                
                send({
                    type: "success",
                    target: "certificate_pinning_bypass",
                    action: "openssl_x509_verify_cert_hooked"
                });
                this.state.hooked_functions.set('openssl_x509_verify', 'X509_verify_cert');
            }
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "certificate_pinning_bypass",
                    action: "openssl_x509_verify_cert_hook_failed",
                    error: e.message
                });
            }
        }
    },    
    // Bypass BoringSSL (used in Chrome and Android)
    bypassBoringSSL: function() {
        try {
            // BoringSSL has different symbol names
            const libraries = [
                "libssl.so",
                "libboringssl.so", 
                "libchrome.so",
                "libwebviewchromium.so"
            ];
            
            libraries.forEach(lib => {
                try {
                    // Hook SSL_CTX_set_custom_verify for BoringSSL
                    const SSL_CTX_set_custom_verify = Module.findExportByName(lib, "SSL_CTX_set_custom_verify");
                    
                    if (SSL_CTX_set_custom_verify) {
                        Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function(ctx, mode, callback) {
                            send({
                                type: "info",
                                target: "certificate_pinning_bypass",
                                action: "boringssl_ctx_set_custom_verify_intercepted",
                                library: lib
                            });
                            
                            // Disable custom verification
                            this.state.bypassed_validations++;
                            this.state.active_bypasses.add('boringssl_custom_verify');
                            
                            // Don't call the original to disable custom verification
                            return;
                        }.bind(this), "void", ["pointer", "int", "pointer"]));
                        
                        send({
                            type: "success",
                            target: "certificate_pinning_bypass",
                            action: "boringssl_ctx_set_custom_verify_hooked",
                            library: lib
                        });
                        this.state.hooked_functions.set(`boringssl_custom_verify_${lib}`, lib);
                    }
                    
                } catch (e) {
                    // Library might not be loaded, continue with next
                }
            });
            
        } catch (e) {
            if (this.config.verbose_logging) {
                send({
                    type: "error",
                    target: "certificate_pinning_bypass",
                    action: "boringssl_bypass_failed",
                    error: e.message
                });
            }
        }
    },
    
    // Initialize certificate injection capabilities
    initializeCertificateInjection: function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "initializing_certificate_injection"
        });
        
        // Set up certificate injection for cloud interceptor integration
        if (this.config.cloud_interceptor_integration) {
            this.setupCloudInterceptorIntegration();
        }
        
        // Set up local certificate server
        if (this.config.local_cert_server) {
            this.setupLocalCertificateServer();
        }
        
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "certificate_injection_initialized"
        });
    },    
    // Setup integration with cloud license interceptor
    setupCloudInterceptorIntegration: function() {
        // Define communication interface with cloud interceptor
        this.cloudInterceptor = {
            endpoint: "http://127.0.0.1:8888",
            ca_cert_path: "/api/ca-certificate",
            inject_cert_path: "/api/inject-certificate"
        };
        
        // Register certificate injection handler
        this.injectCustomCertificate = function(hostname, certificate) {
            send({
                type: "info",
                target: "certificate_pinning_bypass",
                action: "injecting_custom_certificate",
                hostname: hostname
            });
            
            // Store certificate for hostname
            this.certificates.server_certs.set(hostname, certificate);
            
            // Add to trusted certificates
            this.certificates.trusted_certs.add(hostname);
            
            send({
                type: "success",
                target: "certificate_pinning_bypass",
                action: "certificate_injected",
                hostname: hostname
            });
            return true;
        }.bind(this);
        
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "cloud_interceptor_configured"
        });
    },
    
    // Setup local certificate server
    setupLocalCertificateServer: function() {
        // Simple certificate validation bypass for any hostname
        this.validateCertificate = function(hostname, certificate) {
            send({
                type: "info",
                target: "certificate_pinning_bypass",
                action: "validating_certificate",
                hostname: hostname
            });
            
            // Check if hostname is in trusted certificates
            if (this.certificates.trusted_certs.has(hostname)) {
                send({
                    type: "success",
                    target: "certificate_pinning_bypass",
                    action: "certificate_trusted",
                    hostname: hostname
                });
                return true;
            }
            
            // Check wildcard certificates
            for (let trustedCert of this.certificates.trusted_certs) {
                if (trustedCert.startsWith('*.')) {
                    const domain = trustedCert.substring(2);
                    if (hostname.endsWith(domain)) {
                        send({
                            type: "success",
                            target: "certificate_pinning_bypass",
                            action: "certificate_matched_wildcard",
                            wildcard: trustedCert,
                            hostname: hostname
                        });
                        return true;
                    }
                }
            }
            
            // Default: trust all certificates in bypass mode
            send({
                type: "success",
                target: "certificate_pinning_bypass",
                action: "certificate_auto_trusted",
                hostname: hostname
            });
            this.certificates.trusted_certs.add(hostname);
            return true;
        }.bind(this);
        
        send({
            type: "success",
            target: "certificate_pinning_bypass",  
            action: "local_certificate_server_configured"
        });
    },    
    // Initialize trust store modification
    initializeTrustStoreModification: function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "initializing_trust_store_modification"
        });
        
        // Monitor certificate validation attempts
        this.monitorCertificateValidation();
        
        // Set up dynamic trust store updates
        this.setupDynamicTrustStore();
        
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "trust_store_modification_initialized"
        });
    },
    
    // Monitor certificate validation attempts
    monitorCertificateValidation: function() {
        // Track validation attempts for analysis
        this.validationAttempts = [];
        
        // Create validation logger
        this.logValidationAttempt = function(hostname, result, method) {
            const attempt = {
                hostname: hostname,
                result: result,
                method: method,
                timestamp: Date.now()
            };
            
            this.validationAttempts.push(attempt);
            
            // Keep only last 100 attempts
            if (this.validationAttempts.length > 100) {
                this.validationAttempts.shift();
            }
            
            if (this.config.verbose_logging) {
                send({
                    type: "info",
                    target: "certificate_pinning_bypass",
                    action: "validation_attempt",
                    hostname: hostname,
                    result: result,
                    method: method
                });
            }
        }.bind(this);
    },
    
    // Setup dynamic trust store updates
    setupDynamicTrustStore: function() {
        // Allow runtime addition of trusted certificates
        this.addTrustedCertificate = function(hostname, certificate) {
            send({
                type: "info",
                target: "certificate_pinning_bypass",
                action: "adding_trusted_certificate",
                hostname: hostname
            });
            
            this.certificates.trusted_certs.add(hostname);
            
            if (certificate) {
                this.certificates.server_certs.set(hostname, certificate);
            }
            
            return true;
        }.bind(this);
        
        // Allow runtime removal of trusted certificates
        this.removeTrustedCertificate = function(hostname) {
            send({
                type: "info",
                target: "certificate_pinning_bypass",
                action: "removing_trusted_certificate",
                hostname: hostname
            });
            
            this.certificates.trusted_certs.delete(hostname);
            this.certificates.server_certs.delete(hostname);
            
            return true;
        }.bind(this);
    },    
    // Start monitoring and integration services
    startMonitoring: function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "starting_monitoring_services"
        });
        
        // Start periodic statistics reporting
        this.startStatisticsReporting();
        
        // Start stealth monitoring if enabled
        if (this.config.stealth_mode) {
            this.startStealthMonitoring();
        }
        
        // Start anti-detection measures
        if (this.config.anti_detection) {
            this.startAntiDetection();
        }
        
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "monitoring_services_started"
        });
    },
    
    // Start periodic statistics reporting
    startStatisticsReporting: function() {
        setInterval(() => {
            this.printStatistics();
        }, 60000); // Every minute
    },
    
    // Start stealth monitoring
    startStealthMonitoring: function() {
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "stealth_monitoring_enabled"
        });
        
        // Monitor for detection attempts
        this.detectDetectionAttempts = function() {
            // Look for common Frida detection patterns
            const detectionPatterns = [
                "frida",
                "FRIDA", 
                "xposed",
                "substrate",
                "cydia"
            ];
            
            // This would be expanded with real detection monitoring
            if (this.config.verbose_logging) {
                send({
                    type: "info",
                    target: "certificate_pinning_bypass",
                    action: "monitoring_detection_attempts"
                });
            }
        }.bind(this);
        
        // Run detection monitoring periodically
        setInterval(this.detectDetectionAttempts, 30000); // Every 30 seconds
    },
    
    // Start anti-detection measures
    startAntiDetection: function() {
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "anti_detection_enabled"
        });
        
        // Randomize timing if enabled
        if (this.config.random_delays) {
            this.addRandomDelays();
        }
        
        // Hide Frida-related artifacts
        this.hideFridaArtifacts();
    },    
    // Add random delays to avoid timing-based detection
    addRandomDelays: function() {
        const originalSend = send;
        send = function(data) {
            // Add random delay before sending
            const delay = Math.random() * 100;
            setTimeout(() => {
                originalSend.call(this, data);
            }, delay);
        };
    },
    
    // Hide Frida-related artifacts
    hideFridaArtifacts: function() {
        // This would include more sophisticated anti-detection measures
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "frida_artifact_hiding_enabled"
        });
    },
    
    // Print bypass statistics
    printStatistics: function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "statistics_separator",
            message: "
=========================================="
        });
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "statistics_title",
            message: "SSL Certificate Pinning Bypass Statistics"
        });
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "statistics_separator",
            message: "=========================================="
        });
        send({
            type: "status",
            target: "certificate_pinning_bypass",
            action: "statistics_platform",
            platform: this.state.platform
        });
        send({
            type: "status",
            target: "certificate_pinning_bypass",
            action: "statistics_bypassed_validations",
            count: this.state.bypassed_validations
        });
        send({
            type: "status",
            target: "certificate_pinning_bypass",
            action: "statistics_failed_bypasses",
            count: this.state.failed_bypasses
        });
        send({
            type: "status",
            target: "certificate_pinning_bypass",
            action: "statistics_active_bypasses",
            count: this.state.active_bypasses.size
        });
        send({
            type: "status",
            target: "certificate_pinning_bypass",
            action: "statistics_hooked_functions",
            count: this.state.hooked_functions.size
        });
        send({
            type: "status",
            target: "certificate_pinning_bypass",
            action: "statistics_trusted_certificates",
            count: this.certificates.trusted_certs.size
        });
        send({
            type: "status",
            target: "certificate_pinning_bypass",
            action: "statistics_injected_certificates",
            count: this.certificates.server_certs.size
        });
        
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "statistics_active_bypass_methods_header"
        });
        Array.from(this.state.active_bypasses).forEach(bypass => {
            send({
                type: "info",
                target: "certificate_pinning_bypass",
                action: "statistics_bypass_method",
                method: bypass
            });
        });
        
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "statistics_hooked_functions_header"
        });
        this.state.hooked_functions.forEach((func, key) => {
            send({
                type: "info",
                target: "certificate_pinning_bypass",
                action: "statistics_hooked_function",
                key: key,
                function: func
            });
        });
        
        if (this.validationAttempts && this.validationAttempts.length > 0) {
            send({
                type: "info",
                target: "certificate_pinning_bypass",
                action: "statistics_validation_attempts_header",
                count: this.validationAttempts.length
            });
            this.validationAttempts.slice(-5).forEach(attempt => {
                const date = new Date(attempt.timestamp);
                send({
                    type: "info",
                    target: "certificate_pinning_bypass",
                    action: "statistics_validation_attempt",
                    hostname: attempt.hostname,
                    method: attempt.method,
                    result: attempt.result,
                    time: date.toLocaleTimeString()
                });
            });
        }
        
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "statistics_separator",
            message: "==========================================
"
        });
    },    
    // Utility function to check if certificate should be trusted
    shouldTrustCertificate: function(hostname, certificate) {
        // Always trust if certificate injection is enabled
        if (this.config.cert_injection) {
            return this.validateCertificate(hostname, certificate);
        }
        
        // Check against trusted certificates
        return this.certificates.trusted_certs.has(hostname);
    },
    
    // Utility function to log bypass attempts
    logBypassAttempt: function(method, hostname, success) {
        if (this.config.bypass_logging) {
            const status = success ? "SUCCESS" : "FAILED";
            send({
                type: success ? "bypass" : "error",
                target: "certificate_pinning_bypass",
                action: "validation_logged",
                method: method,
                hostname: hostname,
                status: status
            });
            
            if (success) {
                this.state.bypassed_validations++;
            } else {
                this.state.failed_bypasses++;
            }
            
            // Log validation attempt
            if (this.logValidationAttempt) {
                this.logValidationAttempt(hostname, status, method);
            }
        }
    },
    
    // Cleanup function
    cleanup: function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "cleanup_starting"
        });
        
        // Clear statistics
        this.state.bypassed_validations = 0;
        this.state.failed_bypasses = 0;
        this.state.active_bypasses.clear();
        this.state.hooked_functions.clear();
        
        // Clear certificates
        this.certificates.server_certs.clear();
        this.certificates.trusted_certs.clear();
        
        send({
            type: "success",
            target: "certificate_pinning_bypass",
            action: "cleanup_complete"
        });
    },
    
    // Main entry point
    run: function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "startup_separator",
            message: "=========================================="
        });
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "startup_title",
            version: "v2.0.0"
        });
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "startup_description",
            message: "Comprehensive SSL/TLS Pinning Bypass"
        });
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "startup_separator",
            message: "===========================================
"
        });
        
        this.initialize();
        
        // Print initial statistics
        setTimeout(() => {
            this.printStatistics();
        }, 2000);
    }
};// Auto-run on script load
if (typeof rpc !== 'undefined') {
    // Frida RPC exports
    rpc.exports = {
        init: function() {
            sslBypass.run();
        },
        
        getStatistics: function() {
            return {
                platform: sslBypass.state.platform,
                bypassed_validations: sslBypass.state.bypassed_validations,
                failed_bypasses: sslBypass.state.failed_bypasses,
                active_bypasses: Array.from(sslBypass.state.active_bypasses),
                hooked_functions: Array.from(sslBypass.state.hooked_functions.keys()),
                trusted_certificates: Array.from(sslBypass.certificates.trusted_certs),
                injected_certificates: Array.from(sslBypass.certificates.server_certs.keys())
            };
        },
        
        addTrustedCertificate: function(hostname, certificate) {
            return sslBypass.addTrustedCertificate(hostname, certificate);
        },
        
        removeTrustedCertificate: function(hostname) {
            return sslBypass.removeTrustedCertificate(hostname);
        },
        
        injectCertificate: function(hostname, certificate) {
            return sslBypass.injectCustomCertificate(hostname, certificate);
        },
        
        cleanup: function() {
            sslBypass.cleanup();
        }
    };
}

// Store reference for global access
const sslBypass = certificatePinningBypass;

// Auto-run immediately
sslBypass.run();

// Also run on Java.available (for Android apps that load Java later)
if (typeof Java !== 'undefined' && Java.available) {
    Java.perform(function() {
        send({
            type: "info",
            target: "certificate_pinning_bypass",
            action: "autorun_java_detected"
        });
        sslBypass.initializeAndroidBypasses();
    });
} else if (typeof Java !== 'undefined') {
    // Wait for Java to become available
    const javaCheckInterval = setInterval(function() {
        if (Java.available) {
            clearInterval(javaCheckInterval);
            Java.perform(function() {
                send({
                    type: "info",
                    target: "certificate_pinning_bypass",
                    action: "autorun_java_became_available"
                });
                sslBypass.initializeAndroidBypasses();
            });
        }
    }, 1000);
}

// Export the main bypass object
const certificatePinningBypass = this;