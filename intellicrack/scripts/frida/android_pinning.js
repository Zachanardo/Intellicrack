const pinnedCerts = [];
const bypassedConnections = [];
const activity = [];
const MAX_LOG = 1000;

function log(message, level = 'info') {
    const entry = {
        timestamp: new Date().toISOString(),
        level: level,
        message: message,
    };
    send({ type: 'log', data: entry });
    activity.push(entry);
    if (activity.length > MAX_LOG) {
        activity.shift();
    }
}

function logError(message) {
    log(message, 'error');
}

if (!Java.available) {
    logError('Java runtime not available - not an Android app');
    send({ type: 'bypass_failure', platform: 'Android', reason: 'Java not available' });
} else {
    log('Java runtime detected - initializing Android certificate pinning bypass');

    Java.perform(() => {
        try {
            const OkHttpCertificatePinner = Java.use('okhttp3.CertificatePinner');

            OkHttpCertificatePinner.check.overload(
                'java.lang.String',
                'java.util.List'
            ).implementation = (hostname, peerCertificates) => {
                log(`OkHttp3 CertificatePinner.check: Bypassing for hostname="${hostname}"`);

                const certCount = peerCertificates.size();
                for (let i = 0; i < certCount; i++) {
                    try {
                        const _cert = peerCertificates.get(i);
                        const certInfo = {
                            timestamp: new Date().toISOString(),
                            hostname: hostname,
                            certificateIndex: i,
                            bypassed: true,
                            method: 'OkHttp3 CertificatePinner',
                        };
                        pinnedCerts.push(certInfo);
                        if (pinnedCerts.length > MAX_LOG) {
                            pinnedCerts.shift();
                        }
                    } catch (e) {
                        logError(`Failed to extract certificate info: ${e.message}`);
                    }
                }

                send({ type: 'pinning_bypass', method: 'OkHttp3', hostname: hostname });
            };
            log('Successfully hooked OkHttp3 CertificatePinner.check');
        } catch (_e) {
            log('OkHttp3 CertificatePinner not found (not using OkHttp or different version)');
        }

        try {
            const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

            TrustManagerImpl.verifyChain.implementation = (
                untrustedChain,
                trustAnchorChain,
                host,
                clientAuth,
                _ocspData,
                _tlsSctData
            ) => {
                log(`TrustManagerImpl.verifyChain: Bypassing for host="${host}"`);

                const chainInfo = {
                    timestamp: new Date().toISOString(),
                    host: host,
                    untrustedChainLength: untrustedChain.length,
                    trustAnchorChainLength: trustAnchorChain ? trustAnchorChain.length : 0,
                    clientAuth: clientAuth,
                    bypassed: true,
                    method: 'TrustManagerImpl',
                };
                bypassedConnections.push(chainInfo);
                if (bypassedConnections.length > MAX_LOG) {
                    bypassedConnections.shift();
                }

                send({ type: 'trust_manager_bypass', host: host });
                return untrustedChain;
            };
            log('Successfully hooked TrustManagerImpl.verifyChain');
        } catch (e) {
            logError(`Failed to hook TrustManagerImpl: ${e.message}`);
        }

        try {
            const NetworkSecurityTrustManager = Java.use(
                'android.security.net.config.NetworkSecurityTrustManager'
            );

            NetworkSecurityTrustManager.checkPins.implementation = _pins => {
                log('NetworkSecurityTrustManager.checkPins: Bypassing pin check');
                send({ type: 'network_security_bypass' });
            };
            log('Successfully hooked NetworkSecurityTrustManager.checkPins');
        } catch (_e) {
            log('NetworkSecurityTrustManager not found or different API level');
        }

        try {
            const _X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const _X509TrustManagerExtensions = Java.use(
                'android.net.http.X509TrustManagerExtensions'
            );

            const _X509Certificate = Java.use('java.security.cert.X509Certificate');
            const _emptyArray = Java.array('Ljava.security.cert.X509Certificate;', []);

            Java.choose('javax.net.ssl.X509TrustManager', {
                onMatch: instance => {
                    try {
                        const className = instance.$className;
                        log(`Found X509TrustManager implementation: ${className}`);

                        if (instance.checkServerTrusted) {
                            const _originalCheckServerTrusted = instance.checkServerTrusted;
                            instance.checkServerTrusted.overload(
                                '[Ljava.security.cert.X509Certificate;',
                                'java.lang.String'
                            ).implementation = (chain, authType) => {
                                log(
                                    `X509TrustManager.checkServerTrusted: Bypassing for class="${className}", authType="${authType}"`
                                );

                                const certInfo = {
                                    timestamp: new Date().toISOString(),
                                    className: className,
                                    authType: authType,
                                    chainLength: chain.length,
                                    bypassed: true,
                                    method: 'X509TrustManager',
                                };
                                bypassedConnections.push(certInfo);
                                if (bypassedConnections.length > MAX_LOG) {
                                    bypassedConnections.shift();
                                }

                                send({ type: 'x509_bypass', className: className });
                            };
                        }

                        if (
                            instance.checkServerTrusted?.overload(
                                '[Ljava.security.cert.X509Certificate;',
                                'java.lang.String',
                                'java.lang.String'
                            )
                        ) {
                            instance.checkServerTrusted.overload(
                                '[Ljava.security.cert.X509Certificate;',
                                'java.lang.String',
                                'java.lang.String'
                            ).implementation = (_chain, _authType, host) => {
                                log(
                                    `X509TrustManager.checkServerTrusted (with host): Bypassing for host="${host}"`
                                );
                                send({ type: 'x509_bypass_with_host', host: host });
                            };
                        }
                    } catch (e) {
                        logError(`Failed to hook X509TrustManager instance: ${e.message}`);
                    }
                },
                onComplete: () => {
                    log('Completed X509TrustManager enumeration and hooking');
                },
            });
        } catch (e) {
            logError(`Failed to enumerate X509TrustManager implementations: ${e.message}`);
        }

        try {
            const SSLContext = Java.use('javax.net.ssl.SSLContext');
            const originalInit = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );

            const _TrustManager = Java.use('javax.net.ssl.TrustManager');
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

            const CustomTrustManager = Java.registerClass({
                name: 'com.intellicrack.CustomTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: (_chain, _authType) => {
                        log('CustomTrustManager.checkClientTrusted: Accepting all');
                    },
                    checkServerTrusted: (_chain, authType) => {
                        log('CustomTrustManager.checkServerTrusted: Accepting all certificates');
                        send({ type: 'custom_trust_manager_bypass', authType: authType });
                    },
                    getAcceptedIssuers: () =>
                        Java.array('Ljava.security.cert.X509Certificate;', []),
                },
            });

            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (keyManagers, _trustManagers, secureRandom) {
                log('SSLContext.init: Injecting custom TrustManager');

                const customTrustManager = CustomTrustManager.$new();
                const customTrustManagers = Java.array('Ljavax.net.ssl.TrustManager;', [
                    customTrustManager,
                ]);

                originalInit.call(this, keyManagers, customTrustManagers, secureRandom);
            };
            log('Successfully hooked SSLContext.init and registered CustomTrustManager');
        } catch (e) {
            logError(`Failed to hook SSLContext.init: ${e.message}`);
        }

        try {
            const WebViewClient = Java.use('android.webkit.WebViewClient');

            WebViewClient.onReceivedSslError.implementation = (_view, handler, error) => {
                log('WebViewClient.onReceivedSslError: Auto-proceeding through SSL error');

                const errorInfo = {
                    timestamp: new Date().toISOString(),
                    primaryError: error.getPrimaryError(),
                    url: error.getUrl(),
                    bypassed: true,
                    method: 'WebViewClient',
                };
                bypassedConnections.push(errorInfo);
                if (bypassedConnections.length > MAX_LOG) {
                    bypassedConnections.shift();
                }

                send({ type: 'webview_ssl_bypass', url: error.getUrl() });
                handler.proceed();
            };
            log('Successfully hooked WebViewClient.onReceivedSslError');
        } catch (e) {
            logError(`Failed to hook WebViewClient: ${e.message}`);
        }

        try {
            const _HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');

            Java.choose('javax.net.ssl.HostnameVerifier', {
                onMatch: instance => {
                    try {
                        const className = instance.$className;
                        log(`Found HostnameVerifier implementation: ${className}`);

                        if (instance.verify) {
                            instance.verify.overload(
                                'java.lang.String',
                                'javax.net.ssl.SSLSession'
                            ).implementation = (hostname, _session) => {
                                log(
                                    `HostnameVerifier.verify: Auto-verifying hostname="${hostname}"`
                                );
                                send({ type: 'hostname_verifier_bypass', hostname: hostname });
                                return true;
                            };
                        }
                    } catch (e) {
                        logError(`Failed to hook HostnameVerifier instance: ${e.message}`);
                    }
                },
                onComplete: () => {
                    log('Completed HostnameVerifier enumeration and hooking');
                },
            });
        } catch (e) {
            logError(`Failed to enumerate HostnameVerifier implementations: ${e.message}`);
        }

        try {
            const PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');

            PinningTrustManager.checkServerTrusted.implementation = (_chain, _authType) => {
                log('Appcelerator PinningTrustManager: Bypassing');
                send({ type: 'appcelerator_bypass' });
            };
            log('Successfully hooked Appcelerator PinningTrustManager');
        } catch (_e) {
            log('Appcelerator PinningTrustManager not found');
        }

        try {
            const _WorkManagerUtils = Java.use('androidx.work.impl.utils.WorkManagerUtils');
            log('WorkManager detected - additional SSL handling may be needed');
        } catch (_e) {}

        log('Android certificate pinning bypass initialization complete');
        send({ type: 'bypass_success', platform: 'Android' });
    });
}

rpc.exports = {
    getPinnedCertificates: () => pinnedCerts,
    getBypassedConnections: () => bypassedConnections,
    getActivity: () => activity,
    clearLogs: () => {
        activity.length = 0;
        pinnedCerts.length = 0;
        bypassedConnections.length = 0;
        log('All logs cleared');
        return true;
    },
    getBypassStatus: () => ({
        active: Java.available,
        platform: 'Android',
        bypassMethods: [
            'OkHttp3 CertificatePinner',
            'TrustManagerImpl',
            'NetworkSecurityTrustManager',
            'X509TrustManager',
            'SSLContext',
            'WebViewClient',
            'HostnameVerifier',
            'Appcelerator',
        ],
        pinnedCertCount: pinnedCerts.length,
        bypassedConnectionCount: bypassedConnections.length,
    }),
    testBypass: () => {
        if (!Java.available) {
            return {
                success: false,
                message: 'Java runtime not available',
            };
        }

        log('Testing Android pinning bypass functionality');
        return {
            success: true,
            message: 'Android certificate pinning bypass is active',
            stats: {
                pinnedCerts: pinnedCerts.length,
                bypassedConnections: bypassedConnections.length,
            },
        };
    },
};
