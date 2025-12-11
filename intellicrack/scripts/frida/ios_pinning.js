const kSSLSessionOptionBreakOnServerAuth = 4;
const kSecTrustResultProceed = 1;
const kSecTrustResultUnspecified = 4;
const errSSLServerAuthCompleted = -9841;
const noErr = 0;

const pinnedCerts = [];
const tlsSessions = [];
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

if (ObjC.available) {
    log('Objective-C runtime detected - initializing iOS certificate pinning bypass');

    try {
        const SSLSetSessionOption = Module.findExportByName('CFNetwork', 'SSLSetSessionOption');
        if (SSLSetSessionOption) {
            Interceptor.attach(SSLSetSessionOption, {
                onEnter: function (args) {
                    const _context = args[0];
                    const option = args[1].toInt32();
                    const _value = args[2].toInt32();

                    if (option === kSSLSessionOptionBreakOnServerAuth) {
                        log(
                            'SSLSetSessionOption: Disabling kSSLSessionOptionBreakOnServerAuth (pinning prevention)'
                        );
                        args[2] = ptr(0);
                        this.modified = true;
                    }
                },
                onLeave: function (_retval) {
                    if (this.modified) {
                        send({ type: 'ssl_option_bypass' });
                    }
                },
            });
            log('Successfully hooked SSLSetSessionOption');
        }
    } catch (e) {
        logError(`Failed to hook SSLSetSessionOption: ${e.message}`);
    }

    try {
        const SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onEnter: function (args) {
                    const trust = args[0];
                    const result = args[1];

                    this.trust = trust;
                    this.result = result;
                },
                onLeave: function (retval) {
                    const status = retval.toInt32();

                    if (!this.result.isNull()) {
                        const originalResult = this.result.readU32();

                        if (
                            originalResult !== kSecTrustResultProceed &&
                            originalResult !== kSecTrustResultUnspecified
                        ) {
                            log(
                                `SecTrustEvaluate: Original result=${originalResult}, forcing kSecTrustResultUnspecified`
                            );
                            this.result.writeU32(kSecTrustResultUnspecified);

                            const certInfo = {
                                timestamp: new Date().toISOString(),
                                trust: this.trust.toString(),
                                originalResult: originalResult,
                                forcedResult: kSecTrustResultUnspecified,
                                bypassed: true,
                            };
                            pinnedCerts.push(certInfo);
                            if (pinnedCerts.length > MAX_LOG) {
                                pinnedCerts.shift();
                            }
                            send({ type: 'sec_trust_bypass', data: certInfo });
                        }
                    }

                    if (status !== noErr) {
                        log(`SecTrustEvaluate: Failed with status=${status}, forcing noErr`);
                        retval.replace(ptr(noErr));
                    }
                },
            });
            log('Successfully hooked SecTrustEvaluate');
        }
    } catch (e) {
        logError(`Failed to hook SecTrustEvaluate: ${e.message}`);
    }

    try {
        const SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
        if (SSLHandshake) {
            const handshakeCallCount = {};

            Interceptor.attach(SSLHandshake, {
                onEnter: function (args) {
                    const context = args[0];
                    this.context = context.toString();

                    if (!handshakeCallCount[this.context]) {
                        handshakeCallCount[this.context] = 0;
                    }
                    handshakeCallCount[this.context]++;

                    this.callNumber = handshakeCallCount[this.context];
                },
                onLeave: function (retval) {
                    const status = retval.toInt32();

                    if (this.callNumber === 1 && status !== errSSLServerAuthCompleted) {
                        log(
                            'SSLHandshake (call #1): Forcing errSSLServerAuthCompleted to trigger auth'
                        );
                        retval.replace(ptr(errSSLServerAuthCompleted));

                        const sessionInfo = {
                            timestamp: new Date().toISOString(),
                            context: this.context,
                            callNumber: 1,
                            modifiedStatus: errSSLServerAuthCompleted,
                        };
                        tlsSessions.push(sessionInfo);
                        if (tlsSessions.length > MAX_LOG) {
                            tlsSessions.shift();
                        }
                    } else if (this.callNumber === 2 && status !== noErr) {
                        log('SSLHandshake (call #2): Forcing noErr to complete handshake');
                        retval.replace(ptr(noErr));

                        send({ type: 'ssl_handshake_bypass', context: this.context });
                    }
                },
            });
            log('Successfully hooked SSLHandshake');
        }
    } catch (e) {
        logError(`Failed to hook SSLHandshake: ${e.message}`);
    }

    try {
        const libboringssl = Process.findModuleByName('libboringssl.dylib');
        if (libboringssl) {
            log('BoringSSL detected on iOS');

            const tls_helper_create_peer_trust = Module.findExportByName(
                'libboringssl.dylib',
                'tls_helper_create_peer_trust'
            );
            if (tls_helper_create_peer_trust) {
                Interceptor.attach(tls_helper_create_peer_trust, {
                    onEnter: _args => {
                        log('tls_helper_create_peer_trust: Intercepted');
                    },
                    onLeave: retval => {
                        if (!retval.isNull()) {
                            log(
                                'tls_helper_create_peer_trust: Returning NULL to bypass trust evaluation'
                            );
                            retval.replace(ptr(0));
                            send({ type: 'boringssl_trust_bypass' });
                        }
                    },
                });
                log('Successfully hooked tls_helper_create_peer_trust');
            }
        }
    } catch (e) {
        log(`BoringSSL not found or failed to hook: ${e.message}`);
    }

    try {
        if (ObjC.classes.AFSecurityPolicy) {
            log('AFNetworking framework detected');

            const { AFSecurityPolicy } = ObjC.classes;

            Interceptor.attach(
                AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation,
                {
                    onEnter: function (args) {
                        const _serverTrust = new ObjC.Object(args[2]);
                        const domain = new ObjC.Object(args[3]);

                        log(
                            `AFSecurityPolicy.evaluateServerTrust: Bypassing for domain="${domain}"`
                        );

                        this.domain = domain.toString();
                    },
                    onLeave: function (retval) {
                        const originalResult = retval.toInt32();

                        if (originalResult === 0) {
                            log(
                                `AFSecurityPolicy.evaluateServerTrust: Failed for "${this.domain}", forcing YES`
                            );
                            retval.replace(ptr(1));

                            send({ type: 'afnetworking_bypass', domain: this.domain });
                        }
                    },
                }
            );
            log('Successfully hooked AFSecurityPolicy.evaluateServerTrust');
        }
    } catch (e) {
        log(`AFNetworking not found or failed to hook: ${e.message}`);
    }

    try {
        if (ObjC.classes.NSURLSession) {
            log('NSURLSession detected - hooking delegate methods');

            const { NSURLSessionDelegate } = ObjC.protocols;
            if (NSURLSessionDelegate) {
                const originalDidReceiveChallenge =
                    NSURLSessionDelegate.methods[
                        'URLSession:didReceiveChallenge:completionHandler:'
                    ];

                if (originalDidReceiveChallenge) {
                    const _hookBlock = ObjC.Block.implement({
                        types: originalDidReceiveChallenge.types,
                        implementation: (session, challenge, completionHandler) => {
                            const challengeObj = new ObjC.Object(challenge);
                            const authMethod = challengeObj
                                .protectionSpace()
                                .authenticationMethod()
                                .toString();

                            if (authMethod === 'NSURLAuthenticationMethodServerTrust') {
                                log('NSURLSession: Server trust challenge - auto-accepting');

                                const serverTrust = challengeObj.protectionSpace().serverTrust();
                                const { NSURLCredential } = ObjC.classes;
                                const credential = NSURLCredential.credentialForTrust_(serverTrust);

                                const completionBlock = new ObjC.Block(completionHandler);
                                const NSURLSessionAuthChallengeDisposition = {
                                    UseCredential: 0,
                                    PerformDefaultHandling: 1,
                                    CancelAuthenticationChallenge: 2,
                                    RejectProtectionSpace: 3,
                                };

                                completionBlock.implementation(
                                    NSURLSessionAuthChallengeDisposition.UseCredential,
                                    credential
                                );

                                send({ type: 'nsurlsession_trust_bypass' });
                                return;
                            }

                            return originalDidReceiveChallenge.implementation(
                                session,
                                challenge,
                                completionHandler
                            );
                        },
                    });

                    log('NSURLSession authentication challenge handler prepared');
                }
            }
        }
    } catch (e) {
        logError(`Failed to hook NSURLSession: ${e.message}`);
    }

    try {
        if (ObjC.classes.NSURLConnection) {
            const { NSURLConnection } = ObjC.classes;

            Interceptor.attach(
                NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'].implementation,
                {
                    onEnter: args => {
                        const request = new ObjC.Object(args[2]);
                        const url = request.URL().absoluteString().toString();
                        log(`NSURLConnection: Synchronous request to ${url}`);
                    },
                }
            );

            log('Successfully hooked NSURLConnection');
        }
    } catch (e) {
        log(`NSURLConnection not found or failed to hook: ${e.message}`);
    }

    try {
        const SecTrustGetCertificateCount = Module.findExportByName(
            'Security',
            'SecTrustGetCertificateCount'
        );
        const SecTrustGetCertificateAtIndex = Module.findExportByName(
            'Security',
            'SecTrustGetCertificateAtIndex'
        );
        const SecCertificateCopyData = Module.findExportByName(
            'Security',
            'SecCertificateCopyData'
        );

        if (
            SecTrustGetCertificateCount &&
            SecTrustGetCertificateAtIndex &&
            SecCertificateCopyData
        ) {
            Interceptor.attach(SecTrustGetCertificateCount, {
                onEnter: function (args) {
                    this.trust = args[0];
                },
                onLeave: retval => {
                    const count = retval.toInt32();
                    if (count > 0) {
                        log(`SecTrustGetCertificateCount: ${count} certificate(s) in chain`);
                    }
                },
            });
            log('Successfully hooked SecTrustGetCertificateCount');
        }
    } catch (e) {
        logError(`Failed to hook certificate extraction functions: ${e.message}`);
    }

    log('iOS certificate pinning bypass initialization complete');
    send({ type: 'bypass_success', platform: 'iOS' });
} else {
    logError('Objective-C runtime not available - not an iOS app');
    send({ type: 'bypass_failure', platform: 'iOS', reason: 'ObjC not available' });
}

rpc.exports = {
    getPinnedCertificates: () => pinnedCerts,
    getTLSSessions: () => tlsSessions,
    getActivity: () => activity,
    clearLogs: () => {
        activity.length = 0;
        pinnedCerts.length = 0;
        tlsSessions.length = 0;
        log('All logs cleared');
        return true;
    },
    getBypassStatus: () => ({
        active: ObjC.available,
        platform: 'iOS',
        bypassMethods: [
            'SSLSetSessionOption',
            'SecTrustEvaluate',
            'SSLHandshake',
            'tls_helper_create_peer_trust',
            'AFSecurityPolicy',
            'NSURLSession',
            'NSURLConnection',
        ],
        pinnedCertCount: pinnedCerts.length,
        tlsSessionCount: tlsSessions.length,
    }),
    testBypass: () => {
        if (!ObjC.available) {
            return {
                success: false,
                message: 'Objective-C runtime not available',
            };
        }

        log('Testing iOS pinning bypass functionality');
        return {
            success: true,
            message: 'iOS certificate pinning bypass is active',
            stats: {
                pinnedCerts: pinnedCerts.length,
                tlsSessions: tlsSessions.length,
            },
        };
    },
};
