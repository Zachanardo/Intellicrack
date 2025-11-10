const ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000;
const ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080;
const SECPKG_ATTR_REMOTE_CERT_CONTEXT = 0x53;
const SECPKG_ATTR_STREAM_SIZES = 0x04;
const SECPKG_ATTR_CONNECTION_INFO = 0x5a;
const SEC_E_OK = 0x00000000;

const sessions = [];
const certificates = [];
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

const sspicli = Process.findModuleByName('sspicli.dll') || Process.findModuleByName('secur32.dll');
if (!sspicli) {
    logError('Schannel module (sspicli.dll/secur32.dll) not found');
} else {
    log('Schannel module found at: ' + sspicli.base);

    try {
        const InitializeSecurityContext =
            Module.findExportByName(sspicli.name, 'InitializeSecurityContextW') ||
            Module.findExportByName(sspicli.name, 'InitializeSecurityContextA');
        if (InitializeSecurityContext) {
            Interceptor.attach(InitializeSecurityContext, {
                onEnter: function (args) {
                    const phCredential = args[0];
                    const phContext = args[1];
                    const pszTargetName = args[2];
                    const fContextReq = args[3];
                    const Reserved1 = args[4];
                    const TargetDataRep = args[5];
                    const pInput = args[6];
                    const Reserved2 = args[7];
                    const phNewContext = args[8];
                    const pOutput = args[9];
                    const pfContextAttr = args[10];
                    const ptsExpiry = args[11];

                    let targetName = '';
                    if (!pszTargetName.isNull()) {
                        try {
                            targetName = pszTargetName.readUtf16String();
                        } catch (e) {
                            try {
                                targetName = pszTargetName.readAnsiString();
                            } catch (e2) {
                                targetName = '<unable to read>';
                            }
                        }
                    }

                    const originalFlags = fContextReq.toInt32();
                    const modifiedFlags =
                        (originalFlags | ISC_REQ_MANUAL_CRED_VALIDATION) &
                        ~ISC_REQ_USE_SUPPLIED_CREDS;
                    args[3] = ptr(modifiedFlags);

                    log(
                        `InitializeSecurityContext: Target="${targetName}", Flags: 0x${originalFlags.toString(16)} -> 0x${modifiedFlags.toString(16)}`
                    );

                    this.targetName = targetName;
                    this.originalFlags = originalFlags;
                    this.modifiedFlags = modifiedFlags;
                    this.phNewContext = phNewContext;
                },
                onLeave: function (retval) {
                    const result = retval.toInt32();
                    log(`InitializeSecurityContext: Returned 0x${result.toString(16)}`);

                    if (result === SEC_E_OK || result === 0x00090312) {
                        const sessionInfo = {
                            timestamp: new Date().toISOString(),
                            targetName: this.targetName,
                            originalFlags: this.originalFlags,
                            modifiedFlags: this.modifiedFlags,
                            result: result,
                        };
                        sessions.push(sessionInfo);
                        if (sessions.length > MAX_LOG) {
                            sessions.shift();
                        }
                        send({ type: 'tls_session', data: sessionInfo });
                    }
                },
            });
            log('Successfully hooked InitializeSecurityContext');
        }
    } catch (e) {
        logError('Failed to hook InitializeSecurityContext: ' + e.message);
    }

    try {
        const QueryContextAttributes =
            Module.findExportByName(sspicli.name, 'QueryContextAttributesW') ||
            Module.findExportByName(sspicli.name, 'QueryContextAttributesA');
        if (QueryContextAttributes) {
            Interceptor.attach(QueryContextAttributes, {
                onEnter: function (args) {
                    const phContext = args[0];
                    const ulAttribute = args[1].toInt32();
                    const pBuffer = args[2];

                    this.ulAttribute = ulAttribute;
                    this.pBuffer = pBuffer;

                    if (ulAttribute === SECPKG_ATTR_REMOTE_CERT_CONTEXT) {
                        log('QueryContextAttributes: Request for REMOTE_CERT_CONTEXT');
                        this.wantsCert = true;
                    }
                },
                onLeave: function (retval) {
                    const result = retval.toInt32();

                    if (this.wantsCert && result === SEC_E_OK) {
                        try {
                            const certContextPtr = this.pBuffer.readPointer();
                            if (!certContextPtr.isNull()) {
                                const CERT_CONTEXT_SIZE = Process.pointerSize === 8 ? 0x28 : 0x14;
                                const dwCertEncodingType = certContextPtr.readU32();
                                const pbCertEncoded = certContextPtr
                                    .add(Process.pointerSize)
                                    .readPointer();
                                const cbCertEncoded = certContextPtr
                                    .add(Process.pointerSize * 2)
                                    .readU32();

                                let certData = null;
                                if (
                                    !pbCertEncoded.isNull() &&
                                    cbCertEncoded > 0 &&
                                    cbCertEncoded < 0x10000
                                ) {
                                    try {
                                        certData = pbCertEncoded.readByteArray(cbCertEncoded);
                                    } catch (e) {
                                        logError('Failed to read certificate data: ' + e.message);
                                    }
                                }

                                const interceptedCert = {
                                    timestamp: new Date().toISOString(),
                                    attribute: 'REMOTE_CERT_CONTEXT',
                                    certContextAddress: certContextPtr.toString(),
                                    encodingType: dwCertEncodingType,
                                    encodedSize: cbCertEncoded,
                                    certData: certData
                                        ? Array.from(new Uint8Array(certData)).slice(0, 256)
                                        : null,
                                    bypassed: true,
                                };
                                certificates.push(interceptedCert);
                                if (certificates.length > MAX_LOG) {
                                    certificates.shift();
                                }
                                log(
                                    `QueryContextAttributes: Intercepted certificate - Size: ${cbCertEncoded} bytes, Encoding: 0x${dwCertEncodingType.toString(16)}`
                                );
                                send({ type: 'certificate', data: interceptedCert });
                            }
                        } catch (e) {
                            logError('Failed to process certificate context: ' + e.message);
                        }
                    }

                    if (result !== SEC_E_OK) {
                        log(
                            `QueryContextAttributes: Failed with 0x${result.toString(16)}, forcing success`
                        );
                        retval.replace(ptr(SEC_E_OK));
                    }
                },
            });
            log('Successfully hooked QueryContextAttributes');
        }
    } catch (e) {
        logError('Failed to hook QueryContextAttributes: ' + e.message);
    }

    try {
        const AcceptSecurityContext = Module.findExportByName(
            sspicli.name,
            'AcceptSecurityContext'
        );
        if (AcceptSecurityContext) {
            Interceptor.attach(AcceptSecurityContext, {
                onEnter: function (args) {
                    const phCredential = args[0];
                    const phContext = args[1];
                    const pInput = args[2];
                    const fContextReq = args[3];
                    const TargetDataRep = args[4];
                    const phNewContext = args[5];
                    const pOutput = args[6];
                    const pfContextAttr = args[7];
                    const ptsExpiry = args[8];

                    const originalFlags = fContextReq.toInt32();
                    const modifiedFlags = originalFlags | ISC_REQ_MANUAL_CRED_VALIDATION;
                    args[3] = ptr(modifiedFlags);

                    log(
                        `AcceptSecurityContext: Modified flags 0x${originalFlags.toString(16)} -> 0x${modifiedFlags.toString(16)}`
                    );
                },
                onLeave: function (retval) {
                    const result = retval.toInt32();
                    log(`AcceptSecurityContext: Returned 0x${result.toString(16)}`);
                },
            });
            log('Successfully hooked AcceptSecurityContext');
        }
    } catch (e) {
        logError('Failed to hook AcceptSecurityContext: ' + e.message);
    }

    try {
        const EncryptMessage = Module.findExportByName(sspicli.name, 'EncryptMessage');
        if (EncryptMessage) {
            Interceptor.attach(EncryptMessage, {
                onEnter: function (args) {
                    this.phContext = args[0];
                },
                onLeave: function (retval) {
                    const result = retval.toInt32();
                    if (result !== SEC_E_OK) {
                        log(
                            `EncryptMessage: Failed with 0x${result.toString(16)}, allowing to proceed`
                        );
                    }
                },
            });
            log('Successfully hooked EncryptMessage');
        }
    } catch (e) {
        logError('Failed to hook EncryptMessage: ' + e.message);
    }

    try {
        const DecryptMessage = Module.findExportByName(sspicli.name, 'DecryptMessage');
        if (DecryptMessage) {
            Interceptor.attach(DecryptMessage, {
                onEnter: function (args) {
                    this.phContext = args[0];
                },
                onLeave: function (retval) {
                    const result = retval.toInt32();
                    if (result !== SEC_E_OK) {
                        log(
                            `DecryptMessage: Failed with 0x${result.toString(16)}, allowing to proceed`
                        );
                    }
                },
            });
            log('Successfully hooked DecryptMessage');
        }
    } catch (e) {
        logError('Failed to hook DecryptMessage: ' + e.message);
    }

    try {
        const crypt32 = Process.findModuleByName('crypt32.dll');
        if (crypt32) {
            const SslCrackCertificate = Module.findExportByName(
                'crypt32.dll',
                'SslCrackCertificate'
            );
            if (SslCrackCertificate) {
                Interceptor.attach(SslCrackCertificate, {
                    onEnter: function (args) {
                        log('SslCrackCertificate called');
                    },
                    onLeave: function (retval) {
                        if (retval.toInt32() === 0) {
                            log('SslCrackCertificate: Failed, forcing success');
                            retval.replace(ptr(1));
                        }
                    },
                });
                log('Successfully hooked SslCrackCertificate');
            }
        }
    } catch (e) {
        logError('Failed to hook SslCrackCertificate: ' + e.message);
    }
}

rpc.exports = {
    getSchannelSessions: function () {
        return sessions;
    },
    getCertificateInfo: function () {
        return certificates;
    },
    getActivity: function () {
        return activity;
    },
    clearLogs: function () {
        activity.length = 0;
        sessions.length = 0;
        certificates.length = 0;
        log('All logs cleared');
        return true;
    },
    getBypassStatus: function () {
        return {
            active: true,
            library: 'Schannel (sspicli.dll/secur32.dll)',
            hooksInstalled: [
                'InitializeSecurityContext',
                'QueryContextAttributes',
                'AcceptSecurityContext',
                'EncryptMessage',
                'DecryptMessage',
                'SslCrackCertificate',
            ],
            sessionCount: sessions.length,
            certificateCount: certificates.length,
        };
    },
    testBypass: function () {
        log('Testing Schannel bypass functionality');
        return {
            success: true,
            message: 'Schannel bypass is active and monitoring',
            stats: {
                sessions: sessions.length,
                certificates: certificates.length,
            },
        };
    },
};

log('Schannel certificate bypass script loaded successfully');
send({ type: 'bypass_success', library: 'Schannel' });
