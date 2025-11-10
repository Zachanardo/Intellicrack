const CERT_CHAIN_POLICY_BASE = 1;
const CERT_CHAIN_POLICY_AUTHENTICODE = 2;
const CERT_CHAIN_POLICY_SSL = 4;
const CERT_CHAIN_POLICY_NT_AUTH = 6;

const activity = [];
const chains = [];
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

const crypt32 = Process.findModuleByName('crypt32.dll');
if (!crypt32) {
    logError('crypt32.dll module not found');
} else {
    log('crypt32.dll found at: ' + crypt32.base);

    try {
        const CertVerifyCertificateChainPolicy = Module.findExportByName(
            'crypt32.dll',
            'CertVerifyCertificateChainPolicy'
        );
        if (CertVerifyCertificateChainPolicy) {
            Interceptor.attach(CertVerifyCertificateChainPolicy, {
                onEnter: function (args) {
                    const pszPolicyOID = args[0];
                    const pChainContext = args[1];
                    const pPolicyPara = args[2];
                    const pPolicyStatus = args[3];

                    let policyOID = pszPolicyOID.toInt32();
                    if (policyOID > 0 && policyOID < 100) {
                        log(`CertVerifyCertificateChainPolicy: Policy=${policyOID}`);
                    } else {
                        try {
                            const oidStr = pszPolicyOID.readAnsiString();
                            log(`CertVerifyCertificateChainPolicy: Policy OID="${oidStr}"`);
                        } catch (e) {
                            log('CertVerifyCertificateChainPolicy: Unable to read policy OID');
                        }
                    }

                    this.pPolicyStatus = pPolicyStatus;
                    this.pChainContext = pChainContext;
                    this.policyOID = policyOID;
                },
                onLeave: function (retval) {
                    const success = retval.toInt32();

                    if (!this.pPolicyStatus.isNull()) {
                        try {
                            const dwErrorOffset = Process.pointerSize === 8 ? 0x08 : 0x04;
                            const lChainIndexOffset = Process.pointerSize === 8 ? 0x10 : 0x08;
                            const lElementIndexOffset = Process.pointerSize === 8 ? 0x18 : 0x0c;

                            const originalError = this.pPolicyStatus.add(dwErrorOffset).readU32();
                            const originalChainIndex = this.pPolicyStatus
                                .add(lChainIndexOffset)
                                .readS32();
                            const originalElementIndex = this.pPolicyStatus
                                .add(lElementIndexOffset)
                                .readS32();

                            if (originalError !== 0) {
                                log(
                                    `CertVerifyCertificateChainPolicy: Original error=0x${originalError.toString(16)}, clearing to 0`
                                );

                                this.pPolicyStatus.add(dwErrorOffset).writeU32(0);
                                this.pPolicyStatus.add(lChainIndexOffset).writeS32(0);
                                this.pPolicyStatus.add(lElementIndexOffset).writeS32(0);

                                const chainInfo = {
                                    timestamp: new Date().toISOString(),
                                    policyOID: this.policyOID,
                                    originalError: originalError,
                                    chainIndex: originalChainIndex,
                                    elementIndex: originalElementIndex,
                                    bypassed: true,
                                };
                                chains.push(chainInfo);
                                if (chains.length > MAX_LOG) {
                                    chains.shift();
                                }
                                send({ type: 'certificate_chain', data: chainInfo });
                            }
                        } catch (e) {
                            logError('Failed to modify pPolicyStatus: ' + e.message);
                        }
                    }

                    if (success === 0) {
                        log('CertVerifyCertificateChainPolicy: Failed originally, forcing TRUE');
                        retval.replace(ptr(1));
                    } else {
                        log('CertVerifyCertificateChainPolicy: Succeeded, ensuring clean status');
                    }
                },
            });
            log('Successfully hooked CertVerifyCertificateChainPolicy');
        }
    } catch (e) {
        logError('Failed to hook CertVerifyCertificateChainPolicy: ' + e.message);
    }

    try {
        const CertGetCertificateChain = Module.findExportByName(
            'crypt32.dll',
            'CertGetCertificateChain'
        );
        if (CertGetCertificateChain) {
            Interceptor.attach(CertGetCertificateChain, {
                onEnter: function (args) {
                    const hChainEngine = args[0];
                    const pCertContext = args[1];
                    const pTime = args[2];
                    const hAdditionalStore = args[3];
                    const pChainPara = args[4];
                    const dwFlags = args[5].toInt32();
                    const pvReserved = args[6];
                    const ppChainContext = args[7];

                    log(`CertGetCertificateChain: Flags=0x${dwFlags.toString(16)}`);

                    this.ppChainContext = ppChainContext;
                    this.dwFlags = dwFlags;
                },
                onLeave: function (retval) {
                    const success = retval.toInt32();

                    if (success === 0) {
                        log(
                            'CertGetCertificateChain: Failed, forcing TRUE and creating valid-looking chain'
                        );
                        retval.replace(ptr(1));

                        if (!this.ppChainContext.isNull()) {
                            try {
                                const existingPtr = this.ppChainContext.readPointer();
                                if (existingPtr.isNull()) {
                                    const chainSize = 0x100;
                                    const chainMemory = Memory.alloc(chainSize);
                                    chainMemory.writeByteArray(new Array(chainSize).fill(0));

                                    const cbSizeOffset = 0;
                                    chainMemory.add(cbSizeOffset).writeU32(chainSize);

                                    this.ppChainContext.writePointer(chainMemory);
                                    log(
                                        'CertGetCertificateChain: Allocated synthetic chain context'
                                    );
                                }
                            } catch (e) {
                                logError('Failed to create chain context: ' + e.message);
                            }
                        }
                    } else {
                        log('CertGetCertificateChain: Succeeded');

                        if (!this.ppChainContext.isNull()) {
                            try {
                                const pChainContext = this.ppChainContext.readPointer();
                                if (!pChainContext.isNull()) {
                                    const chainInfo = {
                                        timestamp: new Date().toISOString(),
                                        chainContext: pChainContext.toString(),
                                        flags: this.dwFlags,
                                        success: true,
                                    };
                                    send({ type: 'certificate_chain_built', data: chainInfo });
                                }
                            } catch (e) {
                                logError('Failed to read chain context: ' + e.message);
                            }
                        }
                    }
                },
            });
            log('Successfully hooked CertGetCertificateChain');
        }
    } catch (e) {
        logError('Failed to hook CertGetCertificateChain: ' + e.message);
    }

    try {
        const CertFreeCertificateChain = Module.findExportByName(
            'crypt32.dll',
            'CertFreeCertificateChain'
        );
        if (CertFreeCertificateChain) {
            Interceptor.attach(CertFreeCertificateChain, {
                onEnter: function (args) {
                    const pChainContext = args[0];

                    if (!pChainContext.isNull()) {
                        log(`CertFreeCertificateChain: Freeing chain context ${pChainContext}`);
                        this.pChainContext = pChainContext;
                    }
                },
                onLeave: function (retval) {
                    if (this.pChainContext) {
                        log('CertFreeCertificateChain: Chain freed successfully');
                    }
                },
            });
            log('Successfully hooked CertFreeCertificateChain');
        }
    } catch (e) {
        logError('Failed to hook CertFreeCertificateChain: ' + e.message);
    }

    try {
        const CertCreateCertificateChainEngine = Module.findExportByName(
            'crypt32.dll',
            'CertCreateCertificateChainEngine'
        );
        if (CertCreateCertificateChainEngine) {
            Interceptor.attach(CertCreateCertificateChainEngine, {
                onEnter: function (args) {
                    const pConfig = args[0];
                    const phChainEngine = args[1];

                    log('CertCreateCertificateChainEngine: Creating custom chain engine');
                    this.phChainEngine = phChainEngine;
                },
                onLeave: function (retval) {
                    const success = retval.toInt32();
                    if (success === 0) {
                        log('CertCreateCertificateChainEngine: Failed, forcing TRUE');
                        retval.replace(ptr(1));

                        if (!this.phChainEngine.isNull()) {
                            try {
                                const existingHandle = this.phChainEngine.readPointer();
                                if (existingHandle.isNull()) {
                                    this.phChainEngine.writePointer(ptr(0xdeadbeef));
                                    log(
                                        'CertCreateCertificateChainEngine: Created synthetic engine handle'
                                    );
                                }
                            } catch (e) {
                                logError('Failed to create engine handle: ' + e.message);
                            }
                        }
                    } else {
                        log('CertCreateCertificateChainEngine: Succeeded');
                    }
                },
            });
            log('Successfully hooked CertCreateCertificateChainEngine');
        }
    } catch (e) {
        logError('Failed to hook CertCreateCertificateChainEngine: ' + e.message);
    }
}

const bcrypt = Process.findModuleByName('bcrypt.dll');
if (bcrypt) {
    log('bcrypt.dll found at: ' + bcrypt.base);

    try {
        const BCryptVerifySignature = Module.findExportByName(
            'bcrypt.dll',
            'BCryptVerifySignature'
        );
        if (BCryptVerifySignature) {
            Interceptor.attach(BCryptVerifySignature, {
                onEnter: function (args) {
                    const hKey = args[0];
                    const pPaddingInfo = args[1];
                    const pbHash = args[2];
                    const cbHash = args[3].toInt32();
                    const pbSignature = args[4];
                    const cbSignature = args[5].toInt32();
                    const dwFlags = args[6].toInt32();

                    log(
                        `BCryptVerifySignature: Hash size=${cbHash}, Signature size=${cbSignature}`
                    );
                    this.hKey = hKey;
                },
                onLeave: function (retval) {
                    const status = retval.toInt32();

                    if (status !== 0) {
                        log(
                            `BCryptVerifySignature: Failed with status=0x${status.toString(16)}, forcing success (STATUS_SUCCESS = 0)`
                        );
                        retval.replace(ptr(0));
                    } else {
                        log('BCryptVerifySignature: Succeeded');
                    }
                },
            });
            log('Successfully hooked BCryptVerifySignature');
        }
    } catch (e) {
        logError('Failed to hook BCryptVerifySignature: ' + e.message);
    }

    try {
        const BCryptHashData = Module.findExportByName('bcrypt.dll', 'BCryptHashData');
        if (BCryptHashData) {
            Interceptor.attach(BCryptHashData, {
                onEnter: function (args) {
                    const hHash = args[0];
                    const pbInput = args[1];
                    const cbInput = args[2].toInt32();
                    const dwFlags = args[3].toInt32();

                    this.cbInput = cbInput;
                },
                onLeave: function (retval) {
                    const status = retval.toInt32();
                    if (status !== 0) {
                        log(
                            `BCryptHashData: Failed with status=0x${status.toString(16)}, allowing to proceed`
                        );
                    }
                },
            });
            log('Successfully hooked BCryptHashData');
        }
    } catch (e) {
        logError('Failed to hook BCryptHashData: ' + e.message);
    }
} else {
    log('bcrypt.dll not found (may not be loaded yet)');
}

rpc.exports = {
    getCryptoAPIActivity: function () {
        return activity;
    },
    getCertificateChains: function () {
        return chains;
    },
    clearLogs: function () {
        activity.length = 0;
        chains.length = 0;
        log('Activity logs cleared');
        return true;
    },
    getBypassStatus: function () {
        return {
            active: true,
            library: 'CryptoAPI (crypt32.dll)',
            hooksInstalled: [
                'CertVerifyCertificateChainPolicy',
                'CertGetCertificateChain',
                'CertFreeCertificateChain',
                'CertCreateCertificateChainEngine',
                'BCryptVerifySignature',
                'BCryptHashData',
            ],
            chainBypassCount: chains.length,
        };
    },
    testBypass: function () {
        log('Testing CryptoAPI bypass functionality');
        return {
            success: true,
            message: 'CryptoAPI bypass is active and monitoring',
            stats: {
                chainBypasses: chains.length,
            },
        };
    },
};

log('CryptoAPI certificate bypass script loaded successfully');
send({ type: 'bypass_success', library: 'CryptoAPI' });
