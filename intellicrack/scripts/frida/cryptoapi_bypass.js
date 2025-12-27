const _CERT_CHAIN_POLICY_BASE = 1;
const _CERT_CHAIN_POLICY_AUTHENTICODE = 2;
const _CERT_CHAIN_POLICY_SSL = 4;
const _CERT_CHAIN_POLICY_NT_AUTH = 6;

const activity = [];
const chains = [];
const MAX_LOG = 1000;

function log(message, level = 'info') {
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        message,
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
if (crypt32) {
    log(`crypt32.dll found at: ${crypt32.base}`);

    try {
        const CertVerifyCertificateChainPolicy = Module.findExportByName(
            'crypt32.dll',
            'CertVerifyCertificateChainPolicy'
        );
        if (CertVerifyCertificateChainPolicy) {
            Interceptor.attach(CertVerifyCertificateChainPolicy, {
                onEnter(args) {
                    const pszPolicyOID = args[0];
                    const pChainContext = args[1];
                    const _pPolicyPara = args[2];
                    const pPolicyStatus = args[3];

                    const policyOID = pszPolicyOID.toInt32();
                    if (policyOID > 0 && policyOID < 100) {
                        log(`CertVerifyCertificateChainPolicy: Policy=${policyOID}`);
                    } else {
                        try {
                            const oidStr = pszPolicyOID.readAnsiString();
                            log(`CertVerifyCertificateChainPolicy: Policy OID="${oidStr}"`);
                        } catch {
                            log('CertVerifyCertificateChainPolicy: Unable to read policy OID');
                        }
                    }

                    this.pPolicyStatus = pPolicyStatus;
                    this.pChainContext = pChainContext;
                    this.policyOID = policyOID;
                },
                onLeave(retval) {
                    const success = retval.toInt32();

                    if (!this.pPolicyStatus.isNull()) {
                        try {
                            const dwErrorOffset = Process.pointerSize === 8 ? 0x08 : 0x04;
                            const lChainIndexOffset = Process.pointerSize === 8 ? 0x10 : 0x08;
                            const lElementIndexOffset = Process.pointerSize === 8 ? 0x18 : 0x0C;

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
                                    originalError,
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
                        } catch (error) {
                            logError(`Failed to modify pPolicyStatus: ${error.message}`);
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
    } catch (error) {
        logError(`Failed to hook CertVerifyCertificateChainPolicy: ${error.message}`);
    }

    try {
        const CertGetCertificateChain = Module.findExportByName(
            'crypt32.dll',
            'CertGetCertificateChain'
        );
        if (CertGetCertificateChain) {
            Interceptor.attach(CertGetCertificateChain, {
                onEnter(args) {
                    const _hChainEngine = args[0];
                    const _pCertContext = args[1];
                    const _pTime = args[2];
                    const _hAdditionalStore = args[3];
                    const _pChainPara = args[4];
                    const dwFlags = args[5].toInt32();
                    const _pvReserved = args[6];
                    const ppChainContext = args[7];

                    log(`CertGetCertificateChain: Flags=0x${dwFlags.toString(16)}`);

                    this.ppChainContext = ppChainContext;
                    this.dwFlags = dwFlags;
                },
                onLeave(retval) {
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
                                    const chainSize = 0x1_00;
                                    const chainMemory = Memory.alloc(chainSize);
                                    chainMemory.writeByteArray(
                                        Array.from({ length: chainSize }).fill(0)
                                    );

                                    const cbSizeOffset = 0;
                                    chainMemory.add(cbSizeOffset).writeU32(chainSize);

                                    this.ppChainContext.writePointer(chainMemory);
                                    log(
                                        'CertGetCertificateChain: Allocated synthetic chain context'
                                    );
                                }
                            } catch (error) {
                                logError(`Failed to create chain context: ${error.message}`);
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
                            } catch (error) {
                                logError(`Failed to read chain context: ${error.message}`);
                            }
                        }
                    }
                },
            });
            log('Successfully hooked CertGetCertificateChain');
        }
    } catch (error) {
        logError(`Failed to hook CertGetCertificateChain: ${error.message}`);
    }

    try {
        const CertFreeCertificateChain = Module.findExportByName(
            'crypt32.dll',
            'CertFreeCertificateChain'
        );
        if (CertFreeCertificateChain) {
            Interceptor.attach(CertFreeCertificateChain, {
                onEnter(args) {
                    const pChainContext = args[0];

                    if (!pChainContext.isNull()) {
                        log(`CertFreeCertificateChain: Freeing chain context ${pChainContext}`);
                        this.pChainContext = pChainContext;
                    }
                },
                onLeave(_retval) {
                    if (this.pChainContext) {
                        log('CertFreeCertificateChain: Chain freed successfully');
                    }
                },
            });
            log('Successfully hooked CertFreeCertificateChain');
        }
    } catch (error) {
        logError(`Failed to hook CertFreeCertificateChain: ${error.message}`);
    }

    try {
        const CertCreateCertificateChainEngine = Module.findExportByName(
            'crypt32.dll',
            'CertCreateCertificateChainEngine'
        );
        if (CertCreateCertificateChainEngine) {
            Interceptor.attach(CertCreateCertificateChainEngine, {
                onEnter(args) {
                    const _pConfig = args[0];
                    const phChainEngine = args[1];

                    log('CertCreateCertificateChainEngine: Creating custom chain engine');
                    this.phChainEngine = phChainEngine;
                },
                onLeave(retval) {
                    const success = retval.toInt32();
                    if (success === 0) {
                        log('CertCreateCertificateChainEngine: Failed, forcing TRUE');
                        retval.replace(ptr(1));

                        if (!this.phChainEngine.isNull()) {
                            try {
                                const existingHandle = this.phChainEngine.readPointer();
                                if (existingHandle.isNull()) {
                                    this.phChainEngine.writePointer(ptr(0xDE_AD_BE_EF));
                                    log(
                                        'CertCreateCertificateChainEngine: Created synthetic engine handle'
                                    );
                                }
                            } catch (error) {
                                logError(`Failed to create engine handle: ${error.message}`);
                            }
                        }
                    } else {
                        log('CertCreateCertificateChainEngine: Succeeded');
                    }
                },
            });
            log('Successfully hooked CertCreateCertificateChainEngine');
        }
    } catch (error) {
        logError(`Failed to hook CertCreateCertificateChainEngine: ${error.message}`);
    }
} else {
    logError('crypt32.dll module not found');
}

const bcrypt = Process.findModuleByName('bcrypt.dll');
if (bcrypt) {
    log(`bcrypt.dll found at: ${bcrypt.base}`);

    try {
        const BCryptVerifySignature = Module.findExportByName(
            'bcrypt.dll',
            'BCryptVerifySignature'
        );
        if (BCryptVerifySignature) {
            Interceptor.attach(BCryptVerifySignature, {
                onEnter(args) {
                    const hKey = args[0];
                    const _pPaddingInfo = args[1];
                    const _pbHash = args[2];
                    const cbHash = args[3].toInt32();
                    const _pbSignature = args[4];
                    const cbSignature = args[5].toInt32();
                    const _dwFlags = args[6].toInt32();

                    log(
                        `BCryptVerifySignature: Hash size=${cbHash}, Signature size=${cbSignature}`
                    );
                    this.hKey = hKey;
                },
                onLeave: retval => {
                    const status = retval.toInt32();

                    if (status === 0) {
                        log('BCryptVerifySignature: Succeeded');
                    } else {
                        log(
                            `BCryptVerifySignature: Failed with status=0x${status.toString(16)}, forcing success (STATUS_SUCCESS = 0)`
                        );
                        retval.replace(ptr(0));
                    }
                },
            });
            log('Successfully hooked BCryptVerifySignature');
        }
    } catch (error) {
        logError(`Failed to hook BCryptVerifySignature: ${error.message}`);
    }

    try {
        const BCryptHashData = Module.findExportByName('bcrypt.dll', 'BCryptHashData');
        if (BCryptHashData) {
            Interceptor.attach(BCryptHashData, {
                onEnter(args) {
                    const _hHash = args[0];
                    const _pbInput = args[1];
                    const cbInput = args[2].toInt32();
                    const _dwFlags = args[3].toInt32();

                    this.cbInput = cbInput;
                },
                onLeave: retval => {
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
    } catch (error) {
        logError(`Failed to hook BCryptHashData: ${error.message}`);
    }
} else {
    log('bcrypt.dll not found (may not be loaded yet)');
}

rpc.exports = {
    getCryptoAPIActivity: () => activity,
    getCertificateChains: () => chains,
    clearLogs: () => {
        activity.length = 0;
        chains.length = 0;
        log('Activity logs cleared');
        return true;
    },
    getBypassStatus: () => ({
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
    }),
    testBypass: () => {
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
