/**
 * Arxan TransformIT Runtime Bypass Script
 *
 * Comprehensive Frida script for bypassing Arxan protection mechanisms at runtime:
 * - Anti-debugging detection
 * - Integrity checking
 * - License validation
 * - RASP mechanisms
 * - Anti-tampering
 * - String decryption
 *
 * Copyright (C) 2025 Zachary Flint
 *
 * This file is part of Intellicrack.
 */

console.log('[Arxan Bypass] Initializing comprehensive runtime bypass...');

const ArxanBypass = {
    config: {
        logLevel: 'info',
        bypassAntiDebug: true,
        bypassIntegrity: true,
        bypassLicense: true,
        bypassRASP: true,
        decryptStrings: false,
    },

    hooks: {
        installed: 0,
        failed: 0,
    },

    log: function (level, message) {
        const levels = { debug: 0, info: 1, warn: 2, error: 3 };
        const configLevel = levels[this.config.logLevel] || 1;

        if (levels[level] >= configLevel) {
            console.log(`[Arxan ${level.toUpperCase()}] ${message}`);
        }
    },

    bypassAntiDebug: function () {
        this.log('info', 'Installing anti-debugging bypasses...');

        const isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        if (isDebuggerPresent) {
            Interceptor.replace(isDebuggerPresent, new NativeCallback(() => 0, 'int', []));
            this.hooks.installed++;
            this.log('info', 'Bypassed IsDebuggerPresent');
        }

        const checkRemoteDebugger = Module.findExportByName(
            'kernel32.dll',
            'CheckRemoteDebuggerPresent'
        );
        if (checkRemoteDebugger) {
            Interceptor.attach(checkRemoteDebugger, {
                onEnter: function (args) {
                    this.pbDebuggerPresent = args[1];
                },
                onLeave: function (retval) {
                    if (this.pbDebuggerPresent && !this.pbDebuggerPresent.isNull()) {
                        this.pbDebuggerPresent.writeU8(0);
                    }
                    retval.replace(1);
                },
            });
            this.hooks.installed++;
            this.log('info', 'Bypassed CheckRemoteDebuggerPresent');
        }

        const ntQueryInfo = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
        if (ntQueryInfo) {
            Interceptor.attach(ntQueryInfo, {
                onEnter: function (args) {
                    this.infoClass = args[1].toInt32();
                    this.info = args[2];
                },
                onLeave: function (retval) {
                    if (this.infoClass === 7 || this.infoClass === 30 || this.infoClass === 31) {
                        if (this.info && !this.info.isNull()) {
                            this.info.writePointer(ptr(0));
                        }
                        retval.replace(0);
                    }
                },
            });
            this.hooks.installed++;
            this.log(
                'info',
                'Bypassed NtQueryInformationProcess (DebugPort, DebugObjectHandle, DebugFlags)'
            );
        }

        const ntSetInfo = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
        if (ntSetInfo) {
            Interceptor.attach(ntSetInfo, {
                onEnter: function (args) {
                    const infoClass = args[1].toInt32();
                    if (infoClass === 0x11) {
                        this.shouldBlock = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.shouldBlock) {
                        retval.replace(0);
                    }
                },
            });
            this.hooks.installed++;
            this.log('info', 'Bypassed NtSetInformationThread (HideFromDebugger)');
        }

        const outputDebugString = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
        if (outputDebugString) {
            Interceptor.replace(
                outputDebugString,
                new NativeCallback(
                    _lpOutputString => {

                    },
                    'void',
                    ['pointer']
                )
            );
            this.hooks.installed++;
            this.log('debug', 'Neutralized OutputDebugStringA');
        }

        try {
            const peb =
                Process.pointerSize === 8
                    ? ptr(Process.getCurrentThreadId()).readU64()
                    : ptr(Process.getCurrentThreadId()).readU32();

            if (peb) {
                const beingDebugged = peb.add(Process.pointerSize === 8 ? 0x02 : 0x02);
                Memory.protect(beingDebugged, 1, 'rw-');
                beingDebugged.writeU8(0);
                this.log('info', 'Patched PEB.BeingDebugged flag');
            }
        } catch (e) {
            this.log('debug', `Could not patch PEB directly: ${e.message}`);
        }

        this.log('info', 'Anti-debugging bypass complete');
    },

    bypassIntegrityChecks: function () {
        this.log('info', 'Installing integrity check bypasses...');

        const cryptHashData = Module.findExportByName('Advapi32.dll', 'CryptHashData');
        if (cryptHashData) {
            Interceptor.replace(
                cryptHashData,
                new NativeCallback((_hHash, _pbData, _dwDataLen, _dwFlags) => 1, 'int', [
                    'pointer',
                    'pointer',
                    'uint',
                    'uint',
                ])
            );
            this.hooks.installed++;
            this.log('info', 'Bypassed CryptHashData');
        }

        const cryptVerifySignature = Module.findExportByName(
            'Advapi32.dll',
            'CryptVerifySignature'
        );
        if (cryptVerifySignature) {
            Interceptor.replace(
                cryptVerifySignature,
                new NativeCallback(
                    (_hHash, _pbSignature, _dwSigLen, _hPubKey, _sDescription, _dwFlags) => 1,
                    'int',
                    ['pointer', 'pointer', 'uint', 'pointer', 'pointer', 'uint']
                )
            );
            this.hooks.installed++;
            this.log('info', 'Bypassed CryptVerifySignature');
        }

        const winVerifyTrust = Module.findExportByName('Wintrust.dll', 'WinVerifyTrust');
        if (winVerifyTrust) {
            Interceptor.replace(
                winVerifyTrust,
                new NativeCallback((_hwnd, _pgActionID, _pWVTData) => 0, 'int', [
                    'pointer',
                    'pointer',
                    'pointer',
                ])
            );
            this.hooks.installed++;
            this.log('info', 'Bypassed WinVerifyTrust');
        }

        const certVerifyChain = Module.findExportByName(
            'Crypt32.dll',
            'CertVerifyCertificateChainPolicy'
        );
        if (certVerifyChain) {
            Interceptor.attach(certVerifyChain, {
                onEnter: function (args) {
                    this.pPolicyStatus = args[3];
                },
                onLeave: function (retval) {
                    if (this.pPolicyStatus && !this.pPolicyStatus.isNull()) {
                        this.pPolicyStatus.writeU32(0);
                        this.pPolicyStatus.add(4).writeU32(0);
                    }
                    retval.replace(1);
                },
            });
            this.hooks.installed++;
            this.log('info', 'Bypassed CertVerifyCertificateChainPolicy');
        }

        const memcmp = Module.findExportByName(null, 'memcmp');
        if (memcmp) {
            Interceptor.attach(memcmp, {
                onEnter: function (args) {
                    this.size = args[2].toInt32();
                },
                onLeave: function (retval) {
                    if (
                        this.size === 16 ||
                        this.size === 20 ||
                        this.size === 32 ||
                        this.size === 64
                    ) {
                        retval.replace(0);
                    }
                },
            });
            this.hooks.installed++;
            this.log('info', 'Hooked memcmp for hash comparison bypass');
        }

        const checkSumMapped = Module.findExportByName('Imagehlp.dll', 'CheckSumMappedFile');
        if (checkSumMapped) {
            Interceptor.attach(checkSumMapped, {
                onEnter: function (args) {
                    this.headerSum = args[2];
                    this.checkSum = args[3];
                },
                onLeave: function (_retval) {
                    if (this.headerSum && !this.headerSum.isNull()) {
                        this.headerSum.writeU32(0x12345678);
                    }
                    if (this.checkSum && !this.checkSum.isNull()) {
                        this.checkSum.writeU32(0x12345678);
                    }
                },
            });
            this.hooks.installed++;
            this.log('info', 'Bypassed CheckSumMappedFile');
        }

        this.log('info', 'Integrity check bypass complete');
    },

    bypassLicenseValidation: function () {
        this.log('info', 'Installing license validation bypasses...');

        const licensePatterns = [
            'license',
            'serial',
            'activation',
            'registration',
            'validate',
            'verify_key',
            'check_license',
            'product_key',
            'trial',
        ];

        const modules = Process.enumerateModules();
        let foundLicenseFuncs = 0;

        modules.forEach(module => {
            try {
                const exports = module.enumerateExports();

                exports.forEach(exp => {
                    const lowerName = exp.name.toLowerCase();

                    if (licensePatterns.some(pattern => lowerName.includes(pattern))) {
                        try {
                            Interceptor.replace(
                                exp.address,
                                new NativeCallback(() => 1, 'int', [])
                            );

                            foundLicenseFuncs++;
                            this.log('debug', `Bypassed license function: ${exp.name}`);
                        } catch (e) {
                            this.log('debug', `Could not hook ${exp.name}: ${e.message}`);
                        }
                    }
                });
            } catch (e) {
                this.log('debug', `Error enumerating exports for ${module.name}: ${e.message}`);
            }
        });

        if (foundLicenseFuncs > 0) {
            this.hooks.installed += foundLicenseFuncs;
            this.log('info', `Bypassed ${foundLicenseFuncs} license validation functions`);
        } else {
            this.log('warn', 'No obvious license validation functions found');
        }

        const regQuery = Module.findExportByName('Advapi32.dll', 'RegQueryValueExA');
        if (regQuery) {
            Interceptor.attach(regQuery, {
                onEnter: function (args) {
                    this.valueName = args[1].readUtf8String();
                    this.data = args[3];
                },
                onLeave: function (retval) {
                    if (this.valueName?.toLowerCase().includes('license')) {
                        if (this.data && !this.data.isNull()) {
                            this.data.writeUtf8String('BYPASSED-LICENSE-KEY-ARXAN');
                        }
                        retval.replace(0);
                    }
                },
            });
            this.hooks.installed++;
            this.log('info', 'Hooked RegQueryValueExA for license key injection');
        }

        this.log('info', 'License validation bypass complete');
    },

    bypassRASP: function () {
        this.log('info', 'Installing RASP mechanism bypasses...');

        const virtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');
        if (virtualProtect) {
            Interceptor.attach(virtualProtect, {
                onEnter: function (args) {
                    this.address = args[0];
                    this.size = args[1];
                    this.newProtect = args[2];
                },
                onLeave: retval => {
                    retval.replace(1);
                },
            });
            this.hooks.installed++;
            this.log('info', 'Hooked VirtualProtect');
        }

        const readProcessMemory = Module.findExportByName('kernel32.dll', 'ReadProcessMemory');
        if (readProcessMemory) {
            Interceptor.attach(readProcessMemory, {
                onLeave: retval => {
                    retval.replace(1);
                },
            });
            this.hooks.installed++;
            this.log('debug', 'Hooked ReadProcessMemory');
        }

        const setUnhandledExceptionFilter = Module.findExportByName(
            'kernel32.dll',
            'SetUnhandledExceptionFilter'
        );
        if (setUnhandledExceptionFilter) {
            Interceptor.replace(
                setUnhandledExceptionFilter,
                new NativeCallback(_lpTopLevelExceptionFilter => ptr(0), 'pointer', ['pointer'])
            );
            this.hooks.installed++;
            this.log('info', 'Bypassed SetUnhandledExceptionFilter');
        }

        const raiseException = Module.findExportByName('kernel32.dll', 'RaiseException');
        if (raiseException) {
            Interceptor.attach(raiseException, {
                onEnter: function (args) {
                    const exceptionCode = args[0].toInt32();
                    if (exceptionCode === 0x80000003 || exceptionCode === 0xc0000005) {
                        this.shouldBlock = true;
                    }
                },
                onLeave: function (_retval) {
                    if (this.shouldBlock) {

                    }
                },
            });
            this.hooks.installed++;
            this.log('info', 'Hooked RaiseException for anti-debugging exceptions');
        }

        const getTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
        if (getTickCount) {
            const baseTime = Date.now();
            Interceptor.replace(
                getTickCount,
                new NativeCallback(() => Date.now() - baseTime, 'uint', [])
            );
            this.hooks.installed++;
            this.log('debug', 'Normalized GetTickCount');
        }

        const queryPerformanceCounter = Module.findExportByName(
            'kernel32.dll',
            'QueryPerformanceCounter'
        );
        if (queryPerformanceCounter) {
            Interceptor.attach(queryPerformanceCounter, {
                onLeave: retval => {
                    retval.replace(1);
                },
            });
            this.hooks.installed++;
            this.log('debug', 'Normalized QueryPerformanceCounter');
        }

        this.log('info', 'RASP bypass complete');
    },

    hookModuleLoads: function () {
        this.log('info', 'Installing module load hooks...');

        const loadLibrary = Module.findExportByName('kernel32.dll', 'LoadLibraryA');
        if (loadLibrary) {
            Interceptor.attach(loadLibrary, {
                onEnter: args => {
                    const moduleName = args[0].readUtf8String();
                    ArxanBypass.log('debug', `LoadLibraryA: ${moduleName}`);

                    if (moduleName?.toLowerCase().includes('arxan')) {
                        ArxanBypass.log('warn', `Detected Arxan module load: ${moduleName}`);
                    }
                },
            });
            this.hooks.installed++;
        }

        const loadLibraryW = Module.findExportByName('kernel32.dll', 'LoadLibraryW');
        if (loadLibraryW) {
            Interceptor.attach(loadLibraryW, {
                onEnter: args => {
                    const moduleName = args[0].readUtf16String();
                    ArxanBypass.log('debug', `LoadLibraryW: ${moduleName}`);

                    if (moduleName?.toLowerCase().includes('arxan')) {
                        ArxanBypass.log('warn', `Detected Arxan module load: ${moduleName}`);
                    }
                },
            });
            this.hooks.installed++;
        }

        this.log('info', 'Module load hooks installed');
    },

    patchInlineChecks: function () {
        this.log('info', 'Scanning for inline integrity checks...');

        const modules = Process.enumerateModules();
        let patchCount = 0;

        modules.forEach(module => {
            if (
                module.name.toLowerCase().includes('arxan') ||
                module.name.toLowerCase().includes('guardit') ||
                module.name.toLowerCase().includes('transform')
            ) {
                this.log('info', `Found potential Arxan module: ${module.name}`);

                try {
                    const crc32Pattern = '33 ?? 8A ?? 8B ?? C1 E8 08';
                    const matches = Memory.scanSync(module.base, module.size, crc32Pattern);

                    matches.forEach(match => {
                        try {
                            Memory.protect(match.address, 16, 'rwx');
                            match.address.writeByteArray([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
                            patchCount++;
                            this.log('debug', `Patched CRC32 check at ${match.address}`);
                        } catch (e) {
                            this.log('debug', `Could not patch at ${match.address}: ${e.message}`);
                        }
                    });
                } catch (e) {
                    this.log('debug', `Error scanning ${module.name}: ${e.message}`);
                }
            }
        });

        if (patchCount > 0) {
            this.log('info', `Patched ${patchCount} inline integrity checks`);
        }
    },

    init: function () {
        this.log('info', '=== Arxan TransformIT Bypass Starting ===');

        if (this.config.bypassAntiDebug) {
            this.bypassAntiDebug();
        }

        if (this.config.bypassIntegrity) {
            this.bypassIntegrityChecks();
        }

        if (this.config.bypassLicense) {
            this.bypassLicenseValidation();
        }

        if (this.config.bypassRASP) {
            this.bypassRASP();
        }

        this.hookModuleLoads();

        setTimeout(() => {
            this.patchInlineChecks();
        }, 1000);

        this.log('info', `=== Arxan Bypass Complete: ${this.hooks.installed} hooks installed ===`);

        return {
            hooksInstalled: this.hooks.installed,
            hooksFailed: this.hooks.failed,
        };
    },
};

const result = ArxanBypass.init();
console.log(`[Arxan Bypass] Initialization complete: ${result.hooksInstalled} hooks active`);
