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

// Production-grade Windows Registry monitor for Frida
// Comprehensive monitoring with Native API hooks, anti-detection, and intelligent data analysis

(() => {
    if (Process.platform !== 'windows') {
        send({
            type: 'error',
            target: 'registry_monitor',
            message: 'Unsupported platform',
            platform: Process.platform,
        });
        return;
    }

    const config = {
        keyFilters: [
            '\\software\\',
            'windows nt\\currentversion',
            'licens',
            'activation',
            'adobe',
            'microsoft',
            'autodesk',
            'unity',
            'jetbrains',
            'serial',
            'productkey',
            'activationid',
            'installid',
            'hwid',
            'machinekey',
            'registration',
            'subscription',
            'trial',
            'evaluation',
            'expire',
            'softkey',
            'dongle',
            'hasp',
            'sentinel',
            'flexlm',
            'license.dat',
            'crypto\\rsa\\',
            'crypto\\keys',
            'policies\\',
            'auth',
            'token',
            'certificate',
            '\\wow6432node\\',
        ],

        includeBacktraceOnMatch: true,
        maxBacktraceFrames: 15,
        captureThreadInfo: true,
        logSuccessfulOps: false,
        logDetailedErrors: true,
        trackHandleLifecycle: true,
        detectDebugging: true,
        bypassAntiDebug: true,
        collectStatistics: true,
        performDeepAnalysis: true,
        detectPatterns: true,
        useCache: true,
        cacheTimeout: 60000,
    };

    const stats = {
        totalCalls: 0,
        byFunction: {},
        byKey: {},
        failedOps: 0,
        successfulOps: 0,
        debugAttempts: 0,
        antiDebugBypassed: 0,
    };

    const handleTracker = new Map();
    const keyPathCache = new Map();
    const threadInfo = new Map();
    const _knownLicenseKeys = new Set();
    const detectedPatterns = new Set();

    function initializeHooks() {
        const _ntdll = Process.getModuleByName('ntdll.dll');
        const _advapi32 = Process.getModuleByName('advapi32.dll');
        const _kernel32 = Process.getModuleByName('kernel32.dll');

        const antiDebugChecks = [
            'NtQueryInformationProcess',
            'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent',
            'NtQuerySystemInformation',
            'NtGetContextThread',
            'NtSetContextThread',
            'NtContinue',
        ];

        antiDebugChecks.forEach(name => {
            const func = Module.findExportByName(null, name);
            if (func) {
                hookAntiDebugFunction(func, name);
            }
        });

        const regFunctions = [
            {
                module: 'ntdll.dll',
                name: 'NtOpenKey',
                onEnter: onNtOpenKeyEnter,
                onLeave: onNtOpenKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtOpenKeyEx',
                onEnter: onNtOpenKeyExEnter,
                onLeave: onNtOpenKeyExLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtCreateKey',
                onEnter: onNtCreateKeyEnter,
                onLeave: onNtCreateKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtQueryKey',
                onEnter: onNtQueryKeyEnter,
                onLeave: onNtQueryKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtQueryValueKey',
                onEnter: onNtQueryValueKeyEnter,
                onLeave: onNtQueryValueKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtSetValueKey',
                onEnter: onNtSetValueKeyEnter,
                onLeave: onNtSetValueKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtDeleteKey',
                onEnter: onNtDeleteKeyEnter,
                onLeave: onNtDeleteKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtDeleteValueKey',
                onEnter: onNtDeleteValueKeyEnter,
                onLeave: onNtDeleteValueKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtEnumerateKey',
                onEnter: onNtEnumerateKeyEnter,
                onLeave: onNtEnumerateKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtEnumerateValueKey',
                onEnter: onNtEnumerateValueKeyEnter,
                onLeave: onNtEnumerateValueKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtClose',
                onEnter: onNtCloseEnter,
                onLeave: null,
            },
            {
                module: 'ntdll.dll',
                name: 'NtFlushKey',
                onEnter: onNtFlushKeyEnter,
                onLeave: onNtFlushKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtQueryMultipleValueKey',
                onEnter: onNtQueryMultipleValueKeyEnter,
                onLeave: onNtQueryMultipleValueKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtRenameKey',
                onEnter: onNtRenameKeyEnter,
                onLeave: onNtRenameKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtLoadKey',
                onEnter: onNtLoadKeyEnter,
                onLeave: onNtLoadKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtUnloadKey',
                onEnter: onNtUnloadKeyEnter,
                onLeave: onNtUnloadKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtSaveKey',
                onEnter: onNtSaveKeyEnter,
                onLeave: onNtSaveKeyLeave,
            },
            {
                module: 'ntdll.dll',
                name: 'NtRestoreKey',
                onEnter: onNtRestoreKeyEnter,
                onLeave: onNtRestoreKeyLeave,
            },

            {
                module: 'advapi32.dll',
                name: 'RegOpenKeyExW',
                onEnter: onRegOpenKeyExWEnter,
                onLeave: onRegOpenKeyExWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegOpenKeyExA',
                onEnter: onRegOpenKeyExAEnter,
                onLeave: onRegOpenKeyExALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegCreateKeyExW',
                onEnter: onRegCreateKeyExWEnter,
                onLeave: onRegCreateKeyExWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegCreateKeyExA',
                onEnter: onRegCreateKeyExAEnter,
                onLeave: onRegCreateKeyExALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegQueryValueExW',
                onEnter: onRegQueryValueExWEnter,
                onLeave: onRegQueryValueExWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegQueryValueExA',
                onEnter: onRegQueryValueExAEnter,
                onLeave: onRegQueryValueExALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegSetValueExW',
                onEnter: onRegSetValueExWEnter,
                onLeave: onRegSetValueExWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegSetValueExA',
                onEnter: onRegSetValueExAEnter,
                onLeave: onRegSetValueExALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegDeleteKeyW',
                onEnter: onRegDeleteKeyWEnter,
                onLeave: onRegDeleteKeyWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegDeleteKeyA',
                onEnter: onRegDeleteKeyAEnter,
                onLeave: onRegDeleteKeyALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegDeleteValueW',
                onEnter: onRegDeleteValueWEnter,
                onLeave: onRegDeleteValueWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegDeleteValueA',
                onEnter: onRegDeleteValueAEnter,
                onLeave: onRegDeleteValueALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegEnumKeyExW',
                onEnter: onRegEnumKeyExWEnter,
                onLeave: onRegEnumKeyExWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegEnumKeyExA',
                onEnter: onRegEnumKeyExAEnter,
                onLeave: onRegEnumKeyExALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegEnumValueW',
                onEnter: onRegEnumValueWEnter,
                onLeave: onRegEnumValueWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegEnumValueA',
                onEnter: onRegEnumValueAEnter,
                onLeave: onRegEnumValueALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegCloseKey',
                onEnter: onRegCloseKeyEnter,
                onLeave: null,
            },
            {
                module: 'advapi32.dll',
                name: 'RegFlushKey',
                onEnter: onRegFlushKeyEnter,
                onLeave: onRegFlushKeyLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegSaveKeyW',
                onEnter: onRegSaveKeyWEnter,
                onLeave: onRegSaveKeyWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegSaveKeyA',
                onEnter: onRegSaveKeyAEnter,
                onLeave: onRegSaveKeyALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegRestoreKeyW',
                onEnter: onRegRestoreKeyWEnter,
                onLeave: onRegRestoreKeyWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegRestoreKeyA',
                onEnter: onRegRestoreKeyAEnter,
                onLeave: onRegRestoreKeyALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegLoadKeyW',
                onEnter: onRegLoadKeyWEnter,
                onLeave: onRegLoadKeyWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegLoadKeyA',
                onEnter: onRegLoadKeyAEnter,
                onLeave: onRegLoadKeyALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegUnLoadKeyW',
                onEnter: onRegUnLoadKeyWEnter,
                onLeave: onRegUnLoadKeyWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegUnLoadKeyA',
                onEnter: onRegUnLoadKeyAEnter,
                onLeave: onRegUnLoadKeyALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegQueryInfoKeyW',
                onEnter: onRegQueryInfoKeyWEnter,
                onLeave: onRegQueryInfoKeyWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegQueryInfoKeyA',
                onEnter: onRegQueryInfoKeyAEnter,
                onLeave: onRegQueryInfoKeyALeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegGetValueW',
                onEnter: onRegGetValueWEnter,
                onLeave: onRegGetValueWLeave,
            },
            {
                module: 'advapi32.dll',
                name: 'RegGetValueA',
                onEnter: onRegGetValueAEnter,
                onLeave: onRegGetValueALeave,
            },
        ];

        regFunctions.forEach(f => {
            const func = Module.findExportByName(f.module, f.name);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: f.onEnter,
                    onLeave: f.onLeave,
                });
            }
        });

        send({
            type: 'info',
            target: 'registry_monitor',
            message: 'Registry monitoring initialized',
            functions_hooked: regFunctions.length,
            anti_debug_hooked: antiDebugChecks.length,
        });
    }

    function hookAntiDebugFunction(funcPtr, funcName) {
        Interceptor.attach(funcPtr, {
            onEnter(args) {
                stats.debugAttempts++;
                if (config.bypassAntiDebug) {
                    if (funcName === 'IsDebuggerPresent') {
                        this.shouldFake = true;
                    } else if (funcName === 'CheckRemoteDebuggerPresent') {
                        this.debuggerPtr = args[1];
                    } else if (
                        funcName === 'NtQueryInformationProcess' &&
                        args[1].toInt32() === 7
                    ) {
                        this.shouldFake = true;
                    }
                }
            },
            onLeave(retval) {
                if (config.bypassAntiDebug && this.shouldFake) {
                    retval.replace(0);
                    stats.antiDebugBypassed++;
                }
                if (this.debuggerPtr) {
                    this.debuggerPtr.writeU8(0);
                    stats.antiDebugBypassed++;
                }
            },
        });
    }

    function getKeyPath(handle) {
        if (!handle || handle.isNull()) {
            return null;
        }

        const cached = keyPathCache.get(handle.toString());
        if (cached && Date.now() - cached.timestamp < config.cacheTimeout) {
            return cached.path;
        }

        try {
            const NtQueryObject = Module.findExportByName('ntdll.dll', 'NtQueryObject');
            if (!NtQueryObject) {
                return null;
            }

            const ObjectNameInformation = 1;
            const bufferSize = 1024;
            const buffer = Memory.alloc(bufferSize);
            const returnLength = Memory.alloc(4);

            const result = new NativeFunction(NtQueryObject, 'uint', [
                'pointer',
                'uint',
                'pointer',
                'uint',
                'pointer',
            ])(handle, ObjectNameInformation, buffer, bufferSize, returnLength);

            if (result === 0) {
                const unicodeString = buffer.add(8);
                const length = unicodeString.readU16();
                const bufferPtr = unicodeString.add(8).readPointer();

                if (!bufferPtr.isNull() && length > 0) {
                    const path = bufferPtr.readUtf16String(length / 2);
                    if (path?.includes('\\REGISTRY\\')) {
                        const cleanPath = path
                            .replace('\\REGISTRY\\MACHINE', 'HKLM')
                            .replace('\\REGISTRY\\USER', 'HKU')
                            .replace('\\REGISTRY\\', '');

                        if (config.useCache) {
                            keyPathCache.set(handle.toString(), {
                                path: cleanPath,
                                timestamp: Date.now(),
                            });
                        }

                        return cleanPath;
                    }
                }
            }
        } catch (_e) {}

        return null;
    }

    function readUnicodeString(ptr) {
        if (!ptr || ptr.isNull()) {
            return null;
        }
        try {
            const length = ptr.readU16();
            const buffer = ptr.add(8).readPointer();
            if (!buffer.isNull() && length > 0) {
                return buffer.readUtf16String(length / 2);
            }
        } catch (_e) {}
        return null;
    }

    function formatRegData(type, dataPtr, dataSize, truncate = false) {
        if (!dataPtr || dataPtr.isNull() || dataSize <= 0) {
            return { formatted: null, raw: null };
        }

        const maxSize = truncate ? 256 : dataSize;
        const actualSize = Math.min(dataSize, maxSize);

        try {
            switch (type) {
                case 1: // REG_SZ
                case 2: // REG_EXPAND_SZ
                    return { formatted: dataPtr.readUtf16String(actualSize / 2) };

                case 3: {
                    // REG_BINARY
                    const bytes = dataPtr.readByteArray(actualSize);
                    const hex = Array.from(bytes, b => `0${b.toString(16)}`.slice(-2)).join(' ');
                    return { formatted: null, raw: hex };
                }

                case 4: // REG_DWORD
                    if (dataSize >= 4) {
                        return {
                            formatted:
                                '0x' +
                                dataPtr.readU32().toString(16) +
                                ' (' +
                                dataPtr.readU32() +
                                ')',
                        };
                    }
                    break;

                case 5: // REG_DWORD_BIG_ENDIAN
                    if (dataSize >= 4) {
                        const val =
                            ((dataPtr.readU8() << 24) |
                                (dataPtr.add(1).readU8() << 16) |
                                (dataPtr.add(2).readU8() << 8) |
                                dataPtr.add(3).readU8()) >>>
                            0;
                        return { formatted: `0x${val.toString(16)} (${val})` };
                    }
                    break;

                case 7: {
                    // REG_MULTI_SZ
                    const strings = [];
                    let offset = 0;
                    while (offset < actualSize - 2) {
                        const str = dataPtr.add(offset).readUtf16String();
                        if (!str || str.length === 0) {
                            break;
                        }
                        strings.push(str);
                        offset += (str.length + 1) * 2;
                    }
                    return { formatted: strings.join('\\0') };
                }

                case 11: // REG_QWORD
                    if (dataSize >= 8) {
                        const low = dataPtr.readU32();
                        const high = dataPtr.add(4).readU32();
                        const val = high * 0x100000000 + low;
                        return { formatted: `0x${val.toString(16)} (${val})` };
                    }
                    break;
            }
        } catch (_e) {}

        return { formatted: null, raw: null };
    }

    function matchesFilters(keyPath, valueName) {
        if (!keyPath) {
            return false;
        }

        const lowerKey = keyPath.toLowerCase();
        const lowerValue = valueName ? valueName.toLowerCase() : '';

        for (const filter of config.keyFilters) {
            const lowerFilter = filter.toLowerCase();
            if (lowerKey.includes(lowerFilter) || lowerValue.includes(lowerFilter)) {
                return true;
            }
        }

        return false;
    }

    function detectLicensePattern(keyPath, valueName, data) {
        if (!config.detectPatterns) {
            return;
        }

        const patterns = [
            {
                regex: /[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}/gi,
                type: 'serial_key',
            },
            {
                regex: /[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/gi,
                type: 'guid',
            },
            { regex: /[A-Z0-9]{32,}/gi, type: 'hash' },
            { regex: /\b\d{10,}\b/g, type: 'timestamp' },
            {
                regex: /-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/g,
                type: 'certificate',
            },
        ];

        const dataStr = data?.formatted ? data.formatted : '';
        const fullPath = `${keyPath}\\${valueName || ''}`;

        patterns.forEach(p => {
            if (p.regex.test(dataStr) || p.regex.test(fullPath)) {
                const detection = {
                    type: p.type,
                    path: fullPath,
                    timestamp: Date.now(),
                };

                if (!detectedPatterns.has(JSON.stringify(detection))) {
                    detectedPatterns.add(JSON.stringify(detection));
                    send({
                        type: 'pattern_detected',
                        target: 'registry_monitor',
                        pattern: p.type,
                        location: fullPath,
                        sample: dataStr.substring(0, 100),
                    });
                }
            }
        });
    }

    function getThreadContext() {
        if (!config.captureThreadInfo) {
            return {};
        }

        const tid = Process.getCurrentThreadId();
        let info = threadInfo.get(tid);

        if (!info || Date.now() - info.timestamp > 1000) {
            info = {
                tid: tid,
                timestamp: Date.now(),
            };

            try {
                const thread = Process.enumerateThreads().find(t => t.id === tid);
                if (thread) {
                    info.state = thread.state;
                    info.context = thread.context;
                }
            } catch (_e) {}

            threadInfo.set(tid, info);
        }

        return info;
    }

    function sendEvent(evt, includeBacktrace = false) {
        if (config.collectStatistics) {
            stats.totalCalls++;
            stats.byFunction[evt.function] = (stats.byFunction[evt.function] || 0) + 1;

            if (evt.key_path) {
                const keyBase = evt.key_path.split('\\').slice(0, 3).join('\\');
                stats.byKey[keyBase] = (stats.byKey[keyBase] || 0) + 1;
            }

            if (evt.success) {
                stats.successfulOps++;
            } else {
                stats.failedOps++;
            }
        }

        if (config.captureThreadInfo) {
            evt.thread = getThreadContext();
        }

        if (includeBacktrace) {
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            evt.backtrace = bt.slice(0, config.maxBacktraceFrames).map(addr => {
                const mod = Process.findModuleByAddress(addr);
                const sym = DebugSymbol.fromAddress(addr);
                return {
                    address: addr.toString(),
                    module: mod ? mod.name : null,
                    symbol: sym.name || null,
                    offset: mod ? addr.sub(mod.base).toString() : null,
                };
            });
        }

        if (!evt.success && !config.logSuccessfulOps) {
            return;
        }

        send(evt);
    }

    function onNtOpenKeyEnter(args) {
        const _keyHandle = args[0];
        const _desiredAccess = args[1].toInt32();
        const objectAttributes = args[2];

        if (!objectAttributes.isNull()) {
            const namePtr = objectAttributes.add(16).readPointer();
            const keyName = readUnicodeString(namePtr);
            this.keyName = keyName;
            this.startTime = Date.now();
        }
    }

    function onNtOpenKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtOpenKey',
            key_name: this.keyName,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        if (success && this.args && this.args[0]) {
            const handle = this.args[0].readPointer();
            const keyPath = getKeyPath(handle);

            if (keyPath) {
                evt.key_path = keyPath;
                handleTracker.set(handle.toString(), keyPath);

                if (config.performDeepAnalysis) {
                    detectLicensePattern(keyPath, null, null);
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(evt.key_path, null);
        sendEvent(evt, includeBt);
    }

    function onNtOpenKeyExEnter(args) {
        onNtOpenKeyEnter.call(this, args);
        this.options = args[3] ? args[3].toInt32() : 0;
    }

    function onNtOpenKeyExLeave(retval) {
        onNtOpenKeyLeave.call(this, retval);
    }

    function onNtCreateKeyEnter(args) {
        const _keyHandle = args[0];
        const _desiredAccess = args[1].toInt32();
        const objectAttributes = args[2];
        const _titleIndex = args[3] ? args[3].toInt32() : 0;
        const classPtr = args[4];
        const createOptions = args[5] ? args[5].toInt32() : 0;
        const disposition = args[6];

        if (!objectAttributes.isNull()) {
            const namePtr = objectAttributes.add(16).readPointer();
            const keyName = readUnicodeString(namePtr);
            this.keyName = keyName;
        }

        this.className = readUnicodeString(classPtr);
        this.createOptions = createOptions;
        this.dispositionPtr = disposition;
        this.startTime = Date.now();
    }

    function onNtCreateKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtCreateKey',
            key_name: this.keyName,
            class_name: this.className,
            create_options: this.createOptions,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        if (success) {
            if (this.dispositionPtr && !this.dispositionPtr.isNull()) {
                evt.disposition =
                    this.dispositionPtr.readU32() === 1 ? 'created_new' : 'opened_existing';
            }

            if (this.args?.[0]) {
                const handle = this.args[0].readPointer();
                const keyPath = getKeyPath(handle);

                if (keyPath) {
                    evt.key_path = keyPath;
                    handleTracker.set(handle.toString(), keyPath);
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(evt.key_path, null);
        sendEvent(evt, includeBt);
    }

    function onNtQueryKeyEnter(args) {
        const keyHandle = args[0];
        const infoClass = args[1].toInt32();
        const _keyInfo = args[2];
        const _length = args[3].toInt32();
        const _resultLength = args[4];

        this.keyHandle = keyHandle;
        this.infoClass = infoClass;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtQueryKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtQueryKey',
            key_path: this.keyPath,
            info_class: this.infoClass,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onNtQueryValueKeyEnter(args) {
        const keyHandle = args[0];
        const valueNamePtr = args[1];
        const infoClass = args[2].toInt32();
        const keyValueInfo = args[3];
        const length = args[4].toInt32();
        const resultLength = args[5];

        this.keyHandle = keyHandle;
        this.valueName = readUnicodeString(valueNamePtr);
        this.infoClass = infoClass;
        this.keyValueInfo = keyValueInfo;
        this.bufferLength = length;
        this.resultLengthPtr = resultLength;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtQueryValueKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtQueryValueKey',
            key_path: this.keyPath,
            value_name: this.valueName,
            info_class: this.infoClass,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        if (success && this.keyValueInfo && !this.keyValueInfo.isNull()) {
            try {
                let dataPtr;
                let dataSize;
                let regType;

                switch (this.infoClass) {
                    case 0: // KeyValueBasicInformation
                        regType = this.keyValueInfo.add(4).readU32();
                        evt.data_type = regType;
                        break;

                    case 1: {
                        // KeyValueFullInformation
                        regType = this.keyValueInfo.add(4).readU32();
                        dataSize = this.keyValueInfo.add(8).readU32();
                        const dataOffset = this.keyValueInfo.add(12).readU32();
                        dataPtr = this.keyValueInfo.add(dataOffset);

                        evt.data_type = regType;
                        evt.data_size = dataSize;

                        if (dataPtr && !dataPtr.isNull() && dataSize > 0) {
                            const formatted = formatRegData(regType, dataPtr, dataSize, true);
                            if (formatted.formatted) {
                                evt.data_formatted = formatted.formatted;
                            }
                            if (formatted.raw) {
                                evt.data_preview_hex = formatted.raw;
                            }

                            if (config.performDeepAnalysis) {
                                detectLicensePattern(this.keyPath, this.valueName, formatted);
                            }
                        }
                        break;
                    }

                    case 2: // KeyValuePartialInformation
                        regType = this.keyValueInfo.add(4).readU32();
                        dataSize = this.keyValueInfo.add(8).readU32();
                        dataPtr = this.keyValueInfo.add(12);

                        evt.data_type = regType;
                        evt.data_size = dataSize;

                        if (dataPtr && !dataPtr.isNull() && dataSize > 0) {
                            const formatted = formatRegData(regType, dataPtr, dataSize, true);
                            if (formatted.formatted) {
                                evt.data_formatted = formatted.formatted;
                            }
                            if (formatted.raw) {
                                evt.data_preview_hex = formatted.raw;
                            }

                            if (config.performDeepAnalysis) {
                                detectLicensePattern(this.keyPath, this.valueName, formatted);
                            }
                        }
                        break;
                }
            } catch (e) {
                evt.parse_error = e.toString();
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onNtSetValueKeyEnter(args) {
        const keyHandle = args[0];
        const valueNamePtr = args[1];
        const _titleIndex = args[2] ? args[2].toInt32() : 0;
        const type = args[3].toInt32();
        const data = args[4];
        const dataSize = args[5].toInt32();

        this.keyHandle = keyHandle;
        this.valueName = readUnicodeString(valueNamePtr);
        this.dataType = type;
        this.dataPtr = data;
        this.dataSize = dataSize;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();

        if (data && !data.isNull() && dataSize > 0) {
            const formatted = formatRegData(type, data, dataSize, true);
            this.dataFormatted = formatted.formatted;
            this.dataRaw = formatted.raw;
        }
    }

    function onNtSetValueKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtSetValueKey',
            key_path: this.keyPath,
            value_name: this.valueName,
            data_type: this.dataType,
            data_size: this.dataSize,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        if (this.dataFormatted) {
            evt.data_formatted = this.dataFormatted;
        }
        if (this.dataRaw) {
            evt.data_preview_hex = this.dataRaw;
        }

        if (config.performDeepAnalysis && success) {
            detectLicensePattern(this.keyPath, this.valueName, {
                formatted: this.dataFormatted,
            });
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onNtDeleteKeyEnter(args) {
        const keyHandle = args[0];
        this.keyHandle = keyHandle;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtDeleteKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtDeleteKey',
            key_path: this.keyPath,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        if (success && this.keyHandle) {
            handleTracker.delete(this.keyHandle.toString());
        }

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onNtDeleteValueKeyEnter(args) {
        const keyHandle = args[0];
        const valueNamePtr = args[1];

        this.keyHandle = keyHandle;
        this.valueName = readUnicodeString(valueNamePtr);
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtDeleteValueKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtDeleteValueKey',
            key_path: this.keyPath,
            value_name: this.valueName,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onNtEnumerateKeyEnter(args) {
        const keyHandle = args[0];
        const index = args[1].toInt32();
        const infoClass = args[2].toInt32();
        const keyInfo = args[3];
        const _length = args[4].toInt32();
        const _resultLength = args[5];

        this.keyHandle = keyHandle;
        this.index = index;
        this.infoClass = infoClass;
        this.keyInfo = keyInfo;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtEnumerateKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtEnumerateKey',
            key_path: this.keyPath,
            index: this.index,
            info_class: this.infoClass,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        if (success && this.keyInfo && !this.keyInfo.isNull()) {
            try {
                let namePtr;
                let nameLength;

                switch (this.infoClass) {
                    case 0: // KeyBasicInformation
                        nameLength = this.keyInfo.add(4).readU32();
                        namePtr = this.keyInfo.add(16);
                        if (nameLength > 0) {
                            evt.subkey_name = namePtr.readUtf16String(nameLength / 2);
                        }
                        break;

                    case 1: {
                        // KeyNodeInformation
                        nameLength = this.keyInfo.add(8).readU32();
                        const nameOffset = this.keyInfo.add(24).readU32();
                        namePtr = this.keyInfo.add(nameOffset);
                        if (nameLength > 0) {
                            evt.subkey_name = namePtr.readUtf16String(nameLength / 2);
                        }
                        break;
                    }

                    case 2: // KeyFullInformation
                        break;
                }
            } catch (e) {
                evt.parse_error = e.toString();
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onNtEnumerateValueKeyEnter(args) {
        const keyHandle = args[0];
        const index = args[1].toInt32();
        const infoClass = args[2].toInt32();
        const keyValueInfo = args[3];
        const _length = args[4].toInt32();
        const _resultLength = args[5];

        this.keyHandle = keyHandle;
        this.index = index;
        this.infoClass = infoClass;
        this.keyValueInfo = keyValueInfo;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtEnumerateValueKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtEnumerateValueKey',
            key_path: this.keyPath,
            index: this.index,
            info_class: this.infoClass,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        if (success && this.keyValueInfo && !this.keyValueInfo.isNull()) {
            try {
                let namePtr;
                let nameLength;
                let dataPtr;
                let dataSize;
                let regType;

                switch (this.infoClass) {
                    case 0: // KeyValueBasicInformation
                        nameLength = this.keyValueInfo.add(4).readU32();
                        namePtr = this.keyValueInfo.add(12);
                        regType = this.keyValueInfo.add(8).readU32();

                        if (nameLength > 0) {
                            evt.value_name = namePtr.readUtf16String(nameLength / 2);
                        }
                        evt.data_type = regType;
                        break;

                    case 1: {
                        // KeyValueFullInformation
                        regType = this.keyValueInfo.add(4).readU32();
                        dataSize = this.keyValueInfo.add(12).readU32();
                        nameLength = this.keyValueInfo.add(8).readU32();
                        const nameOffset = this.keyValueInfo.add(16).readU32();
                        const dataOffset = this.keyValueInfo.add(20).readU32();

                        if (nameLength > 0) {
                            namePtr = this.keyValueInfo.add(nameOffset);
                            evt.value_name = namePtr.readUtf16String(nameLength / 2);
                        }

                        evt.data_type = regType;
                        evt.data_size = dataSize;

                        if (dataSize > 0) {
                            dataPtr = this.keyValueInfo.add(dataOffset);
                            const formatted = formatRegData(regType, dataPtr, dataSize, true);
                            if (formatted.formatted) {
                                evt.data_formatted = formatted.formatted;
                            }
                            if (formatted.raw) {
                                evt.data_preview_hex = formatted.raw;
                            }

                            if (config.performDeepAnalysis) {
                                detectLicensePattern(this.keyPath, evt.value_name, formatted);
                            }
                        }
                        break;
                    }

                    case 2: // KeyValuePartialInformation
                        regType = this.keyValueInfo.add(4).readU32();
                        dataSize = this.keyValueInfo.add(8).readU32();
                        dataPtr = this.keyValueInfo.add(12);

                        evt.data_type = regType;
                        evt.data_size = dataSize;

                        if (dataSize > 0) {
                            const formatted = formatRegData(regType, dataPtr, dataSize, true);
                            if (formatted.formatted) {
                                evt.data_formatted = formatted.formatted;
                            }
                            if (formatted.raw) {
                                evt.data_preview_hex = formatted.raw;
                            }
                        }
                        break;
                }
            } catch (e) {
                evt.parse_error = e.toString();
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, evt.value_name);
        sendEvent(evt, includeBt);
    }

    function onNtCloseEnter(args) {
        const handle = args[0];
        const keyPath = handleTracker.get(handle.toString());

        if (keyPath && config.trackHandleLifecycle) {
            this.keyPath = keyPath;
            this.handle = handle;
            this.startTime = Date.now();
        }
    }

    function onNtFlushKeyEnter(args) {
        const keyHandle = args[0];
        this.keyHandle = keyHandle;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtFlushKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtFlushKey',
            key_path: this.keyPath,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onNtQueryMultipleValueKeyEnter(args) {
        const keyHandle = args[0];
        const valueEntries = args[1];
        const entryCount = args[2].toInt32();
        const valueBuffer = args[3];
        const _bufferLength = args[4] ? args[4].toInt32() : 0;
        const _requiredLength = args[5];

        this.keyHandle = keyHandle;
        this.entryCount = entryCount;
        this.valueEntries = valueEntries;
        this.valueBuffer = valueBuffer;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtQueryMultipleValueKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtQueryMultipleValueKey',
            key_path: this.keyPath,
            entry_count: this.entryCount,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onNtRenameKeyEnter(args) {
        const keyHandle = args[0];
        const newNamePtr = args[1];

        this.keyHandle = keyHandle;
        this.newName = readUnicodeString(newNamePtr);
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtRenameKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtRenameKey',
            key_path: this.keyPath,
            new_name: this.newName,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onNtLoadKeyEnter(args) {
        const targetKey = args[0];
        const sourceFile = args[1];

        this.targetKey = readUnicodeString(targetKey);
        this.sourceFile = readUnicodeString(sourceFile);
        this.startTime = Date.now();
    }

    function onNtLoadKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtLoadKey',
            target_key: this.targetKey,
            source_file: this.sourceFile,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt = config.includeBacktraceOnMatch && success;
        sendEvent(evt, includeBt);
    }

    function onNtUnloadKeyEnter(args) {
        const targetKey = args[0];
        this.targetKey = readUnicodeString(targetKey);
        this.startTime = Date.now();
    }

    function onNtUnloadKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtUnloadKey',
            target_key: this.targetKey,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt = config.includeBacktraceOnMatch && success;
        sendEvent(evt, includeBt);
    }

    function onNtSaveKeyEnter(args) {
        const keyHandle = args[0];
        const _fileHandle = args[1];

        this.keyHandle = keyHandle;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtSaveKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtSaveKey',
            key_path: this.keyPath,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onNtRestoreKeyEnter(args) {
        const keyHandle = args[0];
        const _fileHandle = args[1];
        const flags = args[2] ? args[2].toInt32() : 0;

        this.keyHandle = keyHandle;
        this.flags = flags;
        this.keyPath = getKeyPath(keyHandle);
        this.startTime = Date.now();
    }

    function onNtRestoreKeyLeave(retval) {
        const success = retval.toInt32() === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'NtRestoreKey',
            key_path: this.keyPath,
            flags: this.flags,
            success: success,
            status: retval.toInt32(),
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegOpenKeyExWEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const ulOptions = args[2] ? args[2].toInt32() : 0;
        const samDesired = args[3] ? args[3].toInt32() : 0;
        const phkResult = args[4];

        this.parentKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readUtf16String();
        this.options = ulOptions;
        this.access = samDesired;
        this.resultPtr = phkResult;
        this.startTime = Date.now();
    }

    function onRegOpenKeyExWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegOpenKeyExW',
            parent_key: `0x${this.parentKey.toString(16)}`,
            sub_key: this.subKey,
            options: this.options,
            access: this.access,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.resultPtr && !this.resultPtr.isNull()) {
            const handle = this.resultPtr.readPointer();
            const keyPath = getKeyPath(handle);

            if (keyPath) {
                evt.key_path = keyPath;
                handleTracker.set(handle.toString(), keyPath);

                if (config.performDeepAnalysis) {
                    detectLicensePattern(keyPath, null, null);
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(evt.key_path || this.subKey, null);
        sendEvent(evt, includeBt);
    }

    function onRegOpenKeyExAEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const ulOptions = args[2] ? args[2].toInt32() : 0;
        const samDesired = args[3] ? args[3].toInt32() : 0;
        const phkResult = args[4];

        this.parentKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readAnsiString();
        this.options = ulOptions;
        this.access = samDesired;
        this.resultPtr = phkResult;
        this.startTime = Date.now();
    }

    function onRegOpenKeyExALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegOpenKeyExA',
            parent_key: `0x${this.parentKey.toString(16)}`,
            sub_key: this.subKey,
            options: this.options,
            access: this.access,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.resultPtr && !this.resultPtr.isNull()) {
            const handle = this.resultPtr.readPointer();
            const keyPath = getKeyPath(handle);

            if (keyPath) {
                evt.key_path = keyPath;
                handleTracker.set(handle.toString(), keyPath);
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(evt.key_path || this.subKey, null);
        sendEvent(evt, includeBt);
    }

    function onRegCreateKeyExWEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const _reserved = args[2] ? args[2].toInt32() : 0;
        const lpClass = args[3];
        const dwOptions = args[4] ? args[4].toInt32() : 0;
        const samDesired = args[5] ? args[5].toInt32() : 0;
        const _lpSecurityAttributes = args[6];
        const phkResult = args[7];
        const lpdwDisposition = args[8];

        this.parentKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readUtf16String();
        this.className = lpClass.isNull() ? null : lpClass.readUtf16String();
        this.options = dwOptions;
        this.access = samDesired;
        this.resultPtr = phkResult;
        this.dispositionPtr = lpdwDisposition;
        this.startTime = Date.now();
    }

    function onRegCreateKeyExWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegCreateKeyExW',
            parent_key: `0x${this.parentKey.toString(16)}`,
            sub_key: this.subKey,
            class_name: this.className,
            options: this.options,
            access: this.access,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success) {
            if (this.dispositionPtr && !this.dispositionPtr.isNull()) {
                evt.disposition =
                    this.dispositionPtr.readU32() === 1 ? 'created_new' : 'opened_existing';
            }

            if (this.resultPtr && !this.resultPtr.isNull()) {
                const handle = this.resultPtr.readPointer();
                const keyPath = getKeyPath(handle);

                if (keyPath) {
                    evt.key_path = keyPath;
                    handleTracker.set(handle.toString(), keyPath);
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(evt.key_path || this.subKey, null);
        sendEvent(evt, includeBt);
    }

    function onRegCreateKeyExAEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const _reserved = args[2] ? args[2].toInt32() : 0;
        const lpClass = args[3];
        const dwOptions = args[4] ? args[4].toInt32() : 0;
        const samDesired = args[5] ? args[5].toInt32() : 0;
        const _lpSecurityAttributes = args[6];
        const phkResult = args[7];
        const lpdwDisposition = args[8];

        this.parentKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readAnsiString();
        this.className = lpClass.isNull() ? null : lpClass.readAnsiString();
        this.options = dwOptions;
        this.access = samDesired;
        this.resultPtr = phkResult;
        this.dispositionPtr = lpdwDisposition;
        this.startTime = Date.now();
    }

    function onRegCreateKeyExALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegCreateKeyExA',
            parent_key: `0x${this.parentKey.toString(16)}`,
            sub_key: this.subKey,
            class_name: this.className,
            options: this.options,
            access: this.access,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success) {
            if (this.dispositionPtr && !this.dispositionPtr.isNull()) {
                evt.disposition =
                    this.dispositionPtr.readU32() === 1 ? 'created_new' : 'opened_existing';
            }

            if (this.resultPtr && !this.resultPtr.isNull()) {
                const handle = this.resultPtr.readPointer();
                const keyPath = getKeyPath(handle);

                if (keyPath) {
                    evt.key_path = keyPath;
                    handleTracker.set(handle.toString(), keyPath);
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(evt.key_path || this.subKey, null);
        sendEvent(evt, includeBt);
    }

    function onRegQueryValueExWEnter(args) {
        const hKey = args[0];
        const lpValueName = args[1];
        const _lpReserved = args[2];
        const lpType = args[3];
        const lpData = args[4];
        const lpcbData = args[5];

        this.hKey = hKey;
        this.valueName = lpValueName.isNull() ? null : lpValueName.readUtf16String();
        this.lpType = lpType;
        this.lpData = lpData;
        this.lpcbData = lpcbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegQueryValueExWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegQueryValueExW',
            key_path: this.keyPath,
            value_name: this.valueName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.lpType && !this.lpType.isNull()) {
            const regType = this.lpType.readU32();
            evt.data_type = regType;

            if (this.lpcbData && !this.lpcbData.isNull()) {
                const dataSize = this.lpcbData.readU32();
                evt.data_size = dataSize;

                if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
                    const formatted = formatRegData(regType, this.lpData, dataSize, true);
                    if (formatted.formatted) {
                        evt.data_formatted = formatted.formatted;
                    }
                    if (formatted.raw) {
                        evt.data_preview_hex = formatted.raw;
                    }

                    if (config.performDeepAnalysis) {
                        detectLicensePattern(this.keyPath, this.valueName, formatted);
                    }
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onRegQueryValueExAEnter(args) {
        const hKey = args[0];
        const lpValueName = args[1];
        const _lpReserved = args[2];
        const lpType = args[3];
        const lpData = args[4];
        const lpcbData = args[5];

        this.hKey = hKey;
        this.valueName = lpValueName.isNull() ? null : lpValueName.readAnsiString();
        this.lpType = lpType;
        this.lpData = lpData;
        this.lpcbData = lpcbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegQueryValueExALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegQueryValueExA',
            key_path: this.keyPath,
            value_name: this.valueName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.lpType && !this.lpType.isNull()) {
            const regType = this.lpType.readU32();
            evt.data_type = regType;

            if (this.lpcbData && !this.lpcbData.isNull()) {
                const dataSize = this.lpcbData.readU32();
                evt.data_size = dataSize;

                if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
                    const formatted = formatRegData(regType, this.lpData, dataSize, true);
                    if (formatted.formatted) {
                        evt.data_formatted = formatted.formatted;
                    }
                    if (formatted.raw) {
                        evt.data_preview_hex = formatted.raw;
                    }

                    if (config.performDeepAnalysis) {
                        detectLicensePattern(this.keyPath, this.valueName, formatted);
                    }
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onRegSetValueExWEnter(args) {
        const hKey = args[0];
        const lpValueName = args[1];
        const _reserved = args[2] ? args[2].toInt32() : 0;
        const dwType = args[3] ? args[3].toInt32() : 0;
        const lpData = args[4];
        const cbData = args[5] ? args[5].toInt32() : 0;

        this.hKey = hKey;
        this.valueName = lpValueName.isNull() ? null : lpValueName.readUtf16String();
        this.dataType = dwType;
        this.dataSize = cbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());

        if (lpData && !lpData.isNull() && cbData > 0) {
            const formatted = formatRegData(dwType, lpData, cbData, true);
            this.dataFormatted = formatted.formatted;
            this.dataRaw = formatted.raw;
        }

        this.startTime = Date.now();
    }

    function onRegSetValueExWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegSetValueExW',
            key_path: this.keyPath,
            value_name: this.valueName,
            data_type: this.dataType,
            data_size: this.dataSize,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (this.dataFormatted) {
            evt.data_formatted = this.dataFormatted;
        }
        if (this.dataRaw) {
            evt.data_preview_hex = this.dataRaw;
        }

        if (config.performDeepAnalysis && success) {
            detectLicensePattern(this.keyPath, this.valueName, {
                formatted: this.dataFormatted,
            });
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onRegSetValueExAEnter(args) {
        const hKey = args[0];
        const lpValueName = args[1];
        const _reserved = args[2] ? args[2].toInt32() : 0;
        const dwType = args[3] ? args[3].toInt32() : 0;
        const lpData = args[4];
        const cbData = args[5] ? args[5].toInt32() : 0;

        this.hKey = hKey;
        this.valueName = lpValueName.isNull() ? null : lpValueName.readAnsiString();
        this.dataType = dwType;
        this.dataSize = cbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());

        if (lpData && !lpData.isNull() && cbData > 0) {
            const formatted = formatRegData(dwType, lpData, cbData, true);
            this.dataFormatted = formatted.formatted;
            this.dataRaw = formatted.raw;
        }

        this.startTime = Date.now();
    }

    function onRegSetValueExALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegSetValueExA',
            key_path: this.keyPath,
            value_name: this.valueName,
            data_type: this.dataType,
            data_size: this.dataSize,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (this.dataFormatted) {
            evt.data_formatted = this.dataFormatted;
        }
        if (this.dataRaw) {
            evt.data_preview_hex = this.dataRaw;
        }

        if (config.performDeepAnalysis && success) {
            detectLicensePattern(this.keyPath, this.valueName, {
                formatted: this.dataFormatted,
            });
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onRegDeleteKeyWEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readUtf16String();

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegDeleteKeyWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegDeleteKeyW',
            key_path: this.keyPath,
            sub_key: this.subKey,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, this.subKey);
        sendEvent(evt, includeBt);
    }

    function onRegDeleteKeyAEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readAnsiString();

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegDeleteKeyALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegDeleteKeyA',
            key_path: this.keyPath,
            sub_key: this.subKey,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, this.subKey);
        sendEvent(evt, includeBt);
    }

    function onRegDeleteValueWEnter(args) {
        const hKey = args[0];
        const lpValueName = args[1];

        this.hKey = hKey;
        this.valueName = lpValueName.isNull() ? null : lpValueName.readUtf16String();

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegDeleteValueWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegDeleteValueW',
            key_path: this.keyPath,
            value_name: this.valueName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onRegDeleteValueAEnter(args) {
        const hKey = args[0];
        const lpValueName = args[1];

        this.hKey = hKey;
        this.valueName = lpValueName.isNull() ? null : lpValueName.readAnsiString();

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegDeleteValueALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegDeleteValueA',
            key_path: this.keyPath,
            value_name: this.valueName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onRegEnumKeyExWEnter(args) {
        const hKey = args[0];
        const dwIndex = args[1] ? args[1].toInt32() : 0;
        const lpName = args[2];
        const lpcchName = args[3];
        const _lpReserved = args[4];
        const _lpClass = args[5];
        const _lpcchClass = args[6];
        const _lpftLastWriteTime = args[7];

        this.hKey = hKey;
        this.index = dwIndex;
        this.lpName = lpName;
        this.lpcchName = lpcchName;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegEnumKeyExWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegEnumKeyExW',
            key_path: this.keyPath,
            index: this.index,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.lpName && !this.lpName.isNull()) {
            evt.subkey_name = this.lpName.readUtf16String();
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, evt.subkey_name);
        sendEvent(evt, includeBt);
    }

    function onRegEnumKeyExAEnter(args) {
        const hKey = args[0];
        const dwIndex = args[1] ? args[1].toInt32() : 0;
        const lpName = args[2];
        const lpcchName = args[3];
        const _lpReserved = args[4];
        const _lpClass = args[5];
        const _lpcchClass = args[6];
        const _lpftLastWriteTime = args[7];

        this.hKey = hKey;
        this.index = dwIndex;
        this.lpName = lpName;
        this.lpcchName = lpcchName;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegEnumKeyExALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegEnumKeyExA',
            key_path: this.keyPath,
            index: this.index,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.lpName && !this.lpName.isNull()) {
            evt.subkey_name = this.lpName.readAnsiString();
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, evt.subkey_name);
        sendEvent(evt, includeBt);
    }

    function onRegEnumValueWEnter(args) {
        const hKey = args[0];
        const dwIndex = args[1] ? args[1].toInt32() : 0;
        const lpValueName = args[2];
        const lpcchValueName = args[3];
        const _lpReserved = args[4];
        const lpType = args[5];
        const lpData = args[6];
        const lpcbData = args[7];

        this.hKey = hKey;
        this.index = dwIndex;
        this.lpValueName = lpValueName;
        this.lpcchValueName = lpcchValueName;
        this.lpType = lpType;
        this.lpData = lpData;
        this.lpcbData = lpcbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegEnumValueWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegEnumValueW',
            key_path: this.keyPath,
            index: this.index,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success) {
            if (this.lpValueName && !this.lpValueName.isNull()) {
                evt.value_name = this.lpValueName.readUtf16String();
            }

            if (this.lpType && !this.lpType.isNull()) {
                const regType = this.lpType.readU32();
                evt.data_type = regType;

                if (this.lpcbData && !this.lpcbData.isNull()) {
                    const dataSize = this.lpcbData.readU32();
                    evt.data_size = dataSize;

                    if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
                        const formatted = formatRegData(regType, this.lpData, dataSize, true);
                        if (formatted.formatted) {
                            evt.data_formatted = formatted.formatted;
                        }
                        if (formatted.raw) {
                            evt.data_preview_hex = formatted.raw;
                        }
                    }
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, evt.value_name);
        sendEvent(evt, includeBt);
    }

    function onRegEnumValueAEnter(args) {
        const hKey = args[0];
        const dwIndex = args[1] ? args[1].toInt32() : 0;
        const lpValueName = args[2];
        const lpcchValueName = args[3];
        const _lpReserved = args[4];
        const lpType = args[5];
        const lpData = args[6];
        const lpcbData = args[7];

        this.hKey = hKey;
        this.index = dwIndex;
        this.lpValueName = lpValueName;
        this.lpcchValueName = lpcchValueName;
        this.lpType = lpType;
        this.lpData = lpData;
        this.lpcbData = lpcbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegEnumValueALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegEnumValueA',
            key_path: this.keyPath,
            index: this.index,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success) {
            if (this.lpValueName && !this.lpValueName.isNull()) {
                evt.value_name = this.lpValueName.readAnsiString();
            }

            if (this.lpType && !this.lpType.isNull()) {
                const regType = this.lpType.readU32();
                evt.data_type = regType;

                if (this.lpcbData && !this.lpcbData.isNull()) {
                    const dataSize = this.lpcbData.readU32();
                    evt.data_size = dataSize;

                    if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
                        const formatted = formatRegData(regType, this.lpData, dataSize, true);
                        if (formatted.formatted) {
                            evt.data_formatted = formatted.formatted;
                        }
                        if (formatted.raw) {
                            evt.data_preview_hex = formatted.raw;
                        }
                    }
                }
            }
        }

        const includeBt =
            config.includeBacktraceOnMatch &&
            success &&
            matchesFilters(this.keyPath, evt.value_name);
        sendEvent(evt, includeBt);
    }

    function onRegCloseKeyEnter(args) {
        const hKey = args[0];
        const keyPath = handleTracker.get(hKey.toString());

        if (keyPath && config.trackHandleLifecycle) {
            this.keyPath = keyPath;
            this.hKey = hKey;
            this.startTime = Date.now();
        }
    }

    function onRegFlushKeyEnter(args) {
        const hKey = args[0];

        this.hKey = hKey;
        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegFlushKeyLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegFlushKey',
            key_path: this.keyPath,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegSaveKeyWEnter(args) {
        const hKey = args[0];
        const lpFile = args[1];
        const _lpSecurityAttributes = args[2];

        this.hKey = hKey;
        this.fileName = lpFile.isNull() ? null : lpFile.readUtf16String();

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegSaveKeyWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegSaveKeyW',
            key_path: this.keyPath,
            file_name: this.fileName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegSaveKeyAEnter(args) {
        const hKey = args[0];
        const lpFile = args[1];
        const _lpSecurityAttributes = args[2];

        this.hKey = hKey;
        this.fileName = lpFile.isNull() ? null : lpFile.readAnsiString();

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegSaveKeyALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegSaveKeyA',
            key_path: this.keyPath,
            file_name: this.fileName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegRestoreKeyWEnter(args) {
        const hKey = args[0];
        const lpFile = args[1];
        const dwFlags = args[2] ? args[2].toInt32() : 0;

        this.hKey = hKey;
        this.fileName = lpFile.isNull() ? null : lpFile.readUtf16String();
        this.flags = dwFlags;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegRestoreKeyWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegRestoreKeyW',
            key_path: this.keyPath,
            file_name: this.fileName,
            flags: this.flags,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegRestoreKeyAEnter(args) {
        const hKey = args[0];
        const lpFile = args[1];
        const dwFlags = args[2] ? args[2].toInt32() : 0;

        this.hKey = hKey;
        this.fileName = lpFile.isNull() ? null : lpFile.readAnsiString();
        this.flags = dwFlags;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegRestoreKeyALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegRestoreKeyA',
            key_path: this.keyPath,
            file_name: this.fileName,
            flags: this.flags,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegLoadKeyWEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const lpFile = args[2];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readUtf16String();
        this.fileName = lpFile.isNull() ? null : lpFile.readUtf16String();
        this.startTime = Date.now();
    }

    function onRegLoadKeyWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegLoadKeyW',
            parent_key: `0x${this.hKey.toString(16)}`,
            sub_key: this.subKey,
            file_name: this.fileName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt = config.includeBacktraceOnMatch && success;
        sendEvent(evt, includeBt);
    }

    function onRegLoadKeyAEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const lpFile = args[2];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readAnsiString();
        this.fileName = lpFile.isNull() ? null : lpFile.readAnsiString();
        this.startTime = Date.now();
    }

    function onRegLoadKeyALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegLoadKeyA',
            parent_key: `0x${this.hKey.toString(16)}`,
            sub_key: this.subKey,
            file_name: this.fileName,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt = config.includeBacktraceOnMatch && success;
        sendEvent(evt, includeBt);
    }

    function onRegUnLoadKeyWEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readUtf16String();
        this.startTime = Date.now();
    }

    function onRegUnLoadKeyWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegUnLoadKeyW',
            parent_key: `0x${this.hKey.toString(16)}`,
            sub_key: this.subKey,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt = config.includeBacktraceOnMatch && success;
        sendEvent(evt, includeBt);
    }

    function onRegUnLoadKeyAEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readAnsiString();
        this.startTime = Date.now();
    }

    function onRegUnLoadKeyALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegUnLoadKeyA',
            parent_key: `0x${this.hKey.toString(16)}`,
            sub_key: this.subKey,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt = config.includeBacktraceOnMatch && success;
        sendEvent(evt, includeBt);
    }

    function onRegQueryInfoKeyWEnter(args) {
        const hKey = args[0];

        this.hKey = hKey;
        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegQueryInfoKeyWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegQueryInfoKeyW',
            key_path: this.keyPath,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegQueryInfoKeyAEnter(args) {
        const hKey = args[0];

        this.hKey = hKey;
        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegQueryInfoKeyALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegQueryInfoKeyA',
            key_path: this.keyPath,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(this.keyPath, null);
        sendEvent(evt, includeBt);
    }

    function onRegGetValueWEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const lpValue = args[2];
        const dwFlags = args[3] ? args[3].toInt32() : 0;
        const pdwType = args[4];
        const pvData = args[5];
        const pcbData = args[6];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readUtf16String();
        this.valueName = lpValue.isNull() ? null : lpValue.readUtf16String();
        this.flags = dwFlags;
        this.lpType = pdwType;
        this.lpData = pvData;
        this.lpcbData = pcbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegGetValueWLeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegGetValueW',
            key_path: this.keyPath,
            sub_key: this.subKey,
            value_name: this.valueName,
            flags: this.flags,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.lpType && !this.lpType.isNull()) {
            const regType = this.lpType.readU32();
            evt.data_type = regType;

            if (this.lpcbData && !this.lpcbData.isNull()) {
                const dataSize = this.lpcbData.readU32();
                evt.data_size = dataSize;

                if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
                    const formatted = formatRegData(regType, this.lpData, dataSize, true);
                    if (formatted.formatted) {
                        evt.data_formatted = formatted.formatted;
                    }
                    if (formatted.raw) {
                        evt.data_preview_hex = formatted.raw;
                    }
                }
            }
        }

        const keyPath = this.keyPath + (this.subKey ? `\\${this.subKey}` : '');
        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    function onRegGetValueAEnter(args) {
        const hKey = args[0];
        const lpSubKey = args[1];
        const lpValue = args[2];
        const dwFlags = args[3] ? args[3].toInt32() : 0;
        const pdwType = args[4];
        const pvData = args[5];
        const pcbData = args[6];

        this.hKey = hKey;
        this.subKey = lpSubKey.isNull() ? null : lpSubKey.readAnsiString();
        this.valueName = lpValue.isNull() ? null : lpValue.readAnsiString();
        this.flags = dwFlags;
        this.lpType = pdwType;
        this.lpData = pvData;
        this.lpcbData = pcbData;

        const keyPath = getKeyPath(hKey);
        this.keyPath = keyPath || handleTracker.get(hKey.toString());
        this.startTime = Date.now();
    }

    function onRegGetValueALeave(retval) {
        const success = retval === 0;
        const evt = {
            type: 'registry_operation',
            target: 'registry_monitor',
            function: 'RegGetValueA',
            key_path: this.keyPath,
            sub_key: this.subKey,
            value_name: this.valueName,
            flags: this.flags,
            success: success,
            status: retval,
            duration: Date.now() - this.startTime,
        };

        if (success && this.lpType && !this.lpType.isNull()) {
            const regType = this.lpType.readU32();
            evt.data_type = regType;

            if (this.lpcbData && !this.lpcbData.isNull()) {
                const dataSize = this.lpcbData.readU32();
                evt.data_size = dataSize;

                if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
                    const formatted = formatRegData(regType, this.lpData, dataSize, true);
                    if (formatted.formatted) {
                        evt.data_formatted = formatted.formatted;
                    }
                    if (formatted.raw) {
                        evt.data_preview_hex = formatted.raw;
                    }
                }
            }
        }

        const keyPath = this.keyPath + (this.subKey ? `\\${this.subKey}` : '');
        const includeBt =
            config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
    }

    initializeHooks();
})();
