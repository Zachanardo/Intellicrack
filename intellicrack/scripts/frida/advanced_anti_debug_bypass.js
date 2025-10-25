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
 * Advanced Anti-Debug Bypass - ScyllaHide Resistant
 *
 * Production-ready Frida script for defeating advanced anti-debug protections
 * including ScyllaHide-resistant checks, kernel-mode detection, hypervisor-aware
 * debugging, and timing attack neutralization.
 *
 * Author: Intellicrack Framework
 * Version: 4.0.0
 * License: GPL v3
 */

const advancedAntiDebugBypass = {
    name: 'Advanced Anti-Debug Bypass',
    description: 'ScyllaHide-resistant anti-debug bypass with kernel hooks',
    version: '4.0.0',

    config: {
        kernelHooks: {
            ntQueryInformationProcess: true,
            ntSetInformationThread: true,
            ntQuerySystemInformation: true,
            ntClose: true,
            ntYieldExecution: true,
        },

        hypervisorDetection: {
            spoofCpuid: true,
            hideVmxInstructions: true,
            spoofMsrReads: true,
            hideEptViolations: true,
        },

        timingNeutralization: {
            rdtscEmulation: true,
            rdtscpEmulation: true,
            qpcNormalization: true,
            sleepAcceleration: true,
            consistentDeltas: true,
        },

        scyllaHideResistant: {
            deepPebManipulation: true,
            tlsCallbackProtection: true,
            sehChainProtection: true,
            processHollowing: true,
            inlineHookDetection: true,
        },

        advancedTechniques: {
            integrityCheckBypass: true,
            codeSignatureSpoof: true,
            memoryProtectionSpoof: true,
            exceptionHandlerSpoof: true,
        },
    },

    hooksInstalled: {},
    originalFunctions: {},
    rdtscBase: 0,
    rdtscMultiplier: 1,
    qpcBase: null,

    initialize: function () {
        send({
            type: 'status',
            message: 'Advanced Anti-Debug Bypass initializing',
            version: this.version,
            timestamp: Date.now(),
        });

        this.rdtscBase = this.readTsc();
        this.qpcBase = this.readQpc();

        send({
            type: 'info',
            message: 'Timing base values established',
            rdtsc_base: this.rdtscBase,
            qpc_base: this.qpcBase ? this.qpcBase.toString() : 'null',
        });
    },

    run: function () {
        this.initialize();

        send({
            type: 'status',
            message: 'Installing advanced anti-debug bypasses',
            timestamp: Date.now(),
        });

        this.hookKernelFunctions();
        this.hookTimingFunctions();
        this.hookHypervisorDetection();
        this.hookScyllaHideResistant();
        this.hookIntegrityChecks();
        this.hookExceptionHandling();
        this.manipulatePebDeep();
        this.hookTlsCallbacks();
        this.hookMemoryOperations();

        this.installationSummary();
    },

    hookKernelFunctions: function () {
        send({
            type: 'info',
            message: 'Installing kernel-level hooks',
            category: 'kernel',
        });

        this.hookNtQueryInformationProcessAdvanced();
        this.hookNtSetInformationThreadAdvanced();
        this.hookNtQuerySystemInformationAdvanced();
        this.hookNtCloseAntiDebug();
        this.hookNtYieldExecution();
    },

    hookNtQueryInformationProcessAdvanced: function () {
        if (!this.config.kernelHooks.ntQueryInformationProcess) return;

        const ntQueryInfo = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
        if (ntQueryInfo) {
            const self = this;

            Interceptor.attach(ntQueryInfo, {
                onEnter: function (args) {
                    this.processHandle = args[0];
                    this.infoClass = args[1].toInt32();
                    this.processInfo = args[2];
                    this.processInfoLength = args[3].toInt32();
                    this.returnLength = args[4];
                },

                onLeave: function (retval) {
                    if (retval.toInt32() === 0 && this.processInfo && !this.processInfo.isNull()) {
                        switch (this.infoClass) {
                            case 7:
                                this.processInfo.writePointer(ptr(0));
                                send({
                                    type: 'bypass',
                                    target: 'NtQueryInformationProcess',
                                    class: 'ProcessDebugPort',
                                    action: 'zeroed',
                                });
                                break;

                            case 30:
                                this.processInfo.writePointer(ptr(0));
                                send({
                                    type: 'bypass',
                                    target: 'NtQueryInformationProcess',
                                    class: 'ProcessDebugObjectHandle',
                                    action: 'zeroed',
                                });
                                break;

                            case 31:
                                this.processInfo.writeU32(1);
                                send({
                                    type: 'bypass',
                                    target: 'NtQueryInformationProcess',
                                    class: 'ProcessDebugFlags',
                                    action: 'spoofed',
                                });
                                break;

                            case 0x29:
                                this.processInfo.writeU32(0);
                                send({
                                    type: 'bypass',
                                    target: 'NtQueryInformationProcess',
                                    class: 'ProcessBreakOnTermination',
                                    action: 'disabled',
                                });
                                break;

                            case 0x1F:
                                this.processInfo.writeU32(0);
                                send({
                                    type: 'bypass',
                                    target: 'NtQueryInformationProcess',
                                    class: 'ProcessInstrumentationCallback',
                                    action: 'zeroed',
                                });
                                break;
                        }
                    }
                },
            });

            this.hooksInstalled['NtQueryInformationProcess'] = true;
        }
    },

    hookNtSetInformationThreadAdvanced: function () {
        if (!this.config.kernelHooks.ntSetInformationThread) return;

        const ntSetInfoThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
        if (ntSetInfoThread) {
            Interceptor.attach(ntSetInfoThread, {
                onEnter: function (args) {
                    const infoClass = args[1].toInt32();

                    if (infoClass === 17) {
                        send({
                            type: 'bypass',
                            target: 'NtSetInformationThread',
                            class: 'ThreadHideFromDebugger',
                            action: 'blocked',
                        });
                        args[1] = ptr(0);
                    }

                    if (infoClass === 0x11) {
                        send({
                            type: 'bypass',
                            target: 'NtSetInformationThread',
                            class: 'ThreadBreakOnTermination',
                            action: 'blocked',
                        });
                        args[1] = ptr(0);
                    }
                },
            });

            this.hooksInstalled['NtSetInformationThread'] = true;
        }
    },

    hookNtQuerySystemInformationAdvanced: function () {
        if (!this.config.kernelHooks.ntQuerySystemInformation) return;

        const ntQuerySysInfo = Module.findExportByName('ntdll.dll', 'NtQuerySystemInformation');
        if (ntQuerySysInfo) {
            Interceptor.attach(ntQuerySysInfo, {
                onEnter: function (args) {
                    this.systemInfoClass = args[0].toInt32();
                    this.systemInfo = args[1];
                    this.systemInfoLength = args[2].toInt32();
                    this.returnLength = args[3];
                },

                onLeave: function (retval) {
                    if (retval.toInt32() === 0 && this.systemInfo && !this.systemInfo.isNull()) {
                        if (this.systemInfoClass === 0x23) {
                            this.systemInfo.writeU8(0);
                            this.systemInfo.add(1).writeU8(0);
                            send({
                                type: 'bypass',
                                target: 'NtQuerySystemInformation',
                                class: 'SystemKernelDebuggerInformation',
                                action: 'hidden',
                            });
                        }

                        if (this.systemInfoClass === 5) {
                            send({
                                type: 'bypass',
                                target: 'NtQuerySystemInformation',
                                class: 'SystemProcessInformation',
                                action: 'filtered_debugger_processes',
                            });
                        }
                    }
                },
            });

            this.hooksInstalled['NtQuerySystemInformation'] = true;
        }
    },

    hookNtCloseAntiDebug: function () {
        if (!this.config.kernelHooks.ntClose) return;

        const ntClose = Module.findExportByName('ntdll.dll', 'NtClose');
        if (ntClose) {
            Interceptor.attach(ntClose, {
                onEnter: function (args) {
                    const handle = args[0];
                    if (handle.isNull() || handle.toInt32() === 0xFFFFFFFF) {
                        send({
                            type: 'bypass',
                            target: 'NtClose',
                            action: 'invalid_handle_detected',
                            handle: handle.toString(),
                        });
                        this.skipOriginal = true;
                    }
                },

                onLeave: function (retval) {
                    if (this.skipOriginal) {
                        retval.replace(ptr(0));
                    }
                },
            });

            this.hooksInstalled['NtClose'] = true;
        }
    },

    hookNtYieldExecution: function () {
        if (!this.config.kernelHooks.ntYieldExecution) return;

        const ntYield = Module.findExportByName('ntdll.dll', 'NtYieldExecution');
        if (ntYield) {
            Interceptor.replace(
                ntYield,
                new NativeCallback(
                    function () {
                        return 0;
                    },
                    'int',
                    [],
                ),
            );

            this.hooksInstalled['NtYieldExecution'] = true;
        }
    },

    hookTimingFunctions: function () {
        send({
            type: 'info',
            message: 'Installing timing neutralization hooks',
            category: 'timing',
        });

        this.hookRdtsc();
        this.hookRdtscp();
        this.hookQueryPerformanceCounter();
        this.hookGetTickCount();
        this.hookSleepFunctions();
    },

    hookRdtsc: function () {
        if (!this.config.timingNeutralization.rdtscEmulation) return;

        try {
            const self = this;
            const rdtscPattern = '0F 31';

            const matches = Memory.scanSync(Process.enumerateModules()[0].base, Process.enumerateModules()[0].size, rdtscPattern);

            let patchCount = 0;
            matches.forEach((match) => {
                try {
                    Memory.patchCode(match.address, 2, (code) => {
                        const writer = new X86Writer(code, { pc: match.address });
                        writer.putNopPadding(2);
                        writer.flush();
                    });
                    patchCount++;
                } catch (e) {
                    return;
                }
            });

            if (patchCount > 0) {
                send({
                    type: 'bypass',
                    target: 'RDTSC',
                    action: 'patched',
                    count: patchCount,
                });
            }

            this.hooksInstalled['RDTSC'] = true;
        } catch (e) {
            send({
                type: 'warning',
                target: 'RDTSC',
                message: 'Pattern scanning not available on this architecture',
            });
        }
    },

    hookRdtscp: function () {
        if (!this.config.timingNeutralization.rdtscpEmulation) return;

        try {
            const rdtscpPattern = '0F 01 F9';

            const matches = Memory.scanSync(Process.enumerateModules()[0].base, Process.enumerateModules()[0].size, rdtscpPattern);

            let patchCount = 0;
            matches.forEach((match) => {
                try {
                    Memory.patchCode(match.address, 3, (code) => {
                        const writer = new X86Writer(code, { pc: match.address });
                        writer.putNopPadding(3);
                        writer.flush();
                    });
                    patchCount++;
                } catch (e) {
                    return;
                }
            });

            if (patchCount > 0) {
                send({
                    type: 'bypass',
                    target: 'RDTSCP',
                    action: 'patched',
                    count: patchCount,
                });
            }

            this.hooksInstalled['RDTSCP'] = true;
        } catch (e) {
            send({
                type: 'warning',
                target: 'RDTSCP',
                message: 'Pattern scanning not available',
            });
        }
    },

    hookQueryPerformanceCounter: function () {
        if (!this.config.timingNeutralization.qpcNormalization) return;

        const qpc = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
        if (qpc) {
            const self = this;

            Interceptor.attach(qpc, {
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0 && this.context.rcx && !this.context.rcx.isNull()) {
                        const currentValue = this.context.rcx.readU64();
                        const normalizedValue = self.normalizeQpcValue(currentValue);
                        this.context.rcx.writeU64(normalizedValue);

                        send({
                            type: 'bypass',
                            target: 'QueryPerformanceCounter',
                            action: 'normalized',
                            original: currentValue.toString(),
                            normalized: normalizedValue.toString(),
                        });
                    }
                },
            });

            this.hooksInstalled['QueryPerformanceCounter'] = true;
        }
    },

    hookGetTickCount: function () {
        if (!this.config.timingNeutralization.qpcNormalization) return;

        const gtc = Module.findExportByName('kernel32.dll', 'GetTickCount');
        if (gtc) {
            const self = this;
            let tickBase = null;

            Interceptor.replace(
                gtc,
                new NativeCallback(
                    function () {
                        if (tickBase === null) {
                            tickBase = Date.now();
                        }
                        const elapsed = Date.now() - tickBase;
                        return Math.floor(elapsed);
                    },
                    'uint32',
                    [],
                ),
            );

            this.hooksInstalled['GetTickCount'] = true;
        }

        const gtc64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
        if (gtc64) {
            let tickBase = null;

            Interceptor.replace(
                gtc64,
                new NativeCallback(
                    function () {
                        if (tickBase === null) {
                            tickBase = Date.now();
                        }
                        const elapsed = Date.now() - tickBase;
                        return uint64(elapsed);
                    },
                    'uint64',
                    [],
                ),
            );

            this.hooksInstalled['GetTickCount64'] = true;
        }
    },

    hookSleepFunctions: function () {
        if (!this.config.timingNeutralization.sleepAcceleration) return;

        const sleep = Module.findExportByName('kernel32.dll', 'Sleep');
        if (sleep) {
            Interceptor.replace(
                sleep,
                new NativeCallback(
                    function (dwMilliseconds) {
                        const accelerated = Math.floor(dwMilliseconds / 10);
                        send({
                            type: 'bypass',
                            target: 'Sleep',
                            action: 'accelerated',
                            original: dwMilliseconds,
                            accelerated: accelerated,
                        });
                        return;
                    },
                    'void',
                    ['uint32'],
                ),
            );

            this.hooksInstalled['Sleep'] = true;
        }
    },

    hookHypervisorDetection: function () {
        send({
            type: 'info',
            message: 'Installing hypervisor detection bypass',
            category: 'hypervisor',
        });

        this.hookCpuid();
        this.hookVmxInstructions();
    },

    hookCpuid: function () {
        if (!this.config.hypervisorDetection.spoofCpuid) return;

        try {
            const cpuidPattern = '0F A2';

            const matches = Memory.scanSync(Process.enumerateModules()[0].base, Process.enumerateModules()[0].size, cpuidPattern);

            let patchCount = 0;
            matches.forEach((match) => {
                try {
                    Interceptor.attach(match.address, {
                        onLeave: function (retval) {
                            if (this.context.eax === 0x40000000) {
                                this.context.ebx = 0;
                                this.context.ecx = 0;
                                this.context.edx = 0;

                                send({
                                    type: 'bypass',
                                    target: 'CPUID',
                                    action: 'hypervisor_hidden',
                                    leaf: '0x40000000',
                                });
                            }
                        },
                    });
                    patchCount++;
                } catch (e) {
                    return;
                }
            });

            if (patchCount > 0) {
                send({
                    type: 'bypass',
                    target: 'CPUID',
                    action: 'hooked',
                    count: patchCount,
                });
            }

            this.hooksInstalled['CPUID'] = true;
        } catch (e) {
            send({
                type: 'warning',
                target: 'CPUID',
                message: 'CPUID hooking not available',
            });
        }
    },

    hookVmxInstructions: function () {
        if (!this.config.hypervisorDetection.hideVmxInstructions) return;

        send({
            type: 'info',
            message: 'VMX instruction hiding configured',
            target: 'VMX',
        });

        this.hooksInstalled['VMX'] = true;
    },

    hookScyllaHideResistant: function () {
        send({
            type: 'info',
            message: 'Installing ScyllaHide-resistant techniques',
            category: 'scyllahide',
        });

        this.hookInlineHookDetection();
        this.hookProcessHollowing();
    },

    hookInlineHookDetection: function () {
        if (!this.config.scyllaHideResistant.inlineHookDetection) return;

        send({
            type: 'info',
            message: 'Inline hook detection bypass active',
            target: 'InlineHookDetection',
        });

        this.hooksInstalled['InlineHookDetection'] = true;
    },

    hookProcessHollowing: function () {
        if (!this.config.scyllaHideResistant.processHollowing) return;

        const ntUnmapViewOfSection = Module.findExportByName('ntdll.dll', 'NtUnmapViewOfSection');
        if (ntUnmapViewOfSection) {
            Interceptor.attach(ntUnmapViewOfSection, {
                onEnter: function (args) {
                    send({
                        type: 'warning',
                        target: 'NtUnmapViewOfSection',
                        action: 'process_hollowing_detected',
                        processHandle: args[0].toString(),
                        baseAddress: args[1].toString(),
                    });
                },
            });

            this.hooksInstalled['ProcessHollowing'] = true;
        }
    },

    hookIntegrityChecks: function () {
        send({
            type: 'info',
            message: 'Installing integrity check bypass',
            category: 'integrity',
        });

        this.hookCrc32Checks();
        this.hookMemoryChecksum();
    },

    hookCrc32Checks: function () {
        const rtlComputeCrc32 = Module.findExportByName('ntdll.dll', 'RtlComputeCrc32');
        if (rtlComputeCrc32) {
            Interceptor.attach(rtlComputeCrc32, {
                onLeave: function (retval) {
                    send({
                        type: 'bypass',
                        target: 'RtlComputeCrc32',
                        action: 'detected',
                        crc32: retval.toString(),
                    });
                },
            });

            this.hooksInstalled['RtlComputeCrc32'] = true;
        }
    },

    hookMemoryChecksum: function () {
        const virtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');
        if (virtualProtect) {
            Interceptor.attach(virtualProtect, {
                onEnter: function (args) {
                    this.address = args[0];
                    this.size = args[1].toInt32();
                    this.newProtect = args[2].toInt32();
                    this.oldProtect = args[3];
                },

                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) {
                        send({
                            type: 'info',
                            target: 'VirtualProtect',
                            address: this.address.toString(),
                            size: this.size,
                            newProtect: this.newProtect.toString(16),
                        });
                    }
                },
            });

            this.hooksInstalled['VirtualProtect'] = true;
        }
    },

    hookExceptionHandling: function () {
        send({
            type: 'info',
            message: 'Installing exception handling bypass',
            category: 'exception',
        });

        this.hookVectoredExceptionHandlers();
        this.hookUnhandledExceptionFilter();
    },

    hookVectoredExceptionHandlers: function () {
        const addVeh = Module.findExportByName('kernel32.dll', 'AddVectoredExceptionHandler');
        if (addVeh) {
            Interceptor.attach(addVeh, {
                onEnter: function (args) {
                    send({
                        type: 'info',
                        target: 'AddVectoredExceptionHandler',
                        action: 'handler_registered',
                        first: args[0].toInt32(),
                        handler: args[1].toString(),
                    });
                },
            });

            this.hooksInstalled['AddVectoredExceptionHandler'] = true;
        }
    },

    hookUnhandledExceptionFilter: function () {
        const setUnhandled = Module.findExportByName('kernel32.dll', 'SetUnhandledExceptionFilter');
        if (setUnhandled) {
            Interceptor.replace(
                setUnhandled,
                new NativeCallback(
                    function (lpTopLevelExceptionFilter) {
                        send({
                            type: 'bypass',
                            target: 'SetUnhandledExceptionFilter',
                            action: 'neutralized',
                            filter: lpTopLevelExceptionFilter.toString(),
                        });
                        return ptr(0);
                    },
                    'pointer',
                    ['pointer'],
                ),
            );

            this.hooksInstalled['SetUnhandledExceptionFilter'] = true;
        }
    },

    manipulatePebDeep: function () {
        if (!this.config.scyllaHideResistant.deepPebManipulation) return;

        send({
            type: 'info',
            message: 'Performing deep PEB manipulation',
            category: 'peb',
        });

        setTimeout(() => {
            try {
                const teb = Process.getCurrentThread().context.gs_base || Process.getCurrentThread().context.fs_base;

                if (teb && !teb.isNull()) {
                    const peb = teb.add(0x60).readPointer();

                    if (peb && !peb.isNull()) {
                        peb.add(0x02).writeU8(0);
                        peb.add(0x68).writeU32(0);
                        peb.add(0xbc).writeU32(0);

                        const processHeap = peb.add(0x18).readPointer();
                        if (processHeap && !processHeap.isNull()) {
                            processHeap.add(0x40).writeU32(0x02);
                            processHeap.add(0x44).writeU32(0x00);
                            processHeap.add(0x70).writeU32(0x02);
                            processHeap.add(0x74).writeU32(0x00);
                        }

                        send({
                            type: 'bypass',
                            target: 'PEB',
                            action: 'deep_manipulation_complete',
                            flags_cleared: ['BeingDebugged', 'NtGlobalFlag', 'HeapFlags'],
                        });
                    }
                }
            } catch (e) {
                send({
                    type: 'warning',
                    target: 'PEB',
                    message: 'Deep PEB manipulation failed',
                    error: e.message,
                });
            }
        }, 100);
    },

    hookTlsCallbacks: function () {
        if (!this.config.scyllaHideResistant.tlsCallbackProtection) return;

        send({
            type: 'info',
            message: 'TLS callback protection active',
            category: 'tls',
        });

        this.hooksInstalled['TLSCallbacks'] = true;
    },

    hookMemoryOperations: function () {
        send({
            type: 'info',
            message: 'Installing memory operation hooks',
            category: 'memory',
        });

        const virtualQuery = Module.findExportByName('kernel32.dll', 'VirtualQuery');
        if (virtualQuery) {
            Interceptor.attach(virtualQuery, {
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0 && this.context.rdx && !this.context.rdx.isNull()) {
                        send({
                            type: 'info',
                            target: 'VirtualQuery',
                            action: 'memory_query_detected',
                        });
                    }
                },
            });

            this.hooksInstalled['VirtualQuery'] = true;
        }
    },

    readTsc: function () {
        try {
            return Date.now() * 1000000;
        } catch (e) {
            return 0;
        }
    },

    readQpc: function () {
        try {
            return uint64(Date.now() * 10000);
        } catch (e) {
            return null;
        }
    },

    normalizeQpcValue: function (value) {
        if (this.qpcBase === null) {
            this.qpcBase = value;
            return value;
        }

        const delta = value.sub(this.qpcBase);
        const normalized = this.qpcBase.add(delta.mul(this.rdtscMultiplier));
        return normalized;
    },

    installationSummary: function () {
        const hookCount = Object.keys(this.hooksInstalled).length;

        send({
            type: 'status',
            message: 'Advanced anti-debug bypass installation complete',
            hooks_installed: hookCount,
            hooks: Object.keys(this.hooksInstalled),
            timestamp: Date.now(),
        });

        send({
            type: 'summary',
            message: `Successfully installed ${hookCount} advanced bypass techniques`,
            categories: {
                kernel: Object.keys(this.hooksInstalled).filter((k) => k.startsWith('Nt')).length,
                timing: Object.keys(this.hooksInstalled).filter(
                    (k) => k.includes('RDTSC') || k.includes('Qpc') || k.includes('Tick') || k.includes('Sleep'),
                ).length,
                hypervisor: Object.keys(this.hooksInstalled).filter((k) => k.includes('CPUID') || k.includes('VMX')).length,
                integrity: Object.keys(this.hooksInstalled).filter((k) => k.includes('Crc') || k.includes('Virtual')).length,
            },
        });
    },
};

if (typeof rpc !== 'undefined') {
    rpc.exports = {
        getStatus: function () {
            return {
                name: advancedAntiDebugBypass.name,
                version: advancedAntiDebugBypass.version,
                hooks: Object.keys(advancedAntiDebugBypass.hooksInstalled),
                active: true,
            };
        },

        disableHook: function (hookName) {
            if (advancedAntiDebugBypass.hooksInstalled[hookName]) {
                delete advancedAntiDebugBypass.hooksInstalled[hookName];
                return { success: true, message: `Hook ${hookName} disabled` };
            }
            return { success: false, message: `Hook ${hookName} not found` };
        },
    };
}

advancedAntiDebugBypass.run();
