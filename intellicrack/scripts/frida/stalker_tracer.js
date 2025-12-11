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

send({
    type: 'status',
    message: 'Initializing Frida Stalker - Dynamic Code Tracing Engine',
    category: 'stalker_tracer',
});

const config = {
    traceInstructions: true,
    traceAPICalls: true,
    collectCoverage: true,
    filterByModule: null,
    filterByFunction: null,
    maxTraceEvents: 1000000,
    excludeModules: ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll'],
    focusOnLicensing: true,
};

const stats = {
    totalInstructions: 0,
    uniqueBlocks: new Set(),
    apiCalls: new Map(),
    modules: new Map(),
    traces: [],
    coverage: new Map(),
    licensingRoutines: [],
};

const licenseKeywords = [
    'license',
    'serial',
    'key',
    'activation',
    'register',
    'trial',
    'validate',
    'check',
    'verify',
    'auth',
    'crack',
    'protect',
];

function isLicensingRelated(name) {
    if (!name) {
        return false;
    }
    const lower = name.toLowerCase();
    return licenseKeywords.some(keyword => lower.includes(keyword));
}

function formatAddress(addr) {
    return ptr(addr).toString();
}

function getModuleInfo(address) {
    const module = Process.findModuleByAddress(address);
    if (module) {
        const offset = address.sub(module.base);
        return {
            name: module.name,
            base: formatAddress(module.base),
            offset: formatAddress(offset),
            path: module.path,
        };
    }
    return null;
}

function shouldExcludeModule(moduleName) {
    if (!moduleName) {
        return false;
    }
    return config.excludeModules.some(excluded =>
        moduleName.toLowerCase().includes(excluded.toLowerCase())
    );
}

const apiHooks = new Map();

function setupAPIMonitoring() {
    const criticalAPIs = [
        { module: 'advapi32.dll', name: 'RegOpenKeyExW' },
        { module: 'advapi32.dll', name: 'RegQueryValueExW' },
        { module: 'advapi32.dll', name: 'RegSetValueExW' },
        { module: 'kernel32.dll', name: 'CreateFileW' },
        { module: 'kernel32.dll', name: 'ReadFile' },
        { module: 'kernel32.dll', name: 'WriteFile' },
        { module: 'kernel32.dll', name: 'GetVolumeInformationW' },
        { module: 'iphlpapi.dll', name: 'GetAdaptersInfo' },
        { module: 'crypt32.dll', name: 'CryptDecrypt' },
        { module: 'crypt32.dll', name: 'CryptEncrypt' },
        { module: 'bcrypt.dll', name: 'BCryptDecrypt' },
        { module: 'bcrypt.dll', name: 'BCryptEncrypt' },
        { module: 'wininet.dll', name: 'InternetOpenW' },
        { module: 'wininet.dll', name: 'HttpSendRequestW' },
        { module: 'ws2_32.dll', name: 'connect' },
        { module: 'ws2_32.dll', name: 'send' },
        { module: 'ws2_32.dll', name: 'recv' },
    ];

    criticalAPIs.forEach(api => {
        const addr = Module.findExportByName(api.module, api.name);
        if (addr) {
            try {
                Interceptor.attach(addr, {
                    onEnter: function (_args) {
                        const tid = Process.getCurrentThreadId();
                        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(formatAddress)
                            .slice(0, 10);

                        const callInfo = {
                            api: `${api.module}!${api.name}`,
                            tid: tid,
                            timestamp: Date.now(),
                            backtrace: backtrace,
                        };

                        if (!stats.apiCalls.has(api.name)) {
                            stats.apiCalls.set(api.name, []);
                        }
                        stats.apiCalls.get(api.name).push(callInfo);

                        send({
                            type: 'api_call',
                            data: callInfo,
                            licensing: isLicensingRelated(api.name),
                        });
                    },
                });
                apiHooks.set(api.name, addr);
            } catch (e) {
                send({
                    type: 'error',
                    message: `Failed to hook ${api.module}!${api.name}: ${e.message}`,
                });
            }
        }
    });

    send({
        type: 'status',
        message: `API monitoring configured - ${apiHooks.size} hooks installed`,
        category: 'api_monitor',
    });
}

function createStalkerTransformer() {
    return {
        events: {
            call: true,
            ret: false,
            exec: false,
            block: true,
            compile: false,
        },
        onReceive: events => {
            const parsed = Stalker.parse(events, {
                annotate: true,
                stringify: false,
            });

            parsed.forEach(event => {
                if (event[0] === 'call') {
                    const [, target] = event;
                    const moduleInfo = getModuleInfo(target);

                    if (moduleInfo && !shouldExcludeModule(moduleInfo.name)) {
                        stats.totalInstructions++;

                        const key = `${moduleInfo.name}:${moduleInfo.offset}`;
                        if (!stats.coverage.has(key)) {
                            stats.coverage.set(key, {
                                module: moduleInfo.name,
                                offset: moduleInfo.offset,
                                address: formatAddress(target),
                                hitCount: 0,
                                licensing: false,
                            });
                        }

                        const coverageEntry = stats.coverage.get(key);
                        coverageEntry.hitCount++;

                        if (isLicensingRelated(moduleInfo.name)) {
                            coverageEntry.licensing = true;
                            if (!stats.licensingRoutines.includes(key)) {
                                stats.licensingRoutines.push(key);
                            }
                        }
                    }
                } else if (event[0] === 'block') {
                    const [, blockStart] = event;
                    const blockId = formatAddress(blockStart);
                    stats.uniqueBlocks.add(blockId);
                }
            });

            if (stats.totalInstructions % 10000 === 0) {
                send({
                    type: 'progress',
                    instructions: stats.totalInstructions,
                    blocks: stats.uniqueBlocks.size,
                    coverage_entries: stats.coverage.size,
                    licensing_routines: stats.licensingRoutines.length,
                });
            }
        },
    };
}

function startStalking(_targetFunction) {
    send({
        type: 'status',
        message: 'Starting Stalker on current thread',
        category: 'stalker',
    });

    const transformer = createStalkerTransformer();

    Stalker.follow(Process.getCurrentThreadId(), {
        events: transformer.events,
        onReceive: transformer.onReceive,
    });

    send({
        type: 'status',
        message: 'Stalker active - collecting execution traces',
        category: 'stalker',
    });
}

function stopStalking() {
    Stalker.unfollow(Process.getCurrentThreadId());
    Stalker.flush();

    send({
        type: 'status',
        message: 'Stalker stopped - processing results',
        category: 'stalker',
    });

    const coverageData = Array.from(stats.coverage.entries()).map(([key, data]) => ({
        key: key,
        ...data,
    }));

    const apiCallData = Array.from(stats.apiCalls.entries()).map(([name, calls]) => ({
        api: name,
        count: calls.length,
        calls: calls.slice(0, 100),
    }));

    send({
        type: 'trace_complete',
        data: {
            total_instructions: stats.totalInstructions,
            unique_blocks: stats.uniqueBlocks.size,
            coverage_entries: coverageData.length,
            licensing_routines: stats.licensingRoutines.length,
            api_calls: apiCallData.length,
            coverage: coverageData.sort((a, b) => b.hitCount - a.hitCount).slice(0, 500),
            api_summary: apiCallData.sort((a, b) => b.count - a.count),
            licensing_functions: stats.licensingRoutines.slice(0, 100),
        },
    });
}

function traceFunction(moduleName, functionName) {
    const module = Process.getModuleByName(moduleName);
    if (!module) {
        send({
            type: 'error',
            message: `Module ${moduleName} not found`,
        });
        return;
    }

    const exports = module.enumerateExports();
    const targetExport = exports.find(exp => exp.name === functionName);

    if (!targetExport) {
        send({
            type: 'error',
            message: `Function ${functionName} not found in ${moduleName}`,
        });
        return;
    }

    send({
        type: 'status',
        message: `Tracing function ${moduleName}!${functionName} at ${formatAddress(targetExport.address)}`,
        category: 'function_trace',
    });

    const traceData = [];
    let callDepth = 0;
    const maxDepth = 20;

    Interceptor.attach(targetExport.address, {
        onEnter: function (_args) {
            callDepth++;
            if (callDepth > maxDepth) {
                return;
            }

            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => {
                    const info = getModuleInfo(addr);
                    return info ? `${info.name}+${info.offset}` : formatAddress(addr);
                })
                .slice(0, 10);

            const entry = {
                type: 'enter',
                function: `${moduleName}!${functionName}`,
                address: formatAddress(targetExport.address),
                depth: callDepth,
                thread: Process.getCurrentThreadId(),
                timestamp: Date.now(),
                backtrace: backtrace,
            };

            traceData.push(entry);

            Stalker.follow(Process.getCurrentThreadId(), {
                events: {
                    call: true,
                    ret: true,
                },
                onReceive: events => {
                    const parsed = Stalker.parse(events);
                    parsed.forEach(event => {
                        if (traceData.length < 10000) {
                            const moduleInfo = getModuleInfo(event[1]);
                            traceData.push({
                                type: event[0],
                                address: formatAddress(event[1]),
                                module: moduleInfo ? moduleInfo.name : 'unknown',
                                offset: moduleInfo ? moduleInfo.offset : '0x0',
                            });
                        }
                    });
                },
            });
        },
        onLeave: retval => {
            if (callDepth <= maxDepth) {
                traceData.push({
                    type: 'leave',
                    function: `${moduleName}!${functionName}`,
                    return_value: formatAddress(retval),
                    depth: callDepth,
                    timestamp: Date.now(),
                });

                Stalker.unfollow(Process.getCurrentThreadId());
                Stalker.flush();

                send({
                    type: 'function_trace_complete',
                    function: `${moduleName}!${functionName}`,
                    trace_length: traceData.length,
                    trace: traceData.slice(0, 1000),
                });
            }
            callDepth--;
        },
    });
}

function collectModuleCoverage(moduleName) {
    const module = Process.getModuleByName(moduleName);
    if (!module) {
        send({
            type: 'error',
            message: `Module ${moduleName} not found`,
        });
        return;
    }

    send({
        type: 'status',
        message: `Collecting coverage for module ${moduleName}`,
        category: 'module_coverage',
    });

    const moduleBase = module.base;
    const moduleSize = module.size;
    const blocksCovered = new Set();

    Stalker.follow(Process.getCurrentThreadId(), {
        events: {
            call: false,
            ret: false,
            exec: true,
            block: true,
        },
        transform: iterator => {
            let instruction = iterator.next();
            while (instruction !== null) {
                const addr = instruction.address;

                if (addr.compare(moduleBase) >= 0 && addr.compare(moduleBase.add(moduleSize)) < 0) {
                    const offset = addr.sub(moduleBase);
                    blocksCovered.add(formatAddress(offset));

                    iterator.putCallout(() => {
                        stats.totalInstructions++;
                    });
                }

                iterator.keep();
                instruction = iterator.next();
            }
        },
    });

    setTimeout(() => {
        Stalker.unfollow(Process.getCurrentThreadId());
        Stalker.flush();

        send({
            type: 'module_coverage_complete',
            module: moduleName,
            base: formatAddress(moduleBase),
            size: moduleSize,
            blocks_covered: blocksCovered.size,
            coverage_percentage: (blocksCovered.size / (moduleSize / 16)) * 100,
            blocks: Array.from(blocksCovered).slice(0, 1000),
        });
    }, 5000);
}

function analyzeLicensingFlow() {
    send({
        type: 'status',
        message: 'Analyzing licensing validation flow',
        category: 'licensing_analysis',
    });

    const licensingAPIs = [
        { module: 'advapi32.dll', name: 'RegOpenKeyExW' },
        { module: 'advapi32.dll', name: 'RegQueryValueExW' },
        { module: 'crypt32.dll', name: 'CryptDecrypt' },
        { module: 'bcrypt.dll', name: 'BCryptDecrypt' },
    ];

    const licensingEvents = [];
    const hooks = [];

    licensingAPIs.forEach(api => {
        const addr = Module.findExportByName(api.module, api.name);
        if (addr) {
            const hook = Interceptor.attach(addr, {
                onEnter: function (_args) {
                    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    const callers = backtrace
                        .map(addr => {
                            const info = getModuleInfo(addr);
                            return info
                                ? {
                                      module: info.name,
                                      offset: info.offset,
                                      address: formatAddress(addr),
                                  }
                                : null;
                        })
                        .filter(x => x !== null);

                    const licensingCaller = callers.find(c => isLicensingRelated(c.module));

                    if (licensingCaller) {
                        licensingEvents.push({
                            api: `${api.module}!${api.name}`,
                            timestamp: Date.now(),
                            thread: Process.getCurrentThreadId(),
                            caller: licensingCaller,
                            backtrace: callers.slice(0, 5),
                        });

                        send({
                            type: 'licensing_event',
                            data: licensingEvents[licensingEvents.length - 1],
                        });
                    }
                },
            });
            hooks.push(hook);
        }
    });

    send({
        type: 'status',
        message: `Licensing flow analysis active - ${hooks.length} hooks installed`,
        category: 'licensing_analysis',
    });
}

rpc.exports = {
    startStalking: startStalking,
    stopStalking: stopStalking,
    traceFunction: traceFunction,
    collectModuleCoverage: collectModuleCoverage,
    analyzeLicensingFlow: analyzeLicensingFlow,
    getStats: () => ({
        totalInstructions: stats.totalInstructions,
        uniqueBlocks: stats.uniqueBlocks.size,
        coverageEntries: stats.coverage.size,
        licensingRoutines: stats.licensingRoutines.length,
        apiCalls: stats.apiCalls.size,
    }),
    setConfig: newConfig => {
        Object.assign(config, newConfig);
        send({
            type: 'status',
            message: 'Configuration updated',
            config: config,
        });
    },
};

setupAPIMonitoring();
analyzeLicensingFlow();

send({
    type: 'ready',
    message: 'Stalker tracer initialized and ready',
    capabilities: [
        'instruction_tracing',
        'api_monitoring',
        'code_coverage',
        'function_tracing',
        'module_coverage',
        'licensing_flow_analysis',
    ],
});
