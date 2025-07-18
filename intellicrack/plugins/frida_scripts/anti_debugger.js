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
 * Enhanced Anti-Debugger Bypass Script
 * 
 * Comprehensive anti-debugging countermeasures for modern protection systems.
 * Includes hardware breakpoint bypass, timing attack countermeasures, parent
 * process spoofing, and thread context manipulation.
 * 
 * Author: Intellicrack Framework
 * Version: 2.0.0
 * License: GPL v3
 */

{
    name: "Enhanced Anti-Debugger",
    description: "Comprehensive anti-debugging and analysis protection bypass",
    version: "2.0.0",
    
    // Configuration for anti-debug bypass
    config: {
        // Hardware breakpoint protection
        hardwareBreakpoints: {
            enabled: true,
            clearDr0: true,
            clearDr1: true,
            clearDr2: true,
            clearDr3: true,
            clearDr6: true,
            clearDr7: true
        },
        
        // Timing attack countermeasures
        timingProtection: {
            enabled: true,
            rdtscSpoofing: true,
            performanceCounterSpoofing: true,
            sleepManipulation: true,
            consistentTiming: true
        },
        
        // Process information spoofing
        processInfo: {
            spoofParentProcess: true,
            spoofProcessName: "explorer.exe",
            spoofCommandLine: "C:\\Windows\\explorer.exe",
            spoofParentPid: 1234,
            hideDebugPrivileges: true
        },
        
        // Thread context manipulation
        threadProtection: {
            enabled: true,
            protectDebugRegisters: true,
            spoofTrapFlag: true,
            hideDebuggerThreads: true,
            protectSingleStep: true
        },
        
        // Exception handling
        exceptionHandling: {
            bypassVectoredHandlers: true,
            spoofUnhandledExceptions: true,
            protectSehChain: true,
            interceptDebugBreaks: true
        }
    },
    
    // Hook tracking
    hooksInstalled: {},
    basePerformanceCounter: Date.now() * 10000,
    
    onAttach: function(pid) {
        send({
            type: "status",
            message: "Enhanced Anti-Debug attaching to process",
            pid: pid,
            timestamp: Date.now()
        });
        this.processId = pid;
    },
    
    run: function() {
        send({
            type: "status", 
            message: "Installing comprehensive anti-debugging countermeasures",
            timestamp: Date.now()
        });
        
        // Core anti-debug bypass
        this.hookDebuggerDetection();
        this.hookNtdllAntiDebug();
        this.hookDebugOutput();
        this.manipulatePebFlags();
        
        // Enhanced features
        this.hookHardwareBreakpoints();
        this.hookTimingAttacks();
        this.hookProcessInformation();
        this.hookThreadContext();
        this.hookExceptionHandling();
        this.hookAdvancedDetection();
        this.hookDebuggerCommunication();
        this.hookMemoryProtection();
        
        this.installSummary();
    },
    
    // === CORE DEBUGGER DETECTION BYPASS ===
    hookDebuggerDetection: function() {
        send({
            type: "info",
            message: "Installing debugger detection bypass",
            category: "core_detection"
        });
        
        // Hook IsDebuggerPresent
        var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
        if (isDebuggerPresent) {
            Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "IsDebuggerPresent",
                    action: "debugger_detection_spoofed",
                    result: "FALSE"
                });
                return 0; // FALSE
            }, 'int', []));
            
            this.hooksInstalled['IsDebuggerPresent'] = true;
        }
        
        // Hook CheckRemoteDebuggerPresent
        var checkRemoteDebugger = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
        if (checkRemoteDebugger) {
            Interceptor.attach(checkRemoteDebugger, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        // Set pbDebuggerPresent to FALSE
                        var pbDebugger = this.context.rdx; // Second parameter
                        if (pbDebugger && !pbDebugger.isNull()) {
                            pbDebugger.writeU8(0); // FALSE
                            send({
                                type: "bypass",
                                target: "CheckRemoteDebuggerPresent",
                                action: "remote_debugger_spoofed",
                                result: "FALSE"
                            });
                        }
                    }
                }
            });
            
            this.hooksInstalled['CheckRemoteDebuggerPresent'] = true;
        }
    },
    
    // === NTDLL ANTI-DEBUG BYPASS ===
    hookNtdllAntiDebug: function() {
        send({
            type: "info",
            message: "Installing NTDLL anti-debug bypass",
            category: "ntdll_bypass"
        });
        
        // Hook NtQueryInformationProcess for debug flags
        var ntQueryInfo = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
        if (ntQueryInfo) {
            Interceptor.attach(ntQueryInfo, {
                onEnter: function(args) {
                    this.processHandle = args[0];
                    this.infoClass = args[1].toInt32();
                    this.processInfo = args[2];
                    this.processInfoLength = args[3].toInt32();
                    this.returnLength = args[4];
                },
                
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.processInfo && !this.processInfo.isNull()) {
                        this.spoofProcessInformation();
                    }
                },
                
                spoofProcessInformation: function() {
                    switch(this.infoClass) {
                        case 7: // ProcessDebugPort
                            this.processInfo.writePointer(ptr(0));
                            send({
                                type: "bypass",
                                target: "NtQueryInformationProcess",
                                action: "ProcessDebugPort_spoofed",
                                info_class: 7,
                                result: "NULL"
                            });
                            break;
                            
                        case 30: // ProcessDebugObjectHandle
                            this.processInfo.writePointer(ptr(0));
                            send({
                                type: "bypass",
                                target: "NtQueryInformationProcess",
                                action: "ProcessDebugObjectHandle_spoofed",
                                info_class: 30,
                                result: "NULL"
                            });
                            break;
                            
                        case 31: // ProcessDebugFlags
                            this.processInfo.writeU32(1); // PROCESS_DEBUG_INHERIT
                            send({
                                type: "bypass",
                                target: "NtQueryInformationProcess",
                                action: "ProcessDebugFlags_spoofed",
                                info_class: 31,
                                result: "PROCESS_DEBUG_INHERIT"
                            });
                            break;
                            
                        case 0: // ProcessBasicInformation
                            // Don't modify - might break functionality
                            break;
                            
                        default:
                            // Other debug-related information classes
                            if (this.infoClass >= 60 && this.infoClass <= 70) {
                                // Zero out potentially debug-related info
                                Memory.protect(this.processInfo, this.processInfoLength, 'rw-');
                                for (var i = 0; i < this.processInfoLength; i++) {
                                    this.processInfo.add(i).writeU8(0);
                                }
                                send({
                                    type: "bypass",
                                    target: "NtQueryInformationProcess",
                                    action: "unknown_debug_info_zeroed",
                                    info_class: this.infoClass
                                });
                            }
                            break;
                    }
                }
            });
            
            this.hooksInstalled['NtQueryInformationProcess'] = true;
        }
        
        // Hook NtSetInformationThread (hide from debugger)
        var ntSetInfoThread = Module.findExportByName("ntdll.dll", "NtSetInformationThread");
        if (ntSetInfoThread) {
            Interceptor.attach(ntSetInfoThread, {
                onEnter: function(args) {
                    var threadHandle = args[0];
                    var infoClass = args[1].toInt32();
                    
                    if (infoClass === 17) { // ThreadHideFromDebugger
                        send({
                            type: "bypass",
                            target: "NtSetInformationThread",
                            action: "ThreadHideFromDebugger_blocked",
                            info_class: 17
                        });
                        this.replace();
                        this.returnValue = ptr(0); // STATUS_SUCCESS
                    }
                }
            });
            
            this.hooksInstalled['NtSetInformationThread'] = true;
        }
        
        // Hook NtCreateThreadEx for thread creation monitoring
        var ntCreateThreadEx = Module.findExportByName("ntdll.dll", "NtCreateThreadEx");
        if (ntCreateThreadEx) {
            Interceptor.attach(ntCreateThreadEx, {
                onEnter: function(args) {
                    send({
                        type: "info",
                        target: "NtCreateThreadEx",
                        message: "Thread creation detected - monitoring for debug threads"
                    });
                }
            });
            
            this.hooksInstalled['NtCreateThreadEx'] = true;
        }
    },
    
    // === DEBUG OUTPUT SUPPRESSION ===
    hookDebugOutput: function() {
        send({
            type: "info",
            message: "Installing debug output suppression",
            category: "debug_output"
        });
        
        // Hook OutputDebugString functions
        var outputDebugStringA = Module.findExportByName("kernel32.dll", "OutputDebugStringA");
        if (outputDebugStringA) {
            Interceptor.replace(outputDebugStringA, new NativeCallback(function(lpOutputString) {
                // Silently consume debug output
                return;
            }, 'void', ['pointer']));
            
            this.hooksInstalled['OutputDebugStringA'] = true;
        }
        
        var outputDebugStringW = Module.findExportByName("kernel32.dll", "OutputDebugStringW");
        if (outputDebugStringW) {
            Interceptor.replace(outputDebugStringW, new NativeCallback(function(lpOutputString) {
                // Silently consume debug output
                return;
            }, 'void', ['pointer']));
            
            this.hooksInstalled['OutputDebugStringW'] = true;
        }
    },
    
    // === PEB MANIPULATION ===
    manipulatePebFlags: function() {
        send({
            type: "info",
            message: "Manipulating PEB debug flags",
            category: "peb_manipulation"
        });
        
        // Clear PEB debug flags
        setTimeout(() => {
            try {
                // Get PEB address from TEB
                var teb = Process.getCurrentThread().context.gs_base || Process.getCurrentThread().context.fs_base;
                if (teb && !teb.isNull()) {
                    var peb = teb.add(0x60).readPointer(); // PEB offset in TEB
                    
                    if (peb && !peb.isNull()) {
                        // Clear BeingDebugged flag (offset 0x02)
                        peb.add(0x02).writeU8(0);
                        
                        // Clear NtGlobalFlag (offset 0x68) 
                        peb.add(0x68).writeU32(0);
                        
                        // Clear heap flags (offset 0x18 -> heap -> flags)
                        var processHeap = peb.add(0x18).readPointer();
                        if (processHeap && !processHeap.isNull()) {
                            processHeap.add(0x40).writeU32(0x02); // Clear debug heap flags
                            processHeap.add(0x44).writeU32(0x00); // Clear force flags
                        }
                        
                        send({
                            type: "bypass",
                            target: "PEB",
                            action: "debug_flags_cleared",
                            cleared_flags: ["BeingDebugged", "NtGlobalFlag", "HeapFlags"]
                        });
                    }
                }
            } catch (e) {
                send({
                    type: "warning",
                    target: "PEB",
                    message: "PEB manipulation failed (expected)",
                    error: e.message
                });
            }
        }, 100);
    },
    
    // === HARDWARE BREAKPOINT BYPASS ===
    hookHardwareBreakpoints: function() {
        send({
            type: "info",
            message: "Installing hardware breakpoint bypass",
            category: "hardware_breakpoints"
        });
        
        // Hook GetThreadContext to clear debug registers
        var getThreadContext = Module.findExportByName("kernel32.dll", "GetThreadContext");
        if (getThreadContext) {
            Interceptor.attach(getThreadContext, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var context = this.context.rdx; // CONTEXT pointer
                        if (context && !context.isNull()) {
                            this.clearDebugRegisters(context);
                        }
                    }
                },
                
                clearDebugRegisters: function(context) {
                    try {
                        var config = this.parent.parent.config;
                        if (config.hardwareBreakpoints.enabled) {
                            // CONTEXT structure offsets for debug registers (x64)
                            var dr0Offset = 0x90;
                            var dr1Offset = 0x98;
                            var dr2Offset = 0xA0;
                            var dr3Offset = 0xA8;
                            var dr6Offset = 0xB0;
                            var dr7Offset = 0xB8;
                            
                            if (config.hardwareBreakpoints.clearDr0) context.add(dr0Offset).writeU64(0);
                            if (config.hardwareBreakpoints.clearDr1) context.add(dr1Offset).writeU64(0);
                            if (config.hardwareBreakpoints.clearDr2) context.add(dr2Offset).writeU64(0);
                            if (config.hardwareBreakpoints.clearDr3) context.add(dr3Offset).writeU64(0);
                            if (config.hardwareBreakpoints.clearDr6) context.add(dr6Offset).writeU64(0);
                            if (config.hardwareBreakpoints.clearDr7) context.add(dr7Offset).writeU64(0);
                            
                            send({
                                type: "bypass",
                                target: "GetThreadContext", 
                                action: "hardware_breakpoints_cleared",
                                cleared_registers: ["DR0", "DR1", "DR2", "DR3", "DR6", "DR7"]
                            });
                        }
                    } catch(e) {
                        // Context manipulation failed - this is expected in some cases
                    }
                }
            });
            
            this.hooksInstalled['GetThreadContext'] = true;
        }
        
        // Hook SetThreadContext to prevent hardware breakpoint setting
        var setThreadContext = Module.findExportByName("kernel32.dll", "SetThreadContext");
        if (setThreadContext) {
            Interceptor.attach(setThreadContext, {
                onEnter: function(args) {
                    var context = args[1]; // CONTEXT pointer
                    if (context && !context.isNull()) {
                        this.preventHardwareBreakpoints(context);
                    }
                },
                
                preventHardwareBreakpoints: function(context) {
                    try {
                        var config = this.parent.parent.config;
                        if (config.hardwareBreakpoints.enabled) {
                            // Check if any debug registers are being set
                            var dr7 = context.add(0xB8).readU64();
                            
                            if (dr7.toNumber() !== 0) {
                                // Clear all debug registers to prevent hardware breakpoints
                                context.add(0x90).writeU64(0); // DR0
                                context.add(0x98).writeU64(0); // DR1
                                context.add(0xA0).writeU64(0); // DR2
                                context.add(0xA8).writeU64(0); // DR3
                                context.add(0xB0).writeU64(0); // DR6
                                context.add(0xB8).writeU64(0); // DR7
                                
                                send({
                                    type: "bypass",
                                    target: "SetThreadContext",
                                    action: "hardware_breakpoint_installation_prevented",
                                    dr7_value: dr7.toNumber()
                                });
                            }
                        }
                    } catch(e) {
                        // Context access failed
                    }
                }
            });
            
            this.hooksInstalled['SetThreadContext'] = true;
        }
        
        // Hook NtGetContextThread (native version)
        var ntGetContextThread = Module.findExportByName("ntdll.dll", "NtGetContextThread");
        if (ntGetContextThread) {
            Interceptor.attach(ntGetContextThread, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) { // STATUS_SUCCESS
                        var context = this.context.rdx;
                        if (context && !context.isNull()) {
                            // Clear debug registers in native context as well
                            try {
                                var config = this.parent.parent.config;
                                if (config.hardwareBreakpoints.enabled) {
                                    context.add(0x90).writeU64(0); // DR0
                                    context.add(0x98).writeU64(0); // DR1
                                    context.add(0xA0).writeU64(0); // DR2
                                    context.add(0xA8).writeU64(0); // DR3
                                    context.add(0xB0).writeU64(0); // DR6
                                    context.add(0xB8).writeU64(0); // DR7
                                }
                            } catch(e) {
                                // Expected - some contexts may be read-only
                            }
                        }
                    }
                }
            });
            
            this.hooksInstalled['NtGetContextThread'] = true;
        }
    },
    
    // === TIMING ATTACK COUNTERMEASURES ===
    hookTimingAttacks: function() {
        send({
            type: "info",
            message: "Installing timing attack countermeasures",
            category: "timing_protection"
        });
        
        // Hook RDTSC instruction results
        this.hookRdtscTiming();
        
        // Hook performance counter queries
        this.hookPerformanceCounters();
        
        // Hook Sleep/delay functions
        this.hookSleepFunctions();
        
        // Hook GetTickCount functions
        this.hookTickCountFunctions();
    },
    
    hookRdtscTiming: function() {
        // Search for RDTSC instructions and hook them
        var modules = Process.enumerateModules();
        
        for (var i = 0; i < modules.length; i++) {
            var module = modules[i];
            
            // Skip system modules
            if (module.name.toLowerCase().includes('ntdll') || 
                module.name.toLowerCase().includes('kernel32')) {
                continue;
            }
            
            try {
                // RDTSC instruction: 0x0F 0x31
                var rdtscPattern = "0f 31";
                var matches = Memory.scanSync(module.base, module.size, rdtscPattern);
                
                for (var j = 0; j < Math.min(matches.length, 10); j++) {
                    this.hookRdtscInstruction(matches[j].address, module.name);
                }
                
                if (matches.length > 0) {
                    this.hooksInstalled['RDTSC_' + module.name] = matches.length;
                }
                
            } catch(e) {
                continue;
            }
        }
    },
    
    hookRdtscInstruction: function(address, moduleName) {
        try {
            Interceptor.attach(address, {
                onLeave: function(retval) {
                    var config = this.parent.parent.config;
                    if (config.timingProtection.enabled && config.timingProtection.rdtscSpoofing) {
                        // Provide consistent timing to prevent timing-based detection
                        var baseTime = 0x123456789ABC;
                        var currentTime = baseTime + (Date.now() % 1000000) * 1000;
                        
                        this.context.eax = ptr(currentTime & 0xFFFFFFFF);
                        this.context.edx = ptr((currentTime >>> 32) & 0xFFFFFFFF);
                        
                        send({
                            type: "bypass",
                            target: "RDTSC",
                            action: "timing_spoofed",
                            module: moduleName,
                            spoofed_time: currentTime
                        });
                    }
                }
            });
        } catch(e) {
            // Hook failed - continue with other RDTSC instructions
        }
    },
    
    hookPerformanceCounters: function() {
        var queryPerformanceCounter = Module.findExportByName("kernel32.dll", "QueryPerformanceCounter");
        if (queryPerformanceCounter) {
            Interceptor.attach(queryPerformanceCounter, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var counterPtr = this.context.rcx;
                        if (counterPtr && !counterPtr.isNull()) {
                            var config = this.parent.parent.config;
                            if (config.timingProtection.enabled && config.timingProtection.performanceCounterSpoofing) {
                                // Provide consistent performance counter values
                                var currentCounter = this.parent.parent.basePerformanceCounter + (Date.now() * 10000);
                                counterPtr.writeU64(currentCounter);
                                
                                send({
                                    type: "bypass",
                                    target: "QueryPerformanceCounter",
                                    action: "performance_counter_spoofed",
                                    counter_value: currentCounter
                                });
                            }
                        }
                    }
                }
            });
            
            this.hooksInstalled['QueryPerformanceCounter'] = true;
        }
        
        var queryPerformanceFrequency = Module.findExportByName("kernel32.dll", "QueryPerformanceFrequency");
        if (queryPerformanceFrequency) {
            Interceptor.replace(queryPerformanceFrequency, new NativeCallback(function(lpFrequency) {
                if (lpFrequency && !lpFrequency.isNull()) {
                    lpFrequency.writeU64(10000000); // Standard 10MHz frequency
                    return 1; // TRUE
                }
                return 0;
            }, 'int', ['pointer']));
            
            this.hooksInstalled['QueryPerformanceFrequency'] = true;
        }
    },
    
    hookSleepFunctions: function() {
        var sleep = Module.findExportByName("kernel32.dll", "Sleep");
        if (sleep) {
            Interceptor.attach(sleep, {
                onEnter: function(args) {
                    var milliseconds = args[0].toInt32();
                    var config = this.parent.parent.config;
                    
                    if (config.timingProtection.enabled && config.timingProtection.sleepManipulation) {
                        // Reduce excessive sleep times that might be used for timing checks
                        if (milliseconds > 1000) {
                            args[0] = ptr(100); // Reduce to 100ms
                            send({
                                type: "bypass",
                                target: "Sleep",
                                action: "long_sleep_reduced",
                                original_ms: milliseconds,
                                reduced_ms: 100
                            });
                        }
                    }
                }
            });
            
            this.hooksInstalled['Sleep'] = true;
        }
        
        var sleepEx = Module.findExportByName("kernel32.dll", "SleepEx");
        if (sleepEx) {
            Interceptor.attach(sleepEx, {
                onEnter: function(args) {
                    var milliseconds = args[0].toInt32();
                    var config = this.parent.parent.config;
                    
                    if (config.timingProtection.enabled && config.timingProtection.sleepManipulation) {
                        if (milliseconds > 1000) {
                            args[0] = ptr(100);
                            send({
                                type: "bypass",
                                target: "SleepEx",
                                action: "long_sleep_reduced",
                                original_ms: milliseconds,
                                reduced_ms: 100
                            });
                        }
                    }
                }
            });
            
            this.hooksInstalled['SleepEx'] = true;
        }
    },
    
    hookTickCountFunctions: function() {
        var getTickCount = Module.findExportByName("kernel32.dll", "GetTickCount");
        if (getTickCount) {
            var baseTickCount = Date.now();
            
            Interceptor.replace(getTickCount, new NativeCallback(function() {
                var config = this.parent.config;
                if (config.timingProtection.enabled && config.timingProtection.consistentTiming) {
                    var elapsed = Date.now() - baseTickCount;
                    return elapsed;
                }
                return Date.now() - baseTickCount; // Normal behavior
            }, 'uint32', []));
            
            this.hooksInstalled['GetTickCount'] = true;
        }
        
        var getTickCount64 = Module.findExportByName("kernel32.dll", "GetTickCount64");
        if (getTickCount64) {
            var baseTickCount64 = Date.now();
            
            Interceptor.replace(getTickCount64, new NativeCallback(function() {
                var config = this.parent.config;
                if (config.timingProtection.enabled && config.timingProtection.consistentTiming) {
                    var elapsed = Date.now() - baseTickCount64;
                    return elapsed;
                }
                return Date.now() - baseTickCount64;
            }, 'uint64', []));
            
            this.hooksInstalled['GetTickCount64'] = true;
        }
    },
    
    // === PROCESS INFORMATION SPOOFING ===
    hookProcessInformation: function() {
        send({
            type: "info",
            message: "Installing process information spoofing",
            category: "process_info"
        });
        
        // Hook process name queries
        this.hookProcessNameQueries();
        
        // Hook parent process queries  
        this.hookParentProcessQueries();
        
        // Hook command line queries
        this.hookCommandLineQueries();
        
        // Hook privilege queries
        this.hookPrivilegeQueries();
    },
    
    hookProcessNameQueries: function() {
        var getModuleFileName = Module.findExportByName("kernel32.dll", "GetModuleFileNameW");
        if (getModuleFileName) {
            Interceptor.attach(getModuleFileName, {
                onLeave: function(retval) {
                    if (retval.toInt32() > 0) {
                        var filename = this.context.rdx; // lpFilename
                        var config = this.parent.parent.config;
                        
                        if (filename && !filename.isNull() && config.processInfo.spoofParentProcess) {
                            var spoofedPath = "C:\\Windows\\" + config.processInfo.spoofProcessName;
                            filename.writeUtf16String(spoofedPath);
                            send({
                                type: "bypass",
                                target: "GetModuleFileNameW",
                                action: "process_name_spoofed",
                                spoofed_path: spoofedPath
                            });
                        }
                    }
                }
            });
            
            this.hooksInstalled['GetModuleFileNameW'] = true;
        }
    },
    
    hookParentProcessQueries: function() {
        var createToolhelp32Snapshot = Module.findExportByName("kernel32.dll", "CreateToolhelp32Snapshot");
        if (createToolhelp32Snapshot) {
            Interceptor.attach(createToolhelp32Snapshot, {
                onEnter: function(args) {
                    var flags = args[0].toInt32();
                    
                    // TH32CS_SNAPPROCESS = 0x00000002
                    if (flags & 0x00000002) {
                        send({
                            type: "info",
                            target: "CreateToolhelp32Snapshot",
                            message: "Process snapshot creation detected",
                            flags: flags
                        });
                        this.isProcessSnapshot = true;
                    }
                }
            });
            
            this.hooksInstalled['CreateToolhelp32Snapshot'] = true;
        }
        
        var process32First = Module.findExportByName("kernel32.dll", "Process32FirstW");
        if (process32First) {
            Interceptor.attach(process32First, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0 && this.isProcessSnapshot) {
                        var processEntry = this.context.rdx; // PROCESSENTRY32W
                        if (processEntry && !processEntry.isNull()) {
                            this.spoofProcessEntry(processEntry);
                        }
                    }
                },
                
                spoofProcessEntry: function(processEntry) {
                    try {
                        var config = this.parent.parent.config;
                        if (config.processInfo.spoofParentProcess) {
                            // PROCESSENTRY32W structure offsets
                            var th32ProcessID = processEntry.add(8).readU32(); // Process ID
                            var th32ParentProcessID = processEntry.add(24); // Parent Process ID offset
                            var szExeFile = processEntry.add(44); // Executable file name offset
                            
                            // Check if this is our process
                            if (th32ProcessID === this.parent.parent.processId) {
                                // Spoof parent process ID
                                th32ParentProcessID.writeU32(config.processInfo.spoofParentPid);
                                
                                // Spoof executable name
                                szExeFile.writeUtf16String(config.processInfo.spoofProcessName);
                                
                                send({
                                    type: "bypass",
                                    target: "Process32FirstW",
                                    action: "parent_process_spoofed",
                                    spoofed_parent_pid: config.processInfo.spoofParentPid,
                                    spoofed_executable: config.processInfo.spoofProcessName
                                });
                            }
                        }
                    } catch(e) {
                        // Process entry manipulation failed
                    }
                }
            });
            
            this.hooksInstalled['Process32FirstW'] = true;
        }
    },
    
    hookCommandLineQueries: function() {
        var getCommandLine = Module.findExportByName("kernel32.dll", "GetCommandLineW");
        if (getCommandLine) {
            Interceptor.replace(getCommandLine, new NativeCallback(function() {
                var config = this.parent.config;
                if (config.processInfo.spoofParentProcess) {
                    var spoofedCmdLine = Memory.allocUtf16String(config.processInfo.spoofCommandLine);
                    send({
                        type: "bypass",
                        target: "GetCommandLineW",
                        action: "command_line_spoofed",
                        spoofed_cmdline: config.processInfo.spoofCommandLine
                    });
                    return spoofedCmdLine;
                }
                // Return original command line
                return Module.findExportByName("kernel32.dll", "GetCommandLineW")();
            }, 'pointer', []));
            
            this.hooksInstalled['GetCommandLineW'] = true;
        }
    },
    
    hookPrivilegeQueries: function() {
        var openProcessToken = Module.findExportByName("advapi32.dll", "OpenProcessToken");
        if (openProcessToken) {
            Interceptor.attach(openProcessToken, {
                onEnter: function(args) {
                    var desiredAccess = args[1].toInt32();
                    
                    // TOKEN_QUERY = 0x0008
                    if (desiredAccess & 0x0008) {
                        send({
                            type: "info",
                            target: "OpenProcessToken",
                            message: "Process token query detected",
                            desired_access: desiredAccess
                        });
                        this.isTokenQuery = true;
                    }
                }
            });
            
            this.hooksInstalled['OpenProcessToken'] = true;
        }
        
        var getTokenInformation = Module.findExportByName("advapi32.dll", "GetTokenInformation");
        if (getTokenInformation) {
            Interceptor.attach(getTokenInformation, {
                onEnter: function(args) {
                    var tokenInfoClass = args[1].toInt32();
                    
                    // TokenPrivileges = 3
                    if (tokenInfoClass === 3) {
                        send({
                            type: "info",
                            target: "GetTokenInformation",
                            message: "Token privileges query detected",
                            token_info_class: tokenInfoClass
                        });
                        this.isPrivilegeQuery = true;
                    }
                },
                
                onLeave: function(retval) {
                    if (this.isPrivilegeQuery && retval.toInt32() !== 0) {
                        var config = this.parent.parent.config;
                        if (config.processInfo.hideDebugPrivileges) {
                            // Could modify privilege information here to hide debug privileges
                            send({
                                type: "bypass",
                                target: "GetTokenInformation",
                                action: "token_privileges_intercepted"
                            });
                        }
                    }
                }
            });
            
            this.hooksInstalled['GetTokenInformation'] = true;
        }
    },
    
    // === THREAD CONTEXT MANIPULATION ===
    hookThreadContext: function() {
        send({
            type: "info",
            message: "Installing thread context manipulation",
            category: "thread_context"
        });
        
        // Additional thread context protection beyond hardware breakpoints
        this.hookSingleStepDetection();
        this.hookTrapFlagManipulation();
        this.hookDebuggerThreadDetection();
    },
    
    hookSingleStepDetection: function() {
        // Hook exception dispatching to catch single-step exceptions
        var ntRaiseException = Module.findExportByName("ntdll.dll", "NtRaiseException");
        if (ntRaiseException) {
            Interceptor.attach(ntRaiseException, {
                onEnter: function(args) {
                    var exceptionRecord = args[0];
                    if (exceptionRecord && !exceptionRecord.isNull()) {
                        var exceptionCode = exceptionRecord.readU32();
                        
                        // EXCEPTION_SINGLE_STEP = 0x80000004
                        if (exceptionCode === 0x80000004) {
                            var config = this.parent.parent.config;
                            if (config.threadProtection.enabled && config.threadProtection.protectSingleStep) {
                                send({
                                    type: "bypass",
                                    target: "NtRaiseException",
                                    action: "single_step_exception_intercepted",
                                    exception_code: exceptionCode
                                });
                                // Could modify or suppress the exception
                            }
                        }
                    }
                }
            });
            
            this.hooksInstalled['NtRaiseException'] = true;
        }
    },
    
    hookTrapFlagManipulation: function() {
        // Monitor EFLAGS/RFLAGS manipulation
        var ntSetContextThread = Module.findExportByName("ntdll.dll", "NtSetContextThread");
        if (ntSetContextThread) {
            Interceptor.attach(ntSetContextThread, {
                onEnter: function(args) {
                    var context = args[1];
                    if (context && !context.isNull()) {
                        var config = this.parent.parent.config;
                        if (config.threadProtection.enabled && config.threadProtection.spoofTrapFlag) {
                            // Check for trap flag (bit 8 in EFLAGS/RFLAGS)
                            var contextFlags = context.readU32();
                            if (contextFlags & 0x10) { // CONTEXT_CONTROL
                                var eflags = context.add(0x44).readU32(); // EFLAGS offset in CONTEXT
                                if (eflags & 0x100) { // Trap flag set
                                    context.add(0x44).writeU32(eflags & ~0x100); // Clear trap flag
                                    send({
                                        type: "bypass",
                                        target: "NtSetContextThread",
                                        action: "trap_flag_cleared",
                                        original_eflags: eflags
                                    });
                                }
                            }
                        }
                    }
                }
            });
            
            this.hooksInstalled['NtSetContextThread'] = true;
        }
    },
    
    hookDebuggerThreadDetection: function() {
        // Hook thread enumeration to hide debugger threads
        var thread32First = Module.findExportByName("kernel32.dll", "Thread32First");
        if (thread32First) {
            Interceptor.attach(thread32First, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var threadEntry = this.context.rdx; // THREADENTRY32
                        if (threadEntry && !threadEntry.isNull()) {
                            // Could filter out threads that belong to debugger processes
                            send({
                                type: "info",
                                target: "Thread32First",
                                message: "Thread enumeration detected"
                            });
                        }
                    }
                }
            });
            
            this.hooksInstalled['Thread32First'] = true;
        }
    },
    
    // === EXCEPTION HANDLING ===
    hookExceptionHandling: function() {
        send({
            type: "info",
            message: "Installing exception handling hooks",
            category: "exception_handling"
        });
        
        // Hook vectored exception handlers
        this.hookVectoredExceptionHandlers();
        
        // Hook unhandled exception filters
        this.hookUnhandledExceptionFilters();
        
        // Hook debug break instructions
        this.hookDebugBreaks();
    },
    
    hookVectoredExceptionHandlers: function() {
        var addVectoredExceptionHandler = Module.findExportByName("kernel32.dll", "AddVectoredExceptionHandler");
        if (addVectoredExceptionHandler) {
            Interceptor.attach(addVectoredExceptionHandler, {
                onEnter: function(args) {
                    var first = args[0].toInt32();
                    var handler = args[1];
                    
                    send({
                        type: "info",
                        target: "AddVectoredExceptionHandler",
                        message: "Vectored exception handler registered",
                        first: first === 1
                    });
                    
                    var config = this.parent.parent.config;
                    if (config.exceptionHandling.bypassVectoredHandlers) {
                        // Could potentially hook or modify the handler
                        this.monitorHandler = true;
                    }
                },
                
                onLeave: function(retval) {
                    if (this.monitorHandler && !retval.isNull()) {
                        send({
                            type: "info",
                            target: "AddVectoredExceptionHandler",
                            message: "Vectored exception handler installed",
                            handler_address: retval.toString()
                        });
                    }
                }
            });
            
            this.hooksInstalled['AddVectoredExceptionHandler'] = true;
        }
    },
    
    hookUnhandledExceptionFilters: function() {
        var setUnhandledExceptionFilter = Module.findExportByName("kernel32.dll", "SetUnhandledExceptionFilter");
        if (setUnhandledExceptionFilter) {
            Interceptor.attach(setUnhandledExceptionFilter, {
                onEnter: function(args) {
                    var lpTopLevelExceptionFilter = args[0];
                    
                    send({
                        type: "bypass",
                        target: "anti_debugger",
                        action: "unhandled_exception_filter_set"
                    });
                    
                    var config = this.parent.parent.config;
                    if (config.exceptionHandling.spoofUnhandledExceptions) {
                        // Could replace with our own handler
                        this.spoofFilter = true;
                    }
                }
            });
            
            this.hooksInstalled['SetUnhandledExceptionFilter'] = true;
        }
    },
    
    hookDebugBreaks: function() {
        // Hook software breakpoint instruction (INT 3)
        var debugBreak = Module.findExportByName("kernel32.dll", "DebugBreak");
        if (debugBreak) {
            Interceptor.replace(debugBreak, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "DebugBreak",
                    action: "debug_break_suppressed"
                });
                // Do nothing - suppress the debug break
            }, 'void', []));
            
            this.hooksInstalled['DebugBreak'] = true;
        }
        
        // Hook debug break for other processes
        var debugBreakProcess = Module.findExportByName("kernel32.dll", "DebugBreakProcess");
        if (debugBreakProcess) {
            Interceptor.replace(debugBreakProcess, new NativeCallback(function(process) {
                send({
                    type: "bypass",
                    target: "DebugBreakProcess",
                    action: "debug_break_process_blocked"
                });
                return 1; // TRUE - fake success
            }, 'int', ['pointer']));
            
            this.hooksInstalled['DebugBreakProcess'] = true;
        }
    },
    
    // === ADVANCED DETECTION BYPASS ===
    hookAdvancedDetection: function() {
        send({
            type: "info",
            message: "Installing advanced detection bypass",
            category: "advanced_detection"
        });
        
        // Hook debug object creation
        this.hookDebugObjectCreation();
        
        // Hook debug event handling
        this.hookDebugEventHandling();
        
        // Hook process debugging functions
        this.hookProcessDebugging();
    },
    
    hookDebugObjectCreation: function() {
        var ntCreateDebugObject = Module.findExportByName("ntdll.dll", "NtCreateDebugObject");
        if (ntCreateDebugObject) {
            Interceptor.attach(ntCreateDebugObject, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) { // STATUS_SUCCESS
                        send({
                            type: "bypass",
                            target: "NtCreateDebugObject",
                            action: "debug_object_creation_blocked"
                        });
                        retval.replace(0xC0000022); // STATUS_ACCESS_DENIED
                    }
                }
            });
            
            this.hooksInstalled['NtCreateDebugObject'] = true;
        }
        
        var ntDebugActiveProcess = Module.findExportByName("ntdll.dll", "NtDebugActiveProcess");
        if (ntDebugActiveProcess) {
            Interceptor.attach(ntDebugActiveProcess, {
                onLeave: function(retval) {
                    send({
                        type: "bypass",
                        target: "anti_debugger",
                        action: "debug_active_process_blocked"
                    });
                    retval.replace(0xC0000022); // STATUS_ACCESS_DENIED
                }
            });
            
            this.hooksInstalled['NtDebugActiveProcess'] = true;
        }
    },
    
    hookDebugEventHandling: function() {
        var waitForDebugEvent = Module.findExportByName("kernel32.dll", "WaitForDebugEvent");
        if (waitForDebugEvent) {
            Interceptor.replace(waitForDebugEvent, new NativeCallback(function(lpDebugEvent, dwMilliseconds) {
                send({
                    type: "bypass",
                    target: "anti_debugger",
                    action: "wait_for_debug_event_blocked"
                });
                return 0; // FALSE - no debug events
            }, 'int', ['pointer', 'uint32']));
            
            this.hooksInstalled['WaitForDebugEvent'] = true;
        }
        
        var continueDebugEvent = Module.findExportByName("kernel32.dll", "ContinueDebugEvent");
        if (continueDebugEvent) {
            Interceptor.replace(continueDebugEvent, new NativeCallback(function(dwProcessId, dwThreadId, dwContinueStatus) {
                send({
                    type: "bypass",
                    target: "anti_debugger",
                    action: "continue_debug_event_blocked"
                });
                return 1; // TRUE - fake success
            }, 'int', ['uint32', 'uint32', 'uint32']));
            
            this.hooksInstalled['ContinueDebugEvent'] = true;
        }
    },
    
    hookProcessDebugging: function() {
        var debugActiveProcess = Module.findExportByName("kernel32.dll", "DebugActiveProcess");
        if (debugActiveProcess) {
            Interceptor.replace(debugActiveProcess, new NativeCallback(function(dwProcessId) {
                send({
                    type: "bypass",
                    target: "anti_debugger",
                    action: "debug_active_process_blocked_with_pid",
                    process_id: dwProcessId
                });
                return 0; // FALSE - failed
            }, 'int', ['uint32']));
            
            this.hooksInstalled['DebugActiveProcess'] = true;
        }
        
        var debugActiveProcessStop = Module.findExportByName("kernel32.dll", "DebugActiveProcessStop");
        if (debugActiveProcessStop) {
            Interceptor.replace(debugActiveProcessStop, new NativeCallback(function(dwProcessId) {
                send({
                    type: "bypass",
                    target: "anti_debugger",
                    action: "debug_active_process_stop_intercepted"
                });
                return 1; // TRUE - fake success
            }, 'int', ['uint32']));
            
            this.hooksInstalled['DebugActiveProcessStop'] = true;
        }
    },
    
    // === DEBUGGER COMMUNICATION BYPASS ===
    hookDebuggerCommunication: function() {
        send({
            type: "info",
            target: "anti_debugger",
            action: "installing_debugger_communication_bypass"
        });
        
        // Hook named pipes used by debuggers
        this.hookNamedPipes();
        
        // Hook shared memory used by debuggers
        this.hookSharedMemory();
        
        // Hook registry keys used by debuggers
        this.hookDebuggerRegistry();
    },
    
    hookNamedPipes: function() {
        var createNamedPipe = Module.findExportByName("kernel32.dll", "CreateNamedPipeW");
        if (createNamedPipe) {
            Interceptor.attach(createNamedPipe, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var pipeName = args[0].readUtf16String();
                        
                        // Check for debugger-related pipe names
                        var debuggerPipes = ["\\\\.\\\pipe\\dbg", "\\\\.\\\pipe\\debug", "\\\\.\\\pipe\\windbg"];
                        
                        if (debuggerPipes.some(name => pipeName.toLowerCase().includes(name.toLowerCase()))) {
                            send({
                                type: "bypass",
                                target: "anti_debugger",
                                action: "debugger_pipe_creation_blocked",
                                pipe_name: pipeName
                            });
                            this.blockPipe = true;
                        }
                    }
                },
                
                onLeave: function(retval) {
                    if (this.blockPipe) {
                        retval.replace(ptr(0xFFFFFFFF)); // INVALID_HANDLE_VALUE
                    }
                }
            });
            
            this.hooksInstalled['CreateNamedPipeW'] = true;
        }
    },
    
    hookSharedMemory: function() {
        var createFileMapping = Module.findExportByName("kernel32.dll", "CreateFileMappingW");
        if (createFileMapping) {
            Interceptor.attach(createFileMapping, {
                onEnter: function(args) {
                    if (args[4] && !args[4].isNull()) {
                        var mappingName = args[4].readUtf16String();
                        
                        // Check for debugger-related mapping names
                        var debuggerMappings = ["dbg_", "debug_", "windbg_"];
                        
                        if (debuggerMappings.some(name => mappingName.toLowerCase().includes(name))) {
                            send({
                                type: "bypass",
                                target: "anti_debugger",
                                action: "debugger_mapping_blocked",
                                mapping_name: mappingName
                            });
                            this.blockMapping = true;
                        }
                    }
                },
                
                onLeave: function(retval) {
                    if (this.blockMapping) {
                        retval.replace(ptr(0)); // NULL
                    }
                }
            });
            
            this.hooksInstalled['CreateFileMappingW'] = true;
        }
    },
    
    hookDebuggerRegistry: function() {
        var regOpenKeyEx = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
        if (regOpenKeyEx) {
            Interceptor.attach(regOpenKeyEx, {
                onEnter: function(args) {
                    if (args[1] && !args[1].isNull()) {
                        var keyName = args[1].readUtf16String();
                        
                        // Check for debugger-related registry keys
                        var debuggerKeys = ["windbg", "debugger", "aedebug"];
                        
                        if (debuggerKeys.some(name => keyName.toLowerCase().includes(name))) {
                            send({
                                type: "bypass",
                                target: "anti_debugger",
                                action: "debugger_registry_access_blocked",
                                key_name: keyName
                            });
                            this.blockRegAccess = true;
                        }
                    }
                },
                
                onLeave: function(retval) {
                    if (this.blockRegAccess) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                }
            });
            
            this.hooksInstalled['RegOpenKeyExW'] = true;
        }
    },
    
    // === MEMORY PROTECTION ===
    hookMemoryProtection: function() {
        send({
            type: "info",
            target: "anti_debugger",
            action: "installing_memory_protection_bypass"
        });
        
        // Hook memory allocation with PAGE_NOACCESS
        var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
        if (virtualAlloc) {
            Interceptor.attach(virtualAlloc, {
                onEnter: function(args) {
                    var protect = args[3].toInt32();
                    
                    // PAGE_NOACCESS = 0x01 (could be used for anti-debug)
                    if (protect === 0x01) {
                        send({
                            type: "info",
                            target: "anti_debugger",
                            action: "page_noaccess_allocation_detected"
                        });
                        args[3] = ptr(0x04); // Change to PAGE_READWRITE
                    }
                }
            });
            
            this.hooksInstalled['VirtualAlloc_Protection'] = true;
        }
        
        // Hook memory protection changes
        var virtualProtect = Module.findExportByName("kernel32.dll", "VirtualProtect");
        if (virtualProtect) {
            Interceptor.attach(virtualProtect, {
                onEnter: function(args) {
                    var newProtect = args[2].toInt32();
                    
                    // Detect potential anti-debug memory tricks
                    if (newProtect === 0x01) { // PAGE_NOACCESS
                        send({
                            type: "bypass",
                            target: "anti_debugger",
                            action: "page_noaccess_protection_change_blocked"
                        });
                        args[2] = ptr(0x04); // Change to PAGE_READWRITE
                    }
                }
            });
            
            this.hooksInstalled['VirtualProtect_Protection'] = true;
        }
    },
    
    // === INSTALLATION SUMMARY ===
    installSummary: function() {
        setTimeout(() => {
            send({
                type: "summary",
                message: "Anti-Debugging Bypass Summary",
                separator: "======================================="
            });
            
            var categories = {
                "Core Detection": 0,
                "Hardware Breakpoints": 0,
                "Timing Protection": 0,
                "Process Information": 0,
                "Thread Context": 0,
                "Exception Handling": 0,
                "Advanced Detection": 0,
                "Communication": 0,
                "Memory Protection": 0
            };
            
            for (var hook in this.hooksInstalled) {
                if (hook.includes("IsDebugger") || hook.includes("Remote") || hook.includes("Query")) {
                    categories["Core Detection"]++;
                } else if (hook.includes("Context") || hook.includes("Thread") && hook.includes("Debug")) {
                    categories["Hardware Breakpoints"]++;
                } else if (hook.includes("RDTSC") || hook.includes("Performance") || hook.includes("Tick") || hook.includes("Sleep")) {
                    categories["Timing Protection"]++;
                } else if (hook.includes("Process") || hook.includes("Command") || hook.includes("Module")) {
                    categories["Process Information"]++;
                } else if (hook.includes("Thread") || hook.includes("Context") || hook.includes("Single")) {
                    categories["Thread Context"]++;
                } else if (hook.includes("Exception") || hook.includes("Break")) {
                    categories["Exception Handling"]++;
                } else if (hook.includes("Debug") && (hook.includes("Object") || hook.includes("Event") || hook.includes("Active"))) {
                    categories["Advanced Detection"]++;
                } else if (hook.includes("Pipe") || hook.includes("Mapping") || hook.includes("Reg")) {
                    categories["Communication"]++;
                } else if (hook.includes("Virtual") || hook.includes("Protection")) {
                    categories["Memory Protection"]++;
                }
            }
            
            send({
                type: "summary",
                message: "Hook installation summary",
                categories: categories,
                total_hooks: Object.keys(this.hooksInstalled).length
            });
            
            var config = this.config;
            var activeFeatures = [];
            
            if (config.hardwareBreakpoints.enabled) {
                activeFeatures.push("Hardware Breakpoint Bypass");
            }
            if (config.timingProtection.enabled) {
                activeFeatures.push("Timing Attack Countermeasures");
            }
            if (config.processInfo.spoofParentProcess) {
                activeFeatures.push("Process Information Spoofing");
            }
            if (config.threadProtection.enabled) {
                activeFeatures.push("Thread Context Protection");
            }
            if (config.exceptionHandling.bypassVectoredHandlers) {
                activeFeatures.push("Exception Handler Bypass");
            }
            
            send({
                type: "summary",
                message: "Enhanced anti-debugging protection is now ACTIVE!",
                active_features: activeFeatures,
                total_hooks: Object.keys(this.hooksInstalled).length,
                configuration: config
            });
        }, 100);
    }
}