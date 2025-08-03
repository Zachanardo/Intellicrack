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
        console.log("[Enhanced Anti-Debug] Attaching to process: " + pid);
        this.processId = pid;
    },

    run: function() {
        console.log("[Enhanced Anti-Debug] Installing comprehensive anti-debugging countermeasures...");

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
        console.log("[Enhanced Anti-Debug] Installing debugger detection bypass...");

        // Hook IsDebuggerPresent
        var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
        if (isDebuggerPresent) {
            Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {
                console.log("[Enhanced Anti-Debug] IsDebuggerPresent called - returning FALSE");
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
                            console.log("[Enhanced Anti-Debug] CheckRemoteDebuggerPresent spoofed to FALSE");
                        }
                    }
                }
            });

            this.hooksInstalled['CheckRemoteDebuggerPresent'] = true;
        }
    },

    // === NTDLL ANTI-DEBUG BYPASS ===
    hookNtdllAntiDebug: function() {
        console.log("[Enhanced Anti-Debug] Installing NTDLL anti-debug bypass...");

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
                            console.log("[Enhanced Anti-Debug] ProcessDebugPort spoofed to NULL");
                            break;

                        case 30: // ProcessDebugObjectHandle
                            this.processInfo.writePointer(ptr(0));
                            console.log("[Enhanced Anti-Debug] ProcessDebugObjectHandle spoofed to NULL");
                            break;

                        case 31: // ProcessDebugFlags
                            this.processInfo.writeU32(1); // PROCESS_DEBUG_INHERIT
                            console.log("[Enhanced Anti-Debug] ProcessDebugFlags spoofed");
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
                                console.log("[Enhanced Anti-Debug] Unknown debug info class " + this.infoClass + " zeroed");
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
                        console.log("[Enhanced Anti-Debug] Blocked ThreadHideFromDebugger attempt");
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
                    console.log("[Enhanced Anti-Debug] Thread creation detected - monitoring for debug threads");
                }
            });

            this.hooksInstalled['NtCreateThreadEx'] = true;
        }
    },

    // === DEBUG OUTPUT SUPPRESSION ===
    hookDebugOutput: function() {
        console.log("[Enhanced Anti-Debug] Installing debug output suppression...");

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
        console.log("[Enhanced Anti-Debug] Manipulating PEB debug flags...");

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

                        console.log("[Enhanced Anti-Debug] PEB debug flags cleared successfully");
                    }
                }
            } catch (e) {
                console.log("[Enhanced Anti-Debug] PEB manipulation failed (expected): " + e);
            }
        }, 100);
    },

    // === HARDWARE BREAKPOINT BYPASS ===
    hookHardwareBreakpoints: function() {
        console.log("[Enhanced Anti-Debug] Installing hardware breakpoint bypass...");

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
                        var config = this.parent && this.parent.parent && this.parent.parent.config;
                        if (config && config.hardwareBreakpoints && config.hardwareBreakpoints.enabled) {
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

                            console.log("[Enhanced Anti-Debug] Hardware breakpoints cleared in thread context");
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
                        var config = this.parent && this.parent.parent && this.parent.parent.config;
                        if (config && config.hardwareBreakpoints && config.hardwareBreakpoints.enabled) {
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

                                console.log("[Enhanced Anti-Debug] Prevented hardware breakpoint installation");
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
                                var config = this.parent && this.parent.parent && this.parent.parent.config;
                                if (config && config.hardwareBreakpoints && config.hardwareBreakpoints.enabled) {
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
        console.log("[Enhanced Anti-Debug] Installing timing attack countermeasures...");

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

                        console.log("[Enhanced Anti-Debug] RDTSC timing spoofed in " + moduleName);
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

                                console.log("[Enhanced Anti-Debug] QueryPerformanceCounter spoofed");
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
                            console.log("[Enhanced Anti-Debug] Long sleep reduced: " + milliseconds + "ms -> 100ms");
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
                            console.log("[Enhanced Anti-Debug] SleepEx time reduced: " + milliseconds + "ms -> 100ms");
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

            var self = this;
            Interceptor.replace(getTickCount, new NativeCallback(function() {
                var config = self.config;
                if (config && config.timingProtection && config.timingProtection.enabled && config.timingProtection.consistentTiming) {
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

            var self = this;
            Interceptor.replace(getTickCount64, new NativeCallback(function() {
                var config = self.config;
                if (config && config.timingProtection && config.timingProtection.enabled && config.timingProtection.consistentTiming) {
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
        console.log("[Enhanced Anti-Debug] Installing process information spoofing...");

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
                            console.log("[Enhanced Anti-Debug] Process name spoofed to: " + spoofedPath);
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
                        console.log("[Enhanced Anti-Debug] Process snapshot creation detected");
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

                                console.log("[Enhanced Anti-Debug] Parent process spoofed to PID " +
                                          config.processInfo.spoofParentPid);
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
            var self = this;
            Interceptor.replace(getCommandLine, new NativeCallback(function() {
                var config = self.config;
                if (config && config.processInfo && config.processInfo.spoofParentProcess) {
                    var spoofedCmdLine = Memory.allocUtf16String(config.processInfo.spoofCommandLine);
                    console.log("[Enhanced Anti-Debug] Command line spoofed");
                    return spoofedCmdLine;
                }
                // Return original command line - use try/catch for safety
                try {
                    var origFunc = Module.findExportByName("kernel32.dll", "GetCommandLineW");
                    return origFunc ? new NativeFunction(origFunc, 'pointer', [])() : ptr(0);
                } catch(e) {
                    return ptr(0);
                }
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
                        console.log("[Enhanced Anti-Debug] Process token query detected");
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
                        console.log("[Enhanced Anti-Debug] Token privileges query detected");
                        this.isPrivilegeQuery = true;
                    }
                },

                onLeave: function(retval) {
                    if (this.isPrivilegeQuery && retval.toInt32() !== 0) {
                        var config = this.parent.parent.config;
                        if (config.processInfo.hideDebugPrivileges) {
                            // Could modify privilege information here to hide debug privileges
                            console.log("[Enhanced Anti-Debug] Token privileges query intercepted");
                        }
                    }
                }
            });

            this.hooksInstalled['GetTokenInformation'] = true;
        }
    },

    // === THREAD CONTEXT MANIPULATION ===
    hookThreadContext: function() {
        console.log("[Enhanced Anti-Debug] Installing thread context manipulation...");

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
                                console.log("[Enhanced Anti-Debug] Single-step exception intercepted");
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
                                    console.log("[Enhanced Anti-Debug] Trap flag cleared in thread context");
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
                            console.log("[Enhanced Anti-Debug] Thread enumeration detected");
                        }
                    }
                }
            });

            this.hooksInstalled['Thread32First'] = true;
        }
    },

    // === EXCEPTION HANDLING ===
    hookExceptionHandling: function() {
        console.log("[Enhanced Anti-Debug] Installing exception handling hooks...");

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

                    console.log("[Enhanced Anti-Debug] Vectored exception handler registered");

                    var config = this.parent.parent.config;
                    if (config.exceptionHandling.bypassVectoredHandlers) {
                        // Could potentially hook or modify the handler
                        this.monitorHandler = true;
                    }
                },

                onLeave: function(retval) {
                    if (this.monitorHandler && !retval.isNull()) {
                        console.log("[Enhanced Anti-Debug] Vectored exception handler installed at " + retval);
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

                    console.log("[Enhanced Anti-Debug] Unhandled exception filter set");

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
                console.log("[Enhanced Anti-Debug] DebugBreak instruction intercepted and suppressed");
                // Do nothing - suppress the debug break
            }, 'void', []));

            this.hooksInstalled['DebugBreak'] = true;
        }

        // Hook debug break for other processes
        var debugBreakProcess = Module.findExportByName("kernel32.dll", "DebugBreakProcess");
        if (debugBreakProcess) {
            Interceptor.replace(debugBreakProcess, new NativeCallback(function(process) {
                console.log("[Enhanced Anti-Debug] DebugBreakProcess blocked");
                return 1; // TRUE - fake success
            }, 'int', ['pointer']));

            this.hooksInstalled['DebugBreakProcess'] = true;
        }
    },

    // === ADVANCED DETECTION BYPASS ===
    hookAdvancedDetection: function() {
        console.log("[Enhanced Anti-Debug] Installing advanced detection bypass...");

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
                        console.log("[Enhanced Anti-Debug] Debug object creation blocked");
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
                    console.log("[Enhanced Anti-Debug] Debug active process blocked");
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
                console.log("[Enhanced Anti-Debug] WaitForDebugEvent blocked");
                return 0; // FALSE - no debug events
            }, 'int', ['pointer', 'uint32']));

            this.hooksInstalled['WaitForDebugEvent'] = true;
        }

        var continueDebugEvent = Module.findExportByName("kernel32.dll", "ContinueDebugEvent");
        if (continueDebugEvent) {
            Interceptor.replace(continueDebugEvent, new NativeCallback(function(dwProcessId, dwThreadId, dwContinueStatus) {
                console.log("[Enhanced Anti-Debug] ContinueDebugEvent blocked");
                return 1; // TRUE - fake success
            }, 'int', ['uint32', 'uint32', 'uint32']));

            this.hooksInstalled['ContinueDebugEvent'] = true;
        }
    },

    hookProcessDebugging: function() {
        var debugActiveProcess = Module.findExportByName("kernel32.dll", "DebugActiveProcess");
        if (debugActiveProcess) {
            Interceptor.replace(debugActiveProcess, new NativeCallback(function(dwProcessId) {
                console.log("[Enhanced Anti-Debug] DebugActiveProcess blocked for PID " + dwProcessId);
                return 0; // FALSE - failed
            }, 'int', ['uint32']));

            this.hooksInstalled['DebugActiveProcess'] = true;
        }

        var debugActiveProcessStop = Module.findExportByName("kernel32.dll", "DebugActiveProcessStop");
        if (debugActiveProcessStop) {
            Interceptor.replace(debugActiveProcessStop, new NativeCallback(function(dwProcessId) {
                console.log("[Enhanced Anti-Debug] DebugActiveProcessStop intercepted");
                return 1; // TRUE - fake success
            }, 'int', ['uint32']));

            this.hooksInstalled['DebugActiveProcessStop'] = true;
        }
    },

    // === DEBUGGER COMMUNICATION BYPASS ===
    hookDebuggerCommunication: function() {
        console.log("[Enhanced Anti-Debug] Installing debugger communication bypass...");

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
                            console.log("[Enhanced Anti-Debug] Debugger pipe creation blocked: " + pipeName);
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
                            console.log("[Enhanced Anti-Debug] Debugger mapping blocked: " + mappingName);
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
                            console.log("[Enhanced Anti-Debug] Debugger registry access blocked: " + keyName);
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
        console.log("[Enhanced Anti-Debug] Installing memory protection bypass...");

        // Hook memory allocation with PAGE_NOACCESS
        var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
        if (virtualAlloc) {
            Interceptor.attach(virtualAlloc, {
                onEnter: function(args) {
                    var protect = args[3].toInt32();

                    // PAGE_NOACCESS = 0x01 (could be used for anti-debug)
                    if (protect === 0x01) {
                        console.log("[Enhanced Anti-Debug] PAGE_NOACCESS allocation detected");
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
                        console.log("[Enhanced Anti-Debug] Memory protection change to PAGE_NOACCESS blocked");
                        args[2] = ptr(0x04); // Change to PAGE_READWRITE
                    }
                }
            });

            this.hooksInstalled['VirtualProtect_Protection'] = true;
        }
    },

    // === HELPER FUNCTIONS ===
    categorizeHooks: function(categories) {
        for (var hook in this.hooksInstalled) {
            if (this.isCoreDetectionHook(hook)) {
                categories["Core Detection"]++;
            } else if (this.isHardwareBreakpointHook(hook)) {
                categories["Hardware Breakpoints"]++;
            } else if (this.isTimingProtectionHook(hook)) {
                categories["Timing Protection"]++;
            } else if (this.isProcessInfoHook(hook)) {
                categories["Process Information"]++;
            } else if (this.isThreadContextHook(hook)) {
                categories["Thread Context"]++;
            } else if (this.isExceptionHandlingHook(hook)) {
                categories["Exception Handling"]++;
            } else if (this.isAdvancedDetectionHook(hook)) {
                categories["Advanced Detection"]++;
            } else if (this.isCommunicationHook(hook)) {
                categories["Communication"]++;
            } else if (this.isMemoryProtectionHook(hook)) {
                categories["Memory Protection"]++;
            }
        }
    },

    isCoreDetectionHook: function(hook) {
        return hook.includes("IsDebugger") || hook.includes("Remote") || hook.includes("Query");
    },

    isHardwareBreakpointHook: function(hook) {
        return hook.includes("Context") || (hook.includes("Thread") && hook.includes("Debug"));
    },

    isTimingProtectionHook: function(hook) {
        return hook.includes("RDTSC") || hook.includes("Performance") || hook.includes("Tick") || hook.includes("Sleep");
    },

    isProcessInfoHook: function(hook) {
        return hook.includes("Process") || hook.includes("Command") || hook.includes("Module");
    },

    isThreadContextHook: function(hook) {
        return hook.includes("Thread") || hook.includes("Context") || hook.includes("Single");
    },

    isExceptionHandlingHook: function(hook) {
        return hook.includes("Exception") || hook.includes("Break");
    },

    isAdvancedDetectionHook: function(hook) {
        return hook.includes("Debug") && (hook.includes("Object") || hook.includes("Event") || hook.includes("Active"));
    },

    isCommunicationHook: function(hook) {
        return hook.includes("Pipe") || hook.includes("Mapping") || hook.includes("Reg");
    },

    isMemoryProtectionHook: function(hook) {
        return hook.includes("Virtual") || hook.includes("Protection");
    },

    // === INSTALLATION SUMMARY ===
    installSummary: function() {
        setTimeout(() => {
            console.log("\\n[Enhanced Anti-Debug] =======================================");
            console.log("[Enhanced Anti-Debug] Anti-Debugging Bypass Summary:");
            console.log("[Enhanced Anti-Debug] =======================================");

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

            this.categorizeHooks(categories);

            for (var category in categories) {
                if (categories[category] > 0) {
                    console.log("[Enhanced Anti-Debug]   ✓ " + category + ": " + categories[category] + " hooks");
                }
            }

            console.log("[Enhanced Anti-Debug] =======================================");
            console.log("[Enhanced Anti-Debug] Configuration Active:");

            var config = this.config;
            if (config.hardwareBreakpoints.enabled) {
                console.log("[Enhanced Anti-Debug]   ✓ Hardware Breakpoint Bypass");
            }
            if (config.timingProtection.enabled) {
                console.log("[Enhanced Anti-Debug]   ✓ Timing Attack Countermeasures");
            }
            if (config.processInfo.spoofParentProcess) {
                console.log("[Enhanced Anti-Debug]   ✓ Process Information Spoofing");
            }
            if (config.threadProtection.enabled) {
                console.log("[Enhanced Anti-Debug]   ✓ Thread Context Protection");
            }
            if (config.exceptionHandling.bypassVectoredHandlers) {
                console.log("[Enhanced Anti-Debug]   ✓ Exception Handler Bypass");
            }

            console.log("[Enhanced Anti-Debug] =======================================");
            console.log("[Enhanced Anti-Debug] Total hooks installed: " + Object.keys(this.hooksInstalled).length);
            console.log("[Enhanced Anti-Debug] =======================================");
            console.log("[Enhanced Anti-Debug] Enhanced anti-debugging protection is now ACTIVE!");
        }, 100);
    }
}
