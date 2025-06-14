// Anti-Debugger Bypass Script
// Bypasses common anti-debugging techniques used by software protections
// Hooks various Windows APIs to hide debugger presence

console.log("[Anti-Debug] Starting anti-debugger countermeasures...");

// === DEBUGGER PRESENCE DETECTION BYPASS ===

// Hook IsDebuggerPresent
var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
if (isDebuggerPresent) {
    Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {
        console.log("[Anti-Debug] IsDebuggerPresent called - returning FALSE");
        return 0; // FALSE
    }, 'int', []));
}

// Hook CheckRemoteDebuggerPresent
var checkRemoteDebugger = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
if (checkRemoteDebugger) {
    Interceptor.attach(checkRemoteDebugger, {
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                // Set pbDebuggerPresent to FALSE
                var pbDebugger = this.context.r8; // Second parameter
                if (pbDebugger && !pbDebugger.isNull()) {
                    pbDebugger.writeU8(0); // FALSE
                    console.log("[Anti-Debug] CheckRemoteDebuggerPresent spoofed to FALSE");
                }
            }
        }
    });
}

// === NTDLL ANTI-DEBUG BYPASS ===

// Hook NtQueryInformationProcess for debug flags
var ntQueryInfo = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
if (ntQueryInfo) {
    Interceptor.attach(ntQueryInfo, {
        onEnter: function(args) {
            this.infoClass = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) { // STATUS_SUCCESS
                // ProcessDebugPort = 7, ProcessDebugFlags = 31
                if (this.infoClass === 7 || this.infoClass === 31) {
                    var buffer = this.context.r8; // ProcessInformation parameter
                    if (buffer && !buffer.isNull()) {
                        buffer.writeU32(0); // No debug port/flags
                        console.log("[Anti-Debug] NtQueryInformationProcess debug check bypassed");
                    }
                }
            }
        }
    });
}

// Hook NtSetInformationThread (hide from debugger)
var ntSetInfoThread = Module.findExportByName("ntdll.dll", "NtSetInformationThread");
if (ntSetInfoThread) {
    Interceptor.attach(ntSetInfoThread, {
        onEnter: function(args) {
            var infoClass = args[1].toInt32();
            if (infoClass === 17) { // ThreadHideFromDebugger
                console.log("[Anti-Debug] Blocked ThreadHideFromDebugger attempt");
                this.replace();
                this.returnValue = 0; // STATUS_SUCCESS
            }
        }
    });
}

// === DEBUG OUTPUT SUPPRESSION ===

// Hook OutputDebugString to prevent debug output
var outputDebugStringA = Module.findExportByName("kernel32.dll", "OutputDebugStringA");
if (outputDebugStringA) {
    Interceptor.replace(outputDebugStringA, new NativeCallback(function(lpOutputString) {
        // Silently consume debug output
        return;
    }, 'void', ['pointer']));
}

var outputDebugStringW = Module.findExportByName("kernel32.dll", "OutputDebugStringW");
if (outputDebugStringW) {
    Interceptor.replace(outputDebugStringW, new NativeCallback(function(lpOutputString) {
        // Silently consume debug output
        return;
    }, 'void', ['pointer']));
}

// === PEB MANIPULATION ===

// Hook NtQueryInformationProcess for PEB access
var getProcessHeap = Module.findExportByName("kernel32.dll", "GetProcessHeap");
if (getProcessHeap) {
    // Hook to clear BeingDebugged flag in PEB
    setTimeout(function() {
        try {
            var peb = Process.getCurrentProcess().getModuleByName("ntdll.dll").base.add(0x60);
            var beingDebugged = peb.add(0x2);
            beingDebugged.writeU8(0); // Clear BeingDebugged flag
            console.log("[Anti-Debug] PEB BeingDebugged flag cleared");
        } catch (e) {
            console.log("[Anti-Debug] Could not clear PEB flag: " + e);
        }
    }, 100);
}

console.log("[Anti-Debug] Anti-debugger countermeasures installed successfully!");