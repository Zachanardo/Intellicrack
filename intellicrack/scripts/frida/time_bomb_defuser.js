// Time Bomb Defuser Script
// Prevents time-based software expiration by spoofing system time functions
// Returns safe dates to bypass trial periods and time bombs

console.log("[Time Bomb] Starting time bomb defuser...");

// === SYSTEM TIME SPOOFING ===

// Hook GetSystemTime
var getSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
if (getSystemTime) {
    Interceptor.attach(getSystemTime, {
        onLeave: function(retval) {
            var systemTime = this.context.rcx; // SYSTEMTIME pointer
            if (systemTime && !systemTime.isNull()) {
                // Set to a safe date: January 1, 2020
                systemTime.writeU16(2020);      // wYear
                systemTime.add(2).writeU16(1);  // wMonth
                systemTime.add(6).writeU16(1);  // wDay
                systemTime.add(8).writeU16(0);  // wHour
                systemTime.add(10).writeU16(0); // wMinute
                systemTime.add(12).writeU16(0); // wSecond
                console.log("[Time Bomb] GetSystemTime spoofed to January 1, 2020");
            }
        }
    });
}

// Hook GetLocalTime
var getLocalTime = Module.findExportByName("kernel32.dll", "GetLocalTime");
if (getLocalTime) {
    Interceptor.attach(getLocalTime, {
        onLeave: function(retval) {
            var localTime = this.context.rcx; // SYSTEMTIME pointer
            if (localTime && !localTime.isNull()) {
                // Set to a safe date: January 1, 2020
                localTime.writeU16(2020);      // wYear
                localTime.add(2).writeU16(1);  // wMonth
                localTime.add(6).writeU16(1);  // wDay
                localTime.add(8).writeU16(0);  // wHour
                localTime.add(10).writeU16(0); // wMinute
                localTime.add(12).writeU16(0); // wSecond
                console.log("[Time Bomb] GetLocalTime spoofed to January 1, 2020");
            }
        }
    });
}

// === TICK COUNT SPOOFING ===

// Hook GetTickCount
var getTickCount = Module.findExportByName("kernel32.dll", "GetTickCount");
if (getTickCount) {
    var baseTime = Date.now();
    Interceptor.replace(getTickCount, new NativeCallback(function() {
        var elapsed = Date.now() - baseTime;
        return Math.floor(elapsed); // Return consistent tick count
    }, 'uint32', []));
    console.log("[Time Bomb] GetTickCount hooked");
}

// Hook GetTickCount64
var getTickCount64 = Module.findExportByName("kernel32.dll", "GetTickCount64");
if (getTickCount64) {
    var baseTime64 = Date.now();
    Interceptor.replace(getTickCount64, new NativeCallback(function() {
        var elapsed = Date.now() - baseTime64;
        return elapsed;
    }, 'uint64', []));
    console.log("[Time Bomb] GetTickCount64 hooked");
}

// === FILE TIME SPOOFING ===

// Hook GetFileTime
var getFileTime = Module.findExportByName("kernel32.dll", "GetFileTime");
if (getFileTime) {
    Interceptor.attach(getFileTime, {
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                // Spoof file times to safe dates
                var creationTime = this.context.r8;
                var lastAccessTime = this.context.r9;
                var lastWriteTime = this.context.rsp.add(0x28).readPointer();

                // Set to January 1, 2020 (as FILETIME)
                var safeFileTime = ptr("0x01d5e8d6c6c00000"); // Jan 1, 2020 in FILETIME

                if (creationTime && !creationTime.isNull()) {
                    creationTime.writeU64(safeFileTime);
                }
                if (lastAccessTime && !lastAccessTime.isNull()) {
                    lastAccessTime.writeU64(safeFileTime);
                }
                if (lastWriteTime && !lastWriteTime.isNull()) {
                    lastWriteTime.writeU64(safeFileTime);
                }

                console.log("[Time Bomb] File times spoofed");
            }
        }
    });
}

// === C RUNTIME TIME FUNCTIONS ===

// Hook time() function from CRT
var timeFunc = Module.findExportByName("msvcrt.dll", "time");
if (timeFunc) {
    Interceptor.replace(timeFunc, new NativeCallback(function(timer) {
        var safeTime = Math.floor(new Date('2020-01-01').getTime() / 1000);
        if (timer && !timer.isNull()) {
            timer.writeU32(safeTime);
        }
        console.log("[Time Bomb] time() function spoofed to safe date");
        return safeTime;
    }, 'uint32', ['pointer']));
}

// Hook clock() function
var clockFunc = Module.findExportByName("msvcrt.dll", "clock");
if (clockFunc) {
    var startClock = Date.now();
    Interceptor.replace(clockFunc, new NativeCallback(function() {
        var elapsed = Date.now() - startClock;
        return Math.floor(elapsed); // Return elapsed time in ms
    }, 'uint32', []));
    console.log("[Time Bomb] clock() function hooked");
}

// === REGISTRY TIME SPOOFING ===

// Hook registry queries for install dates
var regQueryValueExW = Module.findExportByName("advapi32.dll", "RegQueryValueExW");
if (regQueryValueExW) {
    Interceptor.attach(regQueryValueExW, {
        onEnter: function(args) {
            var valueName = args[1].readUtf16String();
            if (valueName && (valueName.includes("Install") || valueName.includes("Date"))) {
                this.spoofDate = true;
                console.log("[Time Bomb] Registry date query intercepted: " + valueName);
            }
        },
        onLeave: function(retval) {
            if (this.spoofDate && retval.toInt32() === 0) {
                // Spoof installation date to recent date
                var buffer = this.context.r8; // lpData
                var bufferSize = this.context.r9; // lpcbData
                if (buffer && !buffer.isNull()) {
                    var safeDate = "2020-01-01";
                    buffer.writeUtf16String(safeDate);
                    console.log("[Time Bomb] Registry date spoofed to " + safeDate);
                }
            }
        }
    });
}

console.log("[Time Bomb] Time bomb defuser installed successfully!");
