/**
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
 * Comprehensive API Tracing Engine - Frida Script
 * 
 * This script provides comprehensive API call tracing for Windows and Linux
 * systems with real-time analysis and minimal performance impact.
 * 
 * Features:
 * - Cross-platform API hooking (Windows/Linux)
 * - Real-time call logging with parameter capture
 * - Call stack trace reconstruction
 * - Performance optimization with batching
 * - Thread-safe operation
 * - Comprehensive parameter serialization
 * - Memory snapshot capabilities
 * - Error handling and recovery
 */

(function() {
    'use strict';

    // Global configuration
    let config = {
        enabled_categories: ['REGISTRY', 'FILE_SYSTEM', 'NETWORK', 'CRYPTOGRAPHIC', 'SYSTEM_INFO', 
                           'PROCESS_THREAD', 'MEMORY', 'TIMING', 'LICENSING', 'ANTI_DEBUG', 'ANTI_VM', 'HARDWARE'],
        max_call_stack_depth: 32,
        max_parameter_size: 1024,
        max_calls_per_second: 10000,
        batch_size: 100,
        batch_timeout_ms: 100,
        enable_memory_snapshots: false,
        enable_call_correlation: true,
        performance_mode: false
    };

    // Batch processing
    let callBatch = [];
    let batchTimer = null;
    let sequenceCounter = 0;
    let callCount = 0;
    let lastSecond = Math.floor(Date.now() / 1000);

    // Performance monitoring
    let performanceStats = {
        totalCalls: 0,
        hookTime: 0,
        serializationTime: 0,
        stackTraceTime: 0
    };

    // Hook registry
    let installedHooks = new Map();
    let moduleCache = new Map();

    // API categorization mappings
    const API_CATEGORIES = {
        // Registry APIs
        'RegOpenKey': 'REGISTRY', 'RegOpenKeyEx': 'REGISTRY', 'RegCreateKey': 'REGISTRY',
        'RegCreateKeyEx': 'REGISTRY', 'RegQueryValue': 'REGISTRY', 'RegQueryValueEx': 'REGISTRY',
        'RegSetValue': 'REGISTRY', 'RegSetValueEx': 'REGISTRY', 'RegDeleteKey': 'REGISTRY',
        'RegDeleteValue': 'REGISTRY', 'RegCloseKey': 'REGISTRY', 'RegEnumKey': 'REGISTRY',
        'RegEnumValue': 'REGISTRY',

        // File System APIs
        'CreateFile': 'FILE_SYSTEM', 'CreateFileA': 'FILE_SYSTEM', 'CreateFileW': 'FILE_SYSTEM',
        'ReadFile': 'FILE_SYSTEM', 'WriteFile': 'FILE_SYSTEM', 'DeleteFile': 'FILE_SYSTEM',
        'DeleteFileA': 'FILE_SYSTEM', 'DeleteFileW': 'FILE_SYSTEM', 'CopyFile': 'FILE_SYSTEM',
        'MoveFile': 'FILE_SYSTEM', 'FindFirstFile': 'FILE_SYSTEM', 'FindNextFile': 'FILE_SYSTEM',
        'GetFileAttributes': 'FILE_SYSTEM', 'SetFileAttributes': 'FILE_SYSTEM',

        // Network APIs
        'socket': 'NETWORK', 'connect': 'NETWORK', 'send': 'NETWORK', 'recv': 'NETWORK',
        'sendto': 'NETWORK', 'recvfrom': 'NETWORK', 'WSASocket': 'NETWORK', 'WSAConnect': 'NETWORK',
        'InternetOpen': 'NETWORK', 'InternetOpenA': 'NETWORK', 'InternetOpenW': 'NETWORK',
        'InternetConnect': 'NETWORK', 'InternetOpenUrl': 'NETWORK', 'HttpSendRequest': 'NETWORK',
        'WinHttpOpen': 'NETWORK', 'WinHttpConnect': 'NETWORK', 'WinHttpSendRequest': 'NETWORK',

        // Cryptographic APIs
        'CryptAcquireContext': 'CRYPTOGRAPHIC', 'CryptCreateHash': 'CRYPTOGRAPHIC',
        'CryptHashData': 'CRYPTOGRAPHIC', 'CryptEncrypt': 'CRYPTOGRAPHIC', 'CryptDecrypt': 'CRYPTOGRAPHIC',
        'CryptGenKey': 'CRYPTOGRAPHIC', 'CryptImportKey': 'CRYPTOGRAPHIC', 'CryptExportKey': 'CRYPTOGRAPHIC',
        'CertOpenStore': 'CRYPTOGRAPHIC', 'CertFindCertificateInStore': 'CRYPTOGRAPHIC',

        // System Information APIs
        'GetSystemInfo': 'SYSTEM_INFO', 'GetVersionEx': 'SYSTEM_INFO', 'GetComputerName': 'SYSTEM_INFO',
        'GetUserName': 'SYSTEM_INFO', 'GetWindowsDirectory': 'SYSTEM_INFO', 'GetSystemDirectory': 'SYSTEM_INFO',
        'GetEnvironmentVariable': 'SYSTEM_INFO', 'GetSystemMetrics': 'SYSTEM_INFO',

        // Process/Thread APIs
        'CreateProcess': 'PROCESS_THREAD', 'CreateProcessA': 'PROCESS_THREAD', 'CreateProcessW': 'PROCESS_THREAD',
        'OpenProcess': 'PROCESS_THREAD', 'TerminateProcess': 'PROCESS_THREAD', 'CreateThread': 'PROCESS_THREAD',
        'CreateRemoteThread': 'PROCESS_THREAD', 'OpenThread': 'PROCESS_THREAD', 'SuspendThread': 'PROCESS_THREAD',
        'ResumeThread': 'PROCESS_THREAD', 'GetCurrentProcess': 'PROCESS_THREAD', 'GetCurrentThread': 'PROCESS_THREAD',

        // Memory APIs
        'VirtualAlloc': 'MEMORY', 'VirtualAllocEx': 'MEMORY', 'VirtualFree': 'MEMORY',
        'VirtualProtect': 'MEMORY', 'VirtualProtectEx': 'MEMORY', 'WriteProcessMemory': 'MEMORY',
        'ReadProcessMemory': 'MEMORY', 'HeapAlloc': 'MEMORY', 'HeapFree': 'MEMORY',

        // Timing APIs
        'GetSystemTime': 'TIMING', 'GetLocalTime': 'TIMING', 'GetTickCount': 'TIMING',
        'GetTickCount64': 'TIMING', 'QueryPerformanceCounter': 'TIMING', 'QueryPerformanceFrequency': 'TIMING',
        'SetSystemTime': 'TIMING', 'SetLocalTime': 'TIMING', 'Sleep': 'TIMING',

        // Anti-Debug APIs
        'IsDebuggerPresent': 'ANTI_DEBUG', 'CheckRemoteDebuggerPresent': 'ANTI_DEBUG',
        'NtQueryInformationProcess': 'ANTI_DEBUG', 'OutputDebugString': 'ANTI_DEBUG',
        'OutputDebugStringA': 'ANTI_DEBUG', 'OutputDebugStringW': 'ANTI_DEBUG',

        // Anti-VM APIs
        'GetSystemFirmwareTable': 'ANTI_VM', 'SetupDiGetDeviceRegistryProperty': 'ANTI_VM',
        'GetAdaptersInfo': 'ANTI_VM', 'GetVolumeInformation': 'ANTI_VM',

        // Hardware APIs
        'GetDriveType': 'HARDWARE', 'GetDiskFreeSpace': 'HARDWARE', 'DeviceIoControl': 'HARDWARE',
        'GetSystemFirmwareTable': 'HARDWARE'
    };

    // Windows API definitions for hooking
    const WINDOWS_APIS = {
        'kernel32.dll': [
            'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 'DeleteFileA', 'DeleteFileW',
            'CopyFileA', 'CopyFileW', 'MoveFileA', 'MoveFileW', 'GetFileAttributesA', 'GetFileAttributesW',
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualFree', 'VirtualProtect', 'VirtualProtectEx',
            'WriteProcessMemory', 'ReadProcessMemory', 'CreateProcessA', 'CreateProcessW',
            'OpenProcess', 'TerminateProcess', 'CreateThread', 'CreateRemoteThread',
            'GetSystemTime', 'GetLocalTime', 'GetTickCount', 'GetTickCount64', 'Sleep',
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA', 'OutputDebugStringW',
            'GetSystemInfo', 'GetVersionExA', 'GetVersionExW', 'GetComputerNameA', 'GetComputerNameW',
            'GetUserNameA', 'GetUserNameW', 'GetEnvironmentVariableA', 'GetEnvironmentVariableW',
            'GetSystemFirmwareTable', 'GetVolumeInformationA', 'GetVolumeInformationW',
            'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'FreeLibrary'
        ],
        'advapi32.dll': [
            'RegOpenKeyA', 'RegOpenKeyW', 'RegOpenKeyExA', 'RegOpenKeyExW',
            'RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA', 'RegCreateKeyExW',
            'RegQueryValueA', 'RegQueryValueW', 'RegQueryValueExA', 'RegQueryValueExW',
            'RegSetValueA', 'RegSetValueW', 'RegSetValueExA', 'RegSetValueExW',
            'RegDeleteKeyA', 'RegDeleteKeyW', 'RegDeleteValueA', 'RegDeleteValueW',
            'RegCloseKey', 'RegEnumKeyA', 'RegEnumKeyW', 'RegEnumValueA', 'RegEnumValueW',
            'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptCreateHash',
            'CryptHashData', 'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
            'CryptImportKey', 'CryptExportKey', 'CryptReleaseContext'
        ],
        'wininet.dll': [
            'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
            'InternetOpenUrlA', 'InternetOpenUrlW', 'HttpSendRequestA', 'HttpSendRequestW',
            'InternetReadFile', 'InternetWriteFile', 'InternetCloseHandle'
        ],
        'winhttp.dll': [
            'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest',
            'WinHttpSendRequest', 'WinHttpReceiveResponse', 'WinHttpReadData'
        ],
        'ws2_32.dll': [
            'WSAStartup', 'WSACleanup', 'WSASocket', 'WSAConnect', 'WSASend', 'WSARecv',
            'socket', 'connect', 'send', 'recv', 'sendto', 'recvfrom', 'bind', 'listen', 'accept'
        ],
        'ntdll.dll': [
            'NtQueryInformationProcess', 'NtSetInformationProcess', 'NtCreateFile',
            'NtReadFile', 'NtWriteFile', 'NtCreateProcess', 'NtCreateProcessEx',
            'NtAllocateVirtualMemory', 'NtFreeVirtualMemory', 'NtProtectVirtualMemory'
        ]
    };

    // Linux syscalls for hooking
    const LINUX_SYSCALLS = [
        'open', 'openat', 'read', 'write', 'close', 'stat', 'fstat', 'lstat',
        'mmap', 'munmap', 'mprotect', 'brk', 'sbrk',
        'socket', 'connect', 'send', 'recv', 'sendto', 'recvfrom',
        'fork', 'execve', 'clone', 'waitpid',
        'time', 'gettimeofday', 'clock_gettime'
    ];

    /**
     * Utility functions
     */
    
    function getCurrentTimestamp() {
        return Date.now() / 1000.0;
    }

    function getNextSequenceId() {
        return ++sequenceCounter;
    }

    function categorizeAPI(functionName) {
        return API_CATEGORIES[functionName] || 'UNKNOWN';
    }

    function shouldTraceCategory(category) {
        return config.enabled_categories.includes(category);
    }

    function checkCallRateLimit() {
        const currentSecond = Math.floor(Date.now() / 1000);
        if (currentSecond !== lastSecond) {
            callCount = 0;
            lastSecond = currentSecond;
        }
        
        return ++callCount <= config.max_calls_per_second;
    }

    function serializeParameter(param, maxSize) {
        const startTime = Date.now();
        let result;
        
        try {
            if (param === null || param === undefined) {
                result = null;
            } else if (typeof param === 'string') {
                result = param.length > maxSize ? param.substring(0, maxSize) + '...' : param;
            } else if (typeof param === 'number') {
                result = param;
            } else if (typeof param === 'boolean') {
                result = param;
            } else if (param instanceof NativePointer) {
                result = param.toString();
                // Try to read string if it looks like a string pointer
                try {
                    if (!param.isNull() && param.toInt32() > 0x1000) {
                        const str = param.readUtf8String();
                        if (str && str.length > 0 && str.length < 256) {
                            result = `"${str.substring(0, maxSize)}"`;
                        }
                    }
                } catch (e) {
                    // Ignore read errors
                }
            } else if (typeof param === 'object') {
                result = `[object ${param.constructor.name || 'Object'}]`;
            } else {
                result = String(param).substring(0, maxSize);
            }
        } catch (e) {
            result = `[serialization error: ${e.message}]`;
        }
        
        performanceStats.serializationTime += Date.now() - startTime;
        return result;
    }

    function getCallStack(maxDepth) {
        const startTime = Date.now();
        const stack = [];
        
        try {
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
            
            for (let i = 0; i < Math.min(backtrace.length, maxDepth); i++) {
                const frame = backtrace[i];
                let frameInfo = frame.toString();
                
                try {
                    const module = Process.getModuleByAddress(frame);
                    const symbol = DebugSymbol.fromAddress(frame);
                    
                    if (module && symbol) {
                        frameInfo = `${module.name}!${symbol.name}+0x${frame.sub(symbol.address).toString(16)}`;
                    } else if (module) {
                        frameInfo = `${module.name}+0x${frame.sub(module.base).toString(16)}`;
                    }
                } catch (e) {
                    // Keep original frame info if symbol resolution fails
                }
                
                stack.push(frameInfo);
            }
        } catch (e) {
            stack.push(`[stack trace error: ${e.message}]`);
        }
        
        performanceStats.stackTraceTime += Date.now() - startTime;
        return stack;
    }

    function createAPICallObject(direction, module, functionName, args, retval, callStack) {
        return {
            type: 'api_call',
            timestamp: getCurrentTimestamp(),
            thread_id: Process.getCurrentThreadId(),
            process_id: Process.id,
            module: module,
            function: functionName,
            direction: direction,
            parameters: args || [],
            return_value: retval,
            call_stack: callStack || [],
            execution_time_ms: 0,
            category: categorizeAPI(functionName),
            caller_address: null,
            return_address: null,
            error_code: null,
            sequence_id: getNextSequenceId()
        };
    }

    function addToBatch(callData) {
        callBatch.push(callData);
        
        if (callBatch.length >= config.batch_size) {
            flushBatch();
        } else if (!batchTimer) {
            batchTimer = setTimeout(flushBatch, config.batch_timeout_ms);
        }
    }

    function flushBatch() {
        if (batchTimer) {
            clearTimeout(batchTimer);
            batchTimer = null;
        }
        
        if (callBatch.length > 0) {
            try {
                send({
                    type: 'batch',
                    calls: callBatch
                });
            } catch (e) {
                send({
                    type: 'error',
                    message: `Failed to send batch: ${e.message}`
                });
            }
            callBatch = [];
        }
    }

    function createHook(module, functionName) {
        try {
            const moduleHandle = getModuleHandle(module);
            if (!moduleHandle) {
                return null;
            }

            const functionAddress = moduleHandle.getExportByName(functionName);
            if (!functionAddress) {
                return null;
            }

            const category = categorizeAPI(functionName);
            if (!shouldTraceCategory(category)) {
                return null;
            }

            const hook = Interceptor.attach(functionAddress, {
                onEnter: function(args) {
                    const startTime = Date.now();
                    
                    if (!checkCallRateLimit()) {
                        return;
                    }

                    try {
                        // Serialize arguments
                        const serializedArgs = [];
                        for (let i = 0; i < Math.min(args.length, 8); i++) {
                            serializedArgs.push(serializeParameter(args[i], config.max_parameter_size));
                        }

                        // Get call stack if enabled
                        let callStack = [];
                        if (!config.performance_mode) {
                            callStack = getCallStack.call(this, config.max_call_stack_depth);
                        }

                        // Create call object
                        const callData = createAPICallObject(
                            'ENTER',
                            module,
                            functionName,
                            serializedArgs,
                            null,
                            callStack
                        );

                        // Store context for onLeave
                        this.callData = callData;
                        this.startTime = Date.now();

                        // Send or batch the call
                        addToBatch(callData);

                        performanceStats.totalCalls++;
                        performanceStats.hookTime += Date.now() - startTime;

                    } catch (e) {
                        send({
                            type: 'error',
                            message: `Hook onEnter error for ${module}!${functionName}: ${e.message}`
                        });
                    }
                },

                onLeave: function(retval) {
                    if (!this.callData) {
                        return;
                    }

                    try {
                        const executionTime = Date.now() - this.startTime;
                        
                        // Create exit call object
                        const callData = createAPICallObject(
                            'EXIT',
                            module,
                            functionName,
                            [],
                            serializeParameter(retval, config.max_parameter_size),
                            []
                        );

                        callData.execution_time_ms = executionTime;
                        callData.sequence_id = this.callData.sequence_id;

                        // Send or batch the call
                        addToBatch(callData);

                    } catch (e) {
                        send({
                            type: 'error',
                            message: `Hook onLeave error for ${module}!${functionName}: ${e.message}`
                        });
                    }
                }
            });

            return hook;

        } catch (e) {
            send({
                type: 'error',
                message: `Failed to create hook for ${module}!${functionName}: ${e.message}`
            });
            return null;
        }
    }

    function getModuleHandle(moduleName) {
        if (moduleCache.has(moduleName)) {
            return moduleCache.get(moduleName);
        }

        try {
            const module = Process.getModuleByName(moduleName);
            moduleCache.set(moduleName, module);
            return module;
        } catch (e) {
            moduleCache.set(moduleName, null);
            return null;
        }
    }

    function installWindowsHooks() {
        let hooksInstalled = 0;
        
        for (const [moduleName, functions] of Object.entries(WINDOWS_APIS)) {
            for (const functionName of functions) {
                const hook = createHook(moduleName, functionName);
                if (hook) {
                    installedHooks.set(`${moduleName}!${functionName}`, hook);
                    hooksInstalled++;
                }
            }
        }
        
        send({
            type: 'info',
            message: `Installed ${hooksInstalled} Windows API hooks`
        });
    }

    function installLinuxHooks() {
        let hooksInstalled = 0;
        
        // Hook libc functions
        const libc = Module.findExportByName(null, 'malloc');
        if (libc) {
            for (const syscall of LINUX_SYSCALLS) {
                try {
                    const address = Module.findExportByName(null, syscall);
                    if (address) {
                        const hook = createHook('libc.so.6', syscall);
                        if (hook) {
                            installedHooks.set(`libc.so.6!${syscall}`, hook);
                            hooksInstalled++;
                        }
                    }
                } catch (e) {
                    // Ignore if syscall not found
                }
            }
        }
        
        send({
            type: 'info',
            message: `Installed ${hooksInstalled} Linux syscall hooks`
        });
    }

    function installHooks() {
        send({
            type: 'info',
            message: 'Starting API hook installation'
        });

        if (Process.platform === 'windows') {
            installWindowsHooks();
        } else if (Process.platform === 'linux') {
            installLinuxHooks();
        } else {
            send({
                type: 'error',
                message: `Unsupported platform: ${Process.platform}`
            });
            return;
        }

        send({
            type: 'info',
            message: `API tracing initialized with ${installedHooks.size} hooks`
        });
    }

    function uninstallHooks() {
        for (const [name, hook] of installedHooks) {
            try {
                hook.detach();
            } catch (e) {
                send({
                    type: 'error',
                    message: `Failed to detach hook ${name}: ${e.message}`
                });
            }
        }
        
        installedHooks.clear();
        flushBatch();
        
        send({
            type: 'info',
            message: 'All hooks uninstalled'
        });
    }

    function updateConfiguration(newConfig) {
        config = Object.assign(config, newConfig);
        
        send({
            type: 'info',
            message: `Configuration updated: ${JSON.stringify(config)}`
        });
    }

    function getStatistics() {
        return {
            type: 'statistics',
            installed_hooks: installedHooks.size,
            performance_stats: performanceStats,
            batch_size: callBatch.length,
            config: config
        };
    }

    // Message handler
    recv('message', function(message) {
        const data = message.payload || message;
        
        switch (data.type) {
            case 'configure':
                updateConfiguration(data.config || {});
                break;
                
            case 'install_hooks':
                installHooks();
                break;
                
            case 'uninstall_hooks':
                uninstallHooks();
                break;
                
            case 'get_statistics':
                send(getStatistics());
                break;
                
            case 'flush_batch':
                flushBatch();
                break;
                
            default:
                send({
                    type: 'error',
                    message: `Unknown message type: ${data.type}`
                });
        }
    });

    // Auto-install hooks on script load
    setTimeout(installHooks, 100);

    // Periodic batch flushing
    setInterval(function() {
        if (callBatch.length > 0) {
            flushBatch();
        }
    }, config.batch_timeout_ms * 2);

    // Performance statistics reporting
    setInterval(function() {
        send({
            type: 'performance_stats',
            stats: performanceStats,
            batch_size: callBatch.length,
            hooks_count: installedHooks.size
        });
    }, 30000); // Every 30 seconds

    send({
        type: 'info',
        message: 'API Tracing Engine loaded and ready'
    });

})();