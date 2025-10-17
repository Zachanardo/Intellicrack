"""Frida Advanced Hooking Features.

Production-ready implementation of Stalker tracing, heap tracking,
thread monitoring, exception handling, native replacement, and RPC.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import frida


@dataclass
class StalkerTrace:
    """Instruction-level trace from Stalker."""

    thread_id: int
    timestamp: float
    instructions: List[Dict[str, Any]]  # address, mnemonic, operands
    basic_blocks: List[Tuple[int, int]]  # start, end addresses
    call_graph: Dict[int, List[int]]  # caller -> [callees]
    coverage: float  # percentage of code covered


@dataclass
class HeapAllocation:
    """Tracked heap allocation."""

    address: int
    size: int
    timestamp: float
    thread_id: int
    call_stack: List[int]
    freed: bool = False
    freed_timestamp: Optional[float] = None


@dataclass
class ThreadInfo:
    """Thread creation and monitoring info."""

    thread_id: int
    entry_point: int
    stack_base: int
    stack_size: int
    creation_time: float
    termination_time: Optional[float] = None
    parent_thread_id: Optional[int] = None
    name: Optional[str] = None


@dataclass
class ExceptionInfo:
    """Exception handler information."""

    exception_address: int
    exception_code: int
    handler_address: int
    thread_id: int
    timestamp: float
    handled: bool
    exception_record: Dict[str, Any]


class FridaStalkerEngine:
    """Advanced instruction-level tracing with Stalker."""

    def __init__(self, session: frida.core.Session):
        """Initialize the FridaStalkerEngine with a Frida session.

        Args:
            session: Frida session to attach the stalker to.

        """
        self.session = session
        self.traces: Dict[int, StalkerTrace] = {}
        self.script = None
        self._init_stalker()

    def _init_stalker(self):
        """Initialize Stalker script."""
        stalker_script = """
// Stalker Configuration
const STALKER_CONFIG = {
    events: {
        call: true,
        ret: true,
        exec: true,
        block: true,
        compile: false
    },
    onReceive: new NativeCallback(onStalkerData, 'void', ['pointer']),
    transform: new NativeCallback(transformInstruction, 'void', ['pointer'])
};

// Thread tracking
const trackedThreads = new Set();
const instructionLog = [];
const basicBlocks = [];
const callGraph = {};

// Transform function for instruction modification
function transformInstruction(iterator) {
    let instruction = Stalker.parseInstruction(iterator);

    while (instruction !== null) {
        // Log instruction details
        if (STALKER_CONFIG.events.exec) {
            const details = {
                address: instruction.address.toString(),
                mnemonic: instruction.mnemonic,
                opStr: instruction.opStr,
                size: instruction.size
            };
            instructionLog.push(details);
        }

        // Track basic blocks
        if (instruction.mnemonic === 'jmp' ||
            instruction.mnemonic === 'je' ||
            instruction.mnemonic === 'jne' ||
            instruction.mnemonic === 'call' ||
            instruction.mnemonic === 'ret') {

            const blockEnd = instruction.address.toInt32();
            if (basicBlocks.length > 0) {
                const lastBlock = basicBlocks[basicBlocks.length - 1];
                if (!lastBlock.end) {
                    lastBlock.end = blockEnd;
                }
            }
            basicBlocks.push({ start: instruction.next.toInt32(), end: null });
        }

        // Track call graph
        if (instruction.mnemonic === 'call') {
            const caller = instruction.address.toInt32();
            const target = instruction.operands[0].value.toInt32();

            if (!callGraph[caller]) {
                callGraph[caller] = [];
            }
            callGraph[caller].push(target);
        }

        iterator.putCallout(onInstructionExecuted);
        iterator.keep();

        instruction = Stalker.parseInstruction(iterator);
    }
}

// Callback for each instruction execution
function onInstructionExecuted(context) {
    // Limit log size to prevent memory issues
    if (instructionLog.length > 100000) {
        sendTraceData();
        instructionLog.length = 0;
    }
}

// Callback for Stalker data
function onStalkerData(events) {
    const buffer = Memory.readByteArray(events, 16384);
    send({
        type: 'stalker_events',
        payload: {
            threadId: Process.getCurrentThreadId(),
            data: buffer
        }
    }, buffer);
}

// Send accumulated trace data
function sendTraceData() {
    send({
        type: 'stalker_trace',
        payload: {
            threadId: Process.getCurrentThreadId(),
            timestamp: Date.now(),
            instructions: instructionLog.slice(0, 1000),  // Limit for performance
            basicBlocks: basicBlocks.slice(0, 100),
            callGraph: callGraph,
            coverage: calculateCoverage()
        }
    });
}

// Calculate code coverage
function calculateCoverage() {
    const module = Process.enumerateModules()[0];
    const codeSize = module.size;
    const uniqueAddresses = new Set(instructionLog.map(i => i.address));
    return (uniqueAddresses.size / codeSize) * 100;
}

// Start tracing a thread
function startThreadTrace(tid) {
    if (!tid) {
        tid = Process.getCurrentThreadId();
    }

    if (trackedThreads.has(tid)) {
        return { success: false, error: 'Thread already being traced' };
    }

    Stalker.follow(tid, {
        events: STALKER_CONFIG.events,
        onReceive: STALKER_CONFIG.onReceive,
        transform: STALKER_CONFIG.transform
    });

    trackedThreads.add(tid);

    send({
        type: 'stalker_started',
        payload: { threadId: tid }
    });

    return { success: true };
}

// Stop tracing a thread
function stopThreadTrace(tid) {
    if (!trackedThreads.has(tid)) {
        return { success: false, error: 'Thread not being traced' };
    }

    Stalker.unfollow(tid);
    trackedThreads.delete(tid);

    // Send final trace data
    sendTraceData();

    send({
        type: 'stalker_stopped',
        payload: { threadId: tid }
    });

    return { success: true };
}

// Export functions
rpc.exports = {
    startTrace: startThreadTrace,
    stopTrace: stopThreadTrace,
    getTraceData: sendTraceData,
    clearTrace: function() {
        instructionLog.length = 0;
        basicBlocks.length = 0;
        Object.keys(callGraph).forEach(key => delete callGraph[key]);
    }
};

// Auto-start on main thread
startThreadTrace(Process.getCurrentThreadId());
"""

        self.script = self.session.create_script(stalker_script)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message, data):
        """Handle Stalker messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "stalker_trace":
                thread_id = payload["threadId"]
                self.traces[thread_id] = StalkerTrace(
                    thread_id=thread_id,
                    timestamp=payload["timestamp"],
                    instructions=payload["instructions"],
                    basic_blocks=[(b["start"], b["end"]) for b in payload["basicBlocks"] if b["end"]],
                    call_graph=payload["callGraph"],
                    coverage=payload["coverage"],
                )

    def start_trace(self, thread_id: Optional[int] = None) -> bool:
        """Start tracing a thread."""
        try:
            result = self.script.exports.start_trace(thread_id)
            return result["success"]
        except Exception as e:
            print(f"Failed to start trace: {e}")
            return False

    def stop_trace(self, thread_id: int) -> bool:
        """Stop tracing a thread."""
        try:
            result = self.script.exports.stop_trace(thread_id)
            return result["success"]
        except Exception as e:
            print(f"Failed to stop trace: {e}")
            return False

    def get_trace(self, thread_id: int) -> Optional[StalkerTrace]:
        """Get trace for a thread."""
        return self.traces.get(thread_id)


class FridaHeapTracker:
    """Heap allocation tracking."""

    def __init__(self, session: frida.core.Session):
        """Initialize the FridaHeapTracker with a Frida session.

        Args:
            session: Frida session to attach heap tracking to.

        """
        self.session = session
        self.allocations: Dict[int, HeapAllocation] = {}
        self.script = None
        self._init_heap_tracker()

    def _init_heap_tracker(self):
        """Initialize heap tracking script."""
        heap_script = """
// Heap allocation tracking
const allocations = new Map();
const heapStats = {
    totalAllocations: 0,
    totalFrees: 0,
    currentAllocated: 0,
    peakAllocated: 0,
    totalSize: 0
};

// Hook malloc
const malloc = Module.findExportByName(null, 'malloc');
if (malloc) {
    Interceptor.attach(malloc, {
        onEnter: function(args) {
            this.size = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                const allocation = {
                    address: retval.toInt32(),
                    size: this.size,
                    timestamp: Date.now(),
                    threadId: Process.getCurrentThreadId(),
                    callStack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(addr => addr.toInt32())
                };

                allocations.set(retval.toInt32(), allocation);

                heapStats.totalAllocations++;
                heapStats.currentAllocated += this.size;
                heapStats.totalSize += this.size;

                if (heapStats.currentAllocated > heapStats.peakAllocated) {
                    heapStats.peakAllocated = heapStats.currentAllocated;
                }

                send({
                    type: 'heap_alloc',
                    payload: allocation
                });
            }
        }
    });
}

// Hook free
const free = Module.findExportByName(null, 'free');
if (free) {
    Interceptor.attach(free, {
        onEnter: function(args) {
            const addr = args[0].toInt32();
            if (allocations.has(addr)) {
                const allocation = allocations.get(addr);

                heapStats.totalFrees++;
                heapStats.currentAllocated -= allocation.size;

                allocations.delete(addr);

                send({
                    type: 'heap_free',
                    payload: {
                        address: addr,
                        timestamp: Date.now()
                    }
                });
            }
        }
    });
}

// Hook realloc
const realloc = Module.findExportByName(null, 'realloc');
if (realloc) {
    Interceptor.attach(realloc, {
        onEnter: function(args) {
            this.oldPtr = args[0].toInt32();
            this.newSize = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                const newAddr = retval.toInt32();

                // Remove old allocation
                if (this.oldPtr && allocations.has(this.oldPtr)) {
                    const oldAlloc = allocations.get(this.oldPtr);
                    heapStats.currentAllocated -= oldAlloc.size;
                    allocations.delete(this.oldPtr);
                }

                // Add new allocation
                const allocation = {
                    address: newAddr,
                    size: this.newSize,
                    timestamp: Date.now(),
                    threadId: Process.getCurrentThreadId(),
                    callStack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(addr => addr.toInt32())
                };

                allocations.set(newAddr, allocation);
                heapStats.currentAllocated += this.newSize;

                send({
                    type: 'heap_realloc',
                    payload: {
                        oldAddress: this.oldPtr,
                        newAddress: newAddr,
                        size: this.newSize
                    }
                });
            }
        }
    });
}

// Hook calloc
const calloc = Module.findExportByName(null, 'calloc');
if (calloc) {
    Interceptor.attach(calloc, {
        onEnter: function(args) {
            this.count = args[0].toInt32();
            this.size = args[1].toInt32();
            this.totalSize = this.count * this.size;
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                const allocation = {
                    address: retval.toInt32(),
                    size: this.totalSize,
                    timestamp: Date.now(),
                    threadId: Process.getCurrentThreadId(),
                    callStack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(addr => addr.toInt32())
                };

                allocations.set(retval.toInt32(), allocation);
                heapStats.totalAllocations++;
                heapStats.currentAllocated += this.totalSize;

                send({
                    type: 'heap_calloc',
                    payload: allocation
                });
            }
        }
    });
}

// Export functions
rpc.exports = {
    getHeapStats: function() {
        return heapStats;
    },
    getAllocations: function() {
        return Array.from(allocations.values());
    },
    findLeaks: function() {
        const leaks = [];
        const now = Date.now();

        for (const [addr, alloc] of allocations) {
            if (now - alloc.timestamp > 60000) {  // Older than 1 minute
                leaks.push(alloc);
            }
        }

        return leaks;
    }
};

send({ type: 'heap_tracking_ready' });
"""

        self.script = self.session.create_script(heap_script)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message, data):
        """Handle heap tracking messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "heap_alloc":
                addr = payload["address"]
                self.allocations[addr] = HeapAllocation(
                    address=addr,
                    size=payload["size"],
                    timestamp=payload["timestamp"],
                    thread_id=payload["threadId"],
                    call_stack=payload["callStack"],
                )

            elif msg_type == "heap_free":
                addr = payload["address"]
                if addr in self.allocations:
                    self.allocations[addr].freed = True
                    self.allocations[addr].freed_timestamp = payload["timestamp"]

    def get_stats(self) -> Dict[str, Any]:
        """Get heap statistics."""
        return self.script.exports.get_heap_stats()

    def find_leaks(self) -> List[HeapAllocation]:
        """Find potential memory leaks."""
        leaks = self.script.exports.find_leaks()
        return [self.allocations.get(leak["address"]) for leak in leaks if leak["address"] in self.allocations]


class FridaThreadMonitor:
    """Thread creation and termination monitoring."""

    def __init__(self, session: frida.core.Session):
        """Initialize the FridaThreadMonitor with a Frida session.

        Args:
            session: Frida session to monitor threads in.

        """
        self.session = session
        self.threads: Dict[int, ThreadInfo] = {}
        self.script = None
        self._init_thread_monitor()

    def _init_thread_monitor(self):
        """Initialize thread monitoring script."""
        thread_script = """
// Thread monitoring
const threads = new Map();

// Windows thread creation
if (Process.platform === 'windows') {
    const CreateThread = Module.findExportByName('kernel32.dll', 'CreateThread');
    if (CreateThread) {
        Interceptor.attach(CreateThread, {
            onEnter: function(args) {
                this.lpStartAddress = args[2];
                this.lpParameter = args[3];
            },
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    const threadHandle = retval.toInt32();
                    const threadInfo = {
                        threadId: threadHandle,
                        entryPoint: this.lpStartAddress.toInt32(),
                        creationTime: Date.now(),
                        parentThreadId: Process.getCurrentThreadId()
                    };

                    threads.set(threadHandle, threadInfo);

                    send({
                        type: 'thread_created',
                        payload: threadInfo
                    });
                }
            }
        });
    }

    const ExitThread = Module.findExportByName('kernel32.dll', 'ExitThread');
    if (ExitThread) {
        Interceptor.attach(ExitThread, {
            onEnter: function(args) {
                const threadId = Process.getCurrentThreadId();

                send({
                    type: 'thread_terminated',
                    payload: {
                        threadId: threadId,
                        exitCode: args[0].toInt32(),
                        timestamp: Date.now()
                    }
                });
            }
        });
    }
}

// Linux/Android thread creation
else {
    const pthread_create = Module.findExportByName(null, 'pthread_create');
    if (pthread_create) {
        Interceptor.attach(pthread_create, {
            onEnter: function(args) {
                this.threadPtr = args[0];
                this.startRoutine = args[2];
                this.arg = args[3];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) {
                    const threadId = this.threadPtr.readPointer().toInt32();
                    const threadInfo = {
                        threadId: threadId,
                        entryPoint: this.startRoutine.toInt32(),
                        creationTime: Date.now(),
                        parentThreadId: Process.getCurrentThreadId()
                    };

                    threads.set(threadId, threadInfo);

                    send({
                        type: 'thread_created',
                        payload: threadInfo
                    });
                }
            }
        });
    }

    const pthread_exit = Module.findExportByName(null, 'pthread_exit');
    if (pthread_exit) {
        Interceptor.attach(pthread_exit, {
            onEnter: function(args) {
                const threadId = Process.getCurrentThreadId();

                send({
                    type: 'thread_terminated',
                    payload: {
                        threadId: threadId,
                        timestamp: Date.now()
                    }
                });
            }
        });
    }
}

// Get thread information
function getThreadInfo(tid) {
    if (Process.platform === 'windows') {
        // Use Windows API to get thread info
        const GetThreadTimes = new NativeFunction(
            Module.findExportByName('kernel32.dll', 'GetThreadTimes'),
            'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
        );

        const creationTime = Memory.alloc(8);
        const exitTime = Memory.alloc(8);
        const kernelTime = Memory.alloc(8);
        const userTime = Memory.alloc(8);

        if (GetThreadTimes(ptr(tid), creationTime, exitTime, kernelTime, userTime)) {
            return {
                creationTime: creationTime.readU64().toNumber(),
                kernelTime: kernelTime.readU64().toNumber(),
                userTime: userTime.readU64().toNumber()
            };
        }
    }
    return null;
}

// Export functions
rpc.exports = {
    getThreads: function() {
        return Array.from(threads.values());
    },
    getThreadInfo: getThreadInfo,
    getCurrentThreads: function() {
        return Process.enumerateThreads();
    }
};

send({ type: 'thread_monitor_ready' });
"""

        self.script = self.session.create_script(thread_script)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message, data):
        """Handle thread monitoring messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "thread_created":
                tid = payload["threadId"]
                self.threads[tid] = ThreadInfo(
                    thread_id=tid,
                    entry_point=payload["entryPoint"],
                    stack_base=0,  # Would need platform-specific code
                    stack_size=0,
                    creation_time=payload["creationTime"],
                    parent_thread_id=payload.get("parentThreadId"),
                )

            elif msg_type == "thread_terminated":
                tid = payload["threadId"]
                if tid in self.threads:
                    self.threads[tid].termination_time = payload["timestamp"]

    def get_threads(self) -> List[ThreadInfo]:
        """Get all tracked threads."""
        return list(self.threads.values())

    def get_current_threads(self) -> List[Dict[str, Any]]:
        """Get current system threads."""
        return self.script.exports.get_current_threads()


class FridaExceptionHooker:
    """Exception handler hooking."""

    def __init__(self, session: frida.core.Session):
        """Initialize the FridaExceptionHooker with a Frida session.

        Args:
            session: Frida session to hook exceptions in.

        """
        self.session = session
        self.exceptions: List[ExceptionInfo] = []
        self.script = None
        self._init_exception_hooker()

    def _init_exception_hooker(self):
        """Initialize exception hooking script."""
        exception_script = """
// Exception handling hooks
const exceptions = [];

if (Process.platform === 'windows') {
    // Hook SetUnhandledExceptionFilter
    const SetUnhandledExceptionFilter = Module.findExportByName('kernel32.dll', 'SetUnhandledExceptionFilter');
    if (SetUnhandledExceptionFilter) {
        Interceptor.attach(SetUnhandledExceptionFilter, {
            onEnter: function(args) {
                send({
                    type: 'exception_filter_set',
                    payload: {
                        handler: args[0].toInt32()
                    }
                });
            }
        });
    }

    // Hook RtlDispatchException
    const RtlDispatchException = Module.findExportByName('ntdll.dll', 'RtlDispatchException');
    if (RtlDispatchException) {
        Interceptor.attach(RtlDispatchException, {
            onEnter: function(args) {
                const exceptionRecord = args[0];
                const context = args[1];

                const exception = {
                    exceptionCode: exceptionRecord.readU32(),
                    exceptionFlags: exceptionRecord.add(4).readU32(),
                    exceptionAddress: exceptionRecord.add(16).readPointer().toInt32(),
                    numberOfParameters: exceptionRecord.add(20).readU32(),
                    threadId: Process.getCurrentThreadId(),
                    timestamp: Date.now()
                };

                exceptions.push(exception);

                send({
                    type: 'exception_raised',
                    payload: exception
                });
            },
            onLeave: function(retval) {
                const handled = retval.toInt32() !== 0;

                if (exceptions.length > 0) {
                    const lastException = exceptions[exceptions.length - 1];
                    lastException.handled = handled;

                    send({
                        type: 'exception_handled',
                        payload: {
                            handled: handled,
                            exception: lastException
                        }
                    });
                }
            }
        });
    }
}

// Linux signal handling
else {
    const sigaction = Module.findExportByName(null, 'sigaction');
    if (sigaction) {
        Interceptor.attach(sigaction, {
            onEnter: function(args) {
                const signum = args[0].toInt32();
                const handler = args[1];

                send({
                    type: 'signal_handler_set',
                    payload: {
                        signal: signum,
                        handler: handler.toInt32()
                    }
                });
            }
        });
    }
}

// C++ exception handling
const __cxa_throw = Module.findExportByName(null, '__cxa_throw');
if (__cxa_throw) {
    Interceptor.attach(__cxa_throw, {
        onEnter: function(args) {
            const exception = args[0];
            const type = args[1];
            const destructor = args[2];

            send({
                type: 'cpp_exception',
                payload: {
                    exception: exception.toInt32(),
                    type: type.toInt32(),
                    destructor: destructor.toInt32(),
                    threadId: Process.getCurrentThreadId(),
                    timestamp: Date.now()
                }
            });
        }
    });
}

// Export functions
rpc.exports = {
    getExceptions: function() {
        return exceptions;
    },
    clearExceptions: function() {
        exceptions.length = 0;
    }
};

send({ type: 'exception_hooking_ready' });
"""

        self.script = self.session.create_script(exception_script)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message, data):
        """Handle exception messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "exception_raised":
                self.exceptions.append(
                    ExceptionInfo(
                        exception_address=payload.get("exceptionAddress", 0),
                        exception_code=payload.get("exceptionCode", 0),
                        handler_address=0,
                        thread_id=payload["threadId"],
                        timestamp=payload["timestamp"],
                        handled=False,
                        exception_record=payload,
                    )
                )

            elif msg_type == "exception_handled":
                if self.exceptions:
                    self.exceptions[-1].handled = payload["handled"]

    def get_exceptions(self) -> List[ExceptionInfo]:
        """Get all tracked exceptions."""
        return self.exceptions

    def clear_exceptions(self):
        """Clear exception history."""
        self.exceptions.clear()
        self.script.exports.clear_exceptions()


class FridaNativeReplacer:
    """Native function replacement system."""

    def __init__(self, session: frida.core.Session):
        """Initialize the FridaNativeReplacer with a Frida session.

        Args:
            session: Frida session to replace native functions in.

        """
        self.session = session
        self.replacements: Dict[int, Dict[str, Any]] = {}
        self.script = None
        self._init_replacer()

    def _init_replacer(self):
        """Initialize native function replacement."""
        replacer_script = """
// Native function replacement
const replacements = new Map();
const originals = new Map();

// Replace a native function
function replaceNativeFunction(address, newImpl, signature) {
    const addr = ptr(address);

    // Save original
    if (!originals.has(address)) {
        originals.set(address, new NativeFunction(addr, signature.ret, signature.args));
    }

    // Create replacement
    const replacement = new NativeCallback(function() {
        const args = Array.from(arguments);

        // Call custom implementation
        const result = newImpl.apply(this, args);

        // Log replacement call
        send({
            type: 'function_replaced',
            payload: {
                address: address,
                args: args.map(a => a.toString()),
                result: result ? result.toString() : null
            }
        });

        return result;
    }, signature.ret, signature.args);

    // Perform replacement
    Interceptor.replace(addr, replacement);
    replacements.set(address, {
        original: originals.get(address),
        replacement: replacement,
        signature: signature
    });

    return true;
}

// Restore original function
function restoreNativeFunction(address) {
    if (!replacements.has(address)) {
        return false;
    }

    const info = replacements.get(address);
    Interceptor.revert(ptr(address));
    replacements.delete(address);

    send({
        type: 'function_restored',
        payload: { address: address }
    });

    return true;
}

// Call original function
function callOriginal(address, args) {
    if (!originals.has(address)) {
        throw new Error('No original function saved for address: ' + address);
    }

    const original = originals.get(address);
    return original.apply(null, args);
}

// Common replacements for licensing functions
const licensingReplacements = {
    // Always return success for validation
    alwaysValid: function() {
        return 1;  // TRUE
    },

    // Return fixed serial number
    returnSerial: function() {
        const serial = Memory.allocUtf8String('INTL-CRACK-2025-VALID');
        return serial;
    },

    // Return fixed hardware ID
    returnHWID: function() {
        const hwid = Memory.allocUtf8String('ABCD-1234-5678-90EF');
        return hwid;
    },

    // Skip time checks
    skipTimeCheck: function() {
        return 0;  // No expiry
    }
};

// Export functions
rpc.exports = {
    replace: function(address, implName, retType, argTypes) {
        const impl = licensingReplacements[implName];
        if (!impl) {
            throw new Error('Unknown implementation: ' + implName);
        }

        const signature = {
            ret: retType || 'int',
            args: argTypes || []
        };

        return replaceNativeFunction(address, impl, signature);
    },

    restore: restoreNativeFunction,

    callOriginal: callOriginal,

    getReplacements: function() {
        const result = {};
        for (const [addr, info] of replacements) {
            result[addr] = {
                signature: info.signature
            };
        }
        return result;
    }
};

send({ type: 'replacer_ready' });
"""

        self.script = self.session.create_script(replacer_script)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message, data):
        """Handle replacement messages."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "function_replaced":
                addr = payload["address"]
                self.replacements[addr] = {"args": payload["args"], "result": payload["result"]}

    def replace_function(self, address: int, impl_name: str, ret_type: str = "int", arg_types: List[str] = None) -> bool:
        """Replace a native function."""
        try:
            return self.script.exports.replace(address, impl_name, ret_type, arg_types or [])
        except Exception as e:
            print(f"Failed to replace function: {e}")
            return False

    def restore_function(self, address: int) -> bool:
        """Restore original function."""
        try:
            return self.script.exports.restore(address)
        except Exception as e:
            print(f"Failed to restore function: {e}")
            return False


class FridaRPCInterface:
    """RPC interface for complex operations."""

    def __init__(self, session: frida.core.Session):
        """Initialize the FridaRPCInterface with a Frida session.

        Args:
            session: Frida session to create RPC interface for.

        """
        self.session = session
        self.script = None
        self._init_rpc()

    def _init_rpc(self):
        """Initialize RPC interface."""
        rpc_script = """
// RPC Interface for complex operations

// Memory operations
const memoryOps = {
    read: function(address, size) {
        return Memory.readByteArray(ptr(address), size);
    },

    write: function(address, bytes) {
        Memory.writeByteArray(ptr(address), bytes);
        return true;
    },

    allocate: function(size) {
        return Memory.alloc(size).toInt32();
    },

    protect: function(address, size, protection) {
        Memory.protect(ptr(address), size, protection);
        return true;
    },

    scan: function(pattern, limit) {
        const results = [];
        const ranges = Process.enumerateRanges('r--');

        for (const range of ranges) {
            if (results.length >= limit) break;

            try {
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function(address, size) {
                        results.push({
                            address: address.toInt32(),
                            size: size
                        });
                        return results.length < limit;
                    }
                });
            } catch (e) {}
        }

        return results;
    }
};

// Module operations
const moduleOps = {
    enumerate: function() {
        return Process.enumerateModules();
    },

    findExport: function(module, name) {
        const addr = Module.findExportByName(module, name);
        return addr ? addr.toInt32() : null;
    },

    getBaseAddress: function(module) {
        const mod = Module.findBaseAddress(module);
        return mod ? mod.toInt32() : null;
    },

    load: function(path) {
        return Module.load(path).base.toInt32();
    }
};

// Process operations
const processOps = {
    getInfo: function() {
        return {
            pid: Process.id,
            platform: Process.platform,
            arch: Process.arch,
            pageSize: Process.pageSize,
            pointerSize: Process.pointerSize
        };
    },

    terminate: function(exitCode) {
        Process.terminate(exitCode || 0);
    },

    setExceptionHandler: function() {
        Process.setExceptionHandler(function(details) {
            send({
                type: 'exception',
                payload: details
            });
            return true;  // handled
        });
    }
};

// File operations
const fileOps = {
    read: function(path) {
        const file = new File(path, 'rb');
        const contents = file.readBytes();
        file.close();
        return contents;
    },

    write: function(path, data) {
        const file = new File(path, 'wb');
        file.write(data);
        file.close();
        return true;
    },

    exists: function(path) {
        try {
            const file = new File(path, 'rb');
            file.close();
            return true;
        } catch (e) {
            return false;
        }
    }
};

// Registry operations (Windows)
const registryOps = Process.platform === 'windows' ? {
    read: function(hive, key, value) {
        const advapi32 = Module.load('advapi32.dll');
        const kernel32 = Module.load('kernel32.dll');

        // Windows API functions
        const RegOpenKeyExW = new NativeFunction(
            Module.findExportByName('advapi32.dll', 'RegOpenKeyExW'),
            'long', ['pointer', 'pointer', 'ulong', 'ulong', 'pointer']
        );

        const RegQueryValueExW = new NativeFunction(
            Module.findExportByName('advapi32.dll', 'RegQueryValueExW'),
            'long', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
        );

        const RegCloseKey = new NativeFunction(
            Module.findExportByName('advapi32.dll', 'RegCloseKey'),
            'long', ['pointer']
        );

        // Convert hive string to HKEY constant
        const hiveMap = {
            'HKLM': ptr('0x80000002'),
            'HKCU': ptr('0x80000001'),
            'HKCR': ptr('0x80000000'),
            'HKU': ptr('0x80000003'),
            'HKCC': ptr('0x80000005')
        };

        const hKey = hiveMap[hive];
        if (!hKey) return null;

        // Open registry key
        const hKeyHandle = Memory.alloc(Process.pointerSize);
        const keyPath = Memory.allocUtf16String(key);
        const KEY_READ = 0x20019;

        const openResult = RegOpenKeyExW(hKey, keyPath, 0, KEY_READ, hKeyHandle);
        if (openResult !== 0) return null;

        const hKeyValue = hKeyHandle.readPointer();

        // Query value
        const valueName = Memory.allocUtf16String(value);
        const dataSize = Memory.alloc(4);
        dataSize.writeU32(1024);
        const dataBuffer = Memory.alloc(1024);
        const dataType = Memory.alloc(4);

        const queryResult = RegQueryValueExW(
            hKeyValue,
            valueName,
            NULL,
            dataType,
            dataBuffer,
            dataSize
        );

        let result = null;
        if (queryResult === 0) {
            const type = dataType.readU32();
            const size = dataSize.readU32();

            // Parse based on registry value type
            if (type === 1) { // REG_SZ
                result = dataBuffer.readUtf16String();
            } else if (type === 4) { // REG_DWORD
                result = dataBuffer.readU32();
            } else if (type === 11) { // REG_QWORD
                result = dataBuffer.readU64();
            } else if (type === 3) { // REG_BINARY
                result = dataBuffer.readByteArray(size);
            } else if (type === 7) { // REG_MULTI_SZ
                const strings = [];
                let offset = 0;
                while (offset < size - 2) {
                    const str = dataBuffer.add(offset).readUtf16String();
                    if (!str) break;
                    strings.push(str);
                    offset += (str.length + 1) * 2;
                }
                result = strings;
            }
        }

        RegCloseKey(hKeyValue);
        return result;
    },

    write: function(hive, key, value, data) {
        const advapi32 = Module.load('advapi32.dll');

        // Windows API functions
        const RegOpenKeyExW = new NativeFunction(
            Module.findExportByName('advapi32.dll', 'RegOpenKeyExW'),
            'long', ['pointer', 'pointer', 'ulong', 'ulong', 'pointer']
        );

        const RegSetValueExW = new NativeFunction(
            Module.findExportByName('advapi32.dll', 'RegSetValueExW'),
            'long', ['pointer', 'pointer', 'ulong', 'ulong', 'pointer', 'ulong']
        );

        const RegCloseKey = new NativeFunction(
            Module.findExportByName('advapi32.dll', 'RegCloseKey'),
            'long', ['pointer']
        );

        // Convert hive string to HKEY constant
        const hiveMap = {
            'HKLM': ptr('0x80000002'),
            'HKCU': ptr('0x80000001'),
            'HKCR': ptr('0x80000000'),
            'HKU': ptr('0x80000003'),
            'HKCC': ptr('0x80000005')
        };

        const hKey = hiveMap[hive];
        if (!hKey) return false;

        // Open registry key with write access
        const hKeyHandle = Memory.alloc(Process.pointerSize);
        const keyPath = Memory.allocUtf16String(key);
        const KEY_WRITE = 0x20006;

        const openResult = RegOpenKeyExW(hKey, keyPath, 0, KEY_WRITE, hKeyHandle);
        if (openResult !== 0) return false;

        const hKeyValue = hKeyHandle.readPointer();

        // Prepare value data based on type
        const valueName = Memory.allocUtf16String(value);
        let dataBuffer;
        let dataSize;
        let dataType;

        if (typeof data === 'string') {
            dataType = 1; // REG_SZ
            dataBuffer = Memory.allocUtf16String(data);
            dataSize = (data.length + 1) * 2;
        } else if (typeof data === 'number') {
            if (data <= 0xFFFFFFFF) {
                dataType = 4; // REG_DWORD
                dataBuffer = Memory.alloc(4);
                dataBuffer.writeU32(data);
                dataSize = 4;
            } else {
                dataType = 11; // REG_QWORD
                dataBuffer = Memory.alloc(8);
                dataBuffer.writeU64(data);
                dataSize = 8;
            }
        } else if (Array.isArray(data)) {
            if (data.every(item => typeof item === 'string')) {
                dataType = 7; // REG_MULTI_SZ
                const multiStr = data.join('\\0') + '\\0\\0';
                dataBuffer = Memory.allocUtf16String(multiStr);
                dataSize = multiStr.length * 2;
            } else {
                dataType = 3; // REG_BINARY
                dataBuffer = Memory.alloc(data.length);
                dataBuffer.writeByteArray(data);
                dataSize = data.length;
            }
        } else {
            RegCloseKey(hKeyValue);
            return false;
        }

        // Set the registry value
        const setResult = RegSetValueExW(
            hKeyValue,
            valueName,
            0,
            dataType,
            dataBuffer,
            dataSize
        );

        RegCloseKey(hKeyValue);
        return setResult === 0;
    }
} : null;

// Export all operations
rpc.exports = {
    memory: memoryOps,
    module: moduleOps,
    process: processOps,
    file: fileOps,
    registry: registryOps,

    // Custom script execution
    evaluate: function(code) {
        try {
            return eval(code);
        } catch (e) {
            throw new Error(e.toString());
        }
    }
};

send({ type: 'rpc_ready' });
"""

        self.script = self.session.create_script(rpc_script)
        self.script.on("message", lambda m, d: None)
        self.script.load()

    def memory_read(self, address: int, size: int) -> bytes:
        """Read memory."""
        return self.script.exports.memory.read(address, size)

    def memory_write(self, address: int, data: bytes) -> bool:
        """Write memory."""
        return self.script.exports.memory.write(address, data)

    def memory_scan(self, pattern: str, limit: int = 10) -> List[Dict[str, int]]:
        """Scan memory for pattern."""
        return self.script.exports.memory.scan(pattern, limit)

    def module_find_export(self, module: str, name: str) -> Optional[int]:
        """Find module export."""
        return self.script.exports.module.find_export(module, name)

    def evaluate(self, code: str) -> Any:
        """Evaluate JavaScript code."""
        return self.script.exports.evaluate(code)


class FridaAdvancedHooking:
    """Run class for advanced hooking features."""

    def __init__(self, session: frida.core.Session):
        """Initialize the FridaAdvancedHooking with a Frida session.

        Args:
            session: Frida session to attach advanced hooking features to.

        """
        self.session = session
        self.stalker = None
        self.heap_tracker = None
        self.thread_monitor = None
        self.exception_hooker = None
        self.native_replacer = None
        self.rpc_interface = None

    def init_stalker(self) -> FridaStalkerEngine:
        """Initialize Stalker engine."""
        self.stalker = FridaStalkerEngine(self.session)
        return self.stalker

    def init_heap_tracker(self) -> FridaHeapTracker:
        """Initialize heap tracking."""
        self.heap_tracker = FridaHeapTracker(self.session)
        return self.heap_tracker

    def init_thread_monitor(self) -> FridaThreadMonitor:
        """Initialize thread monitoring."""
        self.thread_monitor = FridaThreadMonitor(self.session)
        return self.thread_monitor

    def init_exception_hooker(self) -> FridaExceptionHooker:
        """Initialize exception hooking."""
        self.exception_hooker = FridaExceptionHooker(self.session)
        return self.exception_hooker

    def init_native_replacer(self) -> FridaNativeReplacer:
        """Initialize native function replacement."""
        self.native_replacer = FridaNativeReplacer(self.session)
        return self.native_replacer

    def init_rpc_interface(self) -> FridaRPCInterface:
        """Initialize RPC interface."""
        self.rpc_interface = FridaRPCInterface(self.session)
        return self.rpc_interface

    def init_all(self):
        """Initialize all advanced features."""
        self.init_stalker()
        self.init_heap_tracker()
        self.init_thread_monitor()
        self.init_exception_hooker()
        self.init_native_replacer()
        self.init_rpc_interface()
        return self
