"""Frida Advanced Hooking Features.

Production-ready implementation of Stalker tracing, heap tracking,
thread monitoring, exception handling, native replacement, and RPC.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast

import frida

from intellicrack.utils.type_safety import ensure_dict, validate_type


if TYPE_CHECKING:

    from frida.core import ScriptExportsSync, ScriptMessage


logger = logging.getLogger(__name__)


class MemoryExportsProtocol(Protocol):
    """Protocol for Frida memory exports with read/write/scan methods."""

    def read(self, address: int, size: int) -> bytes:
        """Read memory at address.

        Args:
            address: Memory address to read from.
            size: Number of bytes to read.
        """
        ...

    def write(self, address: int, data: bytes) -> bool:
        """Write data to memory at address.

        Args:
            address: Memory address to write to.
            data: Bytes to write to memory.
        """
        ...

    def scan(self, pattern: str, limit: int) -> list[dict[str, Any]]:
        """Scan memory for pattern.

        Args:
            pattern: Pattern string to search for in memory.
            limit: Maximum number of matches to return.
        """
        ...


class ModuleExportsProtocol(Protocol):
    """Protocol for Frida module exports with find_export method."""

    def find_export(self, module: str, name: str) -> int | None:
        """Find export by name in module.

        Args:
            module: Name of the module to search.
            name: Name of the exported function.
        """
        ...


@dataclass
class StalkerTrace:
    """Instruction-level trace from Stalker."""

    thread_id: int
    timestamp: float
    instructions: list[dict[str, object]]
    basic_blocks: list[tuple[int, int]]
    call_graph: dict[int, list[int]]
    coverage: float


@dataclass
class HeapAllocation:
    """Tracked heap allocation."""

    address: int
    size: int
    timestamp: float
    thread_id: int
    call_stack: list[int]
    freed: bool = False
    freed_timestamp: float | None = None


@dataclass
class ThreadInfo:
    """Thread creation and monitoring info."""

    thread_id: int
    entry_point: int
    stack_base: int
    stack_size: int
    creation_time: float
    termination_time: float | None = None
    parent_thread_id: int | None = None
    name: str | None = None


@dataclass
class ExceptionInfo:
    """Exception handler information."""

    exception_address: int
    exception_code: int
    handler_address: int
    thread_id: int
    timestamp: float
    handled: bool
    exception_record: dict[str, object]


class FridaStalkerEngine:
    """Advanced instruction-level tracing with Stalker."""

    def __init__(self, session: frida.core.Session) -> None:
        """Initialize the FridaStalkerEngine with a Frida session.

        Args:
            session: Frida session to attach the stalker to.
        """
        self.session = session
        self.traces: dict[int, StalkerTrace] = {}
        self.script: frida.core.Script
        self._init_stalker()

    def _init_stalker(self) -> None:
        """Initialize Stalker script.

        Sets up the Frida Stalker engine for instruction-level tracing with
        thread tracking, basic block detection, and call graph analysis.
        Includes comprehensive error handling for crashes, invalid instructions,
        memory access violations, and anti-instrumentation detection.
        """
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
    maxRetries: 3,
    enableRecovery: true,
    maxInstructionLogSize: 100000,
    maxBasicBlocksSize: 10000,
    maxErrorLogSize: 100,
    trustThreshold: 3,
    timingNormalizationEnabled: true
};

// Thread tracking with per-thread state for race condition prevention
const trackedThreads = new Set();
const instructionLog = [];
const basicBlocks = [];
const callGraph = {};
const errorLog = [];
const sessionState = {
    active: true,
    crashCount: 0,
    lastError: null,
    recoveryMode: false
};

// Per-thread state management to prevent race conditions (HIGH-003)
const threadLocalState = new Map();

// Memory validation helper
function isValidMemoryRegion(address) {
    try {
        const ranges = Process.enumerateRanges('r--');
        const addr = ptr(address);

        for (const range of ranges) {
            if (addr.compare(range.base) >= 0 &&
                addr.compare(range.base.add(range.size)) < 0) {
                return true;
            }
        }
        return false;
    } catch (e) {
        logError('Memory validation failed', e, address);
        return false;
    }
}

// Validate instruction boundary
function isValidInstructionBoundary(address, size) {
    try {
        if (size <= 0 || size > 15) {
            return false;
        }

        const addr = ptr(address);
        const endAddr = addr.add(size);

        return isValidMemoryRegion(addr) && isValidMemoryRegion(endAddr.sub(1));
    } catch (e) {
        logError('Instruction boundary validation failed', e, address);
        return false;
    }
}

// Error logging with context and circular buffer (HIGH-002)
function logError(context, error, additionalInfo) {
    const errorEntry = {
        timestamp: Date.now(),
        context: context,
        error: error ? error.toString() : 'Unknown error',
        additionalInfo: additionalInfo || null,
        threadId: Process.getCurrentThreadId(),
        stackTrace: error && error.stack ? error.stack : null
    };

    errorLog.push(errorEntry);

    if (errorLog.length > STALKER_CONFIG.maxErrorLogSize) {
        errorLog.splice(0, errorLog.length - STALKER_CONFIG.maxErrorLogSize);
    }

    send({
        type: 'stalker_error',
        payload: errorEntry
    });
}

// Session recovery mechanism
function attemptRecovery(threadId) {
    if (!STALKER_CONFIG.enableRecovery) {
        return false;
    }

    try {
        sessionState.recoveryMode = true;

        Stalker.flush();
        Stalker.garbageCollect();

        instructionLog.length = Math.min(instructionLog.length, 1000);
        basicBlocks.length = Math.min(basicBlocks.length, 100);

        sessionState.recoveryMode = false;

        send({
            type: 'stalker_recovery_success',
            payload: { threadId: threadId }
        });

        return true;
    } catch (e) {
        sessionState.recoveryMode = false;
        logError('Recovery attempt failed', e, threadId);
        return false;
    }
}

// Transform function with comprehensive error handling (CRITICAL-001, CRITICAL-002 fixes)
function transformInstruction(iterator) {
    if (!sessionState.active) {
        return;
    }

    const currentThreadId = Process.getCurrentThreadId();

    if (!threadLocalState.has(currentThreadId)) {
        threadLocalState.set(currentThreadId, {
            skipCount: 0,
            lastError: null,
            active: true
        });
    }

    const threadState = threadLocalState.get(currentThreadId);
    if (!threadState.active) {
        return;
    }

    let instruction = null;
    let parseAttempts = 0;
    const maxParseAttempts = STALKER_CONFIG.maxRetries;

    try {
        while (parseAttempts < maxParseAttempts) {
            try {
                instruction = iterator.next();
                break;
            } catch (parseError) {
                parseAttempts++;

                if (parseAttempts >= maxParseAttempts) {
                    logError('iterator.next() failed after retries', parseError, {
                        attempts: parseAttempts,
                        iterator: iterator ? iterator.toString() : 'null'
                    });

                    try {
                        iterator.keep();
                    } catch (keepError) {
                        logError('Failed to keep instruction after parse failure', keepError);
                    }
                    return;
                }

                threadState.skipCount++;
                if (threadState.skipCount > 10) {
                    threadState.active = false;
                    return;
                }
            }
        }

        while (instruction !== null) {
            try {
                if (!instruction.address) {
                    logError('Invalid instruction: null address', null, instruction);
                    iterator.keep();
                    break;
                }

                const instructionAddr = instruction.address;
                const instructionSize = instruction.size || 0;

                if (!isValidInstructionBoundary(instructionAddr, instructionSize)) {
                    logError('Invalid instruction boundary detected', null, {
                        address: instructionAddr.toString(),
                        size: instructionSize
                    });
                    iterator.keep();
                    break;
                }

                if (STALKER_CONFIG.events.exec) {
                    try {
                        const details = {
                            address: instructionAddr.toString(),
                            mnemonic: instruction.mnemonic || 'unknown',
                            opStr: instruction.opStr || '',
                            size: instructionSize
                        };

                        if (instructionLog.length < STALKER_CONFIG.maxInstructionLogSize) {
                            instructionLog.push(details);
                        } else if (!sessionState.recoveryMode) {
                            attemptRecovery(Process.getCurrentThreadId());
                        }
                    } catch (logError_) {
                        logError('Failed to log instruction details', logError_, instructionAddr.toString());
                    }
                }

                try {
                    const mnemonic = instruction.mnemonic || '';

                    if (mnemonic === 'jmp' || mnemonic === 'je' || mnemonic === 'jne' ||
                        mnemonic === 'call' || mnemonic === 'ret') {

                        const blockEnd = parseInt(instructionAddr.toString());

                        if (basicBlocks.length > 0 && basicBlocks.length < STALKER_CONFIG.maxBasicBlocksSize) {
                            const lastBlock = basicBlocks[basicBlocks.length - 1];
                            if (lastBlock && !lastBlock.end) {
                                lastBlock.end = blockEnd;
                            }
                        }

                        if (instruction.next && isValidMemoryRegion(instruction.next)) {
                            const nextAddr = parseInt(instruction.next.toString());

                            if (basicBlocks.length < STALKER_CONFIG.maxBasicBlocksSize) {
                                basicBlocks.push({ start: nextAddr, end: null });
                            }
                        }
                    }

                    if (mnemonic === 'call' && instruction.operands && instruction.operands.length > 0) {
                        try {
                            const caller = parseInt(instructionAddr.toString());
                            const targetOperand = instruction.operands[0];

                            if (targetOperand && targetOperand.value) {
                                const target = parseInt(targetOperand.value.toString());

                                if (!callGraph[caller]) {
                                    callGraph[caller] = [];
                                }

                                if (callGraph[caller].length < 100) {
                                    callGraph[caller].push(target);
                                }
                            }
                        } catch (callGraphError) {
                            logError('Failed to track call graph', callGraphError, instructionAddr.toString());
                        }
                    }
                } catch (blockError) {
                    logError('Failed to track basic blocks', blockError, instructionAddr.toString());
                }

                try {
                    iterator.putCallout(onInstructionExecuted);
                } catch (calloutError) {
                    logError('Failed to put callout', calloutError, instructionAddr.toString());
                }

                try {
                    iterator.keep();
                } catch (keepError) {
                    logError('Failed to keep instruction', keepError, instructionAddr.toString());
                }

                let nextInstruction = null;
                parseAttempts = 0;

                while (parseAttempts < maxParseAttempts) {
                    try {
                        nextInstruction = iterator.next();
                        break;
                    } catch (nextParseError) {
                        parseAttempts++;

                        if (parseAttempts >= maxParseAttempts) {
                            logError('Failed to parse next instruction', nextParseError, instructionAddr.toString());
                            return;
                        }

                        threadState.skipCount++;
                        if (threadState.skipCount > 10) {
                            threadState.active = false;
                            return;
                        }
                    }
                }

                instruction = nextInstruction;

            } catch (instructionError) {
                logError('Instruction processing error', instructionError,
                    instruction && instruction.address ? instruction.address.toString() : 'unknown');

                try {
                    iterator.keep();
                } catch (keepError) {
                    logError('Failed to keep instruction after error', keepError);
                }
                break;
            }
        }

    } catch (fatalError) {
        sessionState.crashCount++;
        logError('Fatal transform error', fatalError, {
            crashCount: sessionState.crashCount,
            threadId: Process.getCurrentThreadId()
        });

        if (sessionState.crashCount >= 10) {
            sessionState.active = false;

            send({
                type: 'stalker_disabled',
                payload: {
                    reason: 'Too many crashes',
                    crashCount: sessionState.crashCount
                }
            });
        } else {
            attemptRecovery(Process.getCurrentThreadId());
        }
    }
}

// Callback for each instruction execution with error handling
function onInstructionExecuted(context) {
    try {
        if (instructionLog.length > STALKER_CONFIG.maxInstructionLogSize) {
            try {
                sendTraceData();
                instructionLog.length = 0;
            } catch (sendError) {
                logError('Failed to send trace data from callout', sendError);
                instructionLog.length = Math.floor(instructionLog.length / 2);
            }
        }
    } catch (e) {
        logError('Instruction execution callback error', e);
    }
}

// Callback for Stalker data with error handling
function onStalkerData(events) {
    try {
        if (!events || events.isNull()) {
            logError('Null events pointer in onStalkerData', null);
            return;
        }

        if (!isValidMemoryRegion(events)) {
            logError('Invalid memory region for events', null, events.toString());
            return;
        }

        const bufferSize = 16384;
        const buffer = Memory.readByteArray(events, bufferSize);

        if (!buffer) {
            logError('Failed to read events buffer', null);
            return;
        }

        send({
            type: 'stalker_events',
            payload: {
                threadId: Process.getCurrentThreadId(),
                data: buffer
            }
        }, buffer);

    } catch (e) {
        logError('Stalker data callback error', e);
    }
}

// Send accumulated trace data with error handling
function sendTraceData() {
    try {
        const payload = {
            threadId: Process.getCurrentThreadId(),
            timestamp: Date.now(),
            instructions: instructionLog.slice(0, 1000),
            basicBlocks: basicBlocks.slice(0, 100),
            callGraph: callGraph,
            coverage: calculateCoverage(),
            errors: errorLog.slice(-10)
        };

        send({
            type: 'stalker_trace',
            payload: payload
        });

    } catch (e) {
        logError('Failed to send trace data', e);
    }
}

// Calculate code coverage with error handling
function calculateCoverage() {
    try {
        const modules = Process.enumerateModules();

        if (!modules || modules.length === 0) {
            return 0.0;
        }

        const module = modules[0];
        const codeSize = module.size || 1;

        if (instructionLog.length === 0) {
            return 0.0;
        }

        const uniqueAddresses = new Set(instructionLog.map(i => i.address));
        const coverage = (uniqueAddresses.size / codeSize) * 100;

        return Math.min(coverage, 100.0);

    } catch (e) {
        logError('Coverage calculation error', e);
        return 0.0;
    }
}

// Start tracing a thread with error handling and anti-anti-stalker (CRITICAL-003)
function startThreadTrace(tid) {
    try {
        if (!tid) {
            tid = Process.getCurrentThreadId();
        }

        if (trackedThreads.has(tid)) {
            return { success: false, error: 'Thread already being traced' };
        }

        if (!sessionState.active) {
            return { success: false, error: 'Stalker session is disabled due to crashes' };
        }

        const stalkerConfig = {
            events: STALKER_CONFIG.events,
            onReceive: function(events) {
                onStalkerData(events);
            },
            transform: transformInstruction
        };

        if (STALKER_CONFIG.trustThreshold > 0) {
            Stalker.trustThreshold = STALKER_CONFIG.trustThreshold;
        }

        if (STALKER_CONFIG.timingNormalizationEnabled) {
            Process.setExceptionHandler(function(details) {
                if (details.type === 'access-violation' || details.type === 'illegal-instruction') {
                    send({
                        type: 'anti_trace_detected',
                        payload: {
                            type: details.type,
                            address: details.address ? details.address.toString() : 'unknown',
                            memory: details.memory
                        }
                    });

                    try {
                        Stalker.flush();
                        return true;
                    } catch (e) {
                        logError('Exception handler Stalker.flush failed', e);
                        return false;
                    }
                }
                return false;
            });
        }

        try {
            Stalker.follow(tid, stalkerConfig);
        } catch (followError) {
            logError('Stalker.follow failed', followError, tid);

            if (STALKER_CONFIG.enableRecovery && attemptRecovery(tid)) {
                try {
                    Stalker.follow(tid, stalkerConfig);
                } catch (retryError) {
                    logError('Stalker.follow retry failed', retryError, tid);
                    return { success: false, error: 'Failed to follow thread: ' + retryError.toString() };
                }
            } else {
                return { success: false, error: 'Failed to follow thread: ' + followError.toString() };
            }
        }

        trackedThreads.add(tid);

        send({
            type: 'stalker_started',
            payload: { threadId: tid }
        });

        return { success: true };

    } catch (e) {
        logError('Start trace error', e, tid);
        return { success: false, error: e.toString() };
    }
}

// Stop tracing a thread with cleanup
function stopThreadTrace(tid) {
    try {
        if (!trackedThreads.has(tid)) {
            return { success: false, error: 'Thread not being traced' };
        }

        try {
            Stalker.unfollow(tid);
        } catch (unfollowError) {
            logError('Stalker.unfollow failed', unfollowError, tid);
        }

        try {
            Stalker.flush();
        } catch (flushError) {
            logError('Stalker.flush failed during stop', flushError, tid);
        }

        trackedThreads.delete(tid);

        try {
            sendTraceData();
        } catch (sendError) {
            logError('Failed to send final trace data', sendError, tid);
        }

        send({
            type: 'stalker_stopped',
            payload: { threadId: tid }
        });

        return { success: true };

    } catch (e) {
        logError('Stop trace error', e, tid);
        return { success: false, error: e.toString() };
    }
}

// Flush Stalker with error handling
function flushStalker() {
    try {
        Stalker.flush();
        return { success: true };
    } catch (e) {
        logError('Stalker flush error', e);
        return { success: false, error: e.toString() };
    }
}

// Garbage collect with error handling
function garbageCollectStalker() {
    try {
        Stalker.garbageCollect();
        return { success: true };
    } catch (e) {
        logError('Stalker garbage collect error', e);
        return { success: false, error: e.toString() };
    }
}

// Export functions
rpc.exports = {
    startTrace: startThreadTrace,
    stopTrace: stopThreadTrace,
    getTraceData: sendTraceData,
    clearTrace: function() {
        try {
            instructionLog.length = 0;
            basicBlocks.length = 0;
            Object.keys(callGraph).forEach(key => delete callGraph[key]);
            errorLog.length = 0;
            return { success: true };
        } catch (e) {
            logError('Clear trace error', e);
            return { success: false, error: e.toString() };
        }
    },
    flush: flushStalker,
    garbageCollect: garbageCollectStalker,
    getErrors: function() {
        return errorLog;
    },
    getSessionState: function() {
        return sessionState;
    },
    resetSession: function() {
        try {
            sessionState.active = true;
            sessionState.crashCount = 0;
            sessionState.lastError = null;
            sessionState.recoveryMode = false;
            errorLog.length = 0;
            return { success: true };
        } catch (e) {
            return { success: false, error: e.toString() };
        }
    }
};

// Auto-start on main thread with error handling
try {
    const result = startThreadTrace(Process.getCurrentThreadId());
    if (!result.success) {
        send({
            type: 'stalker_autostart_failed',
            payload: { error: result.error }
        });
    }
} catch (e) {
    logError('Auto-start failed', e);
}
"""

        self.script = self.session.create_script(stalker_script)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message: "ScriptMessage", _data: bytes | None) -> None:
        """Handle Stalker messages.

        Args:
            message: Frida message dictionary containing type and payload.
            _data: Additional binary data from Frida (unused).
        """
        if message["type"] == "send":
            payload = validate_type(message.get("payload", {}), dict)
            msg_type = payload.get("type")

            if msg_type == "stalker_trace":
                thread_id = int(payload["threadId"])
                basic_blocks_raw = validate_type(payload["basicBlocks"], list)
                self.traces[thread_id] = StalkerTrace(
                    thread_id=thread_id,
                    timestamp=float(payload["timestamp"]),
                    instructions=validate_type(payload["instructions"], list),
                    basic_blocks=[(int(b["start"]), int(b["end"])) for b in basic_blocks_raw if b.get("end") is not None],
                    call_graph=validate_type(payload["callGraph"], dict),
                    coverage=float(payload["coverage"]),
                )
            elif msg_type == "stalker_error":
                logger.error(
                    "Stalker error [%s]: %s (Thread: %d, Info: %s)",
                    payload.get("context", "unknown"),
                    payload.get("error", "unknown error"),
                    payload.get("threadId", 0),
                    payload.get("additionalInfo", ""),
                )
            elif msg_type == "stalker_recovery_success":
                logger.info("Stalker recovery successful for thread %d", payload.get("threadId", 0))
            elif msg_type == "stalker_disabled":
                logger.critical(
                    "Stalker disabled: %s (Crashes: %d)",
                    payload.get("reason", "unknown"),
                    payload.get("crashCount", 0),
                )
            elif msg_type == "stalker_autostart_failed":
                logger.warning("Stalker auto-start failed: %s", payload.get("error", "unknown"))
            elif msg_type == "anti_trace_detected":
                logger.warning(
                    "Anti-tracing mechanism detected: %s at %s",
                    payload.get("type", "unknown"),
                    payload.get("address", "unknown"),
                )
        elif message["type"] == "error":
            logger.error("Frida script error: %s", message.get("description", "Unknown error"))

    def start_trace(self, thread_id: int | None = None) -> bool:
        """Start tracing a thread.

        Args:
            thread_id: Thread ID to trace. If None, traces current thread.

        Returns:
            True if tracing started successfully, False otherwise.

        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.start_trace(thread_id), dict)
            return bool(result["success"])
        except Exception:
            logger.exception("Failed to start trace")
            return False

    def stop_trace(self, thread_id: int) -> bool:
        """Stop tracing a thread.

        Args:
            thread_id: Thread ID to stop tracing.

        Returns:
            True if tracing stopped successfully, False otherwise.

        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.stop_trace(thread_id), dict)
            return bool(result["success"])
        except Exception:
            logger.exception("Failed to stop trace")
            return False

    def get_trace(self, thread_id: int) -> StalkerTrace | None:
        """Get trace for a thread.

        Args:
            thread_id: Thread ID to retrieve trace for.

        Returns:
            StalkerTrace object if available, None otherwise.

        """
        return self.traces.get(thread_id)

    def flush(self) -> bool:
        """Flush Stalker to process pending events.

        Returns:
            True if flush succeeded, False otherwise.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.flush(), dict)
            return bool(result.get("success", False))
        except Exception:
            logger.exception("Failed to flush Stalker")
            return False

    def garbage_collect(self) -> bool:
        """Trigger Stalker garbage collection.

        Returns:
            True if garbage collection succeeded, False otherwise.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.garbage_collect(), dict)
            return bool(result.get("success", False))
        except Exception:
            logger.exception("Failed to garbage collect Stalker")
            return False

    def get_errors(self) -> list[dict[str, object]]:
        """Get error log from Stalker.

        Returns:
            List of error entries with context, timestamp, and stack traces.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            errors = validate_type(exports.get_errors(), list)
            return errors
        except Exception:
            logger.exception("Failed to get Stalker errors")
            return []

    def get_session_state(self) -> dict[str, object]:
        """Get current Stalker session state.

        Returns:
            Dictionary containing session state including crash count and active status.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            state = validate_type(exports.get_session_state(), dict)
            return state
        except Exception:
            logger.exception("Failed to get session state")
            return {"active": False, "crashCount": 0, "lastError": None, "recoveryMode": False}

    def reset_session(self) -> bool:
        """Reset Stalker session state and clear errors.

        Returns:
            True if reset succeeded, False otherwise.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.reset_session(), dict)
            return bool(result.get("success", False))
        except Exception:
            logger.exception("Failed to reset Stalker session")
            return False

    def clear_trace(self) -> bool:
        """Clear all trace data.

        Returns:
            True if clear succeeded, False otherwise.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.clear_trace(), dict)
            self.traces.clear()
            return bool(result.get("success", False))
        except Exception:
            logger.exception("Failed to clear trace")
            return False


class FridaHeapTracker:
    """Heap allocation tracking."""

    def __init__(self, session: frida.core.Session) -> None:
        """Initialize the FridaHeapTracker with a Frida session.

        Args:
            session: Frida session to attach heap tracking to.
        """
        self.session = session
        self.allocations: dict[int, HeapAllocation] = {}
        self.script: frida.core.Script
        self._init_heap_tracker()

    def _init_heap_tracker(self) -> None:
        """Initialize heap tracking script.

        Sets up hooks for malloc, free, realloc, and calloc to monitor heap
        allocations and identify potential memory leaks.
        """
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

    def _on_message(self, message: "ScriptMessage", _data: bytes | None) -> None:
        """Handle heap tracking messages.

        Args:
            message: Frida message dictionary containing type and payload.
            _data: Additional binary data from Frida (unused).
        """
        if message["type"] == "send":
            payload = validate_type(message.get("payload", {}), dict)
            msg_type = payload.get("type")

            if msg_type == "heap_alloc":
                addr = int(payload["address"])
                self.allocations[addr] = HeapAllocation(
                    address=addr,
                    size=int(payload["size"]),
                    timestamp=float(payload["timestamp"]),
                    thread_id=int(payload["threadId"]),
                    call_stack=validate_type(payload["callStack"], list),
                )

            elif msg_type == "heap_free":
                addr = int(payload["address"])
                if addr in self.allocations:
                    self.allocations[addr].freed = True
                    self.allocations[addr].freed_timestamp = float(payload["timestamp"])

    def get_stats(self) -> dict[str, object]:
        """Get heap statistics.

        Returns:
            Dictionary containing heap allocation statistics.

        """
        exports: ScriptExportsSync = self.script.exports_sync
        stats = validate_type(exports.get_heap_stats(), dict)
        return stats

    def find_leaks(self) -> list[HeapAllocation]:
        """Find potential memory leaks.

        Returns:
            List of HeapAllocation objects representing potential memory leaks.

        """
        exports: ScriptExportsSync = self.script.exports_sync
        leaks = validate_type(exports.find_leaks(), list)
        leaks_result: list[HeapAllocation] = []
        for leak in leaks:
            addr = int(leak["address"])
            if addr in self.allocations:
                leaks_result.append(self.allocations[addr])
        return leaks_result


class FridaThreadMonitor:
    """Thread creation and termination monitoring."""

    def __init__(self, session: frida.core.Session) -> None:
        """Initialize the FridaThreadMonitor with a Frida session.

        Args:
            session: Frida session to monitor threads in.
        """
        self.session = session
        self.threads: dict[int, ThreadInfo] = {}
        self.script: frida.core.Script
        self._init_thread_monitor()

    def _init_thread_monitor(self) -> None:
        """Initialize thread monitoring script.

        Sets up hooks for Windows CreateThread/ExitThread and POSIX pthread_create/
        pthread_exit to monitor thread lifecycle events across platforms.
        """
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

    def _on_message(self, message: "ScriptMessage", _data: bytes | None) -> None:
        """Handle thread monitoring messages.

        Args:
            message: Frida message dictionary containing type and payload.
            _data: Additional binary data from Frida (unused).
        """
        if message["type"] != "send":
            return
        raw_payload: object = message.get("payload", {})
        payload = ensure_dict(raw_payload, "frida_message_payload")
        msg_type = payload.get("type")

        if msg_type == "thread_created":
            tid = int(payload["threadId"])
            parent_tid = payload.get("parentThreadId")
            self.threads[tid] = ThreadInfo(
                thread_id=tid,
                entry_point=int(payload["entryPoint"]),
                stack_base=0,  # Would need platform-specific code
                stack_size=0,
                creation_time=float(payload["creationTime"]),
                parent_thread_id=int(parent_tid) if parent_tid is not None else None,
            )

        elif msg_type == "thread_terminated":
            tid = int(payload["threadId"])
            if tid in self.threads:
                self.threads[tid].termination_time = float(payload["timestamp"])

    def get_threads(self) -> list[ThreadInfo]:
        """Get all tracked threads.

        Returns:
            List of ThreadInfo objects for all monitored threads.

        """
        return list(self.threads.values())

    def get_current_threads(self) -> list[dict[str, object]]:
        """Get current system threads.

        Returns:
            List of dictionaries containing current system thread information.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            threads = validate_type(exports.get_current_threads(), list)
            return threads
        except Exception:
            logger.exception("Failed to get current threads")
            return []


class FridaExceptionHooker:
    """Exception handler hooking."""

    def __init__(self, session: frida.core.Session) -> None:
        """Initialize the FridaExceptionHooker with a Frida session.

        Args:
            session: Frida session to hook exceptions in.
        """
        self.session = session
        self.exceptions: list[ExceptionInfo] = []
        self.script: frida.core.Script
        self._init_exception_hooker()

    def _init_exception_hooker(self) -> None:
        """Initialize exception hooking script.

        Sets up hooks for Windows exception handling (RtlDispatchException,
        SetUnhandledExceptionFilter), POSIX signal handling (sigaction),
        and C++ exception handling (__cxa_throw).
        """
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

    def _on_message(self, message: "ScriptMessage", _data: bytes | None) -> None:
        """Handle exception messages.

        Args:
            message: Frida message dictionary containing type and payload.
            _data: Additional binary data from Frida (unused).
        """
        if message["type"] == "send":
            payload = validate_type(message.get("payload", {}), dict)
            msg_type = payload.get("type")

            if msg_type == "exception_raised":
                exc_addr_raw = payload.get("exceptionAddress")
                exc_code_raw = payload.get("exceptionCode")
                self.exceptions.append(
                    ExceptionInfo(
                        exception_address=int(exc_addr_raw) if exc_addr_raw is not None else 0,
                        exception_code=int(exc_code_raw) if exc_code_raw is not None else 0,
                        handler_address=0,
                        thread_id=int(payload["threadId"]),
                        timestamp=float(payload["timestamp"]),
                        handled=False,
                        exception_record=validate_type(payload, dict),
                    ),
                )

            elif msg_type == "exception_handled":
                if self.exceptions:
                    self.exceptions[-1].handled = bool(payload["handled"])

    def get_exceptions(self) -> list[ExceptionInfo]:
        """Get all tracked exceptions.

        Returns:
            List of ExceptionInfo objects for all caught exceptions.

        """
        return self.exceptions

    def clear_exceptions(self) -> None:
        """Clear exception history.

        Clears both the local exception list and the Frida script exception list.
        """
        self.exceptions.clear()
        exports: ScriptExportsSync = self.script.exports_sync
        exports.clear_exceptions()


class FridaNativeReplacer:
    """Native function replacement system."""

    def __init__(self, session: frida.core.Session) -> None:
        """Initialize the FridaNativeReplacer with a Frida session.

        Args:
            session: Frida session to replace native functions in.

        """
        self.session = session
        self.replacements: dict[int, dict[str, object]] = {}
        self.script: frida.core.Script
        self._init_replacer()

    def _init_replacer(self) -> None:
        """Initialize native function replacement.

        Sets up the native function replacement system to intercept and replace
        function implementations with custom licensing validation replacements.
        """
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

    def _on_message(self, message: "ScriptMessage", _data: bytes | None) -> None:
        """Handle replacement messages.

        Args:
            message: Frida message dictionary containing type and payload.
            _data: Additional binary data from Frida (unused).
        """
        if message["type"] == "send":
            payload = validate_type(message.get("payload", {}), dict)
            msg_type = payload.get("type")

            if msg_type == "function_replaced":
                addr = int(payload["address"])
                self.replacements[addr] = {"args": payload["args"], "result": payload["result"]}

    def replace_function(
        self,
        address: int,
        impl_name: str,
        ret_type: str = "int",
        arg_types: list[str] | None = None,
    ) -> bool:
        """Replace a native function.

        Args:
            address: Memory address of the function to replace.
            impl_name: Name of the replacement implementation.
            ret_type: Return type of the function (default: "int").
            arg_types: List of argument types (default: empty list).

        Returns:
            True if replacement succeeded, False otherwise.

        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.replace(address, impl_name, ret_type, arg_types), dict)
            return bool(result["success"])
        except Exception:
            logger.exception("Failed to replace function")
            return False

    def restore(self, target_address: int) -> bool:
        """Restore a replaced function.

        Args:
            target_address: Address of the function to restore.

        Returns:
            True if restored successfully, False otherwise.
        """
        try:
            exports: ScriptExportsSync = self.script.exports_sync
            result = validate_type(exports.restore(target_address), dict)
            return bool(result["success"])
        except Exception:
            logger.exception("Failed to restore function")
            return False


class FridaRPCInterface:
    """RPC interface for complex operations."""

    def __init__(self, session: frida.core.Session) -> None:
        """Initialize the FridaRPCInterface with a Frida session.

        Args:
            session: Frida session to create RPC interface for.

        """
        self.session = session
        self.script: frida.core.Script
        self._init_rpc()

    def _init_rpc(self) -> None:
        """Initialize RPC interface.

        Sets up comprehensive RPC operations for memory manipulation, module
        enumeration, process information, file operations, and Windows registry access.
        """
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
        self.script.on("message", lambda m, d: logger.debug("Frida message: %s, data: %s", m, d))
        self.script.load()

    def memory_read(self, address: int, size: int) -> bytes:
        """Read memory.

        Args:
            address: Memory address to read from.
            size: Number of bytes to read.

        Returns:
            Bytes read from the specified memory address.
        """
        exports: ScriptExportsSync = self.script.exports_sync
        memory = cast("MemoryExportsProtocol", exports.memory)
        result = memory.read(address, size)
        return result if isinstance(result, bytes) else bytes(result)

    def memory_write(self, address: int, data: bytes) -> bool:
        """Write memory.

        Args:
            address: Memory address to write to.
            data: Bytes to write to memory.

        Returns:
            True if write succeeded, False otherwise.
        """
        exports: ScriptExportsSync = self.script.exports_sync
        memory = cast("MemoryExportsProtocol", exports.memory)
        result = memory.write(address, data)
        return bool(result)

    def memory_scan(self, pattern: str, limit: int = 10) -> list[dict[str, int]]:
        """Scan memory for pattern.

        Args:
            pattern: Pattern string to search for in memory.
            limit: Maximum number of matches to return (default: 10).

        Returns:
            List of dictionaries containing match address and size.
        """
        exports: ScriptExportsSync = self.script.exports_sync
        memory = cast("MemoryExportsProtocol", exports.memory)
        return validate_type(memory.scan(pattern, limit), list)

    def module_find_export(self, module: str, name: str) -> int | None:
        """Find module export.

        Args:
            module: Name of the module to search.
            name: Name of the exported function.

        Returns:
            Address of the exported function, or None if not found.
        """
        exports: ScriptExportsSync = self.script.exports_sync
        module_obj = cast("ModuleExportsProtocol", exports.module)
        result = module_obj.find_export(module, name)
        return int(result) if result is not None else None

    def evaluate(self, code: str) -> object:
        """Evaluate JavaScript code.

        Args:
            code: JavaScript code string to evaluate.

        Returns:
            Result of the JavaScript evaluation.
        """
        exports: ScriptExportsSync = self.script.exports_sync
        result = exports.evaluate(code)
        return result


class FridaAdvancedHooking:
    """Run class for advanced hooking features."""

    def __init__(self, session: frida.core.Session) -> None:
        """Initialize the FridaAdvancedHooking with a Frida session.

        Args:
            session: Frida session to attach advanced hooking features to.
        """
        self.session = session
        self.stalker: FridaStalkerEngine | None = None
        self.heap_tracker: FridaHeapTracker | None = None
        self.thread_monitor: FridaThreadMonitor | None = None
        self.exception_hooker: FridaExceptionHooker | None = None
        self.native_replacer: FridaNativeReplacer | None = None
        self.rpc_interface: FridaRPCInterface | None = None

    def init_stalker(self) -> FridaStalkerEngine:
        """Initialize Stalker engine.

        Returns:
            FridaStalkerEngine instance for instruction-level tracing.
        """
        stalker_instance = FridaStalkerEngine(self.session)
        self.stalker = stalker_instance
        return stalker_instance

    def init_heap_tracker(self) -> FridaHeapTracker:
        """Initialize heap tracking.

        Returns:
            FridaHeapTracker instance for monitoring heap allocations.
        """
        heap_tracker_instance = FridaHeapTracker(self.session)
        self.heap_tracker = heap_tracker_instance
        return heap_tracker_instance

    def init_thread_monitor(self) -> FridaThreadMonitor:
        """Initialize thread monitoring.

        Returns:
            FridaThreadMonitor instance for tracking thread creation and termination.
        """
        thread_monitor_instance = FridaThreadMonitor(self.session)
        self.thread_monitor = thread_monitor_instance
        return thread_monitor_instance

    def init_exception_hooker(self) -> FridaExceptionHooker:
        """Initialize exception hooking.

        Returns:
            FridaExceptionHooker instance for monitoring exception handlers.
        """
        exception_hooker_instance = FridaExceptionHooker(self.session)
        self.exception_hooker = exception_hooker_instance
        return exception_hooker_instance

    def init_native_replacer(self) -> FridaNativeReplacer:
        """Initialize native function replacement.

        Returns:
            FridaNativeReplacer instance for replacing native function implementations.
        """
        native_replacer_instance = FridaNativeReplacer(self.session)
        self.native_replacer = native_replacer_instance
        return native_replacer_instance

    def init_rpc_interface(self) -> FridaRPCInterface:
        """Initialize RPC interface.

        Returns:
            FridaRPCInterface instance for complex RPC operations.
        """
        rpc_interface_instance = FridaRPCInterface(self.session)
        self.rpc_interface = rpc_interface_instance
        return rpc_interface_instance

    def init_all(self) -> "FridaAdvancedHooking":
        """Initialize all advanced features.

        Returns:
            Self reference for method chaining.
        """
        self.init_stalker()
        self.init_heap_tracker()
        self.init_thread_monitor()
        self.init_exception_hooker()
        self.init_native_replacer()
        self.init_rpc_interface()
        return self
