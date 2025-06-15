"""
Timing Attack Defense

Implements defense mechanisms against timing-based analysis
including anti-sleep acceleration and execution delays.
"""

import ctypes
import logging
import random
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class TimingAttackDefense:
    """
    Defense against timing-based analysis and sleep acceleration.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.TimingAttackDefense")
        self.timing_threads = []
        self.timing_checks = {
            'rdtsc_available': self._check_rdtsc_availability(),
            'performance_counter': True,
            'tick_count': True
        }

    def secure_sleep(self, duration: float, callback: Callable = None) -> bool:
        """
        Sleep with protection against acceleration.
        
        Args:
            duration: Sleep duration in seconds
            callback: Optional callback to execute during sleep
            
        Returns:
            True if sleep completed normally, False if accelerated
        """
        try:
            self.logger.debug(f"Starting secure sleep for {duration} seconds")

            # Use multiple timing sources
            start_time = time.time()
            start_perf = time.perf_counter()
            start_thread = threading.current_thread()

            # Platform-specific timing
            if hasattr(time, 'thread_time'):
                start_thread_time = time.thread_time()
            else:
                start_thread_time = None

            # Windows-specific timing
            if self.timing_checks['tick_count']:
                start_tick = self._get_tick_count()
            else:
                start_tick = None

            # Split sleep into chunks to detect acceleration
            chunk_size = min(1.0, duration / 10)  # Max 1 second chunks
            remaining = duration

            while remaining > 0:
                sleep_time = min(chunk_size, remaining)

                # Actual sleep
                time.sleep(sleep_time)

                # Execute callback if provided
                if callback:
                    callback()

                # Check for timing anomalies
                elapsed_real = time.time() - start_time
                elapsed_perf = time.perf_counter() - start_perf

                # Check if time is accelerated
                drift = abs(elapsed_real - elapsed_perf)
                if drift > 0.1:  # 100ms drift threshold
                    self.logger.warning(f"Timing anomaly detected: {drift:.3f}s drift")
                    return False

                remaining -= sleep_time

            # Final timing verification
            final_elapsed = time.time() - start_time
            expected_elapsed = duration

            # Allow 5% tolerance
            if abs(final_elapsed - expected_elapsed) > (duration * 0.05):
                self.logger.warning(f"Sleep duration mismatch: expected {duration}s, got {final_elapsed}s")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Secure sleep failed: {e}")
            return False

    def stalling_code(self, min_duration: float, max_duration: float) -> None:
        """
        Execute computationally intensive stalling code.
        
        Args:
            min_duration: Minimum stall duration
            max_duration: Maximum stall duration
        """
        try:
            target_duration = random.uniform(min_duration, max_duration)
            self.logger.debug(f"Starting stalling code for ~{target_duration:.1f}s")

            start_time = time.perf_counter()

            # Perform actual computation to consume CPU time
            result = 0
            iterations = 0

            while (time.perf_counter() - start_time) < target_duration:
                # CPU-intensive operations
                for i in range(10000):
                    result += i * i
                    result = (result << 1) ^ (result >> 1)
                    result = result % 2147483647  # Keep in 32-bit range

                iterations += 1

                # Add some randomness
                if random.random() < 0.1:
                    time.sleep(0.001)  # Brief pause

            elapsed = time.perf_counter() - start_time
            self.logger.debug(f"Stalling completed: {elapsed:.2f}s, {iterations} iterations")

        except Exception as e:
            self.logger.error(f"Stalling code failed: {e}")

    def time_bomb(self, trigger_time: float, action: Callable) -> threading.Thread:
        """
        Create a time bomb that triggers after specific duration.
        
        Args:
            trigger_time: Time in seconds until trigger
            action: Function to execute when triggered
            
        Returns:
            Thread handle for the time bomb
        """
        def time_bomb_thread():
            try:
                self.logger.info(f"Time bomb armed for {trigger_time}s")

                # Use secure sleep with verification
                if self.secure_sleep(trigger_time):
                    self.logger.info("Time bomb triggered")
                    action()
                else:
                    self.logger.warning("Time bomb detected acceleration, aborting")

            except Exception as e:
                self.logger.error(f"Time bomb failed: {e}")

        thread = threading.Thread(target=time_bomb_thread, daemon=True)
        thread.start()
        self.timing_threads.append(thread)

        return thread

    def execution_delay(self, check_environment: bool = True) -> None:
        """
        Delay execution to evade automated analysis.
        
        Args:
            check_environment: Perform environment checks during delay
        """
        try:
            self.logger.info("Starting execution delay")

            # Random delay between 30-120 seconds
            delay = random.uniform(30, 120)

            if check_environment:
                # Perform checks during delay
                check_interval = 5.0
                elapsed = 0

                while elapsed < delay:
                    # Check for debugger
                    if self._quick_debugger_check():
                        self.logger.warning("Debugger detected during delay")
                        # Extend delay
                        delay += 60

                    # Check for acceleration
                    if not self.secure_sleep(check_interval):
                        self.logger.warning("Acceleration detected during delay")
                        # Perform stalling
                        self.stalling_code(10, 20)

                    elapsed += check_interval
            else:
                # Simple delay
                self.secure_sleep(delay)

        except Exception as e:
            self.logger.error(f"Execution delay failed: {e}")

    def rdtsc_timing_check(self) -> bool:
        """
        Use RDTSC instruction for precise timing checks.
        
        Returns:
            True if timing is normal, False if anomaly detected
        """
        if not self.timing_checks['rdtsc_available']:
            return True  # Can't check, assume normal

        try:
            # This would use inline assembly or ctypes to execute RDTSC
            # For now, use high-resolution timer as approximation

            # Measure time for known operation
            start = time.perf_counter_ns()

            # Known operation (should take ~1ms)
            total = 0
            for i in range(100000):
                total += i

            end = time.perf_counter_ns()

            elapsed_ns = end - start
            expected_ns = 1000000  # 1ms in nanoseconds

            # Check if execution was too fast (accelerated)
            if elapsed_ns < expected_ns * 0.1:  # 10x faster than expected
                return False

            return True

        except Exception as e:
            self.logger.debug(f"RDTSC check failed: {e}")
            return True

    def anti_acceleration_loop(self, duration: float) -> None:
        """
        Loop that resists sleep acceleration attempts.
        
        Args:
            duration: Total duration to loop
        """
        try:
            self.logger.debug(f"Starting anti-acceleration loop for {duration}s")

            start_time = time.time()
            loops = 0

            while (time.time() - start_time) < duration:
                # Mix of sleep and computation
                if loops % 2 == 0:
                    # Short sleep
                    time.sleep(0.1)
                else:
                    # Computation
                    self.stalling_code(0.05, 0.15)

                loops += 1

                # Verify timing integrity
                if not self.rdtsc_timing_check():
                    self.logger.warning("Timing acceleration detected in loop")
                    # Increase computational load
                    self.stalling_code(1, 2)

        except Exception as e:
            self.logger.error(f"Anti-acceleration loop failed: {e}")

    def _check_rdtsc_availability(self) -> bool:
        """Check if RDTSC instruction is available."""
        try:
            # Check CPU features
            # This would normally check CPUID for RDTSC support
            # For now, assume available on x86/x64
            import platform
            return platform.machine().lower() in ['x86', 'x86_64', 'amd64', 'i386', 'i686']
        except:
            return False

    def _get_tick_count(self) -> Optional[int]:
        """Get system tick count (Windows)."""
        try:
            import platform
            if platform.system() == 'Windows':
                kernel32 = ctypes.windll.kernel32
                return kernel32.GetTickCount64()
        except:
            pass
        return None

    def _quick_debugger_check(self) -> bool:
        """Quick check for debugger presence."""
        try:
            import platform
            if platform.system() == 'Windows':
                kernel32 = ctypes.windll.kernel32
                return bool(kernel32.IsDebuggerPresent())
            else:
                # Linux: check TracerPid
                with open('/proc/self/status', 'r') as f:
                    for line in f:
                        if line.startswith('TracerPid:'):
                            return int(line.split()[1]) != 0
        except:
            pass
        return False

    def generate_timing_defense_code(self) -> str:
        """Generate C code for timing attack defense."""
        code = """
// Timing Attack Defense
#include <windows.h>
#include <time.h>
#include <intrin.h>

// Get CPU timestamp counter
unsigned __int64 GetRDTSC() {
    return __rdtsc();
}

// Secure sleep with anti-acceleration
bool SecureSleep(DWORD milliseconds) {
    DWORD startTick = GetTickCount64();
    unsigned __int64 startTsc = GetRDTSC();
    clock_t startClock = clock();
    
    // Split sleep into chunks
    DWORD chunkSize = min(100, milliseconds / 10);
    DWORD remaining = milliseconds;
    
    while (remaining > 0) {
        DWORD sleepTime = min(chunkSize, remaining);
        Sleep(sleepTime);
        
        // Check timing sources
        DWORD elapsedTick = GetTickCount64() - startTick;
        clock_t elapsedClock = clock() - startClock;
        
        // Detect acceleration
        DWORD expectedElapsed = milliseconds - remaining + sleepTime;
        if (abs((int)(elapsedTick - expectedElapsed)) > 50) {
            return false;  // Timing anomaly
        }
        
        remaining -= sleepTime;
    }
    
    return true;
}

// CPU-intensive stalling
void StallExecution(DWORD milliseconds) {
    unsigned __int64 startTsc = GetRDTSC();
    DWORD startTick = GetTickCount64();
    
    volatile unsigned int result = 0;
    
    while ((GetTickCount64() - startTick) < milliseconds) {
        // CPU-intensive operations
        for (int i = 0; i < 10000; i++) {
            result = (result * 214013 + 2531011) & 0x7FFFFFFF;
            result ^= (result << 13);
            result ^= (result >> 17);
            result ^= (result << 5);
        }
        
        // Check for timing anomalies
        unsigned __int64 tscElapsed = GetRDTSC() - startTsc;
        DWORD tickElapsed = GetTickCount64() - startTick;
        
        // TSC should increase much faster than tick count
        if (tscElapsed < tickElapsed * 1000000) {
            // Possible virtualization/acceleration
            break;
        }
    }
}

// Execution delay with checks
void ExecutionDelay() {
    // Random delay 30-120 seconds
    srand(GetTickCount());
    DWORD delay = 30000 + (rand() % 90000);
    
    DWORD elapsed = 0;
    while (elapsed < delay) {
        // Check for debugger
        if (IsDebuggerPresent()) {
            delay += 60000;  // Add 1 minute
        }
        
        // Secure sleep with verification
        if (!SecureSleep(5000)) {
            // Acceleration detected, use stalling
            StallExecution(10000);
        }
        
        elapsed += 5000;
    }
}

// Usage
ExecutionDelay();  // Delay execution
StallExecution(2000);  // 2 second stall
"""
        return code
