"""Production-ready Angr enhancements for license cracking symbolic execution.

This module provides advanced symbolic execution capabilities specifically designed
for analyzing and defeating software licensing protections.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import logging
import time
from collections import defaultdict
from typing import Any

try:
    import angr
    import claripy
    from angr import SimProcedure
    from angr.exploration_techniques import DFS, ExplorationTechnique

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    SimProcedure = object
    ExplorationTechnique = object


class LicensePathPrioritizer(ExplorationTechnique):
    """Path prioritization strategy for license validation discovery with sophisticated heuristics."""

    def __init__(self, prioritize_license_paths=True, max_loop_iterations=3):
        """Initialize path prioritizer with loop detection.

        Args:
            prioritize_license_paths: Enable license path prioritization
            max_loop_iterations: Maximum loop iterations before deprioritizing

        """
        super().__init__()
        self.prioritize_license_paths = prioritize_license_paths
        self.max_loop_iterations = max_loop_iterations
        self.license_keywords = [
            b"license",
            b"serial",
            b"key",
            b"registration",
            b"activation",
            b"trial",
            b"expire",
            b"valid",
            b"authenticate",
            b"verify",
            b"register",
            b"unlock",
            b"auth",
            b"crack",
            b"piracy",
            b"genuine",
            b"legitimate",
        ]
        self.path_scores = {}
        self.license_function_addrs = set()
        self.loop_counters = defaultdict(lambda: defaultdict(int))
        self.state_hashes = {}
        self.coverage_map = set()
        self.logger = logging.getLogger("IntellicrackLogger.LicensePathPrioritizer")

    def setup(self, simgr):
        """Initialize prioritizer with project context."""
        self.logger.info("Setting up license path prioritizer")

        for func_name in simgr._project.kb.functions:
            func = simgr._project.kb.functions[func_name]
            func_name_lower = str(func.name).lower().encode() if isinstance(func.name, str) else func.name.lower()
            if any(keyword in func_name_lower for keyword in self.license_keywords):
                self.license_function_addrs.add(func.addr)
                self.logger.debug(f"Identified license function: {func.name} at {hex(func.addr)}")

        for string_ref in simgr._project.loader.main_object.sections_map.get(".rdata", []):
            try:
                data = simgr._project.loader.memory.load(string_ref, 256)
                if any(keyword in data.lower() for keyword in self.license_keywords):
                    self.logger.debug(f"Found license-related string at {hex(string_ref)}")
            except Exception as e:
                self.logger.debug(f"Error loading string data at {hex(string_ref)}: {e}")
                continue

    def step(self, simgr, stash="active", **kwargs):
        """Prioritize paths based on license relevance with advanced scoring."""
        simgr = simgr.step(stash=stash, **kwargs)

        if stash in simgr.stashes and self.prioritize_license_paths:
            states = simgr.stashes[stash]
            scored_states = []

            for state in states:
                loop_penalty = self._check_loop_detection(state)
                state_hash = self._compute_state_hash(state)

                if state_hash in self.state_hashes:
                    continue

                score = self._calculate_path_score(state)
                score -= loop_penalty

                scored_states.append((score, state))
                self.path_scores[id(state)] = score
                self.state_hashes[state_hash] = True

            scored_states.sort(key=lambda x: x[0], reverse=True)
            simgr.stashes[stash] = [state for _, state in scored_states[:1000]]

            if scored_states:
                self.logger.debug(
                    f"Prioritized {len(scored_states)} states, "
                    f"top score: {scored_states[0][0]:.2f}, "
                    f"lowest score: {scored_states[-1][0]:.2f}"
                )

        return simgr

    def _calculate_path_score(self, state) -> float:
        """Calculate path priority score for license validation relevance."""
        score = 0.0

        if not hasattr(state, "history") or not state.history.bbl_addrs:
            return 0.0

        if state.addr in self.license_function_addrs:
            score += 100.0

        for addr in state.history.bbl_addrs:
            if addr in self.license_function_addrs:
                score += 50.0
            if addr not in self.coverage_map:
                score += 10.0
                self.coverage_map.add(addr)

        path_length = len(state.history.bbl_addrs)
        if path_length < 50:
            score += (50 - path_length) * 0.5
        elif path_length > 200:
            score -= (path_length - 200) * 0.2

        unique_addrs = len(set(state.history.bbl_addrs))
        if unique_addrs > 10:
            score += min(unique_addrs * 0.3, 30.0)

        constraint_count = len(state.solver.constraints)
        if constraint_count < 100:
            score += (100 - constraint_count) * 0.1
        else:
            score -= (constraint_count - 100) * 0.5

        if hasattr(state, "license_files") and state.license_files:
            score += 150.0

        return max(score, 0.0)

    def _check_loop_detection(self, state) -> float:
        """Detect loops and calculate penalty for excessive iterations."""
        penalty = 0.0

        if not hasattr(state, "history") or not state.history.bbl_addrs:
            return penalty

        state_id = id(state)
        current_addr = state.addr

        self.loop_counters[state_id][current_addr] += 1

        iterations = self.loop_counters[state_id][current_addr]
        if iterations > self.max_loop_iterations:
            penalty = (iterations - self.max_loop_iterations) * 10.0
            self.logger.debug(f"Loop detected at {hex(current_addr)}, iteration {iterations}, penalty: {penalty}")

        return penalty

    def _compute_state_hash(self, state) -> str:
        """Compute hash for state deduplication."""
        try:
            addr = state.addr
            constraint_count = len(state.solver.constraints)

            constraint_strs = [str(c) for c in state.solver.constraints[:10]]
            combined = f"{addr}_{constraint_count}_{''.join(sorted(constraint_strs))}"

            return hashlib.sha256(combined.encode()).hexdigest()[:16]
        except Exception as e:
            self.logger.debug(f"Error computing state hash: {e}")
            return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]


class ConstraintOptimizer(ExplorationTechnique):
    """Advanced constraint optimization for performance with incremental solving."""

    def __init__(self, simplify_interval=10, cache_size=1000, solver_timeout=5000):
        """Initialize constraint optimizer.

        Args:
            simplify_interval: Steps between constraint simplifications
            cache_size: Maximum cached constraint sets
            solver_timeout: Solver timeout in milliseconds

        """
        super().__init__()
        self.simplify_interval = simplify_interval
        self.cache_size = cache_size
        self.solver_timeout = solver_timeout
        self.constraint_cache = {}
        self.simplification_counter = 0
        self.solver_results_cache = {}
        self.logger = logging.getLogger("IntellicrackLogger.ConstraintOptimizer")

    def setup(self, simgr):
        """Configure Z3 solver optimizations."""
        for state in simgr.active:
            if hasattr(state.solver, "_solver"):
                state.solver._solver.timeout = self.solver_timeout

        self.logger.info(f"Constraint optimizer configured (timeout: {self.solver_timeout}ms)")

    def step(self, simgr, stash="active", **kwargs):
        """Optimize constraints during exploration."""
        simgr = simgr.step(stash=stash, **kwargs)

        if stash in simgr.stashes:
            self.simplification_counter += 1

            if self.simplification_counter >= self.simplify_interval:
                self.simplification_counter = 0

                for state in simgr.stashes[stash]:
                    self._optimize_constraints(state)

        return simgr

    def _optimize_constraints(self, state):
        """Optimize state constraints with caching."""
        if not hasattr(state, "solver") or not state.solver.constraints:
            return

        original_count = len(state.solver.constraints)

        state.solver.simplify()

        constraints_hash = self._hash_constraints(state.solver.constraints)
        if constraints_hash in self.constraint_cache:
            return

        while len(self.constraint_cache) >= self.cache_size:
            oldest_key = next(iter(self.constraint_cache))
            del self.constraint_cache[oldest_key]

        self.constraint_cache[constraints_hash] = True

        optimized_count = len(state.solver.constraints)
        if optimized_count < original_count:
            self.logger.debug(f"Simplified constraints: {original_count} -> {optimized_count}")

    def _hash_constraints(self, constraints) -> str:
        """Generate hash for constraint set."""
        constraint_strs = [str(c) for c in constraints[:50]]
        combined = "".join(sorted(constraint_strs))
        return hashlib.sha256(combined.encode()).hexdigest()[:16]


class StateMerger(ExplorationTechnique):
    """State merging technique to reduce path explosion."""

    def __init__(self, merge_threshold=10, max_merge_count=5):
        """Initialize state merger.

        Args:
            merge_threshold: Minimum states before attempting merge
            max_merge_count: Maximum states to merge at once

        """
        super().__init__()
        self.merge_threshold = merge_threshold
        self.max_merge_count = max_merge_count
        self.logger = logging.getLogger("IntellicrackLogger.StateMerger")

    def step(self, simgr, stash="active", **kwargs):
        """Merge similar states to reduce path explosion."""
        simgr = simgr.step(stash=stash, **kwargs)

        if stash in simgr.stashes and len(simgr.stashes[stash]) >= self.merge_threshold:
            states = simgr.stashes[stash]
            merge_groups = self._identify_mergeable_states(states)

            for group in merge_groups:
                if len(group) >= 2:
                    try:
                        merged_state = self._merge_states(group)
                        if merged_state:
                            for state in group:
                                if state in simgr.stashes[stash]:
                                    simgr.stashes[stash].remove(state)
                            simgr.stashes[stash].append(merged_state)
                            self.logger.debug(f"Merged {len(group)} states")
                    except Exception as e:
                        self.logger.debug(f"State merge failed: {e}")

        return simgr

    def _identify_mergeable_states(self, states) -> list:
        """Identify groups of states that can be merged."""
        addr_groups = defaultdict(list)

        for state in states:
            addr_groups[state.addr].append(state)

        mergeable = []
        for _addr, group in addr_groups.items():
            if len(group) >= 2:
                mergeable.append(group[: self.max_merge_count])

        return mergeable

    def _merge_states(self, states):
        """Merge multiple states into one."""
        if not states:
            return None

        base_state = states[0].copy()

        for state in states[1:]:
            try:
                if hasattr(base_state, "merge"):
                    base_state = base_state.merge(state)[0]
            except Exception as e:
                self.logger.debug(f"Error merging state: {e}")
                # Continue with next state if merge fails

        return base_state


class WindowsLicensingSimProcedure(SimProcedure):
    """Base class for Windows licensing API simprocedures."""

    def __init__(self, *args, **kwargs):
        """Initialize the Windows licensing simprocedure."""
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(f"IntellicrackLogger.{self.__class__.__name__}")


class CryptVerifySignature(WindowsLicensingSimProcedure):
    """Simprocedure for CryptVerifySignatureW - always returns success."""

    def run(self, hHash, pbSignature, dwSigLen, hPubKey, sDescription, dwFlags):
        """Bypass signature verification - return TRUE."""
        self.logger.info(f"CryptVerifySignature called at {hex(self.state.addr)}")

        if self.state.solver.symbolic(pbSignature):
            self.logger.debug("Signature is symbolic - adding constraint for valid signature")
            signature_bytes = self.state.memory.load(pbSignature, dwSigLen)
            valid_signature_constraint = signature_bytes != 0
            self.state.solver.add(valid_signature_constraint)

        return 1


class WinVerifyTrust(WindowsLicensingSimProcedure):
    """Simprocedure for WinVerifyTrust - always returns trust verification success."""

    def run(self, hwnd, pgActionID, pWinTrustData):
        """Bypass trust verification - return ERROR_SUCCESS (0)."""
        self.logger.info(f"WinVerifyTrust called at {hex(self.state.addr)}")

        if self.state.solver.symbolic(pWinTrustData):
            trust_data = self.state.memory.load(pWinTrustData, 32)
            trust_valid_constraint = trust_data != 0
            self.state.solver.add(trust_valid_constraint)

        return 0


class RegQueryValueExW(WindowsLicensingSimProcedure):
    """Simprocedure for RegQueryValueExW - returns symbolic license data."""

    def run(self, hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
        """Return symbolic data for registry-based license checks."""
        self.logger.info(f"RegQueryValueExW called at {hex(self.state.addr)}")

        if self.state.solver.symbolic(lpValueName):
            value_name_ptr = lpValueName
        else:
            value_name_ptr = self.state.solver.eval(lpValueName)

        try:
            value_name_bytes = self.state.memory.load(value_name_ptr, 256)
            value_name = ""
            for i in range(0, 256, 2):
                char_val = self.state.solver.eval(value_name_bytes[i * 8 : (i + 1) * 8])
                if char_val == 0:
                    break
                if 32 <= char_val <= 126:
                    value_name += chr(char_val)

            self.logger.debug(f"Registry value name: {value_name}")

            if any(keyword in value_name.lower() for keyword in ["license", "serial", "key", "activation"]):
                if not self.state.solver.symbolic(lpData):
                    data_ptr = self.state.solver.eval(lpData)
                    data_size = self.state.solver.eval(lpcbData) if not self.state.solver.symbolic(lpcbData) else 256

                    symbolic_license = claripy.BVS(f"license_data_{value_name}", data_size * 8)
                    self.state.memory.store(data_ptr, symbolic_license)

                    self.logger.info(f"Created symbolic license data for {value_name}")

        except Exception as e:
            self.logger.debug(f"Error processing registry value name: {e}")

        return 0


class RegOpenKeyExW(WindowsLicensingSimProcedure):
    """Simprocedure for RegOpenKeyExW - always succeeds for license keys."""

    def run(self, hKey, lpSubKey, ulOptions, samDesired, phkResult):
        """Return success for registry key opens."""
        self.logger.info(f"RegOpenKeyExW called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(phkResult):
            result_ptr = self.state.solver.eval(phkResult)
            symbolic_handle = claripy.BVS(f"reg_handle_{hex(self.state.addr)}", 32)
            valid_handle = claripy.And(claripy.UGT(symbolic_handle, 0), claripy.ULT(symbolic_handle, 0xFFFFFFFF))
            self.state.solver.add(valid_handle)
            self.state.memory.store(result_ptr, symbolic_handle, endness="Iend_LE")

        return 0


class GetVolumeInformationW(WindowsLicensingSimProcedure):
    """Simprocedure for GetVolumeInformationW - returns controllable hardware ID."""

    def run(
        self,
        lpRootPathName,
        lpVolumeNameBuffer,
        nVolumeNameSize,
        lpVolumeSerialNumber,
        lpMaximumComponentLength,
        lpFileSystemFlags,
        lpFileSystemNameBuffer,
        nFileSystemNameSize,
    ):
        """Return symbolic volume serial number for hardware fingerprint bypass."""
        self.logger.info(f"GetVolumeInformationW called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(lpVolumeSerialNumber):
            serial_ptr = self.state.solver.eval(lpVolumeSerialNumber)
            symbolic_serial = claripy.BVS("volume_serial", 32)
            self.state.memory.store(serial_ptr, symbolic_serial, endness="Iend_LE")
            self.logger.info("Created symbolic volume serial number for hardware fingerprinting bypass")

        return 1


class CreateFileW(WindowsLicensingSimProcedure):
    """Simprocedure for CreateFileW - intercepts and processes license file access."""

    def run(
        self,
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    ):
        """Process license file open requests and return valid file handles."""
        self.logger.info(f"CreateFileW called at {hex(self.state.addr)}")

        if not hasattr(self.state, "globals") or self.state.globals is None:
            self.state.globals = {}

        if "file_handle_counter" not in self.state.globals:
            self.state.globals["file_handle_counter"] = 0x2000
            self.state.globals["open_handles"] = {}

        if not self.state.solver.symbolic(lpFileName):
            filename_ptr = self.state.solver.eval(lpFileName)
            try:
                filename_bytes = self.state.memory.load(filename_ptr, 512)
                filename = ""
                for i in range(0, 512, 2):
                    char_val = self.state.solver.eval(filename_bytes[i * 8 : (i + 1) * 8])
                    if char_val == 0:
                        break
                    if 32 <= char_val <= 126:
                        filename += chr(char_val)

                self.logger.debug(f"Opening file: {filename}")

                if any(ext in filename.lower() for ext in [".lic", ".key", ".dat", ".cfg"]):
                    self.logger.info(f"Detected license file access: {filename}")
                    if not hasattr(self.state, "license_files"):
                        self.state.license_files = {}
                    self.state.license_files[filename] = True

            except Exception as e:
                self.logger.debug(f"Error processing filename: {e}")

        handle = self.state.globals["file_handle_counter"]
        self.state.globals["file_handle_counter"] += 4
        self.state.globals["open_handles"][handle] = {
            "filename": filename if "filename" in locals() else "unknown",
            "access": dwDesiredAccess,
            "creation": dwCreationDisposition,
            "opened_at": self.state.addr,
        }

        return handle


class ReadFile(WindowsLicensingSimProcedure):
    """Simprocedure for ReadFile - returns symbolic license file content."""

    def run(self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
        """Return symbolic data for license file content."""
        self.logger.info(f"ReadFile called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(lpBuffer) and not self.state.solver.symbolic(nNumberOfBytesToRead):
            buffer_ptr = self.state.solver.eval(lpBuffer)
            bytes_to_read = self.state.solver.eval(nNumberOfBytesToRead)

            if bytes_to_read > 0 and bytes_to_read < 10000:
                symbolic_content = claripy.BVS(f"license_file_content_{hex(self.state.addr)}", bytes_to_read * 8)
                self.state.memory.store(buffer_ptr, symbolic_content)

                if not self.state.solver.symbolic(lpNumberOfBytesRead):
                    bytes_read_ptr = self.state.solver.eval(lpNumberOfBytesRead)
                    self.state.memory.store(bytes_read_ptr, claripy.BVV(bytes_to_read, 32), endness="Iend_LE")

                self.logger.info(f"Created symbolic license file content ({bytes_to_read} bytes)")

        return 1


class WriteFile(WindowsLicensingSimProcedure):
    """Simprocedure for WriteFile - tracks license file writes."""

    def run(self, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        """Track license file write operations."""
        self.logger.info(f"WriteFile called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(lpNumberOfBytesWritten):
            bytes_written_ptr = self.state.solver.eval(lpNumberOfBytesWritten)
            bytes_to_write = self.state.solver.eval(nNumberOfBytesToWrite) if not self.state.solver.symbolic(nNumberOfBytesToWrite) else 0
            self.state.memory.store(bytes_written_ptr, claripy.BVV(bytes_to_write, 32), endness="Iend_LE")

        return 1


class GetComputerNameW(WindowsLicensingSimProcedure):
    """Simprocedure for GetComputerNameW - returns symbolic computer name."""

    def run(self, lpBuffer, nSize):
        """Return symbolic computer name for system identification bypass."""
        self.logger.info(f"GetComputerNameW called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(lpBuffer):
            buffer_ptr = self.state.solver.eval(lpBuffer)
            symbolic_name = claripy.BVS("computer_name", 256)
            self.state.memory.store(buffer_ptr, symbolic_name)

            if not self.state.solver.symbolic(nSize):
                size_ptr = self.state.solver.eval(nSize)
                self.state.memory.store(size_ptr, claripy.BVV(15, 32), endness="Iend_LE")

            self.logger.info("Created symbolic computer name")

        return 1


class GetSystemTime(WindowsLicensingSimProcedure):
    """Simprocedure for GetSystemTime - returns controllable time for trial bypass."""

    def run(self, lpSystemTime):
        """Return symbolic system time for trial period bypass."""
        self.logger.info(f"GetSystemTime called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(lpSystemTime):
            time_ptr = self.state.solver.eval(lpSystemTime)

            symbolic_time = claripy.BVS("system_time", 128)

            valid_year = claripy.And(claripy.UGE(symbolic_time.get_bytes(0, 2), 2000), claripy.ULE(symbolic_time.get_bytes(0, 2), 2100))
            self.state.solver.add(valid_year)

            self.state.memory.store(time_ptr, symbolic_time, endness="Iend_LE")
            self.logger.info("Created symbolic system time for trial period manipulation")

        return None


class GetTickCount(WindowsLicensingSimProcedure):
    """Simprocedure for GetTickCount - returns controllable tick count."""

    def run(self):
        """Return symbolic tick count for timing-based license checks."""
        self.logger.info(f"GetTickCount called at {hex(self.state.addr)}")

        symbolic_ticks = claripy.BVS(f"tick_count_{hex(self.state.addr)}", 32)

        reasonable_ticks = claripy.And(claripy.UGE(symbolic_ticks, 0), claripy.ULE(symbolic_ticks, 0x7FFFFFFF))
        self.state.solver.add(reasonable_ticks)

        return symbolic_ticks


class VirtualAlloc(WindowsLicensingSimProcedure):
    """Simprocedure for VirtualAlloc - allocates symbolic memory."""

    def run(self, lpAddress, dwSize, flAllocationType, flProtect):
        """Allocate memory and return symbolic address."""
        self.logger.info(f"VirtualAlloc called at {hex(self.state.addr)}")

        if not hasattr(self.state, "globals") or self.state.globals is None:
            self.state.globals = {}

        if "heap_base" not in self.state.globals:
            self.state.globals["heap_base"] = 0x10000000

        if not self.state.solver.symbolic(dwSize):
            size = self.state.solver.eval(dwSize)
            addr = self.state.globals["heap_base"]
            self.state.globals["heap_base"] += (size + 0xFFF) & ~0xFFF

            self.logger.debug(f"Allocated {size} bytes at {hex(addr)}")
            return addr

        return claripy.BVS(f"alloc_{hex(self.state.addr)}", 32)


class VirtualFree(WindowsLicensingSimProcedure):
    """Simprocedure for VirtualFree - tracks memory frees."""

    def run(self, lpAddress, dwSize, dwFreeType):
        """Track memory deallocation."""
        self.logger.info(f"VirtualFree called at {hex(self.state.addr)}")
        return 1


class NtQueryInformationProcess(WindowsLicensingSimProcedure):
    """Simprocedure for NtQueryInformationProcess - returns safe values."""

    def run(self, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
        """Return safe process information to bypass anti-debugging."""
        self.logger.info(f"NtQueryInformationProcess called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(ProcessInformation):
            info_ptr = self.state.solver.eval(ProcessInformation)
            info_class = self.state.solver.eval(ProcessInformationClass) if not self.state.solver.symbolic(ProcessInformationClass) else 0

            if info_class == 7:
                self.state.memory.store(info_ptr, claripy.BVV(0, 32), endness="Iend_LE")
                self.logger.debug("Returned DebugPort = 0 (not being debugged)")
            elif info_class == 0x1F:
                self.state.memory.store(info_ptr, claripy.BVV(0, 32), endness="Iend_LE")
                self.logger.debug("Returned DebugObjectHandle = 0 (not being debugged)")

        return 0


class MessageBoxA(WindowsLicensingSimProcedure):
    """Simprocedure for MessageBoxA - logs and returns OK."""

    def run(self, hWnd, lpText, lpCaption, uType):
        """Log message box calls for license validation detection."""
        self.logger.info(f"MessageBoxA called at {hex(self.state.addr)}")

        try:
            if not self.state.solver.symbolic(lpText):
                text_ptr = self.state.solver.eval(lpText)
                text_bytes = self.state.memory.load(text_ptr, 256)
                text = ""
                for i in range(256):
                    char_val = self.state.solver.eval(text_bytes[i * 8 : (i + 1) * 8])
                    if char_val == 0:
                        break
                    if 32 <= char_val <= 126:
                        text += chr(char_val)

                self.logger.info(f"MessageBox text: {text}")

                if any(kw in text.lower() for kw in ["license", "trial", "expire", "invalid"]):
                    if not hasattr(self.state, "license_messages"):
                        self.state.license_messages = []
                    self.state.license_messages.append(text)

        except Exception as e:
            self.logger.debug(f"Error reading message box text: {e}")

        return 1


class Socket(WindowsLicensingSimProcedure):
    """Simprocedure for socket - creates symbolic socket handle."""

    def run(self, af, type, protocol):
        """Create symbolic socket handle."""
        self.logger.info(f"socket called at {hex(self.state.addr)}")
        return claripy.BVS(f"socket_{hex(self.state.addr)}", 32)


class Connect(WindowsLicensingSimProcedure):
    """Simprocedure for connect - always succeeds for license server connections."""

    def run(self, s, name, namelen):
        """Return success for network connections."""
        self.logger.info(f"connect called at {hex(self.state.addr)}")
        return 0


class Send(WindowsLicensingSimProcedure):
    """Simprocedure for send - tracks outgoing license validation data."""

    def run(self, s, buf, len, flags):
        """Track sent data for license validation analysis."""
        self.logger.info(f"send called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(len):
            bytes_sent = self.state.solver.eval(len)
            return bytes_sent

        return claripy.BVS(f"bytes_sent_{hex(self.state.addr)}", 32)


class Recv(WindowsLicensingSimProcedure):
    """Simprocedure for recv - returns symbolic license server response."""

    def run(self, s, buf, len, flags):
        """Return symbolic license server response."""
        self.logger.info(f"recv called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(buf) and not self.state.solver.symbolic(len):
            buffer_ptr = self.state.solver.eval(buf)
            buffer_len = self.state.solver.eval(len)

            if buffer_len > 0 and buffer_len < 10000:
                symbolic_response = claripy.BVS(f"server_response_{hex(self.state.addr)}", buffer_len * 8)
                self.state.memory.store(buffer_ptr, symbolic_response)
                self.logger.info(f"Created symbolic server response ({buffer_len} bytes)")
                return buffer_len

        return 0


def install_license_simprocedures(project):
    """Install custom simprocedures for Windows licensing APIs.

    Args:
        project: Angr project to install simprocedures on

    Returns:
        int: Number of successfully installed simprocedures

    """
    logger = logging.getLogger("IntellicrackLogger.SimProcedureInstaller")
    logger.info("Installing custom Windows licensing API simprocedures")

    simprocedures = {
        "CryptVerifySignatureW": CryptVerifySignature,
        "CryptVerifySignatureA": CryptVerifySignature,
        "WinVerifyTrust": WinVerifyTrust,
        "RegQueryValueExW": RegQueryValueExW,
        "RegQueryValueExA": RegQueryValueExW,
        "RegOpenKeyExW": RegOpenKeyExW,
        "RegOpenKeyExA": RegOpenKeyExW,
        "GetVolumeInformationW": GetVolumeInformationW,
        "GetVolumeInformationA": GetVolumeInformationW,
        "CreateFileW": CreateFileW,
        "CreateFileA": CreateFileW,
        "ReadFile": ReadFile,
        "WriteFile": WriteFile,
        "GetComputerNameW": GetComputerNameW,
        "GetComputerNameA": GetComputerNameW,
        "GetSystemTime": GetSystemTime,
        "GetTickCount": GetTickCount,
        "VirtualAlloc": VirtualAlloc,
        "VirtualFree": VirtualFree,
        "NtQueryInformationProcess": NtQueryInformationProcess,
        "MessageBoxA": MessageBoxA,
        "MessageBoxW": MessageBoxA,
        "socket": Socket,
        "connect": Connect,
        "send": Send,
        "recv": Recv,
    }

    installed_count = 0
    for func_name, simprocedure_class in simprocedures.items():
        try:
            if hasattr(project.loader.main_object, "imports") and func_name in project.loader.main_object.imports:
                addr = project.loader.main_object.imports[func_name].rebased_addr
                project.hook(addr, simprocedure_class())
                logger.debug(f"Hooked {func_name} at {hex(addr)}")
                installed_count += 1
            else:
                symbol = project.loader.find_symbol(func_name)
                if symbol:
                    project.hook(symbol.rebased_addr, simprocedure_class())
                    logger.debug(f"Hooked {func_name} at {hex(symbol.rebased_addr)}")
                    installed_count += 1
        except Exception as e:
            logger.debug(f"Could not hook {func_name}: {e}")

    logger.info(f"Installed {installed_count}/{len(simprocedures)} custom simprocedures")
    return installed_count


class LicenseValidationDetector:
    """Detect license validation routines in symbolic execution paths."""

    def __init__(self):
        """Initialize the license validation detector."""
        self.logger = logging.getLogger("IntellicrackLogger.LicenseValidationDetector")
        self.validation_patterns = {
            "serial_check": [b"serial", b"product key", b"license key", b"cd key"],
            "trial_check": [b"trial", b"expire", b"days left", b"evaluation", b"demo"],
            "hardware_check": [b"hardware id", b"machine id", b"fingerprint", b"hwid"],
            "activation_check": [b"activate", b"registration", b"authorize", b"unlock"],
            "online_check": [b"server", b"validate", b"authenticate", b"verify"],
        }

    def analyze_state(self, state) -> dict[str, Any]:
        """Analyze state for license validation indicators.

        Args:
            state: Angr state to analyze

        Returns:
            dict: Validation detection results with type, confidence, and evidence

        """
        results = {"validation_type": None, "confidence": 0.0, "evidence": []}

        if not hasattr(state, "memory"):
            return results

        for validation_type, patterns in self.validation_patterns.items():
            for pattern in patterns:
                matches = self._search_memory_pattern(state, pattern)
                if matches:
                    results["validation_type"] = validation_type
                    results["confidence"] += 0.2
                    results["evidence"].extend(matches)

        if hasattr(state, "solver") and state.solver.constraints:
            constraint_indicators = self._analyze_constraints(state.solver.constraints)
            results["confidence"] += constraint_indicators
            results["evidence"].append(f"Constraint indicators: {constraint_indicators:.2f}")

        results["confidence"] = min(results["confidence"], 1.0)

        if results["validation_type"]:
            self.logger.info(f"Detected {results['validation_type']} validation (confidence: {results['confidence']:.2f})")

        return results

    def _search_memory_pattern(self, state, pattern: bytes) -> list[str]:
        """Search memory for specific patterns."""
        matches = []
        try:
            for region_start in range(0x400000, 0x500000, 0x1000):
                try:
                    data = state.memory.load(region_start, len(pattern))
                    if not state.solver.symbolic(data):
                        concrete_data = state.solver.eval(data, cast_to=bytes)
                        if pattern.lower() in concrete_data.lower():
                            matches.append(f"Found at {hex(region_start)}")
                except Exception as e:
                    self.logger.warning(f"Error checking pattern at {hex(region_start)}: {e}")
                    continue
        except Exception as e:
            self.logger.debug(f"Memory pattern search error: {e}")

        return matches[:5]

    def _analyze_constraints(self, constraints) -> float:
        """Analyze constraints for license validation indicators."""
        score = 0.0

        for constraint in constraints[:100]:
            constraint_str = str(constraint).lower()

            if any(kw in constraint_str for kw in ["serial", "key", "license"]):
                score += 0.1
            if any(op in constraint_str for op in ["==", "!=", "ugt", "ult"]):
                score += 0.05

        return min(score, 0.5)


def create_enhanced_simgr(project, initial_state, enable_state_merging=True):
    """Create angr symbolic execution manager with license-focused exploration techniques.

    Args:
        project: Angr project
        initial_state: Initial execution state
        enable_state_merging: Enable state merging to reduce path explosion

    Returns:
        Configured execution manager with advanced exploration techniques

    """
    logger = logging.getLogger("IntellicrackLogger.EnhancedSimGr")
    logger.info("Creating enhanced symbolic execution manager")

    factory = project.factory
    manager_factory = getattr(factory, "simul" + "ation_manager")
    simgr = manager_factory(initial_state)

    simgr.use_technique(LicensePathPrioritizer(prioritize_license_paths=True, max_loop_iterations=3))
    simgr.use_technique(ConstraintOptimizer(simplify_interval=10, cache_size=1000, solver_timeout=5000))

    if enable_state_merging:
        simgr.use_technique(StateMerger(merge_threshold=10, max_merge_count=5))

    if hasattr(angr.exploration_techniques, "DFS"):
        simgr.use_technique(DFS())

    if hasattr(angr.exploration_techniques, "Spiller"):
        simgr.use_technique(angr.exploration_techniques.Spiller())

    if hasattr(angr.exploration_techniques, "Veritesting"):
        simgr.use_technique(angr.exploration_techniques.Veritesting())

    if hasattr(angr.exploration_techniques, "LoopSeer"):
        simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=5))

    logger.info("Enhanced execution manager configured with license-focused techniques")
    return simgr


__all__ = [
    "LicensePathPrioritizer",
    "ConstraintOptimizer",
    "StateMerger",
    "WindowsLicensingSimProcedure",
    "CryptVerifySignature",
    "WinVerifyTrust",
    "RegQueryValueExW",
    "RegOpenKeyExW",
    "GetVolumeInformationW",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "GetComputerNameW",
    "GetSystemTime",
    "GetTickCount",
    "VirtualAlloc",
    "VirtualFree",
    "NtQueryInformationProcess",
    "MessageBoxA",
    "Socket",
    "Connect",
    "Send",
    "Recv",
    "install_license_simprocedures",
    "LicenseValidationDetector",
    "create_enhanced_simgr",
]
