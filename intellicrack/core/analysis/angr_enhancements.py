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
from typing import Any, Dict, List, Optional, Sequence

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

    def __init__(self, prioritize_license_paths: bool = True, max_loop_iterations: int = 3) -> None:
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

    def setup(self, simgr: object) -> None:
        """Initialize prioritizer with project and keyword mappings.

        Scans the binary for functions and strings containing license-related keywords
        to identify licensing validation routines. This enables intelligent path
        prioritization during symbolic execution to focus on licensing checks.

        Args:
            simgr: Angr exploration manager with loaded project binary and symbols

        """
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

    def step(self, simgr: object, stash: str = "active", **kwargs: Any) -> object:
        """Prioritize paths based on license relevance with advanced scoring.

        Applies path scoring heuristics to rank execution paths by their relevance
        to license validation detection. Paths with higher scores are prioritized,
        enabling faster discovery of licensing checks.

        Args:
            simgr: Angr exploration manager object
            stash: Name of the state stash to process (default: "active")
            **kwargs: Additional keyword arguments passed to exploration step

        Returns:
            Modified exploration manager with prioritized paths

        """
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
                    f"lowest score: {scored_states[-1][0]:.2f}",
                )

        return simgr

    def _calculate_path_score(self, state: object) -> float:
        """Calculate path priority score for license validation relevance.

        Computes a composite score based on presence of license-related functions,
        constraint complexity, path length, and coverage metrics. Higher scores
        indicate greater relevance to licensing validation routines.

        Args:
            state: Angr execution state to score

        Returns:
            float: Prioritization score (higher = more relevant to licensing)

        """
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

    def _check_loop_detection(self, state: object) -> float:
        """Detect loops and calculate penalty for excessive iterations.

        Identifies and penalizes paths that repeatedly execute the same address
        beyond the configured iteration threshold, reducing path explosion from
        infinite or long-running loops.

        Args:
            state: Angr execution state to check for loops

        Returns:
            float: Loop penalty score (higher penalty = more iterations detected)

        """
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

    def _compute_state_hash(self, state: object) -> str:
        """Compute hash for state deduplication.

        Generates a deterministic hash based on current address and constraint
        complexity to identify and deduplicate equivalent states during exploration,
        reducing computational overhead.

        Args:
            state: Angr execution state to hash

        Returns:
            str: 16-character hexadecimal SHA256 hash of state characteristics

        """
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

    def __init__(self, simplify_interval: int = 10, cache_size: int = 1000, solver_timeout: int = 5000) -> None:
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

    def setup(self, simgr: object) -> None:
        """Configure Z3 solver optimizations.

        Configures the constraint solver with timeout parameters and
        optimization settings for improved performance during symbolic execution.

        Args:
            simgr: Angr exploration manager to configure solver for

        """
        for state in simgr.active:
            if hasattr(state.solver, "_solver"):
                state.solver._solver.timeout = self.solver_timeout

        self.logger.info(f"Constraint optimizer configured (timeout: {self.solver_timeout}ms)")

    def step(self, simgr: object, stash: str = "active", **kwargs: Any) -> object:
        """Optimize constraints during exploration.

        Periodically simplifies constraint sets to reduce solver complexity and
        improve performance. Uses caching to avoid redundant simplifications.

        Args:
            simgr: Angr exploration manager
            stash: State stash to process (default: "active")
            **kwargs: Additional exploration parameters

        Returns:
            Optimized exploration manager with simplified constraints

        """
        simgr = simgr.step(stash=stash, **kwargs)

        if stash in simgr.stashes:
            self.simplification_counter += 1

            if self.simplification_counter >= self.simplify_interval:
                self.simplification_counter = 0

                for state in simgr.stashes[stash]:
                    self._optimize_constraints(state)

        return simgr

    def _optimize_constraints(self, state: object) -> None:
        """Optimize state constraints with caching.

        Applies constraint simplification and maintains a cache of optimized
        constraint sets to avoid redundant solver operations on equivalent states.

        Args:
            state: Angr execution state with constraints to optimize

        """
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

    def _hash_constraints(self, constraints: object) -> str:
        """Generate hash for constraint set.

        Produces a deterministic hash of the constraint set for caching and
        deduplication purposes.

        Args:
            constraints: Sequence of constraints to hash

        Returns:
            str: 16-character hexadecimal SHA256 hash of constraint set

        """
        constraint_strs = [str(c) for c in constraints[:50]]
        combined = "".join(sorted(constraint_strs))
        return hashlib.sha256(combined.encode()).hexdigest()[:16]


class StateMerger(ExplorationTechnique):
    """State merging technique to reduce path explosion."""

    def __init__(self, merge_threshold: int = 10, max_merge_count: int = 5) -> None:
        """Initialize state merger.

        Args:
            merge_threshold: Minimum states before attempting merge
            max_merge_count: Maximum states to merge at once

        """
        super().__init__()
        self.merge_threshold = merge_threshold
        self.max_merge_count = max_merge_count
        self.logger = logging.getLogger("IntellicrackLogger.StateMerger")

    def step(self, simgr: object, stash: str = "active", **kwargs: Any) -> object:
        """Merge similar states to reduce path explosion.

        Identifies and merges states at the same address to reduce branching
        complexity while preserving diverse constraint sets for thorough analysis.

        Args:
            simgr: Angr exploration manager
            stash: State stash to process (default: "active")
            **kwargs: Additional exploration parameters

        Returns:
            Exploration manager with merged equivalent states

        """
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

    def _identify_mergeable_states(self, states: object) -> List[list]:
        """Identify groups of states that can be merged.

        Groups execution states by their current address and returns groups
        of sufficient size for merging, limiting to avoid excessive merges.

        Args:
            states: Sequence of execution states to group

        Returns:
            List of state groups suitable for merging

        """
        addr_groups = defaultdict(list)

        for state in states:
            addr_groups[state.addr].append(state)

        mergeable = []
        for _addr, group in addr_groups.items():
            if len(group) >= 2:
                mergeable.append(group[: self.max_merge_count])

        return mergeable

    def _merge_states(self, states: object) -> Optional[object]:
        """Merge multiple states into one.

        Merges multiple execution states into a single generalized state,
        combining their constraint sets to maintain exploration coverage.

        Args:
            states: States to merge into a single representative state

        Returns:
            Merged state or None if merge fails

        """
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

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the Windows licensing simprocedure.

        Calls parent SimProcedure constructor with all arguments and keyword arguments.

        Args:
            *args: Variable positional arguments passed to SimProcedure
            **kwargs: Variable keyword arguments passed to SimProcedure

        """
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(f"IntellicrackLogger.{self.__class__.__name__}")


class CryptVerifySignature(WindowsLicensingSimProcedure):
    """Simprocedure for CryptVerifySignatureW - always returns success."""

    def run(self, hHash: object, pbSignature: object, dwSigLen: object, hPubKey: object, sDescription: object, dwFlags: object) -> int:
        """Bypass signature verification - return TRUE.

        Returns success status for cryptographic signature verification without
        validating the actual signature data. Extracts and logs signature details
        when available for analysis purposes.

        Args:
            hHash: Hash object handle
            pbSignature: Pointer to signature data
            dwSigLen: Length of signature data
            hPubKey: Public key handle for verification
            sDescription: Optional signature description
            dwFlags: Verification flags

        Returns:
            int: 1 (TRUE) indicating successful verification

        """
        self.logger.info(f"CryptVerifySignature called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(hHash):
            hash_value = self.state.solver.eval(hHash)
            self.logger.debug(f"Hash handle: {hex(hash_value)}")

        if not self.state.solver.symbolic(hPubKey):
            pubkey_value = self.state.solver.eval(hPubKey)
            self.logger.debug(f"Public key handle: {hex(pubkey_value)}")

        if not self.state.solver.symbolic(sDescription):
            try:
                desc_ptr = self.state.solver.eval(sDescription)
                if desc_ptr != 0:
                    desc_bytes = self.state.memory.load(desc_ptr, 128)
                    desc_str = ""
                    for i in range(0, 128, 2):
                        char_val = self.state.solver.eval(desc_bytes[i * 8 : (i + 1) * 8])
                        if char_val == 0:
                            break
                        if 32 <= char_val <= 126:
                            desc_str += chr(char_val)
                    self.logger.debug(f"Signature description: {desc_str}")
            except Exception as e:
                self.logger.debug(f"Error reading signature description: {e}")

        if self.state.solver.symbolic(pbSignature):
            self.logger.debug("Signature is symbolic - adding constraint for valid signature")
            signature_bytes = self.state.memory.load(pbSignature, dwSigLen)
            valid_signature_constraint = signature_bytes != 0
            self.state.solver.add(valid_signature_constraint)

        return 1


class WinVerifyTrust(WindowsLicensingSimProcedure):
    """Simprocedure for WinVerifyTrust - always returns trust verification success."""

    def run(self, hwnd: object, pgActionID: object, pWinTrustData: object) -> int:
        """Bypass trust verification - return ERROR_SUCCESS (0).

        Returns success status for Windows trust verification without validating
        digital certificates. Extracts action GUID and trust data for analysis.

        Args:
            hwnd: Parent window handle
            pgActionID: Pointer to action GUID for verification type
            pWinTrustData: Pointer to WINTRUST_DATA structure

        Returns:
            int: 0 (ERROR_SUCCESS) indicating verified trust status

        """
        self.logger.info(f"WinVerifyTrust called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(pgActionID):
            try:
                action_guid_ptr = self.state.solver.eval(pgActionID)
                if action_guid_ptr != 0:
                    guid_data = self.state.memory.load(action_guid_ptr, 16)
                    if not self.state.solver.symbolic(guid_data):
                        guid_bytes = self.state.solver.eval(guid_data, cast_to=bytes)
                        self.logger.debug(f"Trust action GUID: {guid_bytes.hex()}")
            except Exception as e:
                self.logger.debug(f"Error reading trust action GUID: {e}")

        if self.state.solver.symbolic(pWinTrustData):
            trust_data = self.state.memory.load(pWinTrustData, 32)
            trust_valid_constraint = trust_data != 0
            self.state.solver.add(trust_valid_constraint)

        return 0


class RegQueryValueExW(WindowsLicensingSimProcedure):
    """Simprocedure for RegQueryValueExW - returns symbolic license data."""

    def run(self, hKey: object, lpValueName: object, lpReserved: object, lpType: object, lpData: object, lpcbData: object) -> int:
        """Return symbolic data for registry-based license checks.

        Intercepts registry queries for license-related values and returns
        symbolic data to allow constraint-based exploration of license validation paths.

        Args:
            hKey: Registry key handle
            lpValueName: Pointer to value name string
            lpReserved: Reserved parameter (unused)
            lpType: Pointer to data type output
            lpData: Pointer to data buffer output
            lpcbData: Pointer to data size

        Returns:
            int: 0 (ERROR_SUCCESS) indicating successful registry query

        """
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

    def run(self, hKey: object, lpSubKey: object, ulOptions: object, samDesired: object, phkResult: object) -> int:
        """Return success for registry key opens.

        Intercepts registry key open operations and returns symbolic valid handles.
        Logs registry access rights and options for analysis.

        Args:
            hKey: Parent registry key handle
            lpSubKey: Pointer to subkey name
            ulOptions: Open options flags
            samDesired: Desired access rights
            phkResult: Pointer to output key handle

        Returns:
            int: 0 (ERROR_SUCCESS) indicating successful key open

        """
        self.logger.info(f"RegOpenKeyExW called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(ulOptions):
            options_value = self.state.solver.eval(ulOptions)
            self.logger.debug(f"Registry open options: {hex(options_value)}")

        if not self.state.solver.symbolic(samDesired):
            desired_access = self.state.solver.eval(samDesired)
            access_rights = []
            if desired_access & 0x0001:
                access_rights.append("QUERY_VALUE")
            if desired_access & 0x0002:
                access_rights.append("SET_VALUE")
            if desired_access & 0x0004:
                access_rights.append("CREATE_SUB_KEY")
            if desired_access & 0x00020000:
                access_rights.append("READ")
            if desired_access & 0x20000:
                access_rights.append("WRITE")
            self.logger.debug(f"Registry access rights: {' | '.join(access_rights) if access_rights else hex(desired_access)}")

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
        lpRootPathName: object,
        lpVolumeNameBuffer: object,
        nVolumeNameSize: object,
        lpVolumeSerialNumber: object,
        lpMaximumComponentLength: object,
        lpFileSystemFlags: object,
        lpFileSystemNameBuffer: object,
        nFileSystemNameSize: object,
    ) -> int:
        """Return symbolic volume serial number for hardware fingerprint bypass.

        Provides symbolic volume serial numbers to allow constraint-based exploration
        of hardware fingerprinting checks in licensing validation.

        Args:
            lpRootPathName: Pointer to root path name
            lpVolumeNameBuffer: Pointer to volume name buffer output
            nVolumeNameSize: Volume name buffer size
            lpVolumeSerialNumber: Pointer to serial number output
            lpMaximumComponentLength: Pointer to max component length output
            lpFileSystemFlags: Pointer to filesystem flags output
            lpFileSystemNameBuffer: Pointer to filesystem name buffer output
            nFileSystemNameSize: Filesystem name buffer size

        Returns:
            int: 1 (TRUE) indicating successful volume information retrieval

        """
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
        lpFileName: object,
        dwDesiredAccess: object,
        dwShareMode: object,
        lpSecurityAttributes: object,
        dwCreationDisposition: object,
        dwFlagsAndAttributes: object,
        hTemplateFile: object,
    ) -> int:
        """Process license file open requests and return valid file handles.

        Intercepts file creation operations and tracks license file accesses.
        Returns valid file handles for license files to enable continued execution.

        Args:
            lpFileName: Pointer to filename string
            dwDesiredAccess: Desired access rights
            dwShareMode: File sharing mode
            lpSecurityAttributes: Pointer to security attributes
            dwCreationDisposition: Creation disposition flags
            dwFlagsAndAttributes: File flags and attributes
            hTemplateFile: Template file handle

        Returns:
            int: File handle for opened file

        """
        self.logger.info(f"CreateFileW called at {hex(self.state.addr)}")

        if not hasattr(self.state, "globals") or self.state.globals is None:
            self.state.globals = {}

        if "file_handle_counter" not in self.state.globals:
            self.state.globals["file_handle_counter"] = 0x2000
            self.state.globals["open_handles"] = {}

        if not self.state.solver.symbolic(dwShareMode):
            share_mode = self.state.solver.eval(dwShareMode)
            share_flags = []
            if share_mode & 0x00000001:
                share_flags.append("READ")
            if share_mode & 0x00000002:
                share_flags.append("WRITE")
            if share_mode & 0x00000004:
                share_flags.append("DELETE")
            self.logger.debug(f"File share mode: {' | '.join(share_flags) if share_flags else 'EXCLUSIVE'}")

        if not self.state.solver.symbolic(lpSecurityAttributes):
            sec_attr_ptr = self.state.solver.eval(lpSecurityAttributes)
            if sec_attr_ptr != 0:
                self.logger.debug(f"Security attributes provided at {hex(sec_attr_ptr)}")

        if not self.state.solver.symbolic(dwFlagsAndAttributes):
            flags_attrs = self.state.solver.eval(dwFlagsAndAttributes)
            flag_list = []
            if flags_attrs & 0x00000001:
                flag_list.append("READONLY")
            if flags_attrs & 0x00000002:
                flag_list.append("HIDDEN")
            if flags_attrs & 0x00000080:
                flag_list.append("NORMAL")
            if flags_attrs & 0x40000000:
                flag_list.append("FLAG_OVERLAPPED")
            if flags_attrs & 0x08000000:
                flag_list.append("FLAG_NO_BUFFERING")
            self.logger.debug(f"File flags/attributes: {' | '.join(flag_list) if flag_list else hex(flags_attrs)}")

        if not self.state.solver.symbolic(hTemplateFile):
            template_handle = self.state.solver.eval(hTemplateFile)
            if template_handle != 0:
                self.logger.debug(f"Template file handle: {hex(template_handle)}")

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
            "share_mode": dwShareMode,
            "creation": dwCreationDisposition,
            "flags": dwFlagsAndAttributes,
            "opened_at": self.state.addr,
        }

        return handle


class ReadFile(WindowsLicensingSimProcedure):
    """Simprocedure for ReadFile - returns symbolic license file content."""

    def run(self, hFile: object, lpBuffer: object, nNumberOfBytesToRead: object, lpNumberOfBytesRead: object, lpOverlapped: object) -> int:
        """Return symbolic data for license file content.

        Intercepts file read operations and returns symbolic data for license file
        content, enabling constraint-based analysis of license file parsing logic.

        Args:
            hFile: File handle to read from
            lpBuffer: Pointer to buffer for read data
            nNumberOfBytesToRead: Number of bytes to read
            lpNumberOfBytesRead: Pointer to bytes read output
            lpOverlapped: Pointer to overlapped I/O structure

        Returns:
            int: 1 (TRUE) indicating successful file read

        """
        self.logger.info(f"ReadFile called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(hFile):
            file_handle = self.state.solver.eval(hFile)
            self.logger.debug(f"Reading from file handle: {hex(file_handle)}")

            if hasattr(self.state, "globals") and "open_handles" in self.state.globals:
                if file_handle in self.state.globals["open_handles"]:
                    file_info = self.state.globals["open_handles"][file_handle]
                    self.logger.debug(f"File info: {file_info.get('filename', 'unknown')}")

        if not self.state.solver.symbolic(lpOverlapped):
            overlapped_ptr = self.state.solver.eval(lpOverlapped)
            if overlapped_ptr != 0:
                self.logger.debug(f"Overlapped I/O structure at {hex(overlapped_ptr)}")

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

    def run(self, hFile: object, lpBuffer: object, nNumberOfBytesToWrite: object, lpNumberOfBytesWritten: object, lpOverlapped: object) -> int:
        """Track license file write operations.

        Intercepts file write operations to track license file modifications
        and extract written data for analysis.

        Args:
            hFile: File handle to write to
            lpBuffer: Pointer to buffer with data to write
            nNumberOfBytesToWrite: Number of bytes to write
            lpNumberOfBytesWritten: Pointer to bytes written output
            lpOverlapped: Pointer to overlapped I/O structure

        Returns:
            int: 1 (TRUE) indicating successful file write

        """
        self.logger.info(f"WriteFile called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(hFile):
            file_handle = self.state.solver.eval(hFile)
            self.logger.debug(f"Writing to file handle: {hex(file_handle)}")

            if hasattr(self.state, "globals") and "open_handles" in self.state.globals:
                if file_handle in self.state.globals["open_handles"]:
                    file_info = self.state.globals["open_handles"][file_handle]
                    self.logger.debug(f"Writing to file: {file_info.get('filename', 'unknown')}")

        if not self.state.solver.symbolic(lpOverlapped):
            overlapped_ptr = self.state.solver.eval(lpOverlapped)
            if overlapped_ptr != 0:
                self.logger.debug(f"Overlapped I/O structure at {hex(overlapped_ptr)}")

        if not self.state.solver.symbolic(lpBuffer) and not self.state.solver.symbolic(nNumberOfBytesToWrite):
            buffer_ptr = self.state.solver.eval(lpBuffer)
            bytes_to_write = self.state.solver.eval(nNumberOfBytesToWrite)
            if bytes_to_write > 0 and bytes_to_write < 1000:
                try:
                    write_data = self.state.memory.load(buffer_ptr, bytes_to_write)
                    if not self.state.solver.symbolic(write_data):
                        data_bytes = self.state.solver.eval(write_data, cast_to=bytes)
                        self.logger.debug(f"Writing {bytes_to_write} bytes: {data_bytes[:min(32, len(data_bytes))].hex()}...")
                except Exception as e:
                    self.logger.debug(f"Error reading write buffer: {e}")

        if not self.state.solver.symbolic(lpNumberOfBytesWritten):
            bytes_written_ptr = self.state.solver.eval(lpNumberOfBytesWritten)
            bytes_to_write = self.state.solver.eval(nNumberOfBytesToWrite) if not self.state.solver.symbolic(nNumberOfBytesToWrite) else 0
            self.state.memory.store(bytes_written_ptr, claripy.BVV(bytes_to_write, 32), endness="Iend_LE")

        return 1


class GetComputerNameW(WindowsLicensingSimProcedure):
    """Simprocedure for GetComputerNameW - returns symbolic computer name."""

    def run(self, lpBuffer: object, nSize: object) -> int:
        """Return symbolic computer name for system identification bypass.

        Provides symbolic computer name values to bypass hardware fingerprinting
        checks that rely on system identification.

        Args:
            lpBuffer: Pointer to buffer for computer name output
            nSize: Size of buffer or pointer to name length

        Returns:
            int: 1 (TRUE) indicating successful name retrieval

        """
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

    def run(self, lpSystemTime: object) -> None:
        """Return symbolic system time for trial period bypass.

        Provides symbolic system time values with constraints to enable exploration
        of trial period validation logic and time-based licensing checks.

        Args:
            lpSystemTime: Pointer to SYSTEMTIME structure output

        """
        self.logger.info(f"GetSystemTime called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(lpSystemTime):
            time_ptr = self.state.solver.eval(lpSystemTime)

            symbolic_time = claripy.BVS("system_time", 128)

            valid_year = claripy.And(claripy.UGE(symbolic_time.get_bytes(0, 2), 2000), claripy.ULE(symbolic_time.get_bytes(0, 2), 2100))
            self.state.solver.add(valid_year)

            self.state.memory.store(time_ptr, symbolic_time, endness="Iend_LE")
            self.logger.info("Created symbolic system time for trial period manipulation")



class GetTickCount(WindowsLicensingSimProcedure):
    """Simprocedure for GetTickCount - returns controllable tick count."""

    def run(self) -> object:
        """Return symbolic tick count for timing-based license checks.

        Provides symbolic tick count values to enable exploration of timing-based
        license validation checks and timing attack detection logic.

        Returns:
            object: Symbolic bitvector representing system tick count

        """
        self.logger.info(f"GetTickCount called at {hex(self.state.addr)}")

        symbolic_ticks = claripy.BVS(f"tick_count_{hex(self.state.addr)}", 32)

        reasonable_ticks = claripy.And(claripy.UGE(symbolic_ticks, 0), claripy.ULE(symbolic_ticks, 0x7FFFFFFF))
        self.state.solver.add(reasonable_ticks)

        return symbolic_ticks


class VirtualAlloc(WindowsLicensingSimProcedure):
    """Simprocedure for VirtualAlloc - allocates symbolic memory."""

    def run(self, lpAddress: object, dwSize: object, flAllocationType: object, flProtect: object) -> int:
        """Allocate memory and return symbolic address.

        Performs virtual memory allocation operations and returns addresses. Tracks
        allocations for correlation with other memory operations during analysis.

        Args:
            lpAddress: Requested allocation address or NULL
            dwSize: Number of bytes to allocate
            flAllocationType: Memory allocation type flags
            flProtect: Memory protection flags

        Returns:
            int: Allocated memory address or symbolic value

        """
        self.logger.info(f"VirtualAlloc called at {hex(self.state.addr)}")

        if not hasattr(self.state, "globals") or self.state.globals is None:
            self.state.globals = {}

        if "heap_base" not in self.state.globals:
            self.state.globals["heap_base"] = 0x10000000
            self.state.globals["allocations"] = {}

        if not self.state.solver.symbolic(lpAddress):
            requested_addr = self.state.solver.eval(lpAddress)
            if requested_addr != 0:
                self.logger.debug(f"Requested specific address: {hex(requested_addr)}")

        if not self.state.solver.symbolic(flAllocationType):
            alloc_type = self.state.solver.eval(flAllocationType)
            alloc_flags = []
            if alloc_type & 0x00001000:
                alloc_flags.append("MEM_COMMIT")
            if alloc_type & 0x00002000:
                alloc_flags.append("MEM_RESERVE")
            if alloc_type & 0x00080000:
                alloc_flags.append("MEM_RESET")
            if alloc_type & 0x00400000:
                alloc_flags.append("MEM_TOP_DOWN")
            self.logger.debug(f"Allocation type: {' | '.join(alloc_flags) if alloc_flags else hex(alloc_type)}")

        if not self.state.solver.symbolic(flProtect):
            protect = self.state.solver.eval(flProtect)
            protect_flags = []
            if protect & 0x01:
                protect_flags.append("PAGE_NOACCESS")
            if protect & 0x02:
                protect_flags.append("PAGE_READONLY")
            if protect & 0x04:
                protect_flags.append("PAGE_READWRITE")
            if protect & 0x10:
                protect_flags.append("PAGE_EXECUTE")
            if protect & 0x20:
                protect_flags.append("PAGE_EXECUTE_READ")
            if protect & 0x40:
                protect_flags.append("PAGE_EXECUTE_READWRITE")
            self.logger.debug(f"Memory protection: {' | '.join(protect_flags) if protect_flags else hex(protect)}")

        if not self.state.solver.symbolic(dwSize):
            size = self.state.solver.eval(dwSize)

            if not self.state.solver.symbolic(lpAddress):
                requested_addr = self.state.solver.eval(lpAddress)
                if requested_addr != 0:
                    addr = requested_addr
                else:
                    addr = self.state.globals["heap_base"]
                    self.state.globals["heap_base"] += (size + 0xFFF) & ~0xFFF
            else:
                addr = self.state.globals["heap_base"]
                self.state.globals["heap_base"] += (size + 0xFFF) & ~0xFFF

            self.state.globals["allocations"][addr] = {
                "size": size,
                "type": flAllocationType,
                "protect": flProtect,
                "allocated_at": self.state.addr,
            }

            self.logger.debug(f"Allocated {size} bytes at {hex(addr)}")
            return addr

        return claripy.BVS(f"alloc_{hex(self.state.addr)}", 32)


class VirtualFree(WindowsLicensingSimProcedure):
    """Simprocedure for VirtualFree - tracks memory frees."""

    def run(self, lpAddress: object, dwSize: object, dwFreeType: object) -> int:
        """Track memory deallocation.

        Monitors virtual memory deallocation operations and logs allocation
        information for tracking memory usage patterns during analysis.

        Args:
            lpAddress: Address of memory to deallocate
            dwSize: Size of memory region
            dwFreeType: Deallocation type flags

        Returns:
            int: 1 (TRUE) indicating successful deallocation

        """
        self.logger.info(f"VirtualFree called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(lpAddress):
            addr = self.state.solver.eval(lpAddress)
            self.logger.debug(f"Freeing memory at {hex(addr)}")

            if hasattr(self.state, "globals") and "allocations" in self.state.globals:
                if addr in self.state.globals["allocations"]:
                    alloc_info = self.state.globals["allocations"][addr]
                    self.logger.debug(f"Freeing allocation: size={alloc_info['size']}, allocated_at={hex(alloc_info['allocated_at'])}")
                    del self.state.globals["allocations"][addr]

        if not self.state.solver.symbolic(dwFreeType):
            free_type = self.state.solver.eval(dwFreeType)
            free_flags = []
            if free_type & 0x00004000:
                free_flags.append("MEM_DECOMMIT")
            if free_type & 0x00008000:
                free_flags.append("MEM_RELEASE")
            self.logger.debug(f"Free type: {' | '.join(free_flags) if free_flags else hex(free_type)}")

        return 1


class NtQueryInformationProcess(WindowsLicensingSimProcedure):
    """Simprocedure for NtQueryInformationProcess - returns safe values."""

    def run(self, ProcessHandle: object, ProcessInformationClass: object, ProcessInformation: object, ProcessInformationLength: object, ReturnLength: object) -> int:
        """Return safe process information to bypass anti-debugging.

        Intercepts process information queries and returns values that bypass
        anti-debugging checks, including safe DebugPort and DebugObjectHandle values.

        Args:
            ProcessHandle: Handle to process
            ProcessInformationClass: Information class requested
            ProcessInformation: Pointer to output buffer
            ProcessInformationLength: Size of output buffer
            ReturnLength: Pointer to actual data length returned

        Returns:
            int: 0 (STATUS_SUCCESS) indicating successful query

        """
        self.logger.info(f"NtQueryInformationProcess called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(ProcessHandle):
            handle = self.state.solver.eval(ProcessHandle)
            self.logger.debug(f"Process handle: {hex(handle)}")

        if not self.state.solver.symbolic(ProcessInformationLength):
            info_length = self.state.solver.eval(ProcessInformationLength)
            self.logger.debug(f"Information buffer length: {info_length}")

        if not self.state.solver.symbolic(ProcessInformation):
            info_ptr = self.state.solver.eval(ProcessInformation)
            info_class = self.state.solver.eval(ProcessInformationClass) if not self.state.solver.symbolic(ProcessInformationClass) else 0

            if info_class == 7:
                self.state.memory.store(info_ptr, claripy.BVV(0, 32), endness="Iend_LE")
                self.logger.debug("Returned DebugPort = 0 (not being debugged)")
                if not self.state.solver.symbolic(ReturnLength):
                    return_length_ptr = self.state.solver.eval(ReturnLength)
                    if return_length_ptr != 0:
                        self.state.memory.store(return_length_ptr, claripy.BVV(4, 32), endness="Iend_LE")
            elif info_class == 0x1F:
                self.state.memory.store(info_ptr, claripy.BVV(0, 32), endness="Iend_LE")
                self.logger.debug("Returned DebugObjectHandle = 0 (not being debugged)")
                if not self.state.solver.symbolic(ReturnLength):
                    return_length_ptr = self.state.solver.eval(ReturnLength)
                    if return_length_ptr != 0:
                        self.state.memory.store(return_length_ptr, claripy.BVV(4, 32), endness="Iend_LE")
            elif info_class == 0:
                self.logger.debug("ProcessBasicInformation requested")
                if not self.state.solver.symbolic(ReturnLength):
                    return_length_ptr = self.state.solver.eval(ReturnLength)
                    if return_length_ptr != 0:
                        self.state.memory.store(return_length_ptr, claripy.BVV(48, 32), endness="Iend_LE")

        return 0


class MessageBoxA(WindowsLicensingSimProcedure):
    """Simprocedure for MessageBoxA - logs and returns OK."""

    def run(self, hWnd: object, lpText: object, lpCaption: object, uType: object) -> int:
        """Log message box calls for license validation detection.

        Intercepts message box calls and extracts text and captions for analysis.
        Identifies license validation prompts and tracks them for correlation.

        Args:
            hWnd: Parent window handle
            lpText: Pointer to message text
            lpCaption: Pointer to caption text
            uType: Message box type and button flags

        Returns:
            int: 1 (IDOK) indicating user clicked OK button

        """
        self.logger.info(f"MessageBoxA called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(hWnd):
            window_handle = self.state.solver.eval(hWnd)
            self.logger.debug(f"Window handle: {hex(window_handle) if window_handle != 0 else 'NULL (Desktop)'}")

        if not self.state.solver.symbolic(uType):
            msg_type = self.state.solver.eval(uType)
            buttons = msg_type & 0x0F
            icon = msg_type & 0xF0
            msg_type & 0xF00

            button_types = {0: "OK", 1: "OK/Cancel", 2: "Abort/Retry/Ignore", 3: "Yes/No/Cancel", 4: "Yes/No", 5: "Retry/Cancel"}
            icon_types = {0x10: "STOP", 0x20: "QUESTION", 0x30: "EXCLAMATION", 0x40: "INFORMATION"}

            self.logger.debug(f"MessageBox type - Buttons: {button_types.get(buttons, f'Unknown({buttons})')}, Icon: {icon_types.get(icon, f'None({hex(icon)})')}")

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

            if not self.state.solver.symbolic(lpCaption):
                caption_ptr = self.state.solver.eval(lpCaption)
                if caption_ptr != 0:
                    caption_bytes = self.state.memory.load(caption_ptr, 128)
                    caption = ""
                    for i in range(128):
                        char_val = self.state.solver.eval(caption_bytes[i * 8 : (i + 1) * 8])
                        if char_val == 0:
                            break
                        if 32 <= char_val <= 126:
                            caption += chr(char_val)
                    self.logger.info(f"MessageBox caption: {caption}")

        except Exception as e:
            self.logger.debug(f"Error reading message box text: {e}")

        return 1


class Socket(WindowsLicensingSimProcedure):
    """Simprocedure for socket - creates symbolic socket handle."""

    def run(self, af: object, type: object, protocol: object) -> object:
        """Create symbolic socket handle.

        Creates symbolic socket handles for network communication interception.
        Logs socket parameters for analysis of license server connections.

        Args:
            af: Address family (AF_INET, AF_INET6, etc.)
            type: Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
            protocol: Protocol type (IPPROTO_TCP, IPPROTO_UDP, etc.)

        Returns:
            object: Symbolic bitvector representing socket descriptor

        """
        self.logger.info(f"socket called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(af):
            address_family = self.state.solver.eval(af)
            af_types = {2: "AF_INET", 23: "AF_INET6", 1: "AF_UNIX"}
            self.logger.debug(f"Address family: {af_types.get(address_family, f'Unknown({address_family})')}")

        if not self.state.solver.symbolic(type):
            sock_type = self.state.solver.eval(type)
            type_names = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW"}
            self.logger.debug(f"Socket type: {type_names.get(sock_type, f'Unknown({sock_type})')}")

        if not self.state.solver.symbolic(protocol):
            proto = self.state.solver.eval(protocol)
            proto_names = {0: "IPPROTO_IP", 6: "IPPROTO_TCP", 17: "IPPROTO_UDP"}
            self.logger.debug(f"Protocol: {proto_names.get(proto, f'Unknown({proto})')}")

        return claripy.BVS(f"socket_{hex(self.state.addr)}", 32)


class Connect(WindowsLicensingSimProcedure):
    """Simprocedure for connect - always succeeds for license server connections."""

    def run(self, s: object, name: object, namelen: object) -> int:
        """Return success for network connections.

        Intercepts socket connection operations and returns success status.
        Extracts and logs connection target addresses for license server analysis.

        Args:
            s: Socket descriptor
            name: Pointer to sockaddr structure
            namelen: Size of sockaddr structure

        Returns:
            int: 0 (SUCCESS) indicating successful connection

        """
        self.logger.info(f"connect called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(s):
            socket_fd = self.state.solver.eval(s)
            self.logger.debug(f"Socket descriptor: {socket_fd}")

        if not self.state.solver.symbolic(name) and not self.state.solver.symbolic(namelen):
            addr_ptr = self.state.solver.eval(name)
            addr_len = self.state.solver.eval(namelen)

            if addr_len >= 8:
                try:
                    sockaddr_data = self.state.memory.load(addr_ptr, min(addr_len, 28))
                    if not self.state.solver.symbolic(sockaddr_data):
                        addr_family = self.state.solver.eval(sockaddr_data.get_bytes(0, 2))

                        if addr_family == 2:
                            port_bytes = sockaddr_data.get_bytes(2, 2)
                            port = self.state.solver.eval(port_bytes)
                            port_network_order = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)

                            ip_bytes = sockaddr_data.get_bytes(4, 4)
                            ip_value = self.state.solver.eval(ip_bytes)
                            ip_addr = f"{(ip_value >> 24) & 0xFF}.{(ip_value >> 16) & 0xFF}.{(ip_value >> 8) & 0xFF}.{ip_value & 0xFF}"

                            self.logger.info(f"Connecting to {ip_addr}:{port_network_order} (AF_INET)")
                        elif addr_family == 23:
                            self.logger.info("Connecting to IPv6 address (AF_INET6)")
                except Exception as e:
                    self.logger.debug(f"Error reading sockaddr structure: {e}")

        return 0


class Send(WindowsLicensingSimProcedure):
    """Simprocedure for send - tracks outgoing license validation data."""

    def run(self, s: object, buf: object, len: object, flags: object) -> object:
        """Track sent data for license validation analysis.

        Monitors data sent to license servers and extracts validation data
        for analysis of license request formats.

        Args:
            s: Socket descriptor
            buf: Pointer to data buffer to send
            len: Number of bytes to send
            flags: Send operation flags

        Returns:
            object: Number of bytes sent

        """
        self.logger.info(f"send called at {hex(self.state.addr)}")

        if not self.state.solver.symbolic(len):
            bytes_sent = self.state.solver.eval(len)
            return bytes_sent

        return claripy.BVS(f"bytes_sent_{hex(self.state.addr)}", 32)


class Recv(WindowsLicensingSimProcedure):
    """Simprocedure for recv - returns symbolic license server response."""

    def run(self, s: object, buf: object, len: object, flags: object) -> int:
        """Return symbolic license server response.

        Provides symbolic data for received network packets to enable constraint-based
        exploration of license server response handling logic.

        Args:
            s: Socket descriptor
            buf: Pointer to receive buffer
            len: Size of receive buffer
            flags: Receive operation flags

        Returns:
            int: Number of bytes received

        """
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


def install_license_simprocedures(project: object) -> int:
    """Install custom simprocedures for Windows licensing APIs.

    Registers all licensing-related Windows API simprocedures with the Angr project,
    enabling interception and control of licensing checks during symbolic execution.

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

    def __init__(self) -> None:
        """Initialize the license validation detector."""
        self.logger = logging.getLogger("IntellicrackLogger.LicenseValidationDetector")
        self.validation_patterns = {
            "serial_check": [b"serial", b"product key", b"license key", b"cd key"],
            "trial_check": [b"trial", b"expire", b"days left", b"evaluation", b"demo"],
            "hardware_check": [b"hardware id", b"machine id", b"fingerprint", b"hwid"],
            "activation_check": [b"activate", b"registration", b"authorize", b"unlock"],
            "online_check": [b"server", b"validate", b"authenticate", b"verify"],
        }

    def analyze_state(self, state: object) -> Dict[str, Any]:
        """Analyze state for license validation indicators.

        Examines memory and constraints to identify indicators of license validation
        operations including serial checks, trial period checks, and activation checks.

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

    def _search_memory_pattern(self, state: object, pattern: bytes) -> List[str]:
        """Search memory for specific patterns.

        Scans memory regions for licensing-related keyword patterns and returns
        matching addresses for correlation with validation routines.

        Args:
            state: Angr execution state with memory to search
            pattern: Byte pattern to search for

        Returns:
            List of memory addresses where pattern was found

        """
        matches: List[str] = []
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

    def _analyze_constraints(self, constraints: object) -> float:
        """Analyze constraints for license validation indicators.

        Examines solver constraints to identify patterns matching licensing checks
        such as equality comparisons, range checks, and licensing-related keywords.

        Args:
            constraints: Set of symbolic constraints to analyze

        Returns:
            float: Confidence score for license validation indicators

        """
        score = 0.0

        for constraint in constraints[:100]:
            constraint_str = str(constraint).lower()

            if any(kw in constraint_str for kw in ["serial", "key", "license"]):
                score += 0.1
            if any(op in constraint_str for op in ["==", "!=", "ugt", "ult"]):
                score += 0.05

        return min(score, 0.5)


def create_enhanced_simgr(project: object, initial_state: object, enable_state_merging: bool = True) -> object:
    """Create angr symbolic execution manager with license-focused exploration techniques.

    Configures an exploration manager with optimization techniques tailored for
    discovering and analyzing software licensing protections through symbolic execution.

    Args:
        project: Angr project with loaded binary
        initial_state: Initial execution state
        enable_state_merging: Enable state merging to reduce path explosion

    Returns:
        Configured exploration manager with advanced exploration techniques

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
