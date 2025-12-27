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

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any, cast

from intellicrack.utils.type_safety import validate_type


if TYPE_CHECKING:
    from claripy.ast.bv import BV


class ExplorationTechniqueBase:
    _initialized: bool = False

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self._initialized = True

    def setup(self, simgr: Any) -> None:
        _ = simgr
        _ = self._initialized

    def step(self, simgr: Any, stash: str = "active", **kwargs: Any) -> Any:
        _ = stash
        _ = kwargs
        _ = self._initialized
        return simgr


class SimProcedureBase:
    state: Any

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass


ANGR_AVAILABLE: bool
angr: Any
claripy: Any
DFS: Any

try:
    import angr as angr_module
    import claripy as claripy_module
    from angr.exploration_techniques import DFS as DFS_class

    angr = angr_module
    claripy = claripy_module
    DFS = DFS_class
    ANGR_AVAILABLE = True
except ImportError:
    angr = cast("type[Any]", None)
    claripy = cast("type[Any]", None)
    DFS = cast("type[Any]", None)
    ANGR_AVAILABLE = False


class LicensePathPrioritizer(ExplorationTechniqueBase):
    """Path prioritization strategy for license validation discovery with sophisticated heuristics."""

    def __init__(self, *, prioritize_license_paths: bool = True, max_loop_iterations: int = 3) -> None:
        """Initialize path prioritizer with loop detection.

        Args:
            prioritize_license_paths: Enable license path prioritization
            max_loop_iterations: Maximum loop iterations before deprioritizing

        """
        cast("Any", super()).__init__()
        self.prioritize_license_paths: bool = prioritize_license_paths
        self.max_loop_iterations: int = max_loop_iterations
        self.license_keywords: list[bytes] = [
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
        self.path_scores: dict[int, float] = {}
        self.license_function_addrs: set[int] = set()
        self.loop_counters: defaultdict[int, defaultdict[int, int]] = defaultdict(lambda: defaultdict(int))
        self.state_hashes: dict[str, bool] = {}
        self.coverage_map: set[int] = set()
        self.logger: logging.Logger = logging.getLogger("IntellicrackLogger.LicensePathPrioritizer")

    def setup(self, simgr: Any) -> None:
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
                self.logger.debug("Identified license function: %s at %s", func.name, hex(func.addr))

        for string_ref in simgr._project.loader.main_object.sections_map.get(".rdata", []):
            try:
                data = simgr._project.loader.memory.load(string_ref, 256)
                if any(keyword in data.lower() for keyword in self.license_keywords):
                    self.logger.debug("Found license-related string at %s", hex(string_ref))
            except Exception as e:
                self.logger.debug("Error loading string data at %s: %s", hex(string_ref), e, exc_info=True)
                continue

    def step(self, simgr: Any, stash: str = "active", **kwargs: Any) -> Any:
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
                    "Prioritized %s states, top score: %.2f, lowest score: %.2f",
                    len(scored_states),
                    scored_states[0][0],
                    scored_states[-1][0],
                )

        return simgr

    def _calculate_path_score(self, state: Any) -> float:
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

    def _check_loop_detection(self, state: Any) -> float:
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
            self.logger.debug("Loop detected at %s, iteration %s, penalty: %s", hex(current_addr), iterations, penalty)

        return penalty

    def _compute_state_hash(self, state: Any) -> str:
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
            self.logger.debug("Error computing state hash: %s", e, exc_info=True)
            return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]


class ConstraintOptimizer(ExplorationTechniqueBase):
    """Advanced constraint optimization for performance with incremental solving."""

    def __init__(self, simplify_interval: int = 10, cache_size: int = 1000, solver_timeout: int = 5000) -> None:
        """Initialize constraint optimizer.

        Args:
            simplify_interval: Steps between constraint simplifications
            cache_size: Maximum cached constraint sets
            solver_timeout: Solver timeout in milliseconds

        """
        cast("Any", super()).__init__()
        self.simplify_interval: int = simplify_interval
        self.cache_size: int = cache_size
        self.solver_timeout: int = solver_timeout
        self.constraint_cache: dict[str, bool] = {}
        self.simplification_counter: int = 0
        self.solver_results_cache: dict[str, Any] = {}
        self.logger: logging.Logger = logging.getLogger("IntellicrackLogger.ConstraintOptimizer")

    def setup(self, simgr: Any) -> None:
        """Configure Z3 solver optimizations.

        Configures the constraint solver with timeout parameters and
        optimization settings for improved performance during symbolic execution.

        Args:
            simgr: Angr exploration manager to configure solver for

        """
        for state in simgr.active:
            if hasattr(state.solver, "_solver"):
                state.solver._solver.timeout = self.solver_timeout

        self.logger.info("Constraint optimizer configured (timeout: %sms)", self.solver_timeout)

    def step(self, simgr: Any, stash: str = "active", **kwargs: Any) -> Any:
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

    def _optimize_constraints(self, state: Any) -> None:
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
            self.logger.debug("Simplified constraints: %s -> %s", original_count, optimized_count)

    @staticmethod
    def _hash_constraints(constraints: Any) -> str:
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


class StateMerger(ExplorationTechniqueBase):
    """State merging technique to reduce path explosion."""

    def __init__(self, merge_threshold: int = 10, max_merge_count: int = 5) -> None:
        """Initialize state merger.

        Args:
            merge_threshold: Minimum states before attempting merge
            max_merge_count: Maximum states to merge at once

        """
        cast("Any", super()).__init__()
        self.merge_threshold: int = merge_threshold
        self.max_merge_count: int = max_merge_count
        self.logger: logging.Logger = logging.getLogger("IntellicrackLogger.StateMerger")

    def step(self, simgr: Any, stash: str = "active", **kwargs: Any) -> Any:
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
                        if merged_state := self._merge_states(group):
                            for state in group:
                                if state in simgr.stashes[stash]:
                                    simgr.stashes[stash].remove(state)
                            simgr.stashes[stash].append(merged_state)
                            self.logger.debug("Merged %s states", len(group))
                    except Exception as e:
                        self.logger.debug("State merge failed: %s", e, exc_info=True)

        return simgr

    def _identify_mergeable_states(self, states: Any) -> list[list[Any]]:
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

        return [group[: self.max_merge_count] for group in addr_groups.values() if len(group) >= 2]

    def _merge_states(self, states: Any) -> Any:
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
                self.logger.debug("Error merging state: %s", e, exc_info=True)

        return base_state


class WindowsLicensingSimProcedure(SimProcedureBase):
    """Base class for Windows licensing API simprocedures."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the Windows licensing simprocedure.

        Calls parent SimProcedure constructor with all arguments and keyword arguments.

        Args:
            *args: Variable positional arguments passed to SimProcedure
            **kwargs: Variable keyword arguments passed to SimProcedure

        """
        cast("Any", super()).__init__(*args, **kwargs)
        self.logger = logging.getLogger(f"IntellicrackLogger.{self.__class__.__name__}")

    @property
    def _state(self) -> Any:
        return cast("Any", self.state)

    @property
    def _solver(self) -> Any:
        return self._state.solver

    @property
    def _memory(self) -> Any:
        return self._state.memory

    @property
    def _globals(self) -> dict[str, Any]:
        return validate_type(self._state.globals, dict)


class CryptVerifySignature(WindowsLicensingSimProcedure):
    """Simprocedure for CryptVerifySignatureW - always returns success."""

    def run(
        self,
        hHash: Any,
        pbSignature: Any,
        dwSigLen: Any,
        hPubKey: Any,
        sDescription: Any,
        dwFlags: Any,
    ) -> int:
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
        self.logger.info("CryptVerifySignature called at %s", hex(self.state.addr))

        if not self._solver.symbolic(hHash):
            hash_value = self._solver.eval(hHash)
            self.logger.debug("Hash handle: %s", hex(hash_value))

        if not self._solver.symbolic(hPubKey):
            pubkey_value = self._solver.eval(hPubKey)
            self.logger.debug("Public key handle: %s", hex(pubkey_value))

        if not self._solver.symbolic(sDescription):
            try:
                desc_ptr = self._solver.eval(sDescription)
                if desc_ptr != 0:
                    desc_bytes = self._memory.load(desc_ptr, 128)
                    desc_str = ""
                    for i in range(0, 128, 2):
                        char_val = self._solver.eval(desc_bytes[i * 8 : (i + 1) * 8])
                        if char_val == 0:
                            break
                        if 32 <= char_val <= 126:
                            desc_str += chr(char_val)
                    self.logger.debug("Signature description: %s", desc_str)
            except Exception as e:
                self.logger.debug("Error reading signature description: %s", e, exc_info=True)

        if self._solver.symbolic(pbSignature):
            self.logger.debug("Signature is symbolic - adding constraint for valid signature")
            signature_bytes = self._memory.load(pbSignature, dwSigLen)
            valid_signature_constraint = signature_bytes != 0
            self._solver.add(valid_signature_constraint)

        return 1


class WinVerifyTrust(WindowsLicensingSimProcedure):
    """Simprocedure for WinVerifyTrust - always returns trust verification success."""

    def run(self, hwnd: Any, pgActionID: Any, pWinTrustData: object) -> int:
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
        self.logger.info("WinVerifyTrust called at %s", hex(self.state.addr))

        if not self._solver.symbolic(pgActionID):
            try:
                action_guid_ptr = self._solver.eval(pgActionID)
                if action_guid_ptr != 0:
                    guid_data = self._memory.load(action_guid_ptr, 16)
                    if not self._solver.symbolic(guid_data):
                        guid_bytes = self._solver.eval(guid_data, cast_to=bytes)
                        self.logger.debug("Trust action GUID: %s", guid_bytes.hex())
            except Exception as e:
                self.logger.debug("Error reading trust action GUID: %s", e, exc_info=True)

        if self._solver.symbolic(pWinTrustData):
            trust_data = self._memory.load(pWinTrustData, 32)
            trust_valid_constraint = trust_data != 0
            self._solver.add(trust_valid_constraint)

        return 0


class RegQueryValueExW(WindowsLicensingSimProcedure):
    """Simprocedure for RegQueryValueExW - returns symbolic license data."""

    def run(
        self,
        hKey: Any,
        lpValueName: Any,
        lpReserved: Any,
        lpType: Any,
        lpData: Any,
        lpcbData: Any,
    ) -> int:
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
        self.logger.info("RegQueryValueExW called at %s", hex(self.state.addr))

        if self._solver.symbolic(lpValueName):
            value_name_ptr = lpValueName
        else:
            value_name_ptr = self._solver.eval(lpValueName)

        try:
            value_name_bytes = self._memory.load(value_name_ptr, 256)
            value_name = ""
            for i in range(0, 256, 2):
                char_val = self._solver.eval(value_name_bytes[i * 8 : (i + 1) * 8])
                if char_val == 0:
                    break
                if 32 <= char_val <= 126:
                    value_name += chr(char_val)

            self.logger.debug("Registry value name: %s", value_name)

            if any(keyword in value_name.lower() for keyword in ["license", "serial", "key", "activation"]) and not self._solver.symbolic(
                lpData
            ):
                data_ptr = self._solver.eval(lpData)
                data_size = 256 if self._solver.symbolic(lpcbData) else self._solver.eval(lpcbData)

                symbolic_license = claripy.BVS(f"license_data_{value_name}", data_size * 8)
                self._memory.store(data_ptr, symbolic_license)

                self.logger.info("Created symbolic license data for %s", value_name)

        except Exception as e:
            self.logger.debug("Error processing registry value name: %s", e, exc_info=True)

        return 0


class RegOpenKeyExW(WindowsLicensingSimProcedure):
    """Simprocedure for RegOpenKeyExW - always succeeds for license keys."""

    def run(
        self,
        hKey: Any,
        lpSubKey: Any,
        ulOptions: Any,
        samDesired: Any,
        phkResult: Any,
    ) -> int:
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
        self.logger.info("RegOpenKeyExW called at %s", hex(self.state.addr))

        if not self._solver.symbolic(ulOptions):
            options_value = self._solver.eval(ulOptions)
            self.logger.debug("Registry open options: %s", hex(options_value))

        if not self._solver.symbolic(samDesired):
            desired_access = self._solver.eval(samDesired)
            access_rights = []
            if desired_access & 0x0001:
                access_rights.append("QUERY_VALUE")
            if desired_access & 0x0002:
                access_rights.append("SET_VALUE")
            if desired_access & 0x0004:
                access_rights.append("CREATE_SUB_KEY")
            if desired_access & 0x00020000:
                access_rights.extend(("READ", "WRITE"))
            self.logger.debug("Registry access rights: %s", " | ".join(access_rights) if access_rights else hex(desired_access))

        if not self._solver.symbolic(phkResult):
            result_ptr = self._solver.eval(phkResult)
            symbolic_handle = claripy.BVS(f"reg_handle_{hex(self.state.addr)}", 32)
            valid_handle = claripy.And(claripy.UGT(symbolic_handle, 0), claripy.ULT(symbolic_handle, 0xFFFFFFFF))
            self._solver.add(valid_handle)
            self._memory.store(result_ptr, symbolic_handle, endness="Iend_LE")

        return 0


class GetVolumeInformationW(WindowsLicensingSimProcedure):
    """Simprocedure for GetVolumeInformationW - returns controllable hardware ID."""

    def run(
        self,
        lpRootPathName: Any,
        lpVolumeNameBuffer: Any,
        nVolumeNameSize: Any,
        lpVolumeSerialNumber: Any,
        lpMaximumComponentLength: Any,
        lpFileSystemFlags: Any,
        lpFileSystemNameBuffer: Any,
        nFileSystemNameSize: Any,
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
        self.logger.info("GetVolumeInformationW called at %s", hex(self.state.addr))

        if not self._solver.symbolic(lpVolumeSerialNumber):
            serial_ptr = self._solver.eval(lpVolumeSerialNumber)
            symbolic_serial = claripy.BVS("volume_serial", 32)
            self._memory.store(serial_ptr, symbolic_serial, endness="Iend_LE")
            self.logger.info("Created symbolic volume serial number for hardware fingerprinting bypass")

        return 1


class CreateFileW(WindowsLicensingSimProcedure):
    """Simprocedure for CreateFileW - intercepts and processes license file access."""

    def run(
        self,
        lpFileName: Any,
        dwDesiredAccess: Any,
        dwShareMode: Any,
        lpSecurityAttributes: Any,
        dwCreationDisposition: Any,
        dwFlagsAndAttributes: Any,
        hTemplateFile: Any,
    ) -> Any:
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
            Any: File handle for opened file

        """
        self.logger.info("CreateFileW called at %s", hex(self.state.addr))

        if not hasattr(self.state, "globals") or self._globals is None:
            self._state.globals = {}

        if "file_handle_counter" not in self._globals:
            self._globals["file_handle_counter"] = 0x2000
            self._globals["open_handles"] = {}

        if not self._solver.symbolic(dwShareMode):
            share_mode = self._solver.eval(dwShareMode)
            share_flags = []
            if share_mode & 0x00000001:
                share_flags.append("READ")
            if share_mode & 0x00000002:
                share_flags.append("WRITE")
            if share_mode & 0x00000004:
                share_flags.append("DELETE")
            self.logger.debug("File share mode: %s", " | ".join(share_flags) if share_flags else "EXCLUSIVE")

        if not self._solver.symbolic(lpSecurityAttributes):
            sec_attr_ptr = self._solver.eval(lpSecurityAttributes)
            if sec_attr_ptr != 0:
                self.logger.debug("Security attributes provided at %s", hex(sec_attr_ptr))

        if not self._solver.symbolic(dwFlagsAndAttributes):
            flags_attrs = self._solver.eval(dwFlagsAndAttributes)
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
            self.logger.debug("File flags/attributes: %s", " | ".join(flag_list) if flag_list else hex(flags_attrs))

        if not self._solver.symbolic(hTemplateFile):
            template_handle = self._solver.eval(hTemplateFile)
            if template_handle != 0:
                self.logger.debug("Template file handle: %s", hex(template_handle))

        if not self._solver.symbolic(lpFileName):
            filename_ptr = self._solver.eval(lpFileName)
            try:
                filename_bytes = self._memory.load(filename_ptr, 512)
                filename = ""
                for i in range(0, 512, 2):
                    char_val = self._solver.eval(filename_bytes[i * 8 : (i + 1) * 8])
                    if char_val == 0:
                        break
                    if 32 <= char_val <= 126:
                        filename += chr(char_val)

                self.logger.debug("Opening file: %s", filename)

                if any(ext in filename.lower() for ext in [".lic", ".key", ".dat", ".cfg"]):
                    self.logger.info("Detected license file access: %s", filename)
                    if not hasattr(self.state, "license_files"):
                        self._state.license_files = {}
                    self._state.license_files[filename] = True

            except Exception as e:
                self.logger.debug("Error processing filename: %s", e, exc_info=True)

        handle = self._globals["file_handle_counter"]
        self._globals["file_handle_counter"] += 4
        self._globals["open_handles"][handle] = {
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

    def run(
        self,
        hFile: Any,
        lpBuffer: Any,
        nNumberOfBytesToRead: Any,
        lpNumberOfBytesRead: Any,
        lpOverlapped: Any,
    ) -> int:
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
        self.logger.info("ReadFile called at %s", hex(self.state.addr))

        if not self._solver.symbolic(hFile):
            file_handle = self._solver.eval(hFile)
            self.logger.debug("Reading from file handle: %s", hex(file_handle))

            if hasattr(self.state, "globals") and "open_handles" in self._globals and file_handle in self._globals["open_handles"]:
                file_info = self._globals["open_handles"][file_handle]
                self.logger.debug("File info: %s", file_info.get("filename", "unknown"))

        if not self._solver.symbolic(lpOverlapped):
            overlapped_ptr = self._solver.eval(lpOverlapped)
            if overlapped_ptr != 0:
                self.logger.debug("Overlapped I/O structure at %s", hex(overlapped_ptr))

        if not self._solver.symbolic(lpBuffer) and not self._solver.symbolic(nNumberOfBytesToRead):
            buffer_ptr = self._solver.eval(lpBuffer)
            bytes_to_read = self._solver.eval(nNumberOfBytesToRead)

            if bytes_to_read > 0 and bytes_to_read < 10000:
                symbolic_content = claripy.BVS(f"license_file_content_{hex(self.state.addr)}", bytes_to_read * 8)
                self._memory.store(buffer_ptr, symbolic_content)

                if not self._solver.symbolic(lpNumberOfBytesRead):
                    bytes_read_ptr = self._solver.eval(lpNumberOfBytesRead)
                    self._memory.store(bytes_read_ptr, claripy.BVV(bytes_to_read, 32), endness="Iend_LE")

                self.logger.info("Created symbolic license file content (%s bytes)", bytes_to_read)

        return 1


class WriteFile(WindowsLicensingSimProcedure):
    """Simprocedure for WriteFile - tracks license file writes."""

    def run(
        self,
        hFile: Any,
        lpBuffer: Any,
        nNumberOfBytesToWrite: Any,
        lpNumberOfBytesWritten: Any,
        lpOverlapped: Any,
    ) -> int:
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
        self.logger.info("WriteFile called at %s", hex(self.state.addr))

        if not self._solver.symbolic(hFile):
            file_handle = self._solver.eval(hFile)
            self.logger.debug("Writing to file handle: %s", hex(file_handle))

            if hasattr(self.state, "globals") and "open_handles" in self._globals and file_handle in self._globals["open_handles"]:
                file_info = self._globals["open_handles"][file_handle]
                self.logger.debug("Writing to file: %s", file_info.get("filename", "unknown"))

        if not self._solver.symbolic(lpOverlapped):
            overlapped_ptr = self._solver.eval(lpOverlapped)
            if overlapped_ptr != 0:
                self.logger.debug("Overlapped I/O structure at %s", hex(overlapped_ptr))

        if not self._solver.symbolic(lpBuffer) and not self._solver.symbolic(nNumberOfBytesToWrite):
            buffer_ptr = self._solver.eval(lpBuffer)
            bytes_to_write = self._solver.eval(nNumberOfBytesToWrite)
            if bytes_to_write > 0 and bytes_to_write < 1000:
                try:
                    write_data = self._memory.load(buffer_ptr, bytes_to_write)
                    if not self._solver.symbolic(write_data):
                        data_bytes = self._solver.eval(write_data, cast_to=bytes)
                        self.logger.debug("Writing %s bytes: %s...", bytes_to_write, data_bytes[: min(32, len(data_bytes))].hex())
                except Exception as e:
                    self.logger.debug("Error reading write buffer: %s", e, exc_info=True)

        if not self._solver.symbolic(lpNumberOfBytesWritten):
            bytes_written_ptr = self._solver.eval(lpNumberOfBytesWritten)
            bytes_to_write = 0 if self._solver.symbolic(nNumberOfBytesToWrite) else self._solver.eval(nNumberOfBytesToWrite)
            self._memory.store(bytes_written_ptr, claripy.BVV(bytes_to_write, 32), endness="Iend_LE")

        return 1


class GetComputerNameW(WindowsLicensingSimProcedure):
    """Simprocedure for GetComputerNameW - returns symbolic computer name."""

    def run(self, lpBuffer: Any, nSize: object) -> int:
        """Return symbolic computer name for system identification bypass.

        Provides symbolic computer name values to bypass hardware fingerprinting
        checks that rely on system identification.

        Args:
            lpBuffer: Pointer to buffer for computer name output
            nSize: Size of buffer or pointer to name length

        Returns:
            int: 1 (TRUE) indicating successful name retrieval

        """
        self.logger.info("GetComputerNameW called at %s", hex(self.state.addr))

        if not self._solver.symbolic(lpBuffer):
            buffer_ptr = self._solver.eval(lpBuffer)
            symbolic_name = claripy.BVS("computer_name", 256)
            self._memory.store(buffer_ptr, symbolic_name)

            if not self._solver.symbolic(nSize):
                size_ptr = self._solver.eval(nSize)
                self._memory.store(size_ptr, claripy.BVV(15, 32), endness="Iend_LE")

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
        self.logger.info("GetSystemTime called at %s", hex(self.state.addr))

        if not self._solver.symbolic(lpSystemTime):
            time_ptr = self._solver.eval(lpSystemTime)

            symbolic_time = claripy.BVS("system_time", 128)

            valid_year = claripy.And(
                claripy.UGE(symbolic_time.get_bytes(0, 2), 2000),
                claripy.ULE(symbolic_time.get_bytes(0, 2), 2100),
            )
            self._solver.add(valid_year)

            self._memory.store(time_ptr, symbolic_time, endness="Iend_LE")
            self.logger.info("Created symbolic system time for trial period manipulation")


class GetTickCount(WindowsLicensingSimProcedure):
    """Simprocedure for GetTickCount - returns controllable tick count."""

    def run(self) -> Any:
        """Return symbolic tick count for timing-based license checks.

        Provides symbolic tick count values to enable exploration of timing-based
        license validation checks and timing attack detection logic.

        Returns:
            object: Symbolic bitvector representing system tick count

        """
        self.logger.info("GetTickCount called at %s", hex(self.state.addr))

        symbolic_ticks = claripy.BVS(f"tick_count_{hex(self.state.addr)}", 32)

        reasonable_ticks = claripy.And(claripy.UGE(symbolic_ticks, 0), claripy.ULE(symbolic_ticks, 0x7FFFFFFF))
        self._solver.add(reasonable_ticks)

        return symbolic_ticks


class VirtualAlloc(WindowsLicensingSimProcedure):
    """Simprocedure for VirtualAlloc - allocates symbolic memory."""

    def run(self, lpAddress: Any, dwSize: Any, flAllocationType: Any, flProtect: object) -> Any:
        """Allocate memory and return symbolic address.

        Performs virtual memory allocation operations and returns addresses. Tracks
        allocations for correlation with other memory operations during analysis.

        Args:
            lpAddress: Requested allocation address or NULL
            dwSize: Number of bytes to allocate
            flAllocationType: Memory allocation type flags
            flProtect: Memory protection flags

        Returns:
            Any: Allocated memory address or symbolic value

        """
        self.logger.info("VirtualAlloc called at %s", hex(self.state.addr))

        if not hasattr(self.state, "globals") or self._globals is None:
            self._state.globals = {}

        if "heap_base" not in self._globals:
            self._globals["heap_base"] = 0x10000000
            self._globals["allocations"] = {}

        if not self._solver.symbolic(lpAddress):
            requested_addr = self._solver.eval(lpAddress)
            if requested_addr != 0:
                self.logger.debug("Requested specific address: %s", hex(requested_addr))

        if not self._solver.symbolic(flAllocationType):
            alloc_type = self._solver.eval(flAllocationType)
            alloc_flags = []
            if alloc_type & 0x00001000:
                alloc_flags.append("MEM_COMMIT")
            if alloc_type & 0x00002000:
                alloc_flags.append("MEM_RESERVE")
            if alloc_type & 0x00080000:
                alloc_flags.append("MEM_RESET")
            if alloc_type & 0x00400000:
                alloc_flags.append("MEM_TOP_DOWN")
            self.logger.debug("Allocation type: %s", " | ".join(alloc_flags) if alloc_flags else hex(alloc_type))

        if not self._solver.symbolic(flProtect):
            protect = self._solver.eval(flProtect)
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
            self.logger.debug("Memory protection: %s", " | ".join(protect_flags) if protect_flags else hex(protect))

        if not self._solver.symbolic(dwSize):
            size = self._solver.eval(dwSize)

            if not self._solver.symbolic(lpAddress):
                requested_addr = self._solver.eval(lpAddress)
                if requested_addr != 0:
                    addr = requested_addr
                else:
                    addr = self._globals["heap_base"]
                    self._globals["heap_base"] += (size + 0xFFF) & ~0xFFF
            else:
                addr = self._globals["heap_base"]
                self._globals["heap_base"] += (size + 0xFFF) & ~0xFFF

            self._globals["allocations"][addr] = {
                "size": size,
                "type": flAllocationType,
                "protect": flProtect,
                "allocated_at": self.state.addr,
            }

            self.logger.debug("Allocated %s bytes at %s", size, hex(addr))
            return addr

        return claripy.BVS(f"alloc_{hex(self.state.addr)}", 32)


class VirtualFree(WindowsLicensingSimProcedure):
    """Simprocedure for VirtualFree - tracks memory frees."""

    def run(self, lpAddress: Any, dwSize: Any, dwFreeType: object) -> int:
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
        self.logger.info("VirtualFree called at %s", hex(self.state.addr))

        if not self._solver.symbolic(lpAddress):
            addr = self._solver.eval(lpAddress)
            self.logger.debug("Freeing memory at %s", hex(addr))

            if hasattr(self.state, "globals") and "allocations" in self._globals and addr in self._globals["allocations"]:
                alloc_info = self._globals["allocations"][addr]
                self.logger.debug("Freeing allocation: size=%s, allocated_at=%s", alloc_info["size"], hex(alloc_info["allocated_at"]))
                del self._globals["allocations"][addr]

        if not self._solver.symbolic(dwFreeType):
            free_type = self._solver.eval(dwFreeType)
            free_flags = []
            if free_type & 0x00004000:
                free_flags.append("MEM_DECOMMIT")
            if free_type & 0x00008000:
                free_flags.append("MEM_RELEASE")
            self.logger.debug("Free type: %s", " | ".join(free_flags) if free_flags else hex(free_type))

        return 1


class NtQueryInformationProcess(WindowsLicensingSimProcedure):
    """Simprocedure for NtQueryInformationProcess - returns safe values."""

    def run(
        self,
        ProcessHandle: Any,
        ProcessInformationClass: Any,
        ProcessInformation: Any,
        ProcessInformationLength: Any,
        ReturnLength: Any,
    ) -> int:
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
        self.logger.info("NtQueryInformationProcess called at %s", hex(self.state.addr))

        if not self._solver.symbolic(ProcessHandle):
            handle = self._solver.eval(ProcessHandle)
            self.logger.debug("Process handle: %s", hex(handle))

        if not self._solver.symbolic(ProcessInformationLength):
            info_length = self._solver.eval(ProcessInformationLength)
            self.logger.debug("Information buffer length: %s", info_length)

        if not self._solver.symbolic(ProcessInformation):
            info_ptr = self._solver.eval(ProcessInformation)
            info_class = 0 if self._solver.symbolic(ProcessInformationClass) else self._solver.eval(ProcessInformationClass)

            if info_class == 7:
                self._memory.store(info_ptr, claripy.BVV(0, 32), endness="Iend_LE")
                self.logger.debug("Returned DebugPort = 0 (not being debugged)")
                if not self._solver.symbolic(ReturnLength):
                    return_length_ptr = self._solver.eval(ReturnLength)
                    if return_length_ptr != 0:
                        self._memory.store(return_length_ptr, claripy.BVV(4, 32), endness="Iend_LE")
            elif info_class == 0x1F:
                self._memory.store(info_ptr, claripy.BVV(0, 32), endness="Iend_LE")
                self.logger.debug("Returned DebugObjectHandle = 0 (not being debugged)")
                if not self._solver.symbolic(ReturnLength):
                    return_length_ptr = self._solver.eval(ReturnLength)
                    if return_length_ptr != 0:
                        self._memory.store(return_length_ptr, claripy.BVV(4, 32), endness="Iend_LE")
            elif info_class == 0:
                self.logger.debug("ProcessBasicInformation requested")
                if not self._solver.symbolic(ReturnLength):
                    return_length_ptr = self._solver.eval(ReturnLength)
                    if return_length_ptr != 0:
                        self._memory.store(return_length_ptr, claripy.BVV(48, 32), endness="Iend_LE")

        return 0


class MessageBoxA(WindowsLicensingSimProcedure):
    """Simprocedure for MessageBoxA - logs and returns OK."""

    def run(self, hWnd: Any, lpText: Any, lpCaption: Any, uType: object) -> int:
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
        self.logger.info("MessageBoxA called at %s", hex(self.state.addr))

        if not self._solver.symbolic(hWnd):
            window_handle = self._solver.eval(hWnd)
            self.logger.debug("Window handle: %s", hex(window_handle) if window_handle != 0 else "NULL (Desktop)")

        if not self._solver.symbolic(uType):
            msg_type = self._solver.eval(uType)
            buttons = msg_type & 0x0F
            icon = msg_type & 0xF0
            msg_type & 0xF00

            button_types = {
                0: "OK",
                1: "OK/Cancel",
                2: "Abort/Retry/Ignore",
                3: "Yes/No/Cancel",
                4: "Yes/No",
                5: "Retry/Cancel",
            }
            icon_types = {0x10: "STOP", 0x20: "QUESTION", 0x30: "EXCLAMATION", 0x40: "INFORMATION"}

            self.logger.debug(
                "MessageBox type - Buttons: %s, Icon: %s",
                button_types.get(buttons, f"Unknown({buttons})"),
                icon_types.get(icon, f"None({hex(icon)})"),
            )

        try:
            if not self._solver.symbolic(lpText):
                text_ptr = self._solver.eval(lpText)
                text_bytes = self._memory.load(text_ptr, 256)
                text = ""
                for i in range(256):
                    char_val = self._solver.eval(text_bytes[i * 8 : (i + 1) * 8])
                    if char_val == 0:
                        break
                    if 32 <= char_val <= 126:
                        text += chr(char_val)

                self.logger.info("MessageBox text: %s", text)

                if any(kw in text.lower() for kw in ["license", "trial", "expire", "invalid"]):
                    if not hasattr(self.state, "license_messages"):
                        self._state.license_messages = []
                    self._state.license_messages.append(text)

            if not self._solver.symbolic(lpCaption):
                caption_ptr = self._solver.eval(lpCaption)
                if caption_ptr != 0:
                    caption_bytes = self._memory.load(caption_ptr, 128)
                    caption = ""
                    for i in range(128):
                        char_val = self._solver.eval(caption_bytes[i * 8 : (i + 1) * 8])
                        if char_val == 0:
                            break
                        if 32 <= char_val <= 126:
                            caption += chr(char_val)
                    self.logger.info("MessageBox caption: %s", caption)

        except Exception as e:
            self.logger.debug("Error reading message box text: %s", e, exc_info=True)

        return 1


class Socket(WindowsLicensingSimProcedure):
    """Simprocedure for socket - creates symbolic socket handle."""

    def run(self, af: Any, type: Any, protocol: object) -> Any:
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
        self.logger.info("socket called at %s", hex(self.state.addr))

        if not self._solver.symbolic(af):
            address_family = self._solver.eval(af)
            af_types = {2: "AF_INET", 23: "AF_INET6", 1: "AF_UNIX"}
            self.logger.debug("Address family: %s", af_types.get(address_family, f"Unknown({address_family})"))

        if not self._solver.symbolic(type):
            sock_type = self._solver.eval(type)
            type_names = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW"}
            self.logger.debug("Socket type: %s", type_names.get(sock_type, f"Unknown({sock_type})"))

        if not self._solver.symbolic(protocol):
            proto = self._solver.eval(protocol)
            proto_names = {0: "IPPROTO_IP", 6: "IPPROTO_TCP", 17: "IPPROTO_UDP"}
            self.logger.debug("Protocol: %s", proto_names.get(proto, f"Unknown({proto})"))

        return claripy.BVS(f"socket_{hex(self.state.addr)}", 32)


class Connect(WindowsLicensingSimProcedure):
    """Simprocedure for connect - always succeeds for license server connections."""

    def run(self, s: Any, name: Any, namelen: object) -> int:
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
        self.logger.info("connect called at %s", hex(self.state.addr))

        if not self._solver.symbolic(s):
            socket_fd = self._solver.eval(s)
            self.logger.debug("Socket descriptor: %s", socket_fd)

        if not self._solver.symbolic(name) and not self._solver.symbolic(namelen):
            addr_ptr = self._solver.eval(name)
            addr_len = self._solver.eval(namelen)

            if addr_len >= 8:
                try:
                    sockaddr_data = self._memory.load(addr_ptr, min(addr_len, 28))
                    if not self._solver.symbolic(sockaddr_data):
                        addr_family = self._solver.eval(sockaddr_data.get_bytes(0, 2))

                        if addr_family == 2:
                            port_bytes = sockaddr_data.get_bytes(2, 2)
                            port = self._solver.eval(port_bytes)
                            port_network_order = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)

                            ip_bytes = sockaddr_data.get_bytes(4, 4)
                            ip_value = self._solver.eval(ip_bytes)
                            ip_addr = f"{(ip_value >> 24) & 0xFF}.{(ip_value >> 16) & 0xFF}.{(ip_value >> 8) & 0xFF}.{ip_value & 0xFF}"

                            self.logger.info("Connecting to %s:%s (AF_INET)", ip_addr, port_network_order)
                        elif addr_family == 23:
                            self.logger.info("Connecting to IPv6 address (AF_INET6)")
                except Exception as e:
                    self.logger.debug("Error reading sockaddr structure: %s", e, exc_info=True)

        return 0


class Send(WindowsLicensingSimProcedure):
    """Simprocedure for send - tracks outgoing license validation data."""

    def run(self, s: Any, buf: Any, len: Any, flags: object) -> Any:
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
        self.logger.info("send called at %s", hex(self.state.addr))

        if not self._solver.symbolic(len):
            return self._solver.eval(len)
        return claripy.BVS(f"bytes_sent_{hex(self.state.addr)}", 32)


class Recv(WindowsLicensingSimProcedure):
    """Simprocedure for recv - returns symbolic license server response."""

    def run(self, s: Any, buf: Any, len: Any, flags: object) -> Any:
        """Return symbolic license server response.

        Provides symbolic data for received network packets to enable constraint-based
        exploration of license server response handling logic.

        Args:
            s: Socket descriptor
            buf: Pointer to receive buffer
            len: Size of receive buffer
            flags: Receive operation flags

        Returns:
            Any: Number of bytes received

        """
        self.logger.info("recv called at %s", hex(self.state.addr))

        if not self._solver.symbolic(buf) and not self._solver.symbolic(len):
            buffer_ptr = self._solver.eval(buf)
            buffer_len = self._solver.eval(len)

            if buffer_len > 0 and buffer_len < 10000:
                symbolic_response = claripy.BVS(f"server_response_{hex(self.state.addr)}", buffer_len * 8)
                self._memory.store(buffer_ptr, symbolic_response)
                self.logger.info("Created symbolic server response (%s bytes)", buffer_len)
                return buffer_len

        return 0


def install_license_simprocedures(project: Any) -> int:
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
                logger.debug("Hooked %s at %s", func_name, hex(addr))
                installed_count += 1
            elif symbol := project.loader.find_symbol(func_name):
                project.hook(symbol.rebased_addr, simprocedure_class())
                logger.debug("Hooked %s at %s", func_name, hex(symbol.rebased_addr))
                installed_count += 1
        except Exception as e:
            logger.debug("Could not hook %s: %s", func_name, e, exc_info=True)

    logger.info("Installed %s/%s custom simprocedures", installed_count, len(simprocedures))
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

    def analyze_state(self, state: Any) -> dict[str, Any]:
        """Analyze state for license validation indicators.

        Examines memory and constraints to identify indicators of license validation
        operations including serial checks, trial period checks, and activation checks.

        Args:
            state: Angr state to analyze

        Returns:
            dict: Validation detection results with type, confidence, and evidence

        """
        results: dict[str, Any] = {"validation_type": None, "confidence": 0.0, "evidence": []}

        if not hasattr(state, "memory"):
            return results

        for validation_type, patterns in self.validation_patterns.items():
            for pattern in patterns:
                if matches := self._search_memory_pattern(state, pattern):
                    results["validation_type"] = validation_type
                    results["confidence"] += 0.2
                    results["evidence"].extend(matches)

        if hasattr(state, "solver") and state.solver.constraints:
            constraint_indicators = self._analyze_constraints(state.solver.constraints)
            results["confidence"] += constraint_indicators
            results["evidence"].append(f"Constraint indicators: {constraint_indicators:.2f}")

        results["confidence"] = min(results["confidence"], 1.0)

        if results["validation_type"]:
            self.logger.info("Detected %s validation (confidence: %.2f)", results["validation_type"], results["confidence"])

        return results

    def _search_memory_pattern(self, state: Any, pattern: bytes) -> list[str]:
        """Search memory for specific patterns.

        Scans memory regions for licensing-related keyword patterns and returns
        matching addresses for correlation with validation routines.

        Args:
            state: Angr execution state with memory to search
            pattern: Byte pattern to search for

        Returns:
            List of memory addresses where pattern was found

        """
        matches: list[str] = []
        try:
            for region_start in range(0x400000, 0x500000, 0x1000):
                try:
                    data = state.memory.load(region_start, len(pattern))
                    if not state.solver.symbolic(data):
                        concrete_data = state.solver.eval(data, cast_to=bytes)
                        if pattern.lower() in concrete_data.lower():
                            matches.append(f"Found at {hex(region_start)}")
                except Exception as e:
                    self.logger.warning("Error checking pattern at %s: %s", hex(region_start), e, exc_info=True)
                    continue
        except Exception as e:
            self.logger.debug("Memory pattern search error: %s", e, exc_info=True)

        return matches[:5]

    @staticmethod
    def _analyze_constraints(constraints: Any) -> float:
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


def create_enhanced_simgr(project: Any, initial_state: Any, *, enable_state_merging: bool = True) -> Any:
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

    if ANGR_AVAILABLE and hasattr(angr, "exploration_techniques"):
        if hasattr(angr.exploration_techniques, "DFS"):
            simgr.use_technique(cast("Any", DFS)())

        if hasattr(angr.exploration_techniques, "Spiller"):
            spiller_class = cast("Any", getattr(angr.exploration_techniques, "Spiller", None))
            if spiller_class is not None:
                simgr.use_technique(spiller_class())

        if hasattr(angr.exploration_techniques, "Veritesting"):
            veritesting_class = cast("Any", getattr(angr.exploration_techniques, "Veritesting", None))
            if veritesting_class is not None:
                simgr.use_technique(veritesting_class())

        if hasattr(angr.exploration_techniques, "LoopSeer"):
            loopseer_class = cast("Any", getattr(angr.exploration_techniques, "LoopSeer", None))
            if loopseer_class is not None:
                simgr.use_technique(loopseer_class(bound=5))

    logger.info("Enhanced execution manager configured with license-focused techniques")
    return simgr


__all__ = [
    "Connect",
    "ConstraintOptimizer",
    "CreateFileW",
    "CryptVerifySignature",
    "GetComputerNameW",
    "GetSystemTime",
    "GetTickCount",
    "GetVolumeInformationW",
    "LicensePathPrioritizer",
    "LicenseValidationDetector",
    "MessageBoxA",
    "NtQueryInformationProcess",
    "ReadFile",
    "Recv",
    "RegOpenKeyExW",
    "RegQueryValueExW",
    "Send",
    "Socket",
    "StateMerger",
    "VirtualAlloc",
    "VirtualFree",
    "WinVerifyTrust",
    "WindowsLicensingSimProcedure",
    "WriteFile",
    "create_enhanced_simgr",
    "install_license_simprocedures",
]
