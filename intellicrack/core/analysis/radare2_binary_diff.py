"""Radare2 Binary Diff Engine.

This module provides real binary diffing capabilities using radare2
for comparing functions, basic blocks, and binary structures.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import r2pipe
except ImportError:
    r2pipe = None

logger = logging.getLogger(__name__)


@dataclass
class FunctionDiff:
    """Represents differences between functions in two binaries."""
    name: str
    status: str  # 'added', 'removed', 'modified', 'unchanged'
    primary_address: Optional[int] = None
    secondary_address: Optional[int] = None
    primary_size: Optional[int] = None
    secondary_size: Optional[int] = None
    size_diff: Optional[int] = None
    basic_block_diff: Optional[Dict[str, Any]] = None
    instruction_diff: Optional[Dict[str, Any]] = None
    similarity_score: float = 0.0
    opcodes_changed: int = 0
    constants_changed: int = 0
    calls_changed: List[str] = field(default_factory=list)


@dataclass
class BasicBlockDiff:
    """Represents differences between basic blocks."""
    address: int
    status: str  # 'added', 'removed', 'modified', 'unchanged'
    primary_size: Optional[int] = None
    secondary_size: Optional[int] = None
    instruction_count_diff: int = 0
    edges_added: List[int] = field(default_factory=list)
    edges_removed: List[int] = field(default_factory=list)
    jump_targets_changed: List[int] = field(default_factory=list)


@dataclass
class StringDiff:
    """Represents differences in strings between binaries."""
    value: str
    status: str  # 'added', 'removed', 'modified'
    primary_address: Optional[int] = None
    secondary_address: Optional[int] = None
    xrefs_primary: List[int] = field(default_factory=list)
    xrefs_secondary: List[int] = field(default_factory=list)


class R2BinaryDiff:
    """Production-ready binary diff engine using radare2."""

    def __init__(self, primary_path: str, secondary_path: Optional[str] = None):
        """Initialize binary diff engine.

        Args:
            primary_path: Path to the primary (original) binary
            secondary_path: Path to the secondary (modified) binary
        """
        self.primary_path = primary_path
        self.secondary_path = secondary_path
        self.logger = logger

        if r2pipe is None:
            self.logger.warning("r2pipe not available, diff functionality limited")
            self.r2pipe_available = False
            self.r2_primary = None
            self.r2_secondary = None
        else:
            self.r2pipe_available = True
            self.r2_primary = None
            self.r2_secondary = None
            self._initialize_r2_sessions()

    def _initialize_r2_sessions(self):
        """Initialize r2pipe sessions for both binaries."""
        if not self.r2pipe_available:
            return

        try:
            self.r2_primary = r2pipe.open(self.primary_path)
            self.r2_primary.cmd("aaa")  # Analyze all
            self.logger.info(f"Initialized r2 session for primary: {self.primary_path}")

            if self.secondary_path:
                self.r2_secondary = r2pipe.open(self.secondary_path)
                self.r2_secondary.cmd("aaa")  # Analyze all
                self.logger.info(f"Initialized r2 session for secondary: {self.secondary_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize r2 sessions: {e}")
            self.r2_primary = None
            self.r2_secondary = None

    def set_secondary_binary(self, secondary_path: str):
        """Set or update the secondary binary for comparison.

        Args:
            secondary_path: Path to the secondary binary
        """
        self.secondary_path = secondary_path

        if self.r2_secondary:
            try:
                self.r2_secondary.quit()
            except:
                pass

        if self.r2pipe_available:
            try:
                self.r2_secondary = r2pipe.open(secondary_path)
                self.r2_secondary.cmd("aaa")
                self.logger.info(f"Set secondary binary: {secondary_path}")
            except Exception as e:
                self.logger.error(f"Failed to set secondary binary: {e}")
                self.r2_secondary = None

    def get_function_diffs(self) -> List[FunctionDiff]:
        """Compare functions between binaries.

        Returns:
            List of FunctionDiff objects describing differences
        """
        if not self.r2_primary or not self.r2_secondary:
            self.logger.error("Both binaries must be loaded for diff")
            return []

        diffs = []

        try:
            # Get functions from both binaries
            primary_funcs = json.loads(self.r2_primary.cmd("aflj"))
            secondary_funcs = json.loads(self.r2_secondary.cmd("aflj"))

            # Create lookup dictionaries
            primary_by_name = {f.get("name", ""): f for f in primary_funcs}
            secondary_by_name = {f.get("name", ""): f for f in secondary_funcs}

            all_func_names = set(primary_by_name.keys()) | set(secondary_by_name.keys())

            for func_name in all_func_names:
                if not func_name:  # Skip empty names
                    continue

                primary_func = primary_by_name.get(func_name)
                secondary_func = secondary_by_name.get(func_name)

                if primary_func and not secondary_func:
                    # Function removed
                    diff = FunctionDiff(
                        name=func_name,
                        status='removed',
                        primary_address=primary_func.get("offset", 0),
                        primary_size=primary_func.get("size", 0)
                    )
                    diffs.append(diff)

                elif not primary_func and secondary_func:
                    # Function added
                    diff = FunctionDiff(
                        name=func_name,
                        status='added',
                        secondary_address=secondary_func.get("offset", 0),
                        secondary_size=secondary_func.get("size", 0)
                    )
                    diffs.append(diff)

                elif primary_func and secondary_func:
                    # Function exists in both - check for modifications
                    primary_size = primary_func.get("size", 0)
                    secondary_size = secondary_func.get("size", 0)

                    # Get detailed comparison
                    similarity = self._calculate_function_similarity(
                        func_name, primary_func, secondary_func
                    )

                    status = 'unchanged' if similarity > 0.95 else 'modified'

                    diff = FunctionDiff(
                        name=func_name,
                        status=status,
                        primary_address=primary_func.get("offset", 0),
                        secondary_address=secondary_func.get("offset", 0),
                        primary_size=primary_size,
                        secondary_size=secondary_size,
                        size_diff=secondary_size - primary_size,
                        similarity_score=similarity
                    )

                    # Get detailed changes if modified
                    if status == 'modified':
                        diff.basic_block_diff = self._get_function_bb_diff(func_name)
                        diff.opcodes_changed = self._count_opcode_changes(func_name)
                        diff.calls_changed = self._get_call_changes(func_name)

                    diffs.append(diff)

            self.logger.info(f"Found {len(diffs)} function differences")

        except Exception as e:
            self.logger.error(f"Failed to get function diffs: {e}")

        return diffs

    def get_basic_block_diffs(self, function_name: str) -> List[BasicBlockDiff]:
        """Compare basic blocks within a function.

        Args:
            function_name: Name of the function to analyze

        Returns:
            List of BasicBlockDiff objects
        """
        if not self.r2_primary or not self.r2_secondary:
            self.logger.error("Both binaries must be loaded for diff")
            return []

        diffs = []

        try:
            # Get basic blocks for the function in both binaries
            self.r2_primary.cmd(f"s {function_name}")
            primary_blocks = json.loads(self.r2_primary.cmd("afbj"))

            self.r2_secondary.cmd(f"s {function_name}")
            secondary_blocks = json.loads(self.r2_secondary.cmd("afbj"))

            # Create lookup by address (normalized)
            primary_by_addr = {bb.get("addr", 0): bb for bb in primary_blocks}
            secondary_by_addr = {bb.get("addr", 0): bb for bb in secondary_blocks}

            # Match blocks by relative position and flow
            matched_blocks = self._match_basic_blocks(primary_blocks, secondary_blocks)

            for primary_addr, secondary_addr in matched_blocks.items():
                primary_bb = primary_by_addr.get(primary_addr)
                secondary_bb = secondary_by_addr.get(secondary_addr)

                if primary_bb and secondary_bb:
                    # Compare the blocks
                    diff = BasicBlockDiff(
                        address=primary_addr,
                        status='modified' if self._blocks_differ(primary_bb, secondary_bb) else 'unchanged',
                        primary_size=primary_bb.get("size", 0),
                        secondary_size=secondary_bb.get("size", 0),
                        instruction_count_diff=len(secondary_bb.get("ops", [])) - len(primary_bb.get("ops", []))
                    )

                    # Analyze edge changes
                    primary_jump = primary_bb.get("jump", 0)
                    primary_fail = primary_bb.get("fail", 0)
                    secondary_jump = secondary_bb.get("jump", 0)
                    secondary_fail = secondary_bb.get("fail", 0)

                    if primary_jump != secondary_jump:
                        diff.jump_targets_changed.append(secondary_jump)
                    if primary_fail != secondary_fail:
                        diff.jump_targets_changed.append(secondary_fail)

                    diffs.append(diff)

            # Find added blocks
            for addr, bb in secondary_by_addr.items():
                if addr not in [v for v in matched_blocks.values()]:
                    diff = BasicBlockDiff(
                        address=addr,
                        status='added',
                        secondary_size=bb.get("size", 0)
                    )
                    diffs.append(diff)

            # Find removed blocks
            for addr, bb in primary_by_addr.items():
                if addr not in matched_blocks:
                    diff = BasicBlockDiff(
                        address=addr,
                        status='removed',
                        primary_size=bb.get("size", 0)
                    )
                    diffs.append(diff)

            self.logger.info(f"Found {len(diffs)} basic block differences in {function_name}")

        except Exception as e:
            self.logger.error(f"Failed to get basic block diffs: {e}")

        return diffs

    def get_string_diffs(self) -> List[StringDiff]:
        """Compare strings between binaries.

        Returns:
            List of StringDiff objects
        """
        if not self.r2_primary or not self.r2_secondary:
            self.logger.error("Both binaries must be loaded for diff")
            return []

        diffs = []

        try:
            # Get strings from both binaries
            primary_strings = json.loads(self.r2_primary.cmd("izj"))
            secondary_strings = json.loads(self.r2_secondary.cmd("izj"))

            # Create lookup by string value
            primary_by_str = {s.get("string", ""): s for s in primary_strings}
            secondary_by_str = {s.get("string", ""): s for s in secondary_strings}

            all_strings = set(primary_by_str.keys()) | set(secondary_by_str.keys())

            for string_val in all_strings:
                if not string_val:  # Skip empty strings
                    continue

                primary_str = primary_by_str.get(string_val)
                secondary_str = secondary_by_str.get(string_val)

                if primary_str and not secondary_str:
                    # String removed
                    diff = StringDiff(
                        value=string_val,
                        status='removed',
                        primary_address=primary_str.get("vaddr", 0),
                        xrefs_primary=self._get_string_xrefs(self.r2_primary, primary_str.get("vaddr", 0))
                    )
                    diffs.append(diff)

                elif not primary_str and secondary_str:
                    # String added
                    diff = StringDiff(
                        value=string_val,
                        status='added',
                        secondary_address=secondary_str.get("vaddr", 0),
                        xrefs_secondary=self._get_string_xrefs(self.r2_secondary, secondary_str.get("vaddr", 0))
                    )
                    diffs.append(diff)

                elif primary_str and secondary_str:
                    # String exists in both - check xrefs
                    primary_xrefs = self._get_string_xrefs(self.r2_primary, primary_str.get("vaddr", 0))
                    secondary_xrefs = self._get_string_xrefs(self.r2_secondary, secondary_str.get("vaddr", 0))

                    if set(primary_xrefs) != set(secondary_xrefs):
                        diff = StringDiff(
                            value=string_val,
                            status='modified',
                            primary_address=primary_str.get("vaddr", 0),
                            secondary_address=secondary_str.get("vaddr", 0),
                            xrefs_primary=primary_xrefs,
                            xrefs_secondary=secondary_xrefs
                        )
                        diffs.append(diff)

            self.logger.info(f"Found {len(diffs)} string differences")

        except Exception as e:
            self.logger.error(f"Failed to get string diffs: {e}")

        return diffs

    def get_import_diffs(self) -> List[Dict[str, Any]]:
        """Compare imports between binaries.

        Returns:
            List of import differences
        """
        if not self.r2_primary or not self.r2_secondary:
            return []

        diffs = []

        try:
            # Get imports
            primary_imports = json.loads(self.r2_primary.cmd("iij"))
            secondary_imports = json.loads(self.r2_secondary.cmd("iij"))

            # Create lookup by name
            primary_by_name = {f"{i.get('libname', '')}::{i.get('name', '')}": i for i in primary_imports}
            secondary_by_name = {f"{i.get('libname', '')}::{i.get('name', '')}": i for i in secondary_imports}

            all_imports = set(primary_by_name.keys()) | set(secondary_by_name.keys())

            for import_name in all_imports:
                if import_name == "::":  # Skip empty
                    continue

                if import_name in primary_by_name and import_name not in secondary_by_name:
                    diffs.append({
                        'name': import_name,
                        'status': 'removed',
                        'details': primary_by_name[import_name]
                    })
                elif import_name not in primary_by_name and import_name in secondary_by_name:
                    diffs.append({
                        'name': import_name,
                        'status': 'added',
                        'details': secondary_by_name[import_name]
                    })

        except Exception as e:
            self.logger.error(f"Failed to get import diffs: {e}")

        return diffs

    def get_comprehensive_diff(self) -> Dict[str, Any]:
        """Get comprehensive diff analysis between binaries.

        Returns:
            Dictionary containing all diff results
        """
        return {
            'functions': self.get_function_diffs(),
            'strings': self.get_string_diffs(),
            'imports': self.get_import_diffs(),
            'metadata': {
                'primary_path': self.primary_path,
                'secondary_path': self.secondary_path,
                'primary_hash': self._get_file_hash(self.r2_primary),
                'secondary_hash': self._get_file_hash(self.r2_secondary),
                'primary_size': self._get_file_size(self.r2_primary),
                'secondary_size': self._get_file_size(self.r2_secondary)
            }
        }

    def _calculate_function_similarity(self, func_name: str, primary_func: Dict, secondary_func: Dict) -> float:
        """Calculate similarity score between two functions.

        Args:
            func_name: Function name
            primary_func: Primary function metadata
            secondary_func: Secondary function metadata

        Returns:
            Similarity score between 0 and 1
        """
        try:
            # Get disassembly for both functions
            self.r2_primary.cmd(f"s {primary_func.get('offset', 0)}")
            primary_ops = self.r2_primary.cmd(f"pdfj @ {func_name}")
            primary_ops = json.loads(primary_ops) if primary_ops else {}

            self.r2_secondary.cmd(f"s {secondary_func.get('offset', 0)}")
            secondary_ops = self.r2_secondary.cmd(f"pdfj @ {func_name}")
            secondary_ops = json.loads(secondary_ops) if secondary_ops else {}

            # Extract opcodes
            primary_opcodes = [op.get("opcode", "") for op in primary_ops.get("ops", [])]
            secondary_opcodes = [op.get("opcode", "") for op in secondary_ops.get("ops", [])]

            if not primary_opcodes and not secondary_opcodes:
                return 1.0
            if not primary_opcodes or not secondary_opcodes:
                return 0.0

            # Calculate Levenshtein distance
            distance = self._levenshtein_distance(primary_opcodes, secondary_opcodes)
            max_len = max(len(primary_opcodes), len(secondary_opcodes))

            similarity = 1.0 - (distance / max_len) if max_len > 0 else 1.0

            return similarity

        except Exception as e:
            self.logger.error(f"Failed to calculate similarity: {e}")
            return 0.0

    def _levenshtein_distance(self, s1: List[str], s2: List[str]) -> int:
        """Calculate Levenshtein distance between two sequences."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _get_function_bb_diff(self, func_name: str) -> Dict[str, Any]:
        """Get basic block diff summary for a function."""
        bb_diffs = self.get_basic_block_diffs(func_name)
        return {
            'total_blocks': len(bb_diffs),
            'added': len([d for d in bb_diffs if d.status == 'added']),
            'removed': len([d for d in bb_diffs if d.status == 'removed']),
            'modified': len([d for d in bb_diffs if d.status == 'modified']),
            'unchanged': len([d for d in bb_diffs if d.status == 'unchanged'])
        }

    def _count_opcode_changes(self, func_name: str) -> int:
        """Count number of opcode changes in a function."""
        try:
            # Get opcodes from both versions
            self.r2_primary.cmd(f"s {func_name}")
            primary_ops = json.loads(self.r2_primary.cmd("pdfj") or "{}")

            self.r2_secondary.cmd(f"s {func_name}")
            secondary_ops = json.loads(self.r2_secondary.cmd("pdfj") or "{}")

            primary_opcodes = [op.get("opcode", "") for op in primary_ops.get("ops", [])]
            secondary_opcodes = [op.get("opcode", "") for op in secondary_ops.get("ops", [])]

            # Count differences
            changes = 0
            for i in range(min(len(primary_opcodes), len(secondary_opcodes))):
                if primary_opcodes[i] != secondary_opcodes[i]:
                    changes += 1

            # Add difference in lengths
            changes += abs(len(primary_opcodes) - len(secondary_opcodes))

            return changes

        except Exception as e:
            self.logger.error(f"Failed to count opcode changes: {e}")
            return 0

    def _get_call_changes(self, func_name: str) -> List[str]:
        """Get list of changed function calls."""
        try:
            # Get calls from both versions
            self.r2_primary.cmd(f"s {func_name}")
            primary_calls = self.r2_primary.cmd("afxj")
            primary_calls = json.loads(primary_calls) if primary_calls else []

            self.r2_secondary.cmd(f"s {func_name}")
            secondary_calls = self.r2_secondary.cmd("afxj")
            secondary_calls = json.loads(secondary_calls) if secondary_calls else []

            # Extract call targets
            primary_targets = set(c.get("ref", "") for c in primary_calls if c.get("type", "") == "call")
            secondary_targets = set(c.get("ref", "") for c in secondary_calls if c.get("type", "") == "call")

            # Find differences
            added = secondary_targets - primary_targets
            removed = primary_targets - secondary_targets

            changes = []
            for target in added:
                changes.append(f"added: {target}")
            for target in removed:
                changes.append(f"removed: {target}")

            return changes

        except Exception as e:
            self.logger.error(f"Failed to get call changes: {e}")
            return []

    def _match_basic_blocks(self, primary_blocks: List[Dict], secondary_blocks: List[Dict]) -> Dict[int, int]:
        """Match basic blocks between two versions of a function."""
        matches = {}

        # Simple matching by relative position for now
        for i, primary_bb in enumerate(primary_blocks):
            if i < len(secondary_blocks):
                matches[primary_bb.get("addr", 0)] = secondary_blocks[i].get("addr", 0)

        return matches

    def _blocks_differ(self, bb1: Dict, bb2: Dict) -> bool:
        """Check if two basic blocks differ significantly."""
        # Compare sizes
        if bb1.get("size", 0) != bb2.get("size", 0):
            return True

        # Compare instruction count
        if len(bb1.get("ops", [])) != len(bb2.get("ops", [])):
            return True

        # Compare jump targets
        if bb1.get("jump", 0) != bb2.get("jump", 0):
            return True
        if bb1.get("fail", 0) != bb2.get("fail", 0):
            return True

        return False

    def _get_string_xrefs(self, r2_session, address: int) -> List[int]:
        """Get cross-references to a string."""
        try:
            r2_session.cmd(f"s {address}")
            xrefs = r2_session.cmd("axtj")
            xrefs = json.loads(xrefs) if xrefs else []
            return [x.get("from", 0) for x in xrefs]
        except:
            return []

    def _get_file_hash(self, r2_session) -> str:
        """Get file hash."""
        try:
            if r2_session:
                result = r2_session.cmd("!rahash2 -a md5 -q $F")
                return result.strip() if result else ""
        except:
            pass
        return ""

    def _get_file_size(self, r2_session) -> int:
        """Get file size."""
        try:
            if r2_session:
                result = r2_session.cmd("i~size[1]")
                return int(result.strip()) if result and result.strip().isdigit() else 0
        except:
            pass
        return 0

    def cleanup(self):
        """Clean up r2 sessions."""
        if self.r2_primary:
            try:
                self.r2_primary.quit()
            except:
                pass
        if self.r2_secondary:
            try:
                self.r2_secondary.quit()
            except:
                pass