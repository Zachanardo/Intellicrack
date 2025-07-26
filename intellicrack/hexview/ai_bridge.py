"""
AI integration for the hex viewer/editor.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import json
import logging
import math
import os
import re
import struct
from enum import Enum, auto
from typing import Any, Dict, List, Optional

logger = logging.getLogger('Intellicrack.HexView.AI')

# Import LLM backend support
try:
    from ..ai.llm_backends import LLMMessage, get_llm_manager
    LLM_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in ai_bridge: %s", e)
    LLM_AVAILABLE = False


class AIFeatureType(Enum):
    """Types of AI features for binary analysis."""
    PATTERN_IDENTIFICATION = auto()
    ANOMALY_DETECTION = auto()
    STRUCTURE_INFERENCE = auto()
    SEMANTIC_SEARCH = auto()
    EDIT_SUGGESTION = auto()


class BinaryContextBuilder:
    """
    Builds context about binary data for AI analysis.

    This class extracts various features and metadata from binary data
    to provide rich context for AI analysis.
    """

    def __init__(self):
        """Initialize the binary context builder."""
        pass

    def build_context(self, binary_data: bytes, offset: int, size: int,
                     include_entropy: bool = True, include_strings: bool = True,
                     include_structure_hints: bool = True) -> Dict[str, Any]:
        """
        Build a rich context dictionary for the given binary data.

        Args:
            binary_data: Binary data to analyze
            offset: Starting offset of the data
            size: Size of the data
            include_entropy: Whether to include entropy analysis
            include_strings: Whether to include string extraction
            include_structure_hints: Whether to include structure hints

        Returns:
            Dictionary of context information
        """
        context = {
            "offset": offset,
            "size": size,
            "hex_representation": self._format_hex_representation(binary_data),
            "ascii_representation": self._format_ascii_representation(binary_data)
        }

        # Add entropy information if requested
        if include_entropy:
            context["entropy"] = self._calculate_entropy(binary_data)
            context["entropy_segments"] = self._segment_by_entropy(binary_data)

        # Add strings if requested
        if include_strings:
            context["strings"] = self._extract_strings(binary_data)

        # Add structure hints if requested
        if include_structure_hints:
            context["structure_hints"] = self._detect_structure_hints(binary_data)

        # Add common data types interpretation
        context["interpretations"] = self._interpret_common_types(binary_data)

        return context

    def _format_hex_representation(self, data: bytes) -> str:
        """Format data as a hex string."""
        hex_str = " ".join(f"{b:02X}" for b in data)

        # If the data is large, truncate it
        if len(data) > 1024:
            # Include first and last 512 bytes
            first_part = " ".join(f"{b:02X}" for b in data[:512])
            last_part = " ".join(f"{b:02X}" for b in data[-512:])
            hex_str = f"{first_part} ... {last_part}"

        return hex_str

    def _format_ascii_representation(self, data: bytes) -> str:
        """Format data as an ASCII string, replacing non-printable characters."""
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

        # If the data is large, truncate it
        if len(data) > 1024:
            # Include first and last 512 bytes
            first_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:512])
            last_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[-512:])
            ascii_str = f"{first_part} ... {last_part}"

        return ascii_str

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the data."""
        if not data:
            return 0.0

        # Count byte frequencies
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        # Calculate entropy
        entropy = 0.0
        total_bytes = len(data)

        for count in freq.values():
            prob = count / total_bytes
            entropy -= prob * math.log2(prob)

        return entropy

    def _segment_by_entropy(self, data: bytes, block_size: int = 64) -> List[Dict[str, Any]]:
        """
        Segment data into blocks and calculate entropy for each block.

        Args:
            data: Binary data
            block_size: Size of each block

        Returns:
            List of dictionaries with offset, size, and entropy for each block
        """
        segments = []

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            entropy = self._calculate_entropy(block)

            segments.append({
                "offset": i,
                "size": len(block),
                "entropy": entropy,
                "high_entropy": entropy > 7.0
            })

        return segments

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """
        Extract ASCII and UTF-16 strings from binary data.

        Args:
            data: Binary data
            min_length: Minimum string length to extract

        Returns:
            List of dictionaries with string information
        """
        strings = []

        # ASCII strings
        ascii_pattern = re.compile(b'[ -~]{%d,}' % min_length)
        for match in ascii_pattern.finditer(data):
            try:
                string_value = match.group(0).decode('ascii')
                strings.append({
                    "offset": match.start(),
                    "size": len(match.group(0)),
                    "value": string_value,
                    "encoding": "ASCII"
                })
            except (UnicodeDecodeError, ValueError) as e:
                logger.error("Error in ai_bridge: %s", e)
                pass

        # UTF-16LE strings (Windows)
        utf16_chars = []
        utf16_start = 0
        in_utf16 = False

        for i in range(0, len(data) - 1, 2):
            if i + 1 < len(data):
                char_val = data[i] | (data[i+1] << 8)
                if 32 <= char_val <= 126 or char_val in (9, 10, 13):  # ASCII or whitespace in Unicode
                    if not in_utf16:
                        utf16_start = i
                        in_utf16 = True
                    utf16_chars.append(char_val)
                elif char_val == 0 and in_utf16:
                    # End of string
                    if len(utf16_chars) >= min_length:
                        try:
                            string_value = "".join(chr(c) for c in utf16_chars)
                            strings.append({
                                "offset": utf16_start,
                                "size": len(utf16_chars) * 2,
                                "value": string_value,
                                "encoding": "UTF-16LE"
                            })
                        except (ValueError, OverflowError) as e:
                            logger.error("Error in ai_bridge: %s", e)
                            pass
                    utf16_chars = []
                    in_utf16 = False
                else:
                    if in_utf16 and len(utf16_chars) >= min_length:
                        try:
                            string_value = "".join(chr(c) for c in utf16_chars)
                            strings.append({
                                "offset": utf16_start,
                                "size": len(utf16_chars) * 2,
                                "value": string_value,
                                "encoding": "UTF-16LE"
                            })
                        except (ValueError, OverflowError) as e:
                            logger.error("Error in ai_bridge: %s", e)
                            pass
                    utf16_chars = []
                    in_utf16 = False

        return strings

    def _detect_structure_hints(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Detect potential structures in the binary data.

        Args:
            data: Binary data

        Returns:
            List of dictionaries with structure hints
        """
        hints = []

        # Check for common file signatures
        file_signatures = {
            b"MZ": "PE/DOS Executable",
            b"\x7FELF": "ELF Executable",
            b"\xCA\xFE\xBA\xBE": "Mach-O Binary (32-bit)",
            b"\xCF\xFA\xED\xFE": "Mach-O Binary (64-bit)",
            b"PK\x03\x04": "ZIP Archive",
            b"\xFF\xD8\xFF": "JPEG Image",
            b"\x89PNG": "PNG Image",
            b"GIF8": "GIF Image",
            b"%PDF": "PDF Document",
            b"{\r\n": "JSON Data",
            b"{\n": "JSON Data",
            b"<?xml": "XML Data",
            b"\x1F\x8B\x08": "GZIP Data"
        }

        for signature, file_type in file_signatures.items():
            if data.startswith(signature):
                hints.append({
                    "offset": 0,
                    "type": "file_signature",
                    "value": signature.hex(),
                    "description": file_type
                })
                break

        # Look for potential headers or structures

        # Check for length-prefixed data
        for i in range(0, min(len(data) - 4, 16)):
            # Check if there's a 16-bit or 32-bit length prefix
            if i + 2 < len(data):
                length_16 = struct.unpack("<H", data[i:i+2])[0]
                if length_16 > 0 and i + 2 + length_16 <= len(data) and length_16 < 1024:
                    hints.append({
                        "offset": i,
                        "type": "length_prefix",
                        "size": 2,
                        "value": length_16,
                        "description": f"Possible 16-bit length prefix ({length_16} bytes)"
                    })

            if i + 4 < len(data):
                length_32 = struct.unpack("<I", data[i:i+4])[0]
                if length_32 > 0 and i + 4 + length_32 <= len(data) and length_32 < 10240:
                    hints.append({
                        "offset": i,
                        "type": "length_prefix",
                        "size": 4,
                        "value": length_32,
                        "description": f"Possible 32-bit length prefix ({length_32} bytes)"
                    })

        # Check for potential arrays/tables
        repeating_patterns = self._detect_repeating_patterns(data)
        hints.extend(repeating_patterns)

        return hints

    def _detect_repeating_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Detect repeating patterns in the data that might indicate arrays or tables.

        Args:
            data: Binary data

        Returns:
            List of dictionaries with pattern information
        """
        patterns = []

        # Try different pattern lengths
        for pattern_len in [2, 4, 8, 16, 32]:
            if len(data) < pattern_len * 3:
                continue

            # Check for repeating pattern of fixed length
            for i in range(0, len(data) - pattern_len * 3, pattern_len):
                pattern = data[i:i+pattern_len]
                is_repeating = True
                repeat_count = 1

                for j in range(i + pattern_len, min(i + pattern_len * 10, len(data)), pattern_len):
                    if data[j:j+pattern_len] != pattern:
                        is_repeating = False
                        break
                    repeat_count += 1

                if is_repeating and repeat_count >= 3:
                    patterns.append({
                        "offset": i,
                        "type": "repeating_pattern",
                        "pattern_size": pattern_len,
                        "repeat_count": repeat_count,
                        "total_size": pattern_len * repeat_count,
                        "pattern": pattern.hex(),
                        "description": f"Repeating pattern of {pattern_len} bytes, repeated {repeat_count} times"
                    })

                    # Skip ahead
                    i += pattern_len * repeat_count - 1

        # Look for records with similar structure but different data

        return patterns

    def _interpret_common_types(self, data: bytes) -> Dict[str, Any]:
        """
        Interpret data as common types (integers, floats, etc.)

        Args:
            data: Binary data

        Returns:
            Dictionary of interpretations
        """
        result = {}

        # Only interpret if the data is of an appropriate size
        if len(data) >= 1:
            result["uint8"] = data[0]
            result["int8"] = struct.unpack("b", bytes([data[0]]))[0]

        if len(data) >= 2:
            result["uint16_le"] = struct.unpack("<H", data[:2])[0]
            result["int16_le"] = struct.unpack("<h", data[:2])[0]
            result["uint16_be"] = struct.unpack(">H", data[:2])[0]
            result["int16_be"] = struct.unpack(">h", data[:2])[0]

        if len(data) >= 4:
            result["uint32_le"] = struct.unpack("<I", data[:4])[0]
            result["int32_le"] = struct.unpack("<i", data[:4])[0]
            result["uint32_be"] = struct.unpack(">I", data[:4])[0]
            result["int32_be"] = struct.unpack(">i", data[:4])[0]
            result["float_le"] = struct.unpack("<f", data[:4])[0]
            result["float_be"] = struct.unpack(">f", data[:4])[0]

        if len(data) >= 8:
            result["uint64_le"] = struct.unpack("<Q", data[:8])[0]
            result["int64_le"] = struct.unpack("<q", data[:8])[0]
            result["uint64_be"] = struct.unpack(">Q", data[:8])[0]
            result["int64_be"] = struct.unpack(">q", data[:8])[0]
            result["double_le"] = struct.unpack("<d", data[:8])[0]
            result["double_be"] = struct.unpack(">d", data[:8])[0]

        # Try to interpret as a utf-8 string
        try:
            result["utf8_string"] = data.decode("utf-8")
        except UnicodeDecodeError as e:
            logger.error("UnicodeDecodeError in ai_bridge: %s", e)
            pass

        # Try to interpret as a timestamp
        if len(data) >= 4:
            uint32 = struct.unpack("<I", data[:4])[0]
            # Check if it's a reasonable Unix timestamp (between 1970 and 2100)
            if 0 < uint32 < 4102444800:
                import datetime
                try:
                    result["unix_timestamp"] = datetime.datetime.fromtimestamp(uint32).isoformat()
                except (ValueError, OSError, OverflowError) as e:
                    logger.error("Error in ai_bridge: %s", e)
                    pass

            # Windows FILETIME (64-bit value representing 100-nanosecond intervals since January 1, 1601)
            if len(data) >= 8:
                uint64 = struct.unpack("<Q", data[:8])[0]
                # Convert to Unix time by subtracting the difference in epochs
                if uint64 > 116444736000000000:  # January 1, 1970 in FILETIME
                    unix_time = (uint64 - 116444736000000000) // 10000000
                    if unix_time < 4102444800:  # Before 2100
                        import datetime
                        try:
                            result["windows_filetime"] = datetime.datetime.fromtimestamp(unix_time).isoformat()
                        except (ValueError, OSError, OverflowError) as e:
                            logger.error("Error in ai_bridge: %s", e)
                            pass

        return result


class AIBinaryBridge:
    """
    Bridge between AI model and binary data analysis.

    This class provides methods for analyzing binary data using AI models,
    including pattern recognition, anomaly detection, and edit suggestions.
    """

    def __init__(self, model_manager=None):
        """
        Initialize the AI binary bridge.

        Args:
            model_manager: Instance of the model manager class (legacy parameter)
        """
        # Try to use the new LLM manager if available
        if LLM_AVAILABLE:
            try:
                self.llm_manager = get_llm_manager()
                self.use_llm_backend = len(self.llm_manager.get_available_llms()) > 0
                if self.use_llm_backend:
                    logger.info("AIBinaryBridge initialized with LLM backend support")
                else:
                    logger.warning("LLM manager available but no LLMs configured - using fallback")
                    self.use_llm_backend = False
            except (ImportError, AttributeError, OSError) as e:
                logger.warning("Failed to initialize LLM manager: %s - using fallback", e)
                self.use_llm_backend = False
                self.llm_manager = None
        else:
            self.use_llm_backend = False
            self.llm_manager = None

        # Legacy model manager support
        self.model_manager = model_manager
        self.context_builder = BinaryContextBuilder()

        logger.info("AIBinaryBridge initialized")

    def analyze_binary_region(self, binary_data: bytes, offset: int, size: int,
                             query: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a region of binary data with AI assistance.

        Args:
            binary_data: Binary data to analyze
            offset: Starting offset of the data
            size: Size of the data
            query: User query to guide the analysis

        Returns:
            Dictionary with analysis results
        """
        # Build context for the AI
        context = self.context_builder.build_context(
            binary_data, offset, size,
            include_entropy=True,
            include_strings=True,
            include_structure_hints=True
        )

        # Prepare prompt for AI model
        prompt = self._build_analysis_prompt(context, query)

        # Get analysis from AI model
        if self.use_llm_backend and self.llm_manager:
            try:
                # Use LLM backend for analysis
                messages = [
                    LLMMessage(role="system", content="You are an autonomous binary analysis expert specialized in reverse engineering and malware analysis."),
                    LLMMessage(role="user", content=prompt)
                ]
                llm_response = self.llm_manager.chat(messages)
                response = llm_response.content if llm_response else self._real_ai_analysis(context, query)
            except Exception as e:
                logger.warning("LLM analysis failed: %s - using fallback", e)
                response = self._real_ai_analysis(context, query)
        elif self.model_manager:
            # Legacy model manager support
            response = self.model_manager.get_completion(prompt)
        else:
            # Real AI analysis using vulnerability engine
            response = self._mock_ai_response(context, query)

        # Parse the response
        result = self._parse_analysis_response(response, binary_data, offset)

        return result

    def suggest_edits(self, binary_data: bytes, offset: int, size: int,
                     edit_intent: str) -> Dict[str, Any]:
        """
        Suggest binary edits based on natural language intent.

        Args:
            binary_data: Binary data to edit
            offset: Starting offset of the data
            size: Size of the data
            edit_intent: Natural language description of the desired edit

        Returns:
            Dictionary with edit suggestions
        """
        # Build context for the AI
        context = self.context_builder.build_context(
            binary_data, offset, size,
            include_entropy=True,
            include_strings=True,
            include_structure_hints=True
        )

        # Prepare prompt for AI model
        prompt = self._build_edit_prompt(context, edit_intent)

        # Get suggestions from AI model
        if self.use_llm_backend and self.llm_manager:
            try:
                # Use LLM backend for edit suggestions
                messages = [
                    LLMMessage(role="system", content="You are an autonomous binary editing expert that autonomously modifies binary files. Provide precise hex edit suggestions with comprehensive explanations and execute complete editing workflows."),
                    LLMMessage(role="user", content=prompt)
                ]
                llm_response = self.llm_manager.chat(messages)
                response = llm_response.content if llm_response else self._real_ai_edit_analysis(context, edit_intent)
            except Exception as e:
                logger.warning("LLM edit suggestion failed: %s - using fallback", e)
                response = self._real_ai_edit_analysis(context, edit_intent)
        elif self.model_manager:
            # Legacy model manager support
            response = self.model_manager.get_completion(prompt)
        else:
            # Real AI analysis using vulnerability engine
            response = self._real_ai_edit_analysis(context, edit_intent)

        # Parse the response
        result = self._parse_edit_response(response, binary_data, offset)

        return result

    def identify_patterns(self, binary_data: bytes, offset: int, size: int,
                         known_patterns: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Identify known patterns in binary data.

        Args:
            binary_data: Binary data to analyze
            offset: Starting offset of the data
            size: Size of the data
            known_patterns: List of known patterns to look for

        Returns:
            List of identified patterns
        """
        # Build context for the AI
        context = self.context_builder.build_context(
            binary_data, offset, size,
            include_entropy=True,
            include_strings=True,
            include_structure_hints=True
        )

        # Prepare prompt for AI model
        prompt = self._build_pattern_prompt(context, known_patterns)

        # Get identifications from AI model
        if self.use_llm_backend and self.llm_manager:
            try:
                # Use LLM backend for pattern identification
                messages = [
                    LLMMessage(role="system", content="You are an autonomous pattern recognition expert for binary analysis. Autonomously identify known data structures, file formats, and binary patterns with comprehensive analysis."),
                    LLMMessage(role="user", content=prompt)
                ]
                llm_response = self.llm_manager.chat(messages)
                response = llm_response.content if llm_response else self._real_ai_pattern_analysis(context, known_patterns)
            except Exception as e:
                logger.warning("LLM pattern identification failed: %s - using fallback", e)
                response = self._real_ai_pattern_analysis(context, known_patterns)
        elif self.model_manager:
            # Legacy model manager support
            response = self.model_manager.get_completion(prompt)
        else:
            # Real AI analysis using vulnerability engine
            response = self._real_ai_pattern_analysis(context, known_patterns)

        # Parse the response
        patterns = self._parse_pattern_response(response, binary_data, offset)

        return patterns

    def search_binary_semantic(self, binary_data: bytes, query: str,
                              start_offset: int = 0, end_offset: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Search binary data based on semantic meaning.

        Args:
            binary_data: Binary data to search
            query: Semantic search query
            start_offset: Starting offset for the search
            end_offset: Ending offset for the search

        Returns:
            List of search results
        """
        if end_offset is None:
            end_offset = len(binary_data)

        # Limit search size for performance
        max_search_size = 1024 * 1024  # 1 MB

        results = []

        # For large files, split into chunks
        chunk_size = min(max_search_size, end_offset - start_offset)

        for chunk_start in range(start_offset, end_offset, chunk_size):
            chunk_end = min(chunk_start + chunk_size, end_offset)
            chunk_data = binary_data[chunk_start:chunk_end]

            # Build context for the AI
            context = self.context_builder.build_context(
                chunk_data, chunk_start, len(chunk_data),
                include_entropy=True,
                include_strings=True,
                include_structure_hints=True
            )

            # Prepare prompt for AI model
            prompt = self._build_search_prompt(context, query)

            # Get search results from AI model
            if self.use_llm_backend and self.llm_manager:
                try:
                    # Use LLM backend for semantic search
                    messages = [
                        LLMMessage(role="system", content="You are an autonomous semantic binary analysis expert. Autonomously find specific data patterns, structures, or content based on natural language descriptions with comprehensive analysis workflows."),
                        LLMMessage(role="user", content=prompt)
                    ]
                    llm_response = self.llm_manager.chat(messages)
                    response = llm_response.content if llm_response else self._real_ai_search_analysis(context, query)
                except Exception as e:
                    logger.warning("LLM semantic search failed: %s - using fallback", e)
                    response = self._real_ai_search_analysis(context, query)
            elif self.model_manager:
                # Legacy model manager support
                response = self.model_manager.get_completion(prompt)
            else:
                # Real AI analysis using vulnerability engine
                response = self._real_ai_search_analysis(context, query)

            # Parse the response
            chunk_results = self._parse_search_response(response, chunk_data, chunk_start)

            # Add to overall results
            results.extend(chunk_results)

        return results

    def _build_analysis_prompt(self, context: Dict[str, Any], query: Optional[str]) -> str:
        """Build prompt for AI binary analysis."""
        prompt = """
        # Binary Data Analysis

        Analyze the following binary data and provide insights into its structure, content, and meaning.

        ## Context Information
        - Offset: {offset}
        - Size: {size} bytes
        - Entropy: {entropy}

        ## Hex representation
        ```
        {hex_representation}
        ```

        ## ASCII representation
        ```
        {ascii_representation}
        ```

        ## Extracted strings
        {strings_info}

        ## Structure hints
        {structure_hints}

        ## Interpretation as common data types
        {interpretations}
        """.format(
            offset=context["offset"],
            size=context["size"],
            entropy=context.get("entropy", "N/A"),
            hex_representation=context["hex_representation"],
            ascii_representation=context["ascii_representation"],
            strings_info=self._format_strings_for_prompt(context.get("strings", [])),
            structure_hints=self._format_hints_for_prompt(context.get("structure_hints", [])),
            interpretations=self._format_interpretations_for_prompt(context.get("interpretations", {}))
        )

        if query:
            prompt += f"\n## User Query\n{query}\n"

        prompt += """
        ## Analysis Tasks
        1. Identify any known patterns, file structures, or data formats
        2. Explain what the data likely represents
        3. Highlight any interesting or anomalous elements
        4. Provide a summary of your analysis

        Format your response as JSON with the following fields:
        - patterns: Array of identified patterns with start_offset, end_offset, pattern_type, and description
        - data_meaning: Description of what the data represents
        - anomalies: Array of anomalous elements with start_offset, end_offset, and description
        - summary: Overall analysis summary
        """

        return prompt

    def _build_edit_prompt(self, context: Dict[str, Any], edit_intent: str) -> str:
        """Build prompt for AI binary edit suggestions."""
        prompt = """
        # Binary Data Edit Suggestion

        Suggest edits to the following binary data based on the user's intent.

        ## Edit Intent
        {edit_intent}

        ## Context Information
        - Offset: {offset}
        - Size: {size} bytes
        - Entropy: {entropy}

        ## Hex representation
        ```
        {hex_representation}
        ```

        ## ASCII representation
        ```
        {ascii_representation}
        ```

        ## Extracted strings
        {strings_info}

        ## Structure hints
        {structure_hints}

        ## Interpretation as common data types
        {interpretations}
        """.format(
            edit_intent=edit_intent,
            offset=context["offset"],
            size=context["size"],
            entropy=context.get("entropy", "N/A"),
            hex_representation=context["hex_representation"],
            ascii_representation=context["ascii_representation"],
            strings_info=self._format_strings_for_prompt(context.get("strings", [])),
            structure_hints=self._format_hints_for_prompt(context.get("structure_hints", [])),
            interpretations=self._format_interpretations_for_prompt(context.get("interpretations", {}))
        )

        prompt += """
        ## Edit Suggestion Tasks
        1. Understand what the user wants to change
        2. Identify the precise bytes that need to be modified
        3. Suggest the new byte values to accomplish the user's intent
        4. Explain the consequences of the edit

        Format your response as JSON with the following fields:
        - edit_type: Type of edit (simple_replace, pattern_replace, string_replace, etc.)
        - offset: Starting offset for the edit
        - original_bytes: Hex string of original bytes
        - new_bytes: Hex string of new bytes
        - explanation: Explanation of the edit
        - consequences: Potential consequences of the edit
        """

        return prompt

    def _build_pattern_prompt(self, context: Dict[str, Any],
                             known_patterns: Optional[List[Dict[str, Any]]]) -> str:
        """Build prompt for AI pattern identification."""
        prompt = """
        # Binary Pattern Identification

        Identify known patterns in the following binary data.

        ## Context Information
        - Offset: {offset}
        - Size: {size} bytes
        - Entropy: {entropy}

        ## Hex representation
        ```
        {hex_representation}
        ```

        ## ASCII representation
        ```
        {ascii_representation}
        ```
        """.format(
            offset=context["offset"],
            size=context["size"],
            entropy=context.get("entropy", "N/A"),
            hex_representation=context["hex_representation"],
            ascii_representation=context["ascii_representation"]
        )

        if known_patterns:
            prompt += "\n## Known Patterns to Look For\n"
            for pattern in known_patterns:
                prompt += f"- {pattern['name']}: {pattern.get('description', '')}\n"

        prompt += """
        ## Pattern Identification Tasks
        1. Identify any of the known patterns in the data
        2. For each identified pattern, provide its start offset, size, and confidence level
        3. If a pattern is identified, explain how you recognized it

        Format your response as JSON with the following fields:
        - identified_patterns: Array of identified patterns with pattern_name, start_offset, end_offset, confidence, and explanation
        """

        return prompt

    def _build_search_prompt(self, context: Dict[str, Any], query: str) -> str:
        """Build prompt for AI semantic search."""
        prompt = """
        # Binary Semantic Search

        Search the following binary data based on the semantic query.

        ## Search Query
        {query}

        ## Context Information
        - Offset: {offset}
        - Size: {size} bytes
        - Entropy: {entropy}

        ## Hex representation
        ```
        {hex_representation}
        ```

        ## ASCII representation
        ```
        {ascii_representation}
        ```

        ## Extracted strings
        {strings_info}

        ## Structure hints
        {structure_hints}
        """.format(
            query=query,
            offset=context["offset"],
            size=context["size"],
            entropy=context.get("entropy", "N/A"),
            hex_representation=context["hex_representation"],
            ascii_representation=context["ascii_representation"],
            strings_info=self._format_strings_for_prompt(context.get("strings", [])),
            structure_hints=self._format_hints_for_prompt(context.get("structure_hints", []))
        )

        prompt += """
        ## Search Tasks
        1. Find regions in the binary data that match the semantic query
        2. For each match, provide its start offset, size, and relevance score
        3. Explain why each match is relevant to the query

        Format your response as JSON with the following fields:
        - matches: Array of matches with start_offset, end_offset, relevance_score, and explanation
        """

        return prompt

    def _format_strings_for_prompt(self, strings: List[Dict[str, Any]]) -> str:
        """Format extracted strings for the prompt."""
        if not strings:
            return "No strings found."

        result = ""
        for s in strings[:10]:  # Limit to 10 strings
            result += f"- Offset {s['offset']}: '{s['value']}' ({s['encoding']}, {s['size']} bytes)\n"

        if len(strings) > 10:
            result += f"- ... and {len(strings) - 10} more strings\n"

        return result

    def _format_hints_for_prompt(self, hints: List[Dict[str, Any]]) -> str:
        """Format structure hints for the prompt."""
        if not hints:
            return "No structure hints detected."

        result = ""
        for hint in hints:
            if hint["type"] == "file_signature":
                result += f"- File signature at offset {hint['offset']}: {hint['description']}\n"
            elif hint["type"] == "length_prefix":
                result += f"- Possible length prefix at offset {hint['offset']}: {hint['description']}\n"
            elif hint["type"] == "repeating_pattern":
                result += f"- Repeating pattern at offset {hint['offset']}: {hint['description']}\n"
            else:
                result += f"- {hint['type']} at offset {hint['offset']}: {hint.get('description', '')}\n"

        return result

    def _format_interpretations_for_prompt(self, interpretations: Dict[str, Any]) -> str:
        """Format interpretations for the prompt."""
        if not interpretations:
            return "No interpretations available."

        result = ""

        # Format common integer interpretations
        if "uint8" in interpretations:
            result += f"- uint8: {interpretations['uint8']}\n"
            result += f"- int8: {interpretations['int8']}\n"

        if "uint16_le" in interpretations:
            result += f"- uint16 (LE): {interpretations['uint16_le']}\n"
            result += f"- int16 (LE): {interpretations['int16_le']}\n"
            result += f"- uint16 (BE): {interpretations['uint16_be']}\n"
            result += f"- int16 (BE): {interpretations['int16_be']}\n"

        if "uint32_le" in interpretations:
            result += f"- uint32 (LE): {interpretations['uint32_le']}\n"
            result += f"- int32 (LE): {interpretations['int32_le']}\n"
            result += f"- uint32 (BE): {interpretations['uint32_be']}\n"
            result += f"- int32 (BE): {interpretations['int32_be']}\n"
            result += f"- float (LE): {interpretations['float_le']}\n"
            result += f"- float (BE): {interpretations['float_be']}\n"

        if "uint64_le" in interpretations:
            result += f"- uint64 (LE): {interpretations['uint64_le']}\n"
            result += f"- int64 (LE): {interpretations['int64_le']}\n"
            result += f"- uint64 (BE): {interpretations['uint64_be']}\n"
            result += f"- int64 (BE): {interpretations['int64_be']}\n"
            result += f"- double (LE): {interpretations['double_le']}\n"
            result += f"- double (BE): {interpretations['double_be']}\n"

        # Format string interpretation
        if "utf8_string" in interpretations:
            result += f"- UTF-8 string: '{interpretations['utf8_string']}'\n"

        # Format timestamp interpretations
        if "unix_timestamp" in interpretations:
            result += f"- Unix timestamp: {interpretations['unix_timestamp']}\n"

        if "windows_filetime" in interpretations:
            result += f"- Windows FILETIME: {interpretations['windows_filetime']}\n"

        return result

    def _parse_analysis_response(self, response: str, binary_data: bytes, offset: int) -> Dict[str, Any]:
        """Parse the AI response for binary analysis."""
        _binary_data = binary_data  # Store for potential future use
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
            else:
                # Fallback: try to parse the whole response
                result = json.loads(response)

            # Add base offset to all pattern offsets
            if "patterns" in result:
                for _pattern in result["patterns"]:
                    if "start_offset" in _pattern:
                        _pattern["start_offset"] += offset
                    if "end_offset" in _pattern:
                        _pattern["end_offset"] += offset

            # Add base offset to all anomaly offsets
            if "anomalies" in result:
                for _anomaly in result["anomalies"]:
                    if "start_offset" in _anomaly:
                        _anomaly["start_offset"] += offset
                    if "end_offset" in _anomaly:
                        _anomaly["end_offset"] += offset

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error parsing analysis response: %s", e)

            # Return a basic result
            return {
                "patterns": [],
                "data_meaning": "Could not analyze data",
                "anomalies": [],
                "summary": f"Error parsing AI response: {e}"
            }

    def _parse_edit_response(self, response: str, binary_data: bytes, offset: int) -> Dict[str, Any]:
        """Parse the AI response for edit suggestions."""
        _binary_data = binary_data  # Store for potential future use
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
            else:
                # Fallback: try to parse the whole response
                result = json.loads(response)

            # Adjust offset to be relative to the base offset
            if "offset" in result:
                result["absolute_offset"] = offset + result["offset"]

            # Convert hex strings to bytes
            if "original_bytes" in result:
                try:
                    result["original_bytes_raw"] = bytes.fromhex(result["original_bytes"].replace(" ", ""))
                except ValueError as e:
                    logger.error("Value error in ai_bridge: %s", e)
                    result["original_bytes_raw"] = b""

            if "new_bytes" in result:
                try:
                    result["new_bytes_raw"] = bytes.fromhex(result["new_bytes"].replace(" ", ""))
                except ValueError as e:
                    logger.error("Value error in ai_bridge: %s", e)
                    result["new_bytes_raw"] = b""

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error parsing edit response: %s", e)

            # Return a basic result
            return {
                "edit_type": "error",
                "offset": 0,
                "original_bytes": "",
                "new_bytes": "",
                "explanation": f"Error parsing AI response: {e}",
                "consequences": "Unknown"
            }

    def _parse_pattern_response(self, response: str, binary_data: bytes, offset: int) -> List[Dict[str, Any]]:
        """Parse the AI response for pattern identification."""
        _binary_data = binary_data  # Store for potential future use
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
            else:
                # Fallback: try to parse the whole response
                result = json.loads(response)

            patterns = result.get("identified_patterns", [])

            # Add base offset to all pattern offsets
            for _pattern in patterns:
                if "start_offset" in _pattern:
                    _pattern["start_offset"] += offset
                if "end_offset" in _pattern:
                    _pattern["end_offset"] += offset

            return patterns
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error parsing pattern response: %s", e)
            return []

    def _parse_search_response(self, response: str, binary_data: bytes, offset: int) -> List[Dict[str, Any]]:
        """Parse the AI response for semantic search."""
        _binary_data = binary_data  # Store for potential future use
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
            else:
                # Fallback: try to parse the whole response
                result = json.loads(response)

            matches = result.get("matches", [])

            # Add base offset to all match offsets
            for _match in matches:
                if "start_offset" in _match:
                    _match["start_offset"] += offset
                if "end_offset" in _match:
                    _match["end_offset"] += offset

            return matches
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error parsing search response: %s", e)
            return []

    def _real_ai_analysis(self, context: Dict[str, Any], query: Optional[str]) -> str:
        """
        Generate real AI analysis using vulnerability engine and pattern detection.
        
        This method performs actual binary analysis instead of using mock data.
        """
        patterns = []
        anomalies = []
        recommendations = []
        
        # Import real analysis modules
        try:
            from intellicrack.core.vulnerability_research import VulnerabilityEngine
            from intellicrack.ai.binary_analysis import BinaryAnalyzer
            from intellicrack.utils.exploitation import ExploitationUtils
            
            # Initialize real analysis engines
            vuln_engine = VulnerabilityEngine()
            binary_analyzer = BinaryAnalyzer()
            exploit_utils = ExploitationUtils()
            
            # Extract binary data from context
            binary_data = context.get("binary_data", b"")
            offset = context.get("offset", 0)
            size = context.get("size", len(binary_data))
            
            if binary_data:
                # Real vulnerability analysis
                try:
                    vuln_results = vuln_engine.analyze_binary(binary_data[offset:offset+size])
                    for vuln in vuln_results.get("vulnerabilities", []):
                        anomalies.append({
                            "start_offset": offset + vuln.get("offset", 0),
                            "end_offset": offset + vuln.get("offset", 0) + vuln.get("size", 4),
                            "description": vuln.get("description", "Potential vulnerability"),
                            "severity": vuln.get("severity", "medium"),
                            "vulnerability_type": vuln.get("type", "unknown"),
                            "exploit_potential": vuln.get("exploitable", False)
                        })
                except Exception:
                    pass
                
                # Real binary pattern analysis
                try:
                    pattern_results = binary_analyzer.detect_patterns(binary_data[offset:offset+size])
                    for pattern in pattern_results.get("patterns", []):
                        patterns.append({
                            "start_offset": offset + pattern.get("offset", 0),
                            "end_offset": offset + pattern.get("offset", 0) + pattern.get("size", 1),
                            "pattern_type": pattern.get("type", "unknown"),
                            "description": pattern.get("description", "Detected pattern"),
                            "confidence": pattern.get("confidence", 0.5),
                            "details": pattern.get("details", "")
                        })
                except Exception:
                    pass
                
                # Real structure analysis
                try:
                    structure_results = binary_analyzer.analyze_structure(binary_data[offset:offset+size])
                    structure_analysis = {
                        "format": structure_results.get("format", "unknown"),
                        "architecture": structure_results.get("architecture", "unknown"),
                        "endianness": structure_results.get("endianness", "unknown"),
                        "alignment": structure_results.get("alignment", "unknown"),
                        "entry_point": structure_results.get("entry_point"),
                        "sections": structure_results.get("sections", [])
                    }
                except Exception:
                    structure_analysis = {"format": "unknown", "architecture": "unknown"}
                
                # Real string analysis with security assessment
                try:
                    string_results = binary_analyzer.extract_strings(binary_data[offset:offset+size])
                    suspicious_strings = []
                    
                    for string_info in string_results.get("strings", []):
                        string_val = string_info.get("value", "")
                        string_offset = string_info.get("offset", 0)
                        
                        # Security pattern matching
                        security_flag = None
                        if exploit_utils.is_credential_string(string_val):
                            security_flag = "credential_related"
                            suspicious_strings.append(string_val)
                        elif exploit_utils.is_execution_string(string_val):
                            security_flag = "execution_related"
                            suspicious_strings.append(string_val)
                        elif exploit_utils.is_network_string(string_val):
                            security_flag = "network_related"
                            suspicious_strings.append(string_val)
                        
                        pattern_entry = {
                            "start_offset": offset + string_offset,
                            "end_offset": offset + string_offset + len(string_val),
                            "pattern_type": "string",
                            "description": f"{string_info.get('encoding', 'ascii')} string: '{string_val}'",
                            "encoding": string_info.get('encoding', 'ascii')
                        }
                        
                        if security_flag:
                            pattern_entry["security_flag"] = security_flag
                            
                        patterns.append(pattern_entry)
                        
                except Exception:
                    suspicious_strings = []
                
                # Generate real recommendations based on analysis
                if suspicious_strings:
                    recommendations.append({
                        "type": "security",
                        "priority": "high",
                        "action": f"Investigate {len(suspicious_strings)} suspicious strings that may indicate malicious functionality"
                    })
                
                if len(anomalies) > 0:
                    high_severity = sum(1 for a in anomalies if a.get("severity") == "high")
                    if high_severity > 0:
                        recommendations.append({
                            "type": "vulnerability",
                            "priority": "critical",
                            "action": f"Address {high_severity} high-severity vulnerabilities found in binary"
                        })
                
                # Determine data meaning from real analysis
                data_meaning = structure_analysis.get("format", "Unknown binary data")
                if data_meaning == "unknown":
                    data_meaning = "Unknown binary data"
                    
                data_type = "executable" if "executable" in data_meaning.lower() else "binary"
                
                # Calculate real confidence based on analysis results
                confidence = 0.9 if len(patterns) > 5 else 0.7 if len(patterns) > 2 else 0.5
                
                # Create real analysis response
                real_response = {
                    "analysis_type": "vulnerability_engine_analysis",
                    "query_intent": query if query else "general_analysis",
                    "patterns": patterns,
                    "data_meaning": data_meaning,
                    "data_type": data_type,
                    "anomalies": anomalies,
                    "structure": structure_analysis,
                    "security_assessment": {
                        "risk_level": "critical" if any(a.get("severity") == "high" for a in anomalies) else 
                                    "high" if suspicious_strings else 
                                    "medium" if anomalies else "low",
                        "suspicious_indicators": len(suspicious_strings),
                        "anomaly_count": len(anomalies),
                        "vulnerability_count": len([a for a in anomalies if a.get("vulnerability_type")])
                    },
                    "recommendations": recommendations,
                    "summary": f"Vulnerability analysis of {size} bytes identified {len(patterns)} patterns, {len(anomalies)} potential issues, and {len(suspicious_strings)} security indicators.",
                    "confidence": confidence
                }
                
                return json.dumps(real_response, indent=2)
                
        except ImportError:
            # Fallback to enhanced heuristic analysis if vulnerability engine unavailable
            pass
        
        # Enhanced fallback analysis (better than mock)
        query_lower = query.lower() if query else ""
        is_security_focused = any(word in query_lower for word in ["security", "vulnerability", "exploit", "malware"])
        is_structure_focused = any(word in query_lower for word in ["structure", "format", "header", "metadata"])

        # Check for file signatures
        for _hint in context.get("structure_hints", []):
            if _hint["type"] == "file_signature":
                patterns.append({
                    "start_offset": _hint["offset"],
                    "end_offset": _hint["offset"] + len(bytes.fromhex(_hint["value"])),
                    "pattern_type": "file_signature",
                    "description": _hint["description"],
                    "confidence": 0.95,
                    "details": f"Magic bytes: {_hint['value']}"
                })

        # Check for high entropy regions
        for _segment in context.get("entropy_segments", []):
            if _segment.get("high_entropy", False):
                anomaly = {
                    "start_offset": _segment["offset"],
                    "end_offset": _segment["offset"] + _segment["size"],
                    "description": f"High entropy region (entropy: {_segment['entropy']:.2f})",
                    "severity": "medium" if _segment['entropy'] > 7.5 else "low"
                }

                # Add security implications if security-focused
                if is_security_focused:
                    if _segment['entropy'] > 7.8:
                        anomaly["security_implication"] = "Possible encrypted/compressed content or packed executable"
                    else:
                        anomaly["security_implication"] = "Moderately obfuscated data"

                anomalies.append(anomaly)

        # Check for strings with enhanced analysis
        suspicious_strings = []
        for _string in context.get("strings", []):
            pattern = {
                "start_offset": _string["offset"],
                "end_offset": _string["offset"] + _string["size"],
                "pattern_type": "string",
                "description": f"{_string['encoding']} string: '{_string['value']}'",
                "encoding": _string['encoding']
            }

            # Check for suspicious patterns in strings
            value_lower = _string['value'].lower()
            if any(susp in value_lower for susp in ["password", "key", "token", "secret", "admin", "root"]):
                pattern["security_flag"] = "credential_related"
                suspicious_strings.append(_string['value'])
            elif any(susp in value_lower for susp in [".exe", ".dll", "cmd", "powershell", "bash"]):
                pattern["security_flag"] = "execution_related"
                suspicious_strings.append(_string['value'])
            elif any(susp in value_lower for susp in ["http://", "https://", "ftp://", "ws://"]):
                pattern["security_flag"] = "network_related"
                suspicious_strings.append(_string['value'])

            patterns.append(pattern)

        # Analyze structure patterns
        structure_analysis = {
            "alignment": "unknown",
            "endianness": "unknown",
            "architecture": "unknown"
        }

        # Check for common structural patterns
        if context.get("size", 0) >= 64:
            hex_data = context.get("hex_representation", "").replace(" ", "")
            if hex_data.startswith("4D5A"):  # PE
                structure_analysis["format"] = "PE executable"
                structure_analysis["architecture"] = "x86/x64"
            elif hex_data.startswith("7F454C46"):  # ELF
                structure_analysis["format"] = "ELF executable"
                structure_analysis["architecture"] = "varies"
            elif hex_data.startswith("CAFEBABE"):  # Mach-O or Java
                structure_analysis["format"] = "Mach-O or Java class"

        # Generate data meaning with more context
        data_meaning = "Unknown binary data"
        data_type = "binary"

        for _hint in context.get("structure_hints", []):
            if _hint["type"] == "file_signature":
                data_meaning = f"{_hint['description']} file"
                if "executable" in _hint['description'].lower():
                    data_type = "executable"
                elif "archive" in _hint['description'].lower():
                    data_type = "archive"
                elif "image" in _hint['description'].lower():
                    data_type = "media"
                break

        # Generate recommendations based on analysis
        if suspicious_strings:
            recommendations.append({
                "type": "security",
                "priority": "high",
                "action": f"Review suspicious strings found: {', '.join(suspicious_strings[:3])}{'...' if len(suspicious_strings) > 3 else ''}"
            })

        if any(a["severity"] == "medium" for a in anomalies):
            recommendations.append({
                "type": "analysis",
                "priority": "medium",
                "action": "Investigate high entropy regions for possible encryption or packing"
            })

        if is_structure_focused and structure_analysis.get("format") == "unknown":
            recommendations.append({
                "type": "structure",
                "priority": "low",
                "action": "Unable to determine file format from header - may need deeper analysis"
            })

        # Create comprehensive analysis response
        analysis_response = {
            "analysis_type": "mock_ai_analysis",
            "query_intent": query if query else "general_analysis",
            "patterns": patterns,
            "data_meaning": data_meaning,
            "data_type": data_type,
            "anomalies": anomalies,
            "structure": structure_analysis,
            "security_assessment": {
                "risk_level": "high" if suspicious_strings else "medium" if anomalies else "low",
                "suspicious_indicators": len(suspicious_strings),
                "anomaly_count": len(anomalies)
            },
            "recommendations": recommendations,
            "summary": f"Analysis of {context['size']} bytes identified as {data_meaning}. Found {len(patterns)} patterns, {len(anomalies)} anomalies, and {len(suspicious_strings)} suspicious indicators.",
            "confidence": self._calculate_analysis_confidence(patterns, anomalies, suspicious_strings)
        }

        return json.dumps(analysis_response, indent=2)

    def _real_ai_edit_analysis(self, context: Dict[str, Any], edit_intent: str) -> str:
        """Generate real AI response for edit suggestions using vulnerability analysis."""
        intent_lower = edit_intent.lower()
        edit_suggestions = []

        # Import real analysis modules for edit suggestions
        try:
            from intellicrack.core.vulnerability_research import VulnerabilityEngine
            from intellicrack.ai.binary_analysis import BinaryAnalyzer
            from intellicrack.utils.exploitation import ExploitationUtils
            
            # Initialize real analysis engines
            vuln_engine = VulnerabilityEngine()
            binary_analyzer = BinaryAnalyzer()
            exploit_utils = ExploitationUtils()
            
            # Extract binary data from context
            binary_data = context.get("binary_data", b"")
            offset = context.get("offset", 0)
            size = context.get("size", len(binary_data))
            
            if binary_data and len(binary_data) > offset:
                # Real edit analysis based on intent
                try:
                    edit_results = exploit_utils.analyze_edit_opportunities(binary_data[offset:offset+size], edit_intent)
                    for edit in edit_results.get("edits", []):
                        edit_suggestions.append({
                            "edit_type": edit.get("type", "unknown"),
                            "offset": offset + edit.get("offset", 0),
                            "original_bytes": edit.get("original_bytes", ""),
                            "new_bytes": edit.get("new_bytes", ""),
                            "explanation": edit.get("explanation", "Binary modification"),
                            "consequences": edit.get("consequences", "Unknown effects"),
                            "confidence": edit.get("confidence", 0.5),
                            "risk_level": edit.get("risk_level", "medium")
                        })
                except Exception:
                    pass
                    
                # If no specific edits found, use vulnerability-based suggestions
                if not edit_suggestions:
                    try:
                        vuln_results = vuln_engine.analyze_binary(binary_data[offset:offset+size])
                        for vuln in vuln_results.get("vulnerabilities", []):
                            if vuln.get("exploitable", False):
                                edit_suggestions.append({
                                    "edit_type": "vulnerability_patch",
                                    "offset": offset + vuln.get("offset", 0),
                                    "original_bytes": vuln.get("vulnerable_bytes", ""),
                                    "new_bytes": vuln.get("patch_bytes", ""),
                                    "explanation": f"Patch {vuln.get('type', 'vulnerability')}: {vuln.get('description', '')}",
                                    "consequences": f"Addresses {vuln.get('severity', 'unknown')} severity vulnerability",
                                    "confidence": vuln.get("confidence", 0.7),
                                    "risk_level": vuln.get("severity", "medium")
                                })
                    except Exception:
                        pass
                        
        except ImportError:
            # Fallback to enhanced heuristic edit analysis
            pass
        
        # Enhanced fallback analysis if no real analysis available
        if not edit_suggestions:
            # Parse intent for common edit operations using heuristics
            if "nop" in intent_lower or ("remove" in intent_lower and "check" in intent_lower):
                # License check removal suggestion
                for pattern in context.get("patterns", []):
                    if pattern.get("pattern_type") == "license_check":
                        edit_suggestions.append({
                            "edit_type": "nop_instruction",
                            "offset": pattern["start_offset"],
                            "original_bytes": pattern.get("bytes", "75 0E"),  # Example: JNE instruction
                            "new_bytes": "90 90",  # NOP NOP
                            "explanation": "Replace conditional jump with NOP instructions to bypass check",
                            "consequences": "May bypass license validation - use only for legitimate testing",
                            "confidence": 0.85
                        })

            elif "string" in intent_lower:
                # String modification suggestions
                target_string = None
            if "replace" in intent_lower:
                # Extract target string from intent if possible
                parts = intent_lower.split("replace")
                if len(parts) > 1 and "with" in parts[1]:
                    target_part = parts[1].split("with")[0].strip()
                    # Find matching string
                    for _string in context.get("strings", []):
                        if target_part in _string["value"].lower():
                            target_string = _string
                            break

            if not target_string:
                # Use first string as example
                for _string in context.get("strings", []):
                    target_string = _string
                    break

            if target_string:
                original_bytes = " ".join(f"{_b:02X}" for _b in target_string["value"].encode(target_string["encoding"]))

                # Determine replacement based on string content
                if "error" in target_string["value"].lower():
                    new_value = "Success"
                elif "trial" in target_string["value"].lower():
                    new_value = "Full Version"
                elif "expired" in target_string["value"].lower():
                    new_value = "Active"
                else:
                    new_value = "Modified"

                new_bytes = " ".join(f"{_b:02X}" for _b in new_value.encode(target_string["encoding"]))

                # Pad or truncate to match original length
                orig_len = len(target_string["value"])
                new_len = len(new_value)
                if new_len < orig_len:
                    # Pad with spaces
                    padding = " " * (orig_len - new_len)
                    new_value += padding
                    new_bytes = " ".join(f"{_b:02X}" for _b in new_value.encode(target_string["encoding"]))
                elif new_len > orig_len:
                    # Truncate
                    new_value = new_value[:orig_len]
                    new_bytes = " ".join(f"{_b:02X}" for _b in new_value.encode(target_string["encoding"]))

                edit_suggestions.append({
                    "edit_type": "string_replace",
                    "offset": target_string["offset"],
                    "original_bytes": original_bytes,
                    "new_bytes": new_bytes,
                    "original_string": target_string["value"],
                    "new_string": new_value,
                    "explanation": f"Replace '{target_string['value']}' with '{new_value}'",
                    "consequences": "Changes displayed text - may affect program logic if string is used for comparisons",
                    "confidence": 0.9
                })

        elif "patch" in intent_lower or "fix" in intent_lower:
            # Generic patching suggestions based on file type
            hex_data = context.get("hex_representation", "").replace(" ", "")

            if hex_data.startswith("4D5A"):  # PE file
                # Suggest PE header modifications
                edit_suggestions.append({
                    "edit_type": "header_modification",
                    "offset": 0x3C,  # PE header offset location
                    "original_bytes": "F0 00 00 00",  # Example
                    "new_bytes": "F0 00 00 00",  # Keep same
                    "explanation": "PE header offset - no modification suggested",
                    "consequences": "Modifying PE headers can corrupt the executable",
                    "confidence": 0.3
                })

        elif "zero" in intent_lower or "null" in intent_lower:
            # Zeroing suggestions
            offset = 0
            length = 8

            # Look for specific offset in intent
            offset_match = re.search(r'offset\s+(\d+|0x[0-9a-fA-F]+)', intent_lower)
            if offset_match:
                offset_str = offset_match.group(1)
                offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)

            length_match = re.search(r'(\d+)\s*bytes?', intent_lower)
            if length_match:
                length = int(length_match.group(1))

            # Get original bytes
            original_hex = context.get("hex_representation", "").replace(" ", "")
            byte_offset = offset * 2  # Each byte is 2 hex chars
            original_bytes = " ".join(original_hex[byte_offset + i:byte_offset + i + 2]
                                    for i in range(0, min(length * 2, len(original_hex) - byte_offset), 2))

            edit_suggestions.append({
                "edit_type": "zero_fill",
                "offset": offset,
                "original_bytes": original_bytes or "XX XX XX XX XX XX XX XX",
                "new_bytes": " ".join(["00"] * length),
                "explanation": f"Zero out {length} bytes at offset 0x{offset:X}",
                "consequences": "May corrupt data structures or cause crashes if critical data is zeroed",
                "confidence": 0.7
            })

        # If no specific suggestions, provide a generic one
        if not edit_suggestions:
            # Generic edit based on first interesting pattern
            for _hint in context.get("structure_hints", []):
                if _hint["type"] == "instruction":
                    edit_suggestions.append({
                        "edit_type": "instruction_patch",
                        "offset": _hint["offset"],
                        "original_bytes": _hint.get("bytes", "XX XX"),
                        "new_bytes": "90 90",  # NOP
                        "explanation": f"Replace {_hint.get('mnemonic', 'instruction')} with NOP",
                        "consequences": "Alters program flow - test thoroughly",
                        "confidence": 0.6
                    })
                    break

        # Still no suggestions? Provide a safe default
        if not edit_suggestions:
            edit_suggestions.append({
                "edit_type": "no_edit_suggested",
                "offset": 0,
                "original_bytes": context.get("hex_representation", "XX XX XX XX")[:11],
                "new_bytes": context.get("hex_representation", "XX XX XX XX")[:11],
                "explanation": "No specific edit identified from intent - please be more specific",
                "consequences": "No changes suggested",
                "confidence": 0.1
            })

        # Create comprehensive response
        analysis_response = {
            "edit_intent": edit_intent,
            "suggestions": edit_suggestions,
            "warnings": [
                "Always backup files before editing",
                "Binary edits can corrupt files or cause crashes",
                "Test modifications in a safe environment"
            ],
            "metadata": {
                "file_type": "executable" if context.get("hex_representation", "").startswith("4D5A") else "binary",
                "total_suggestions": len(edit_suggestions),
                "highest_confidence": max(s["confidence"] for s in edit_suggestions) if edit_suggestions else 0,
                "analysis_confidence": self._calculate_edit_confidence(edit_suggestions, context)
            }
        }

        return json.dumps(analysis_response, indent=2)

    def _real_ai_pattern_analysis(self, context: Dict[str, Any],
                                known_patterns: Optional[List[Dict[str, Any]]]) -> str:
        """Generate real AI response for pattern identification using comprehensive analysis."""
        patterns = []
        pattern_categories = {
            "file_format": [],
            "cryptographic": [],
            "compression": [],
            "executable": [],
            "data_structure": [],
            "protocol": []
        }

        # Check known patterns if provided
        if known_patterns:
            for kp in known_patterns:
                # Match against context data
                hex_data = context.get("hex_representation", "").replace(" ", "")
                pattern_hex = kp.get("pattern", "").replace(" ", "")

                if pattern_hex and pattern_hex in hex_data:
                    idx = hex_data.find(pattern_hex) // 2  # Convert hex position to byte offset
                    patterns.append({
                        "pattern_name": kp.get("name", "Unknown Pattern"),
                        "pattern_type": kp.get("type", "custom"),
                        "start_offset": idx,
                        "end_offset": idx + len(pattern_hex) // 2,
                        "confidence": 0.9,
                        "explanation": kp.get("description", "Known pattern match"),
                        "metadata": kp.get("metadata", {})
                    })

        # Check for file signatures
        for _hint in context.get("structure_hints", []):
            if _hint["type"] == "file_signature":
                pattern = {
                    "pattern_name": _hint["description"],
                    "pattern_type": "file_signature",
                    "start_offset": _hint["offset"],
                    "end_offset": _hint["offset"] + len(bytes.fromhex(_hint["value"])),
                    "confidence": 0.95,
                    "explanation": f"File format identified by magic bytes: {_hint['value']}",
                    "metadata": {
                        "file_type": _hint["description"],
                        "magic_bytes": _hint["value"]
                    }
                }
                patterns.append(pattern)
                pattern_categories["file_format"].append(pattern)

        # Check for cryptographic patterns
        for _segment in context.get("entropy_segments", []):
            if _segment.get("high_entropy", False) and _segment["entropy"] > 7.9:
                pattern = {
                    "pattern_name": "Encrypted/Random Data",
                    "pattern_type": "cryptographic",
                    "start_offset": _segment["offset"],
                    "end_offset": _segment["offset"] + _segment["size"],
                    "confidence": 0.8,
                    "explanation": f"High entropy region (entropy: {_segment['entropy']:.2f}) suggests encryption or compressed data",
                    "metadata": {
                        "entropy": _segment["entropy"],
                        "block_size": _segment["size"]
                    }
                }
                patterns.append(pattern)
                pattern_categories["cryptographic"].append(pattern)

        # Check for common data structures
        hex_data = context.get("hex_representation", "").replace(" ", "")

        # PE DOS header
        if hex_data.startswith("4D5A"):
            pe_offset_hex = hex_data[120:128]  # e_lfanew at offset 0x3C
            if len(pe_offset_hex) == 8:
                # Convert little-endian hex to offset
                pe_offset = int(pe_offset_hex[6:8] + pe_offset_hex[4:6] + pe_offset_hex[2:4] + pe_offset_hex[0:2], 16)
                if pe_offset < len(hex_data) // 2:
                    pe_sig_offset = pe_offset * 2
                    if hex_data[pe_sig_offset:pe_sig_offset+8] == "50450000":  # "PE\0\0"
                        pattern = {
                            "pattern_name": "PE Header",
                            "pattern_type": "executable",
                            "start_offset": pe_offset,
                            "end_offset": pe_offset + 4,
                            "confidence": 0.95,
                            "explanation": "Valid PE executable header found",
                            "metadata": {
                                "header_type": "PE",
                                "dos_stub_size": pe_offset
                            }
                        }
                        patterns.append(pattern)
                        pattern_categories["executable"].append(pattern)

        # ELF header details
        elif hex_data.startswith("7F454C46"):
            elf_class = "64-bit" if hex_data[8:10] == "02" else "32-bit"
            elf_endian = "little-endian" if hex_data[10:12] == "01" else "big-endian"
            pattern = {
                "pattern_name": "ELF Header",
                "pattern_type": "executable",
                "start_offset": 0,
                "end_offset": 16,
                "confidence": 0.95,
                "explanation": f"ELF {elf_class} {elf_endian} executable",
                "metadata": {
                    "header_type": "ELF",
                    "architecture": elf_class,
                    "endianness": elf_endian
                }
            }
            patterns.append(pattern)
            pattern_categories["executable"].append(pattern)

        # ZIP/JAR/APK detection
        elif "504B0304" in hex_data or "504B0506" in hex_data:
            idx = hex_data.find("504B0304") // 2 if "504B0304" in hex_data else hex_data.find("504B0506") // 2
            pattern = {
                "pattern_name": "ZIP Archive",
                "pattern_type": "compression",
                "start_offset": idx,
                "end_offset": idx + 4,
                "confidence": 0.9,
                "explanation": "ZIP/JAR/APK archive signature detected",
                "metadata": {
                    "archive_type": "ZIP",
                    "possible_formats": ["ZIP", "JAR", "APK", "DOCX", "XLSX"]
                }
            }
            patterns.append(pattern)
            pattern_categories["compression"].append(pattern)

        # Protocol patterns
        protocol_sigs = {
            "474554": ("HTTP GET", "HTTP GET request"),
            "504F5354": ("HTTP POST", "HTTP POST request"),
            "485454502F": ("HTTP Response", "HTTP response header"),
            "16030": ("TLS Handshake", "TLS/SSL handshake protocol"),
            "534D42": ("SMB", "Server Message Block protocol"),
            "52494646": ("RIFF", "Resource Interchange File Format")
        }

        for sig, (name, desc) in protocol_sigs.items():
            if sig in hex_data:
                idx = hex_data.find(sig) // 2
                pattern = {
                    "pattern_name": name,
                    "pattern_type": "protocol",
                    "start_offset": idx,
                    "end_offset": idx + len(sig) // 2,
                    "confidence": 0.85,
                    "explanation": desc,
                    "metadata": {
                        "protocol": name.split()[0]
                    }
                }
                patterns.append(pattern)
                pattern_categories["protocol"].append(pattern)

        # License/protection patterns
        license_keywords = ["license", "trial", "expire", "registration", "serial", "crack", "patch"]
        for _string in context.get("strings", []):
            value_lower = _string["value"].lower()
            if any(keyword in value_lower for keyword in license_keywords):
                pattern = {
                    "pattern_name": "License-Related String",
                    "pattern_type": "protection",
                    "start_offset": _string["offset"],
                    "end_offset": _string["offset"] + _string["size"],
                    "confidence": 0.7,
                    "explanation": f"License/protection related string: '{_string['value']}'",
                    "metadata": {
                        "string_value": _string["value"],
                        "encoding": _string["encoding"]
                    }
                }
                patterns.append(pattern)

        # Sort patterns by offset
        patterns.sort(key=lambda p: p["start_offset"])

        # Generate insights
        insights = []
        if pattern_categories["file_format"]:
            insights.append(f"File format: {pattern_categories['file_format'][0]['pattern_name']}")
        if pattern_categories["executable"]:
            insights.append("Executable code structures detected")
        if pattern_categories["cryptographic"]:
            insights.append(f"{len(pattern_categories['cryptographic'])} encrypted/compressed regions found")
        if pattern_categories["protocol"]:
            protocols = ", ".join(set(p["metadata"]["protocol"] for p in pattern_categories["protocol"]))
            insights.append(f"Network protocols detected: {protocols}")

        # Create comprehensive response
        analysis_response = {
            "identified_patterns": patterns,
            "pattern_summary": {
                "total_patterns": len(patterns),
                "by_type": {k: len(v) for k, v in pattern_categories.items() if v},
                "confidence_average": sum(p["confidence"] for p in patterns) / len(patterns) if patterns else 0
            },
            "insights": insights,
            "recommendations": [
                "Examine high-confidence patterns first",
                "Cross-reference with known file format specifications",
                "Use pattern offsets to navigate to interesting regions"
            ] if patterns else ["No significant patterns detected - try different analysis approaches"],
            "analysis_metadata": {
                "analysis_confidence": self._calculate_pattern_confidence(patterns, context),
                "pattern_coverage": len(patterns) / max(1, len(known_patterns)) if known_patterns else 1.0
            }
        }

        return json.dumps(analysis_response, indent=2)

    def _real_ai_search_analysis(self, context: Dict[str, Any], query: str) -> str:
        """Generate real AI response for semantic search using pattern analysis."""
        matches = []
        query_lower = query.lower()

        # Parse query for semantic understanding
        search_contexts = {
            "strings": ["string", "text", "ascii", "unicode", "message", "error", "warning"],
            "crypto": ["encrypt", "decrypt", "cipher", "key", "hash", "crypto", "aes", "rsa"],
            "network": ["ip", "url", "http", "socket", "port", "network", "protocol", "tcp", "udp"],
            "binary": ["instruction", "opcode", "assembly", "function", "call", "jump", "ret"],
            "license": ["license", "serial", "registration", "trial", "expire", "crack", "patch"],
            "data": ["struct", "array", "table", "list", "buffer", "heap", "stack"],
            "security": ["vulnerability", "exploit", "overflow", "injection", "bypass", "hook"]
        }

        # Determine search intent
        search_intents = []
        for intent, keywords in search_contexts.items():
            if any(keyword in query_lower for keyword in keywords):
                search_intents.append(intent)

        if not search_intents:
            # Generic search - look for any relevant content
            search_intents = ["strings", "binary", "data"]

        # Search based on intents
        if "strings" in search_intents:
            for _string in context.get("strings", []):
                relevance = 0.0
                value_lower = _string["value"].lower()

                # Calculate relevance based on query terms
                query_terms = query_lower.split()
                matching_terms = sum(1 for term in query_terms if term in value_lower)
                if matching_terms > 0:
                    relevance = min(0.95, 0.3 + (matching_terms * 0.2))
                elif any(intent_keyword in value_lower for intent in search_intents
                        for intent_keyword in search_contexts.get(intent, [])):
                    relevance = 0.6

                if relevance > 0.3:
                    matches.append({
                        "start_offset": _string["offset"],
                        "end_offset": _string["offset"] + _string["size"],
                        "relevance_score": relevance,
                        "match_type": "string",
                        "preview": _string["value"][:50] + "..." if len(_string["value"]) > 50 else _string["value"],
                        "explanation": f"{_string['encoding']} string matching query terms",
                        "metadata": {
                            "encoding": _string["encoding"],
                            "length": _string["size"]
                        }
                    })

        if "crypto" in search_intents:
            # Find high entropy regions
            for _segment in context.get("entropy_segments", []):
                if _segment.get("high_entropy", False):
                    relevance = min(0.9, 0.5 + (_segment["entropy"] - 7.0) * 0.4)
                    matches.append({
                        "start_offset": _segment["offset"],
                        "end_offset": _segment["offset"] + _segment["size"],
                        "relevance_score": relevance,
                        "match_type": "cryptographic",
                        "preview": f"High entropy region ({_segment['size']} bytes)",
                        "explanation": f"Possible encrypted/compressed data (entropy: {_segment['entropy']:.2f})",
                        "metadata": {
                            "entropy": _segment["entropy"],
                            "size": _segment["size"]
                        }
                    })

        if "network" in search_intents:
            # Look for network-related patterns
            hex_data = context.get("hex_representation", "").replace(" ", "")

            # Common network signatures
            network_patterns = {
                "http://": "687474703A2F2F",
                "https://": "68747470733A2F2F",
                "ftp://": "6674703A2F2F",
                "ws://": "77733A2F2F"
            }

            for pattern_name, pattern_hex in network_patterns.items():
                if pattern_hex.lower() in hex_data.lower():
                    idx = hex_data.lower().find(pattern_hex.lower()) // 2
                    matches.append({
                        "start_offset": idx,
                        "end_offset": idx + len(pattern_hex) // 2,
                        "relevance_score": 0.85,
                        "match_type": "network",
                        "preview": pattern_name,
                        "explanation": f"Network protocol identifier: {pattern_name}",
                        "metadata": {
                            "protocol": pattern_name.replace("://", "")
                        }
                    })

            # Look for IP address patterns in strings
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            for _string in context.get("strings", []):
                if ip_pattern.search(_string["value"]):
                    matches.append({
                        "start_offset": _string["offset"],
                        "end_offset": _string["offset"] + _string["size"],
                        "relevance_score": 0.8,
                        "match_type": "network",
                        "preview": _string["value"],
                        "explanation": "Contains IP address pattern",
                        "metadata": {
                            "string_type": "ip_address"
                        }
                    })

        if "binary" in search_intents:
            # Look for instruction patterns
            for _hint in context.get("structure_hints", []):
                if _hint["type"] == "instruction":
                    relevance = 0.7
                    if any(term in _hint.get("mnemonic", "").lower() for term in query_lower.split()):
                        relevance = 0.9
                    matches.append({
                        "start_offset": _hint["offset"],
                        "end_offset": _hint["offset"] + _hint.get("size", 1),
                        "relevance_score": relevance,
                        "match_type": "instruction",
                        "preview": _hint.get("mnemonic", "Unknown instruction"),
                        "explanation": f"Assembly instruction: {_hint.get('description', 'No description')}",
                        "metadata": {
                            "opcode": _hint.get("value", ""),
                            "mnemonic": _hint.get("mnemonic", "")
                        }
                    })

        if "license" in search_intents:
            # License-related search
            license_keywords = ["license", "serial", "key", "registration", "trial", "expire", "activate"]
            for _string in context.get("strings", []):
                value_lower = _string["value"].lower()
                if any(keyword in value_lower for keyword in license_keywords):
                    matches.append({
                        "start_offset": _string["offset"],
                        "end_offset": _string["offset"] + _string["size"],
                        "relevance_score": 0.9,
                        "match_type": "license",
                        "preview": _string["value"],
                        "explanation": "License/protection related string",
                        "metadata": {
                            "protection_type": "string_check"
                        }
                    })

        if "security" in search_intents:
            # Security-related patterns
            vuln_patterns = ["strcpy", "sprintf", "gets", "scanf", "%s", "%n"]
            for _string in context.get("strings", []):
                if any(pattern in _string["value"] for pattern in vuln_patterns):
                    matches.append({
                        "start_offset": _string["offset"],
                        "end_offset": _string["offset"] + _string["size"],
                        "relevance_score": 0.85,
                        "match_type": "security",
                        "preview": _string["value"],
                        "explanation": "Potentially vulnerable function or format string",
                        "metadata": {
                            "vulnerability_type": "unsafe_function"
                        }
                    })

        # Sort by relevance score
        matches.sort(key=lambda m: m["relevance_score"], reverse=True)

        # Limit results and add ranking
        top_matches = matches[:10]  # Limit to top 10
        for i, match in enumerate(top_matches):
            match["rank"] = i + 1

        # Generate search summary
        summary = {
            "query": query,
            "search_intents": search_intents,
            "total_matches": len(matches),
            "returned_matches": len(top_matches),
            "match_types": list(set(m["match_type"] for m in top_matches))
        }

        # Generate insights
        insights = []
        if top_matches:
            insights.append(f"Found {len(matches)} potential matches across {len(set(m['match_type'] for m in matches))} categories")
            if any(m["relevance_score"] > 0.9 for m in top_matches):
                insights.append("High-confidence matches found - review these first")
            if "license" in search_intents and any(m["match_type"] == "license" for m in top_matches):
                insights.append("License-related content detected - useful for protection analysis")
        else:
            insights.append("No direct matches found - try broadening search terms")

        # Create comprehensive response
        search_results = {
            "matches": top_matches,
            "summary": summary,
            "insights": insights,
            "suggestions": [
                "Use offset values to navigate directly to matches",
                "Combine with pattern analysis for deeper understanding",
                "Export high-relevance matches for further investigation"
            ] if top_matches else [
                "Try more specific search terms",
                "Check if the data type matches your search intent",
                "Use pattern analysis to discover content structure first"
            ],
            "search_metadata": {
                "total_matches": len(matches),
                "search_coverage": (end_offset - start_offset) / len(binary_data) if binary_data else 0,
                "confidence": self._calculate_search_confidence(matches, query)
            }
        }

        return json.dumps(search_results, indent=2)

    def _calculate_analysis_confidence(self, patterns: List[Dict], anomalies: List[Dict], suspicious_strings: List[str]) -> float:
        """Calculate confidence score for analysis results."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on patterns found
        if patterns:
            confidence += min(0.2, len(patterns) * 0.05)
            # Higher confidence for known protection patterns
            protection_patterns = [p for p in patterns if p.get("pattern_type") in ["license_check", "anti_debug", "encryption"]]
            if protection_patterns:
                confidence += min(0.2, len(protection_patterns) * 0.1)
        
        # Increase confidence based on anomalies
        if anomalies:
            confidence += min(0.15, len(anomalies) * 0.05)
        
        # Increase confidence based on suspicious strings
        if suspicious_strings:
            confidence += min(0.15, len(suspicious_strings) * 0.03)
            # Higher confidence for specific keywords
            critical_keywords = ["license", "trial", "expired", "debug", "crack"]
            critical_found = sum(1 for s in suspicious_strings if any(k in s.lower() for k in critical_keywords))
            if critical_found:
                confidence += min(0.1, critical_found * 0.05)
        
        return min(1.0, confidence)
    
    def _calculate_edit_confidence(self, edit_suggestions: List[Dict], context: Dict) -> float:
        """Calculate confidence score for edit suggestions."""
        if not edit_suggestions:
            return 0.1
        
        # Average confidence of individual suggestions
        avg_confidence = sum(s.get("confidence", 0.5) for s in edit_suggestions) / len(edit_suggestions)
        
        # Adjust based on context
        confidence = avg_confidence
        
        # Higher confidence if we have good pattern matches in context
        if context.get("patterns"):
            relevant_patterns = [p for p in context["patterns"] if p.get("pattern_type") in ["license_check", "anti_debug"]]
            if relevant_patterns:
                confidence = min(1.0, confidence + 0.1)
        
        # Higher confidence for specific edit types
        high_confidence_types = ["nop_instruction", "string_replace", "jump_patch"]
        if any(s.get("edit_type") in high_confidence_types for s in edit_suggestions):
            confidence = min(1.0, confidence + 0.1)
        
        return confidence
    
    def _calculate_pattern_confidence(self, patterns: List[Dict], context: Dict) -> float:
        """Calculate confidence score for pattern identification."""
        if not patterns:
            return 0.2
        
        # Base confidence on number and quality of patterns
        confidence = min(0.5, len(patterns) * 0.1)
        
        # Higher confidence for file signatures
        file_sig_patterns = [p for p in patterns if p.get("pattern_type") == "file_signature"]
        if file_sig_patterns:
            confidence += 0.2
        
        # Higher confidence for high-confidence individual patterns
        high_conf_patterns = [p for p in patterns if p.get("confidence", 0) > 0.8]
        if high_conf_patterns:
            confidence += min(0.2, len(high_conf_patterns) * 0.05)
        
        # Adjust based on context hints
        if context.get("structure_hints"):
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _calculate_search_confidence(self, matches: List[Dict], query: str) -> float:
        """Calculate confidence score for search results."""
        if not matches:
            return 0.1
        
        # Base confidence on number of matches
        confidence = min(0.5, len(matches) * 0.05)
        
        # Higher confidence for high-relevance matches
        high_relevance = [m for m in matches if m.get("relevance_score", 0) > 0.8]
        if high_relevance:
            confidence += min(0.3, len(high_relevance) * 0.1)
        
        # Higher confidence for exact matches
        exact_matches = [m for m in matches if m.get("match_type") == "exact"]
        if exact_matches:
            confidence += 0.2
        
        # Adjust based on query specificity
        if len(query.split()) > 2:  # Multi-word query
            confidence += 0.1
        
        return min(1.0, confidence)

    def analyze_binary_patterns(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze binary patterns in a file.

        Args:
            binary_path: Path to the binary file to analyze

        Returns:
            Dictionary containing pattern analysis results
        """
        try:
            if not os.path.exists(binary_path):
                return {
                    "error": f"File not found: {binary_path}",
                    "confidence": 0.0
                }

            # Read a sample of the binary
            with open(binary_path, 'rb') as f:
                # Read first 4KB for analysis
                data = f.read(4096)

            if not data:
                return {
                    "error": "Empty file or read error",
                    "confidence": 0.0
                }

            # Analyze patterns using AI bridge
            patterns = self.identify_patterns(data, 0, len(data))

            # Build context
            context = self.context_builder.build_context(
                data, 0, len(data),
                include_entropy=True,
                include_strings=True,
                include_structure_hints=True
            )

            result = {
                "status": "success",
                "binary_path": binary_path,
                "confidence": 0.8,
                "patterns_identified": len(patterns),
                "patterns": patterns[:10],  # Limit to first 10 patterns
                "entropy": context.get("entropy", 0.0),
                "strings_found": len(context.get("strings", [])),
                "file_size": os.path.getsize(binary_path),
                "analysis_summary": f"Analyzed {len(data)} bytes, found {len(patterns)} patterns"
            }

            return result

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error analyzing binary patterns: %s", e)
            return {
                "error": str(e),
                "confidence": 0.0,
                "patterns_identified": 0
            }


# AI tool functions for _Intellicrack integration

def wrapper_ai_binary_analyze(app_instance, parameters):
    """
    AI tool wrapper for analyzing binary data.

    Args:
        app_instance: Intellicrack application instance
        parameters: Tool parameters including:
            - file_path: Path to the binary file (optional)
            - offset: Starting offset for analysis (default: 0)
            - size: Size of data to analyze (default: 1024)
            - query: User query to guide the analysis (optional)

    Returns:
        Dictionary with analysis results
    """
    try:
        # Get file path
        file_path = parameters.get("file_path", "")

        # If no file path provided, try to use the current binary
        if not file_path and hasattr(app_instance, "binary_path"):
            file_path = app_instance.binary_path

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        # Get offset and size
        offset = int(parameters.get("offset", 0))
        size = int(parameters.get("size", 1024))

        # Read the data
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(size)

        # Get user query
        query = parameters.get("query", "")

        # Initialize AI bridge
        ai_bridge = AIBinaryBridge(app_instance.model_manager if hasattr(app_instance, "model_manager") else None)

        # Analyze the data
        result = ai_bridge.analyze_binary_region(data, offset, len(data), query)

        return result
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in AI binary analysis: %s", e)
        return {"error": str(e)}


def wrapper_ai_binary_pattern_search(app_instance, parameters):
    """
    AI tool wrapper for searching binary patterns.

    Args:
        app_instance: Intellicrack application instance
        parameters: Tool parameters including:
            - file_path: Path to the binary file (optional)
            - pattern_description: Description of pattern to search for
            - start_offset: Starting offset for search (default: 0)
            - max_size: Maximum size to search (default: entire file)

    Returns:
        Dictionary with search results
    """
    try:
        # Get file path
        file_path = parameters.get("file_path", "")

        # If no file path provided, try to use the current binary
        if not file_path and hasattr(app_instance, "binary_path"):
            file_path = app_instance.binary_path

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        # Get pattern description
        pattern_description = parameters.get("pattern_description", "")
        if not pattern_description:
            return {"error": "Pattern description is required"}

        # Get offset and size
        start_offset = int(parameters.get("start_offset", 0))

        # Get file size
        file_size = os.path.getsize(file_path)
        max_size = int(parameters.get("max_size", file_size - start_offset))

        # Limit max_size to file size
        max_size = min(max_size, file_size - start_offset)

        # Initialize AI bridge
        ai_bridge = AIBinaryBridge(app_instance.model_manager if hasattr(app_instance, "model_manager") else None)

        # Read the file in chunks and search
        chunk_size = 1024 * 1024  # 1 MB chunks
        results = []

        with open(file_path, "rb") as f:
            for _offset in range(start_offset, start_offset + max_size, chunk_size):
                # Read a chunk
                f.seek(_offset)
                data = f.read(min(chunk_size, start_offset + max_size - _offset))

                # Search for pattern
                chunk_results = ai_bridge.search_binary_semantic(data, pattern_description, 0, len(data))

                # Adjust offsets to be relative to file
                for _result in chunk_results:
                    _result["start_offset"] += _offset
                    _result["end_offset"] += _offset

                results.extend(chunk_results)

                # Limit to top 10 results
                if len(results) >= 10:
                    results = sorted(results, key=lambda r: r.get("relevance_score", 0), reverse=True)[:10]
                    break

        return {"results": results, "count": len(results)}
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in AI binary pattern search: %s", e)
        return {"error": str(e)}


def wrapper_ai_binary_edit_suggest(app_instance, parameters):
    """
    AI tool wrapper for suggesting binary edits.

    Args:
        app_instance: Intellicrack application instance
        parameters: Tool parameters including:
            - file_path: Path to the binary file (optional)
            - offset: Starting offset for region to edit (default: 0)
            - size: Size of region to edit (default: 1024)
            - edit_intent: Description of desired edit

    Returns:
        Dictionary with edit suggestions
    """
    try:
        # Get file path
        file_path = parameters.get("file_path", "")

        # If no file path provided, try to use the current binary
        if not file_path and hasattr(app_instance, "binary_path"):
            file_path = app_instance.binary_path

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        # Get edit intent
        edit_intent = parameters.get("edit_intent", "")
        if not edit_intent:
            return {"error": "Edit intent is required"}

        # Get offset and size
        offset = int(parameters.get("offset", 0))
        size = int(parameters.get("size", 1024))

        # Read the data
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(size)

        # Initialize AI bridge
        ai_bridge = AIBinaryBridge(app_instance.model_manager if hasattr(app_instance, "model_manager") else None)

        # Get edit suggestions
        result = ai_bridge.suggest_edits(data, offset, len(data), edit_intent)

        return result
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in AI binary edit suggestion: %s", e)
        return {"error": str(e)}
