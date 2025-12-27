"""Pydantic models for binary analysis results.

This module defines structured data types for all binary analysis results,
replacing the previous dict[str, Any] return types with proper Pydantic models
that provide runtime validation and static type checking.

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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BasicFileInfo(BaseModel):
    """Basic file information extracted from any binary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(description="Path to the binary file")
    size: int = Field(ge=0, description="File size in bytes")
    md5: str = Field(default="", description="MD5 hash of the file")
    sha256: str = Field(default="", description="SHA256 hash of the file")
    created: str = Field(default="", description="File creation timestamp")
    modified: str = Field(default="", description="File modification timestamp")


class SectionInfo(BaseModel):
    """Information about a binary section."""

    model_config = ConfigDict(frozen=True, extra="allow")

    name: str = Field(description="Section name")
    virtual_address: str = Field(default="0x0", description="Virtual address as hex string")
    virtual_size: int = Field(default=0, ge=0, description="Virtual size in bytes")
    raw_size: int = Field(default=0, ge=0, description="Raw size in bytes")
    characteristics: int = Field(default=0, description="Section characteristics flags")
    entropy: float = Field(default=0.0, ge=0.0, le=8.0, description="Section entropy (0-8)")
    type: str = Field(default="unknown", description="Section type")
    address: str = Field(default="0x0", description="Section address as hex string")
    size: int = Field(default=0, ge=0, description="Section size")
    flags: int = Field(default=0, description="Section flags")


class ImportInfo(BaseModel):
    """Information about imported DLLs and functions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dll: str = Field(description="DLL name")
    functions: list[str] = Field(default_factory=list, description="List of imported function names")


class ExportInfo(BaseModel):
    """Information about exported functions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(description="Export name")
    address: str = Field(default="0x0", description="Export address as hex string")
    ordinal: int = Field(default=0, ge=0, description="Export ordinal")


class SymbolInfo(BaseModel):
    """Information about a symbol in the binary."""

    model_config = ConfigDict(frozen=True, extra="allow")

    name: str = Field(description="Symbol name")
    value: str = Field(default="0x0", description="Symbol value as hex string")
    type: str = Field(default="unknown", description="Symbol type")
    binding: str = Field(default="", description="Symbol binding")
    visibility: str = Field(default="", description="Symbol visibility")


class ResourceInfo(BaseModel):
    """Information about PE resources."""

    model_config = ConfigDict(frozen=True, extra="allow")

    type: str = Field(description="Resource type")
    name: str = Field(default="", description="Resource name")
    language: str = Field(default="", description="Resource language")
    size: int = Field(default=0, ge=0, description="Resource size in bytes")
    offset: int = Field(default=0, ge=0, description="Resource offset")


class PEAnalysisResult(BaseModel):
    """Result of PE (Windows) binary analysis."""

    model_config = ConfigDict(frozen=False, extra="allow")

    format: Literal["PE"] = Field(default="PE", description="Binary format identifier")
    machine: str = Field(default="unknown", description="Machine type")
    timestamp: str = Field(default="", description="Compilation timestamp")
    subsystem: int = Field(default=0, description="PE subsystem")
    characteristics: int = Field(default=0, description="PE characteristics")
    dll: bool = Field(default=False, description="Whether the binary is a DLL")
    sections: list[SectionInfo] = Field(default_factory=list, description="List of sections")
    imports: list[ImportInfo] = Field(default_factory=list, description="List of imports")
    exports: list[ExportInfo] = Field(default_factory=list, description="List of exports")
    resources: list[ResourceInfo] = Field(default_factory=list, description="List of resources")
    suspicious_indicators: list[str] = Field(default_factory=list, description="List of suspicious indicators found")
    error: str | None = Field(default=None, description="Error message if analysis failed")
    basic_info: BasicFileInfo | None = Field(default=None, description="Basic file information")


class ELFAnalysisResult(BaseModel):
    """Result of ELF (Linux) binary analysis."""

    model_config = ConfigDict(frozen=False, extra="allow")

    format: Literal["ELF"] = Field(default="ELF", description="Binary format identifier")
    machine: str = Field(default="unknown", description="Machine architecture")
    class_: int | str = Field(default=0, alias="class", description="ELF class (32/64-bit)")
    type: str = Field(default="unknown", description="ELF type")
    entry_point: str = Field(default="0x0", description="Entry point address as hex string")
    sections: list[SectionInfo] = Field(default_factory=list, description="List of sections")
    symbols: list[SymbolInfo] = Field(default_factory=list, description="List of symbols")
    libraries: list[str] = Field(default_factory=list, description="List of linked libraries")
    suspicious_indicators: list[str] = Field(default_factory=list, description="List of suspicious indicators")
    error: str | None = Field(default=None, description="Error message if analysis failed")
    basic_info: BasicFileInfo | None = Field(default=None, description="Basic file information")


class MachOHeaderInfo(BaseModel):
    """Information about a Mach-O header."""

    model_config = ConfigDict(frozen=True, extra="allow")

    magic: str = Field(default="0x0", description="Mach-O magic number as hex string")
    cpu_type: str = Field(default="unknown", description="CPU type")
    file_type: str = Field(default="unknown", description="File type")


class MachOSectionInfo(BaseModel):
    """Information about a Mach-O section within a segment."""

    model_config = ConfigDict(frozen=True, extra="allow")

    name: str = Field(description="Section name")
    size: int = Field(default=0, ge=0, description="Section size")
    offset: int = Field(default=0, ge=0, description="Section offset")


class MachOSegmentInfo(BaseModel):
    """Information about a Mach-O segment."""

    model_config = ConfigDict(frozen=True, extra="allow")

    name: str = Field(description="Segment name")
    address: str = Field(default="0x0", description="Virtual address as hex string")
    size: int = Field(default=0, ge=0, description="Virtual size")
    sections: list[MachOSectionInfo] = Field(default_factory=list, description="Sections in this segment")


class MachOAnalysisResult(BaseModel):
    """Result of Mach-O (macOS) binary analysis."""

    model_config = ConfigDict(frozen=False, extra="allow")

    format: Literal["MACHO"] = Field(default="MACHO", description="Binary format identifier")
    headers: list[MachOHeaderInfo] = Field(default_factory=list, description="List of headers")
    segments: list[MachOSegmentInfo] = Field(default_factory=list, description="List of segments")
    symbols: list[SymbolInfo] = Field(default_factory=list, description="List of symbols")
    libraries: list[str] = Field(default_factory=list, description="List of linked libraries")
    error: str | None = Field(default=None, description="Error message if analysis failed")
    basic_info: BasicFileInfo | None = Field(default=None, description="Basic file information")


class FridaScriptSuggestion(BaseModel):
    """Suggestion for a Frida bypass script."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: str = Field(description="Script type (e.g., 'license_bypass', 'anti_debug_bypass')")
    description: str = Field(description="Description of the script's purpose")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score (0-1)")
    complexity: Literal["simple", "moderate", "advanced"] = Field(default="moderate", description="Script complexity level")


class GhidraScriptSuggestion(BaseModel):
    """Suggestion for a Ghidra analysis script."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: str = Field(description="Script type (e.g., 'crypto_analysis')")
    description: str = Field(description="Description of the script's purpose")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score (0-1)")
    complexity: Literal["simple", "moderate", "advanced"] = Field(default="moderate", description="Script complexity level")


class AIScriptSuggestion(BaseModel):
    """AI-generated script suggestions based on analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    frida_scripts: list[FridaScriptSuggestion] = Field(default_factory=list, description="Suggested Frida scripts")
    ghidra_scripts: list[GhidraScriptSuggestion] = Field(default_factory=list, description="Suggested Ghidra scripts")
    auto_generate_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence for auto-generation")
    priority_targets: list[str] = Field(default_factory=list, description="Priority targets for analysis")


class AIAutoGenerationCandidate(BaseModel):
    """Candidate for automatic script generation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: str = Field(description="Target for generation (API name, etc.)")
    type: str = Field(description="Type of generation (api_hook, dynamic_unpacker, etc.)")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    script_type: Literal["frida", "ghidra", "radare2"] = Field(description="Script type to generate")
    description: str = Field(description="Description of what will be generated")


class AutonomousGenerationInfo(BaseModel):
    """Information about autonomous script generation status."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    started: bool = Field(default=False, description="Whether generation has started")
    request: str = Field(default="", description="The generation request")
    targets: list[str] = Field(default_factory=list, description="Target priorities")


class AIIntegrationResult(BaseModel):
    """Result of AI integration with binary analysis."""

    model_config = ConfigDict(frozen=False, extra="allow")

    enabled: bool = Field(description="Whether AI integration is enabled")
    script_suggestions: AIScriptSuggestion | None = Field(default=None, description="Script suggestions from AI")
    recommended_actions: list[str] = Field(default_factory=list, description="Recommended AI actions")
    auto_generation_candidates: list[AIAutoGenerationCandidate] = Field(default_factory=list, description="Candidates for auto-generation")
    autonomous_generation: AutonomousGenerationInfo | None = Field(default=None, description="Autonomous generation status")
    error: str | None = Field(default=None, description="Error message if integration failed")


class PerformanceMetrics(BaseModel):
    """Performance metrics from optimized analysis."""

    model_config = ConfigDict(frozen=True, extra="allow")

    cache_efficiency: float = Field(default=0.0, ge=0.0, le=1.0, description="Cache efficiency ratio")
    analysis_time_ms: float = Field(default=0.0, ge=0.0, description="Analysis time in milliseconds")
    memory_peak_mb: float = Field(default=0.0, ge=0.0, description="Peak memory usage in MB")
    chunks_processed: int = Field(default=0, ge=0, description="Number of chunks processed")


class OptimizedAnalysisResult(BaseModel):
    """Result from performance-optimized binary analysis."""

    model_config = ConfigDict(frozen=False, extra="allow")

    file_path: str = Field(description="Path to the analyzed file")
    file_size: int = Field(ge=0, description="File size in bytes")
    analysis_type: Literal["optimized", "standard"] = Field(default="optimized", description="Type of analysis performed")
    performance_metrics: PerformanceMetrics = Field(default_factory=PerformanceMetrics, description="Performance metrics")
    cache_efficiency: float = Field(default=0.0, ge=0.0, le=1.0, description="Cache efficiency")
    strategy_used: str = Field(default="unknown", description="Analysis strategy used")


class ExploitPayloadResult(BaseModel):
    """Result of exploit payload generation."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    method: str = Field(default="", description="Payload method (patch, function_hijacking, etc.)")
    payload_bytes: str = Field(default="", description="Hex-encoded payload bytes")
    description: str = Field(default="", description="Description of the payload")
    patch_type: str = Field(default="", description="Type of patch")
    instructions: list[str] = Field(default_factory=list, description="Instructions for applying")
    target: str = Field(default="", description="Target path")
    target_exists: bool = Field(default=False, description="Whether target exists")
    error: str | None = Field(default=None, description="Error message if generation failed")


class ExploitStrategyResult(BaseModel):
    """Result of exploit strategy generation."""

    model_config = ConfigDict(frozen=False, extra="allow")

    strategy: str = Field(default="", description="Generated strategy")
    automation_script: str = Field(default="", description="Automation script content")
    error: str | None = Field(default=None, description="Error message if generation failed")


class GenericAnalysisResult(BaseModel):
    """Result for unsupported or unknown binary formats."""

    model_config = ConfigDict(frozen=False, extra="allow")

    format: str = Field(default="unknown", description="Binary format identifier")
    error: str | None = Field(default=None, description="Error message if analysis failed")
    basic_info: BasicFileInfo | None = Field(default=None, description="Basic file information")


BinaryAnalysisResult = PEAnalysisResult | ELFAnalysisResult | MachOAnalysisResult | GenericAnalysisResult
