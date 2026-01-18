"""Script infrastructure for Intellicrack.

This module provides data structures and utilities for AI-generated scripts.
The actual script content is written dynamically by the AI based on analysis
results - there are NO pre-built templates or generated scripts here.

The AI creates scripts from scratch using:
- Analysis results from license_analyzer
- Binary metadata from the disassembly tools
- Runtime information from Frida/debugger sessions

This module only provides:
- Data classes for script metadata and storage
- Validation utilities for script syntax
- Execution context information
- Script management (save, load, execute)
"""

from __future__ import annotations

import ast
import subprocess  # noqa: S404
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from .logging import get_logger
from .process_manager import ProcessManager


_logger = get_logger("core.script_gen")

ScriptType = Literal["frida", "ghidra", "radare2", "python", "x64dbg"]


class ScriptLanguage(Enum):
    """Script language enumeration."""

    JAVASCRIPT = "javascript"
    JAVA = "java"
    PYTHON = "python"
    R2_COMMANDS = "r2_commands"
    X64DBG_SCRIPT = "x64dbg_script"


class BypassStrategy(Enum):
    """Bypass strategy types for license protections.

    These are hints for the AI when writing scripts, not template selectors.
    """

    RETURN_TRUE = "return_true"
    RETURN_FALSE = "return_false"
    RETURN_ZERO = "return_zero"
    RETURN_ONE = "return_one"
    NOP_FUNCTION = "nop_function"
    SKIP_CHECK = "skip_check"
    PATCH_JUMP = "patch_jump"
    HOOK_REPLACE = "hook_replace"
    MEMORY_PATCH = "memory_patch"
    INLINE_PATCH = "inline_patch"
    VIRTUALIZATION_DEFEAT = "virtualization_defeat"


@dataclass
class ScriptContext:
    """Context information for AI script generation.

    Provides the AI with all necessary information to write an effective script.

    Attributes:
        binary_name: Name of the target binary.
        binary_path: Full path to the binary.
        architecture: Target architecture (x86, x64, arm, arm64).
        platform: Target platform (windows, linux, macos).
        module_base: Base address of the main module (if known).
        target_functions: Functions identified for bypass/hooking.
        identified_protections: Protection mechanisms detected.
        crypto_apis: Crypto API calls found in the binary.
        string_references: Relevant string references found.
        magic_constants: Magic constants used in validation.
        additional_context: Any additional context from analysis.
    """

    binary_name: str
    binary_path: Path | None = None
    architecture: str = "x64"
    platform: str = "windows"
    module_base: int | None = None
    target_functions: list[dict[str, Any]] = field(default_factory=list)
    identified_protections: list[str] = field(default_factory=list)
    crypto_apis: list[str] = field(default_factory=list)
    string_references: list[str] = field(default_factory=list)
    magic_constants: list[int] = field(default_factory=list)
    additional_context: dict[str, Any] = field(default_factory=dict)

    def to_prompt_context(self) -> str:
        """Convert context to a string suitable for AI prompts.

        Returns:
            Formatted context string.
        """
        lines = [
            f"Binary: {self.binary_name}",
            f"Architecture: {self.architecture}",
            f"Platform: {self.platform}",
        ]

        if self.binary_path:
            lines.append(f"Path: {self.binary_path}")

        if self.module_base is not None:
            lines.append(f"Module Base: 0x{self.module_base:X}")

        if self.target_functions:
            lines.append("\nTarget Functions:")
            for func in self.target_functions:
                name = func.get("name", "unknown")
                addr = func.get("address", 0)
                strategy = func.get("strategy", "unknown")
                lines.append(f"  - {name} @ 0x{addr:X} (strategy: {strategy})")

        if self.identified_protections:
            lines.append(f"\nProtections: {', '.join(self.identified_protections)}")

        if self.crypto_apis:
            lines.append(f"\nCrypto APIs: {', '.join(self.crypto_apis)}")

        if self.string_references:
            lines.append("\nRelevant Strings:")
            lines.extend(f"  - {s!r}" for s in self.string_references[:20])

        if self.magic_constants:
            lines.append("\nMagic Constants:")
            lines.extend(f"  - 0x{c:X} ({c})" for c in self.magic_constants)

        return "\n".join(lines)


@dataclass
class Script:
    """A script ready for execution.

    Attributes:
        name: Script name.
        script_type: Type of script (frida, ghidra, radare2, python, x64dbg).
        language: Script language.
        content: Script content (written by AI).
        description: Description of what the script does.
        created_at: Generation timestamp.
        context: Context used to generate the script.
        target_functions: Target functions the script operates on.
        verified: Whether the script has been syntax-verified.
        execution_results: Results from script execution (if run).
    """

    name: str
    script_type: ScriptType
    language: ScriptLanguage
    content: str
    description: str
    created_at: datetime = field(default_factory=datetime.now)
    context: ScriptContext | None = None
    target_functions: list[str] = field(default_factory=list)
    verified: bool = False
    execution_results: dict[str, Any] = field(default_factory=dict)

    def save(self, path: Path) -> None:
        """Save script to file.

        Args:
            path: File path to save to.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.content, encoding="utf-8")
        _logger.info("Saved script to %s", path)

    def get_extension(self) -> str:
        """Get the appropriate file extension for this script type.

        Returns:
            File extension including the dot.
        """
        extensions = {
            ScriptLanguage.JAVASCRIPT: ".js",
            ScriptLanguage.JAVA: ".java",
            ScriptLanguage.PYTHON: ".py",
            ScriptLanguage.R2_COMMANDS: ".r2",
            ScriptLanguage.X64DBG_SCRIPT: ".txt",
        }
        return extensions.get(self.language, ".txt")


class ScriptValidator:
    """Validates script syntax before execution."""

    @staticmethod
    def validate_python(content: str) -> tuple[bool, str | None]:
        """Validate Python script syntax.

        Args:
            content: Python script content.

        Returns:
            Tuple of (is_valid, error_message).
        """
        try:
            ast.parse(content)
        except SyntaxError as e:
            return False, f"Syntax error at line {e.lineno}: {e.msg}"
        else:
            return True, None

    @staticmethod
    def validate_javascript(content: str) -> tuple[bool, str | None]:
        """Validate JavaScript syntax using node if available.

        Args:
            content: JavaScript script content.

        Returns:
            Tuple of (is_valid, error_message).
        """
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".js",
                delete=False,
                encoding="utf-8",
            ) as f:
                f.write(content)
                temp_path = f.name

            process_manager = ProcessManager.get_instance()
            result = process_manager.run_tracked(
                ["node", "--check", temp_path],
                name="node-syntax-check",
                timeout=10,
            )

            Path(temp_path).unlink(missing_ok=True)

            if result.returncode == 0:
                return True, None
            return False, result.stderr.strip()

        except FileNotFoundError:
            return True, None
        except subprocess.TimeoutExpired:
            return False, "Validation timed out"
        except Exception:
            return True, None

    @staticmethod
    def validate_java(content: str) -> tuple[bool, str | None]:
        """Basic validation for Java/Ghidra scripts.

        Args:
            content: Java script content.

        Returns:
            Tuple of (is_valid, error_message).
        """
        required_elements = ["import", "public", "void run("]
        for element in required_elements:
            if element not in content:
                return False, f"Missing required element: {element}"

        brace_count = content.count("{") - content.count("}")
        if brace_count != 0:
            return False, f"Unbalanced braces: {brace_count:+d}"

        return True, None

    def validate(self, script: Script) -> tuple[bool, str | None]:
        """Validate a script based on its language.

        Args:
            script: Script to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        validators = {
            ScriptLanguage.PYTHON: self.validate_python,
            ScriptLanguage.JAVASCRIPT: self.validate_javascript,
            ScriptLanguage.JAVA: self.validate_java,
        }

        validator = validators.get(script.language)
        if validator:
            is_valid, error = validator(script.content)
            script.verified = is_valid
            return is_valid, error

        script.verified = True
        return True, None


class ScriptManager:
    """Manages script storage and retrieval.

    Attributes:
        scripts_dir: Directory for storing scripts.
        scripts: In-memory script cache.
    """

    def __init__(self, scripts_dir: Path) -> None:
        """Initialize the script manager.

        Args:
            scripts_dir: Directory for storing scripts.
        """
        self.scripts_dir = scripts_dir
        self.scripts: dict[str, Script] = {}
        self._validator = ScriptValidator()

    def add_script(self, script: Script, validate: bool = True) -> bool:
        """Add a script to the manager.

        Args:
            script: Script to add.
            validate: Whether to validate syntax before adding.

        Returns:
            True if script was added successfully.
        """
        if validate:
            is_valid, error = self._validator.validate(script)
            if not is_valid:
                _logger.error("Script validation failed: %s", error)
                return False

        self.scripts[script.name] = script
        _logger.info("Added script: %s", script.name)
        return True

    def get_script(self, name: str) -> Script | None:
        """Get a script by name.

        Args:
            name: Script name.

        Returns:
            Script or None if not found.
        """
        return self.scripts.get(name)

    def list_scripts(self, script_type: ScriptType | None = None) -> list[str]:
        """List available scripts.

        Args:
            script_type: Optional filter by script type.

        Returns:
            List of script names.
        """
        if script_type is None:
            return list(self.scripts.keys())
        return [
            name
            for name, script in self.scripts.items()
            if script.script_type == script_type
        ]

    def save_script(self, name: str, subdir: str | None = None) -> Path | None:
        """Save a script to disk.

        Args:
            name: Script name.
            subdir: Optional subdirectory within scripts_dir.

        Returns:
            Path where script was saved, or None if not found.
        """
        script = self.scripts.get(name)
        if script is None:
            return None

        target_dir = self.scripts_dir
        if subdir:
            target_dir /= subdir
        target_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{name}{script.get_extension()}"
        path = target_dir / filename
        script.save(path)
        return path

    def load_script(self, path: Path) -> Script | None:
        """Load a script from disk.

        Args:
            path: Path to script file.

        Returns:
            Loaded script or None if failed.
        """
        if not path.exists():
            return None

        content = path.read_text(encoding="utf-8")

        ext = path.suffix.lower()
        language_map = {
            ".js": ScriptLanguage.JAVASCRIPT,
            ".py": ScriptLanguage.PYTHON,
            ".java": ScriptLanguage.JAVA,
            ".r2": ScriptLanguage.R2_COMMANDS,
            ".txt": ScriptLanguage.X64DBG_SCRIPT,
        }
        language = language_map.get(ext, ScriptLanguage.PYTHON)

        script_type: ScriptType
        if language == ScriptLanguage.JAVASCRIPT:
            script_type = "frida"
        elif language == ScriptLanguage.JAVA:
            script_type = "ghidra"
        elif language == ScriptLanguage.R2_COMMANDS:
            script_type = "radare2"
        elif language == ScriptLanguage.X64DBG_SCRIPT:
            script_type = "x64dbg"
        else:
            script_type = "python"

        script = Script(
            name=path.stem,
            script_type=script_type,
            language=language,
            content=content,
            description=f"Loaded from {path}",
        )

        self.scripts[script.name] = script
        return script


def get_frida_api_reference() -> dict[str, str]:
    """Get Frida API reference for AI context.

    Returns:
        Dictionary mapping API categories to usage examples.
    """
    return {
        "process": (
            "Process.findModuleByName(name), Process.enumerateModules(), "
            "Process.enumerateRanges(protection)"
        ),
        "module": (
            "Module.findExportByName(module, name), module.base, module.size, "
            "module.enumerateExports(), module.enumerateImports()"
        ),
        "memory": (
            "Memory.readByteArray(addr, length), Memory.writeByteArray(addr, bytes), "
            "Memory.protect(addr, size, protection), Memory.scanSync(addr, size, pattern)"
        ),
        "interceptor": (
            "Interceptor.attach(target, {onEnter, onLeave}), "
            "Interceptor.replace(target, replacement), "
            "Interceptor.revert(target)"
        ),
        "native_function": (
            "new NativeFunction(addr, retType, argTypes), "
            "new NativeCallback(func, retType, argTypes)"
        ),
        "stalker": (
            "Stalker.follow(threadId, {events, onReceive, transform}), "
            "Stalker.unfollow(threadId)"
        ),
    }


def get_ghidra_api_reference() -> dict[str, str]:
    """Get Ghidra API reference for AI context.

    Returns:
        Dictionary mapping API categories to usage examples.
    """
    return {
        "program": (
            "currentProgram.getListing(), currentProgram.getSymbolTable(), "
            "currentProgram.getMemory()"
        ),
        "functions": (
            "getFunctionAt(addr), getFunctionContaining(addr), "
            "currentProgram.getListing().getFunctions(true)"
        ),
        "symbols": (
            "symbolTable.getSymbols(name), symbol.getReferences(null), "
            "symbol.getAddress()"
        ),
        "decompiler": (
            "DecompInterface(), decompInterface.decompileFunction(func, timeout, monitor)"
        ),
        "patching": (
            "currentProgram.getMemory().setBytes(addr, bytes), "
            "clearListing(addr), createInstruction(addr)"
        ),
    }


def get_radare2_reference() -> dict[str, str]:
    """Get radare2 command reference for AI context.

    Returns:
        Dictionary mapping command categories to examples.
    """
    return {
        "analysis": "aaa (analyze all), af (analyze function), afl (list functions)",
        "seeking": "s addr (seek), s main (seek to main)",
        "printing": "pd N (disassemble N), px N (hexdump N), ps (print string)",
        "writing": "wx bytes (write hex), wa asm (write assembly), wao nop (nop instruction)",
        "flags": "f name @ addr (set flag), f- name (remove flag)",
        "visual": "V (visual mode), VV (visual graph)",
    }


def get_x64dbg_reference() -> dict[str, str]:
    """Get x64dbg command reference for AI context.

    Returns:
        Dictionary mapping command categories to examples.
    """
    return {
        "breakpoints": (
            "bp addr (set bp), bc addr (clear bp), bph addr (hardware bp)"
        ),
        "stepping": "sti (step into), sto (step over), run (continue)",
        "memory": (
            "dump addr (view memory), fill addr,size,byte (fill memory)"
        ),
        "patching": "assemble addr, \"instruction\" (assemble), patch addr, bytes (patch)",
        "scripting": "scriptload path, scriptcmd \"command\"",
    }
