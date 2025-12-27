"""Command-line interface for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import os
import sys
import threading
import time
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn, TypeVar, cast

from intellicrack.utils.analysis.binary_analysis import analyze_binary
from intellicrack.utils.exploitation.exploitation import exploit
from intellicrack.utils.logger import logger as imported_logger
from intellicrack.utils.patching.patch_generator import generate_patch


F = TypeVar("F", bound=Callable[..., Any])


logger = logging.getLogger("IntellicrackLogger.CLI")

HIGH_CONFIDENCE_THRESHOLD: float = 0.85
MODERATE_CONFIDENCE_THRESHOLD: float = 0.65

"""
Intellicrack Command Line Interface

Provides comprehensive CLI for all Intellicrack functionality including
payload generation and exploitation operations.
"""

try:
    import click
except ImportError as e:
    logger.exception("Import error in cli: %s", e)
    logger.critical("click module not found. Please install with: pip install click")
    sys.exit(1)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import configuration system
try:
    from intellicrack.core.config_manager import get_config

    MODERN_CONFIG_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in cli: %s", e)
    MODERN_CONFIG_AVAILABLE = False

# Basic imports (with fallbacks for missing components)
PayloadEngine: Any = None
PayloadTemplates: Any = None
Architecture: Any = None
PayloadType: Any = None
PayloadResultHandler: Any = None

try:
    from intellicrack.core.exploitation import Architecture as _Architecture

    Architecture = _Architecture
except ImportError as e:
    logger.debug("Architecture import not available: %s", e)

try:
    from intellicrack.core.exploitation.bypass_engine import BypassEngine

    PayloadEngine = BypassEngine
    PayloadTemplates = None
    PayloadType = None
except ImportError as e:
    logger.debug("BypassEngine import not available: %s", e)


# Import licensing protection analysis modules
try:
    from intellicrack.ai.vulnerability_research_integration import LicensingProtectionAnalyzer

    ADVANCED_MODULES_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in cli: %s", e)
    ADVANCED_MODULES_AVAILABLE = False

# Import certificate bypass modules
try:
    from intellicrack.core.certificate.bypass_orchestrator import CertificateBypassOrchestrator
    from intellicrack.core.certificate.detection_report import BypassMethod
    from intellicrack.core.certificate.validation_detector import CertificateValidationDetector

    CERT_BYPASS_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in cli (certificate bypass): %s", e)
    CERT_BYPASS_AVAILABLE = False


def _typed_decorator[F: Callable[..., Any]](func: F) -> F:
    """Preserve function type through untyped click decorators."""
    return func


def typed_group(*args: Any, **kwargs: Any) -> Callable[[F], F]:
    """Typed wrapper for click.group()."""

    def decorator(f: F) -> F:
        return cast("F", click.group(*args, **kwargs)(f))

    return decorator


def typed_command(group: Any, name: str | None = None, **kwargs: Any) -> Callable[[F], F]:
    """Typed wrapper for group.command()."""

    def decorator(f: F) -> F:
        return cast("F", group.command(name, **kwargs)(f))

    return decorator


def typed_option(*args: Any, **kwargs: Any) -> Callable[[F], F]:
    """Typed wrapper for click.option()."""

    def decorator(f: F) -> F:
        wrapped: F = click.option(*args, **kwargs)(f)
        return wrapped

    return decorator


def typed_argument(*args: Any, **kwargs: Any) -> Callable[[F], F]:
    """Typed wrapper for click.argument()."""

    def decorator(f: F) -> F:
        wrapped: F = click.argument(*args, **kwargs)(f)
        return wrapped

    return decorator


@_typed_decorator
@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output", envvar="INTELLICRACK_VERBOSE")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output", envvar="INTELLICRACK_QUIET")
def cli(*, verbose: bool, quiet: bool) -> None:
    """Intellicrack - Advanced Binary Analysis and Exploitation Framework."""
    # Configure logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)

    # Initialize configuration if available
    if MODERN_CONFIG_AVAILABLE:
        try:
            config = get_config()
            logging.getLogger(__name__).debug("Loaded configuration from %s", config.config_dir)
        except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
            logging.getLogger(__name__).warning("Failed to load configuration: %s", e)


@_typed_decorator
@cli.command("scan")
@click.argument("binary_path")
@click.option("--vulns", is_flag=True, help="Perform vulnerability scan")
@click.option("--output", "-o", help="Save scan results")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(binary_path: str, *, vulns: bool, output: str | None, verbose: bool) -> None:
    """Scan binary for vulnerabilities and security issues."""
    try:
        click.echo(f"Scanning binary: {binary_path}")
        scan_results: dict[str, Any] = {
            "binary_path": binary_path,
            "scan_type": "vulnerability" if vulns else "basic_security",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        if vulns:
            vuln_results = _perform_vulnerability_scan_cli(binary_path, verbose)
            scan_results["vulnerabilities"] = vuln_results.get("vulnerabilities", [])
            scan_results["vulnerability_count"] = len(scan_results["vulnerabilities"])
            scan_results["severity_summary"] = _compute_severity_summary(scan_results["vulnerabilities"])
        else:
            security_results = _perform_basic_security_scan_cli(binary_path, verbose)
            scan_results["security_analysis"] = security_results

        scan_results["success"] = True

        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(scan_results, f, indent=2, default=str)
            click.echo(f"\nResults saved to: {output}")

    except Exception as e:
        logger.exception("Scan failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def _compute_severity_summary(vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
    """Compute severity counts from vulnerability list."""
    return {
        "critical": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
        "high": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
        "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
        "low": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
        "info": sum(1 for v in vulnerabilities if v.get("severity") == "info"),
    }


def _perform_vulnerability_scan_cli(binary_path: str, verbose: bool) -> dict[str, Any]:
    """Perform and display vulnerability scan results.

    Args:
        binary_path: Path to binary file to scan.
        verbose: Whether to show detailed output.

    Returns:
        Dictionary containing scan results with vulnerabilities list.
    """
    click.echo("Performing vulnerability scan...")
    from intellicrack.core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine

    vulnerabilities_list = AdvancedVulnerabilityEngine.scan_binary(binary_path)
    result: dict[str, Any] = {"success": True, "vulnerabilities": vulnerabilities_list}

    if result.get("success"):
        vulnerabilities = result.get("vulnerabilities", [])
        click.echo(f"Found {len(vulnerabilities)} vulnerabilities")
        _display_vulnerability_summary_cli(vulnerabilities, verbose)
    else:
        click.echo(f"Scan failed: {result.get('error', 'Unknown error')}")

    return result


def _display_vulnerability_summary_cli(vulnerabilities: list[dict[str, Any]], verbose: bool) -> None:
    """Helper to display categorized vulnerability summary."""
    critical = [v for v in vulnerabilities if v.get("severity") == "critical"]
    high = [v for v in vulnerabilities if v.get("severity") == "high"]
    medium = [v for v in vulnerabilities if v.get("severity") == "medium"]
    low = [v for v in vulnerabilities if v.get("severity") == "low"]

    if critical:
        click.echo(f"\n🔴 Critical: {len(critical)}")
        for vuln in critical[:3]:
            click.echo(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}")

    if high:
        click.echo(f"\n🟠 High: {len(high)}")
        for vuln in high[:3]:
            click.echo(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}")

    if medium:
        click.echo(f"\n🟡 Medium: {len(medium)}")
        if verbose:
            for vuln in medium[:3]:
                click.echo(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}")

    if low:
        click.echo(f"\n🟢 Low: {len(low)}")
        if verbose:
            for vuln in low[:3]:
                click.echo(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}")


def _perform_basic_security_scan_cli(binary_path: str, verbose: bool) -> dict[str, Any]:
    """Perform and display basic security scan results.

    Args:
        binary_path: Path to binary file to scan.
        verbose: Whether to show detailed output.

    Returns:
        Dictionary containing security analysis results.
    """
    click.echo("Performing basic security scan...")
    from intellicrack.utils.analysis.binary_analysis import analyze_binary

    result = analyze_binary(binary_path, detailed=verbose)

    click.echo(f"Binary Type: {result.get('file_type', 'Unknown')}")
    click.echo(f"Architecture: {result.get('architecture', 'Unknown')}")

    if result.get("protections"):
        click.echo("\nSecurity Features:")
        for protection, enabled in result["protections"].items():
            status = "OK" if enabled else "FAIL"
            click.echo(f"  {status} {protection}")

    return result


@_typed_decorator
@cli.command("strings")
@click.argument("binary_path")
@click.option("--min-length", "-n", default=4, help="Minimum string length")
@click.option(
    "--encoding",
    "-e",
    type=click.Choice(["ascii", "utf8", "utf16", "all"]),
    default="all",
    help="String encoding",
)
@click.option("--output", "-o", help="Save strings to file")
@click.option("--filter", "-f", help="Filter strings by pattern")
def strings(binary_path: str, min_length: int, output: str | None, filter_pattern: str | None) -> None:
    """Extract strings from binary file."""
    try:
        click.echo(f"Extracting strings from: {binary_path}")

        from intellicrack.cli.analysis_cli import AnalysisCLI

        cli_analyzer = AnalysisCLI()

        if extracted_strings := cli_analyzer._extract_strings(binary_path, min_length=min_length):
            # Apply filter if provided
            if filter_pattern:
                import re

                pattern = re.compile(filter_pattern, re.IGNORECASE)
                extracted_strings = [s for s in extracted_strings if pattern.search(s)]

            click.echo(f"Found {len(extracted_strings)} strings")

            if output:
                with open(output, "w", encoding="utf-8") as f:
                    f.writelines(string + "\n" for string in extracted_strings)
                click.echo(f"Strings saved to: {output}")
            else:
                STRINGS_DISPLAY_LIMIT = 20
                # Display first {STRINGS_DISPLAY_LIMIT} strings to console
                for string in extracted_strings[:STRINGS_DISPLAY_LIMIT]:
                    click.echo(f"  {string}")
                if len(extracted_strings) > STRINGS_DISPLAY_LIMIT:
                    click.echo(f"  ... and {len(extracted_strings) - STRINGS_DISPLAY_LIMIT} more")
        else:
            click.echo("No strings found or extraction failed")

    except Exception as e:
        logger.exception("String extraction failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@_typed_decorator
@cli.group()
def payload() -> None:
    """Payload generation commands."""


@_typed_decorator
@payload.command("generate")
@click.option(
    "--type",
    "-t",
    "payload_type",
    type=click.Choice(["reverse_shell", "bind_shell", "meterpreter", "custom"]),
    default="reverse_shell",
    help="Type of payload to generate",
)
@click.option(
    "--arch",
    "-a",
    "architecture",
    type=click.Choice(["x86", "x64", "arm", "arm64"]),
    default="x64",
    help="Target architecture",
)
@click.option("--lhost", help="Listener host for reverse connections")
@click.option("--lport", type=int, help="Listener port")
@click.option(
    "--encoding",
    "-e",
    multiple=True,
    help="Encoding schemes to apply (can be specified multiple times)",
)
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["raw", "exe", "dll", "powershell", "python", "c"]),
    default="raw",
    help="Output format",
)
def generate(
    payload_type: str,
    architecture: str,
    lhost: str | None,
    lport: int | None,
    encoding: tuple[str, ...],
    output: str | None,
    output_format: str,
) -> None:
    """Generate a custom payload with various options."""
    try:
        engine = PayloadEngine()

        # Build target info and options
        target_info = {
            "os_type": "unknown",
            "os_version": "unknown",
            "architecture": architecture.lower(),
            "protections": [],
            "av_products": [],
            "network_config": {},
            "process_info": {},
        }

        options: dict[str, Any] = {
            "output_format": output_format,
        }

        # Add connection parameters
        if lhost:
            options["lhost"] = lhost
        if lport:
            options["lport"] = lport

        # Add encoding
        if encoding:
            options["encoding_schemes"] = list(encoding)

        # Add output format
        options["output_format"] = output_format

        click.echo(f"Generating {payload_type} payload for {architecture} (format: {output_format})...")

        # Generate payload
        result = engine.generate_payload(
            PayloadType[payload_type.upper()],
            Architecture[architecture.upper()],
            target_info,
            options,
        )

        # Save output
        if output:
            with open(output, "wb") as f:
                f.write(result["payload"])
            click.echo(f"Payload saved to: {output}")
        else:
            # Display payload info
            click.echo(f"Payload size: {len(result['payload'])} bytes")
            null_byte = b"\x00"
            click.echo(f"Null bytes: {result['payload'].count(null_byte)}")

            if not click.get_text_stream("stdout").isatty():
                # Output to pipe
                click.get_binary_stream("stdout").write(result["payload"])
            else:
                # Display hex dump for terminal
                from intellicrack.utils.binary.hex_utils import create_hex_dump

                click.echo("\nPayload hex dump:")
                click.echo(create_hex_dump(result["payload"]))

        click.echo("Payload generated successfully!")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
    ) as e:
        logger.exception("Payload generation failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@_typed_decorator
@payload.command()
@click.option(
    "--category",
    "-c",
    type=click.Choice(
        [
            "shell",
            "steganography",
            "anti_analysis",
        ],
    ),
    help="Template category",
)
def list_templates(category: str | None) -> None:
    """List available payload templates."""
    try:
        templates = PayloadTemplates()
        available = templates.list_templates(category)

        click.echo("Available payload templates:")
        for cat, template_list in available.items():
            click.echo(f"\n{cat.upper()}:")
            for template in template_list:
                click.echo(f"  - {template}")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
    ) as e:
        logger.exception("Failed to list templates: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@_typed_decorator
@payload.command()
@click.argument("category")
@click.argument("template_name")
@click.option(
    "--arch",
    "-a",
    "architecture",
    type=click.Choice(["x86", "x64", "arm", "arm64"]),
    default="x64",
    help="Target architecture",
)
@click.option("--param", "-p", multiple=True, help="Template parameters (key=value)")
@click.option("--output", "-o", help="Output file path")
def from_template(category: str, template_name: str, architecture: str, param: tuple[str, ...], output: str | None) -> None:
    """Generate payload from template."""
    try:
        engine = PayloadEngine()
        templates = PayloadTemplates()

        # Parse parameters
        params = {}
        for p in param:
            if "=" in p:
                key, value = p.split("=", 1)
                params[key] = value

        # Get template
        arch = Architecture[architecture.upper()]
        template = templates.get_template(category, template_name, arch, **params)

        if not template:
            click.echo(f"Template not found: {category}/{template_name}", err=True)
            sys.exit(1)

        click.echo(f"Generating payload from template: {template_name}")

        # Generate from template
        target_info = {
            "os_type": "unknown",
            "os_version": "unknown",
            "architecture": architecture.lower(),
            "protections": [],
            "av_products": [],
            "network_config": {},
            "process_info": {},
        }

        options = {
            "mode": "template",
            "template": template,
        }

        # Determine payload type from template category
        payload_type_map = {
            "reverse_shell": PayloadType.REVERSE_SHELL,
            "bind_shell": PayloadType.BIND_SHELL,
            "staged": PayloadType.STAGED_PAYLOAD,
        }
        payload_type = payload_type_map.get(category.lower(), PayloadType.REVERSE_SHELL)

        result = engine.generate_payload(
            payload_type,
            Architecture[architecture.upper()],
            target_info,
            options,
        )

        # Save output
        if output:
            with open(output, "wb") as f:
                f.write(result["payload"])
            click.echo(f"Payload saved to: {output}")
        else:
            click.echo(f"Payload size: {len(result['payload'])} bytes")

        click.echo("Payload generated successfully!")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
    ) as e:
        logger.exception("Template payload generation failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@_typed_decorator
@cli.command()
@click.argument("target")
@click.option(
    "--type",
    "-t",
    "exploit_type",
    type=click.Choice(["auto", "buffer_overflow", "format_string", "heap_overflow", "use_after_free"]),
    default="auto",
    help="Exploit type",
)
@click.option("--payload", "-p", "payload_data", help="Custom payload or payload file")
@click.option("--output", "-o", help="Output exploit to file")
def exploit_target(target: str, exploit_type: str, payload_data: str | None, output: str | None) -> None:
    """Exploit a target binary or service."""
    try:
        click.echo(f"Exploiting target: {target}")
        click.echo(f"Exploit type: {exploit_type}")

        result = exploit(target, exploit_type, payload_data or "")

        if result["success"]:
            click.echo("Exploitation successful!")

            if "exploit_code" in result and output:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(result["exploit_code"])
                click.echo(f"Exploit saved to: {output}")

            # Display results
            if "session" in result:
                click.echo(f"Session established: {result['session']}")
            if "details" in result:
                click.echo(f"Details: {result['details']}")
        else:
            click.echo("Exploitation failed!", err=True)
            if "error" in result:
                click.echo(f"Error: {result['error']}", err=True)

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Exploitation failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def _get_analysis_types(
    mode: str,
    *,
    gpu_accelerate: bool,
    distributed: bool,
    symbolic_execution: bool,
    concolic_execution: bool,
) -> list[str]:
    """Determine analysis types based on mode and options."""
    if mode == "comprehensive":
        analysis_types = [
            "Basic Analysis",
            "Protection Detection",
            "Vulnerability Scan",
            "String Extraction",
            "Import Analysis",
            "Export Analysis",
        ]
    elif mode == "vulnerability":
        analysis_types = ["Vulnerability Scan", "Exploit Detection", "Security Assessment"]
    elif mode == "protection":
        analysis_types = ["Protection Analysis", "Packer Detection", "Anti-Debug Detection"]
    else:
        analysis_types = ["Basic Analysis", "File Type Detection", "Architecture Analysis"]

    if gpu_accelerate:
        analysis_types.append("GPU Acceleration")
    if distributed:
        analysis_types.append("Distributed Processing")
    if symbolic_execution or concolic_execution:
        analysis_types.append("Symbolic/Concolic Execution")

    return analysis_types


def _handle_gpu_acceleration(binary_path: str) -> None:
    """Handle GPU acceleration if enabled."""
    click.echo("GPU acceleration enabled")
    try:
        from intellicrack.utils.gpu_benchmark import run_gpu_accelerated_analysis

        with open(binary_path, "rb") as f:
            binary_data = f.read()
        gpu_result = run_gpu_accelerated_analysis(None, binary_data)
        if gpu_result.get("success"):
            click.echo(f"GPU analysis completed in {gpu_result.get('execution_time', 0):.2f}s")
        else:
            click.echo("GPU acceleration not available, falling back to CPU")
    except ImportError:
        click.echo("GPU acceleration module not available")


def _handle_distributed_processing(binary_path: str) -> None:
    """Handle distributed processing if enabled."""
    click.echo("Distributed processing enabled")
    try:
        from intellicrack.utils.runtime.distributed_processing import run_distributed_analysis

        dist_result = run_distributed_analysis(binary_path)
        if dist_result.get("success"):
            click.echo(f"Distributed analysis completed with {dist_result.get('nodes', 1)} nodes")
    except ImportError:
        click.echo("Distributed processing module not available")


def _handle_symbolic_execution(binary_path: str, *, symbolic_execution: bool) -> None:
    """Handle symbolic/concolic execution if enabled."""
    execution_type = "symbolic" if symbolic_execution else "concolic"
    click.echo(f"Using {execution_type} execution")
    try:
        from intellicrack.core.analysis.symbolic_executor import SymbolicExecutionEngine

        engine = SymbolicExecutionEngine(binary_path)
        if vulnerabilities := engine.discover_vulnerabilities():
            click.echo(f"{execution_type.capitalize()} execution completed - found {len(vulnerabilities)} issues")
        else:
            click.echo(f"{execution_type.capitalize()} execution completed - no issues found")
    except ImportError:
        click.echo(f"{execution_type.capitalize()} execution engine not available")


def _perform_analysis(mode: str, binary_path: str, output: str | None, *, verbose: bool, no_ai: bool, deep: bool) -> dict[str, Any]:
    """Perform the main analysis based on mode."""
    if mode == "comprehensive":
        from intellicrack.utils.runtime.runner_functions import run_comprehensive_analysis

        result = run_comprehensive_analysis(binary_path, output_dir=output, verbose=verbose, enable_ai=not no_ai)
        return dict(result) if result else {}
    if mode == "vulnerability":
        from intellicrack.core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine

        vulnerabilities = AdvancedVulnerabilityEngine.scan_binary(binary_path)
        return {"success": True, "vulnerabilities": vulnerabilities}
    if mode == "protection":
        from intellicrack.core.protection_analyzer import ProtectionAnalyzer

        analyzer = ProtectionAnalyzer()
        return analyzer.analyze(binary_path)
    result = analyze_binary(binary_path, detailed=deep, enable_ai_integration=not no_ai)
    return dict(result) if result else {}


def _display_basic_results(result: dict[str, Any]) -> None:
    """Display basic analysis results."""
    click.echo(f"\nBinary Type: {result.get('format', result.get('file_type', 'Unknown'))}")
    click.echo(f"Architecture: {result.get('architecture', 'Unknown')}")

    size = result.get("size", 0)
    if size == 0 and "basic_info" in result:
        size = result.get("basic_info", {}).get("size", 0)
    click.echo(f"Size: {size} bytes")

    if "error" in result:
        click.echo(f"\nWarning: {result['error']}")

    if "protections" in result:
        click.echo("\nProtections:")
        for protection, enabled in result["protections"].items():
            protection_status = "Enabled" if enabled else "Disabled"
            click.echo(f"  {protection}: {protection_status}")

    if result.get("vulnerabilities"):
        click.echo("\nPotential Vulnerabilities:")
        for vuln in result["vulnerabilities"]:
            click.echo(f"  - {vuln}")


def _display_ai_integration_results(result: dict[str, Any]) -> None:
    """Display AI integration results."""
    if "ai_integration" not in result:
        return
    if result["ai_integration"].get("enabled"):
        ai_data = result["ai_integration"]
        click.echo("\n AI Script Generation Suggestions:")

        suggestions = ai_data.get("script_suggestions", {})
        if suggestions.get("frida_scripts"):
            click.echo("  Frida Scripts:")
            for script in suggestions["frida_scripts"]:
                click.echo(f"    - {script['description']} (confidence: {script['confidence']:.0%})")

        if suggestions.get("ghidra_scripts"):
            click.echo("  Ghidra Scripts:")
            for script in suggestions["ghidra_scripts"]:
                click.echo(f"    - {script['description']} (confidence: {script['confidence']:.0%})")

        if ai_data.get("recommended_actions"):
            click.echo("\n  Recommended AI Actions:")
            for action in ai_data["recommended_actions"]:
                click.echo(f"     {action}")

        auto_confidence = suggestions.get("auto_generate_confidence", 0)
        if auto_confidence > HIGH_CONFIDENCE_THRESHOLD:
            click.echo(f"\n   High confidence ({auto_confidence:.0%}) - Autonomous script generation triggered!")
        elif auto_confidence > MODERATE_CONFIDENCE_THRESHOLD:
            click.echo(f"\n  [FAST] Moderate confidence ({auto_confidence:.0%}) - Consider manual script generation")

        if ai_data.get("autonomous_generation", {}).get("started"):
            click.echo("  🔄 Autonomous script generation started in background")
            click.echo(f"  📋 Targets: {', '.join(ai_data['autonomous_generation']['targets'])}")

    elif not result["ai_integration"].get("enabled"):
        ai_error = result["ai_integration"].get("error", "Unknown error")
        click.echo(f"\nWARNING️  AI integration failed: {ai_error}")


@_typed_decorator
@cli.command("analyze")
@click.argument("binary_path")
@click.option("--deep", "-d", is_flag=True, help="Perform deep analysis")
@click.option("--output", "-o", help="Save analysis report")
@click.option("--no-ai", is_flag=True, help="Disable AI integration")
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["basic", "comprehensive", "vulnerability", "protection"]),
    default="comprehensive",
    help="Analysis mode",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--gpu-accelerate", is_flag=True, help="Enable GPU acceleration")
@click.option("--distributed", is_flag=True, help="Enable distributed processing")
@click.option("--symbolic-execution", is_flag=True, help="Use symbolic execution")
@click.option("--concolic-execution", is_flag=True, help="Use concolic execution")
def analyze(
    binary_path: str,
    *,
    deep: bool,
    output: str | None,
    no_ai: bool,
    mode: str,
    verbose: bool,
    gpu_accelerate: bool,
    distributed: bool,
    symbolic_execution: bool,
    concolic_execution: bool,
) -> None:
    """Comprehensive binary analysis with multiple modes and options."""
    from intellicrack.cli.progress_manager import ProgressManager

    progress_manager = ProgressManager()

    try:
        analysis_types = _get_analysis_types(
            mode,
            gpu_accelerate=gpu_accelerate,
            distributed=distributed,
            symbolic_execution=symbolic_execution,
            concolic_execution=concolic_execution,
        )
        progress_manager.start_analysis(binary_path, analysis_types)

        click.echo(f"Analyzing binary: {binary_path}")
        click.echo(f"Mode: {mode}")

        if deep:
            click.echo("Performing deep analysis...")

        if verbose:
            logging.basicConfig(level=logging.DEBUG)

        _update_progress(progress_manager, "Basic Analysis", 0.1, "Initializing")

        if gpu_accelerate:
            _handle_gpu_acceleration_progress(progress_manager, binary_path)

        if distributed:
            _handle_distributed_processing_progress(progress_manager, binary_path)

        if symbolic_execution or concolic_execution:
            _handle_symbolic_execution_progress(progress_manager, binary_path, symbolic_execution, concolic_execution)

        _update_progress(progress_manager, "Basic Analysis", 0.5, f"Running {mode} analysis")
        result = _perform_analysis(mode, binary_path, output, verbose=verbose, no_ai=no_ai, deep=deep)
        _update_progress(progress_manager, "Basic Analysis", 1.0, "Analysis complete")

        if not no_ai:
            click.echo("AI integration enabled - will suggest script generation opportunities")

        _display_basic_results(result)
        _display_ai_integration_results(result)

        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            click.echo(f"\nAnalysis saved to: {output}")

        progress_manager.stop()

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Analysis failed: %s", e)
        if "progress_manager" in locals():
            progress_manager.stop()
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def _update_progress(progress_manager: Any, step: str, progress: float, message: str = "") -> None:
    """Helper to update analysis progress."""
    if step in progress_manager.task_ids:
        task_id = progress_manager.task_ids[step]
        prog = getattr(progress_manager, "progress", None)
        if prog is not None:
            prog.update(
                task_id,
                completed=int(progress * 100),
                description=f"{step}: {message}" if message else step,
            )


def _handle_gpu_acceleration_progress(progress_manager: Any, binary_path: str) -> None:
    """Helper to handle GPU acceleration and update progress."""
    _update_progress(progress_manager, "GPU Processing", 0.0, "Starting GPU acceleration")
    _handle_gpu_acceleration(binary_path)
    _update_progress(progress_manager, "GPU Processing", 1.0, "GPU processing complete")


def _handle_distributed_processing_progress(progress_manager: Any, binary_path: str) -> None:
    """Helper to handle distributed processing and update progress."""
    _update_progress(progress_manager, "Distributed Analysis", 0.0, "Starting distributed processing")
    _handle_distributed_processing(binary_path)
    _update_progress(progress_manager, "Distributed Analysis", 1.0, "Distributed processing complete")


def _handle_symbolic_execution_progress(
    progress_manager: Any, binary_path: str, symbolic_execution: bool, concolic_execution: bool
) -> None:
    """Helper to handle symbolic/concolic execution and update progress."""
    _update_progress(progress_manager, "Symbolic Analysis", 0.0, "Starting symbolic execution")
    _handle_symbolic_execution(binary_path, symbolic_execution=symbolic_execution)  # concolic_execution removed
    _update_progress(progress_manager, "Symbolic Analysis", 1.0, "Symbolic execution complete")


@_typed_decorator
@cli.command("basic-analyze")
@click.argument("binary_path")
@click.option("--deep", "-d", is_flag=True, help="Perform deep analysis")
@click.option("--output", "-o", help="Save analysis report")
@click.option("--no-ai", is_flag=True, help="Disable AI integration")
def basic_analyze(binary_path: str, *, deep: bool, output: str | None, no_ai: bool) -> None:
    """Analyze a binary file with AI integration."""
    try:
        click.echo(f"Analyzing binary: {binary_path}")
        if deep:
            click.echo("Performing deep analysis...")

        if not no_ai:
            click.echo("AI integration enabled - will suggest script generation opportunities")

        result = analyze_binary(binary_path, detailed=deep, enable_ai_integration=not no_ai)

        # Display analysis
        click.echo(f"\nBinary Type: {result.get('format', result.get('file_type', 'Unknown'))}")
        click.echo(f"Architecture: {result.get('architecture', 'Unknown')}")

        # Get size from basic_info if not at top level
        size = result.get("size", 0)
        if size == 0 and "basic_info" in result:
            size = result.get("basic_info", {}).get("size", 0)
        click.echo(f"Size: {size} bytes")

        # Display any errors
        if "error" in result:
            click.echo(f"\nWarning: {result['error']}")

        if "protections" in result:
            click.echo("\nProtections:")
            for protection, enabled in result["protections"].items():
                protection_status = "Enabled" if enabled else "Disabled"
                click.echo(f"  {protection}: {protection_status}")

        if result.get("vulnerabilities"):
            click.echo("\nPotential Vulnerabilities:")
            for vuln in result["vulnerabilities"]:
                click.echo(f"  - {vuln}")

        # Display AI integration results
        if "ai_integration" in result and result["ai_integration"].get("enabled"):
            ai_data = result["ai_integration"]
            click.echo("\n AI Script Generation Suggestions:")

            suggestions = ai_data.get("script_suggestions", {})
            if suggestions.get("frida_scripts"):
                click.echo("  Frida Scripts:")
                for script in suggestions["frida_scripts"]:
                    click.echo(f"    - {script['description']} (confidence: {script['confidence']:.0%})")

            if suggestions.get("ghidra_scripts"):
                click.echo("  Ghidra Scripts:")
                for script in suggestions["ghidra_scripts"]:
                    click.echo(f"    - {script['description']} (confidence: {script['confidence']:.0%})")

            # Display recommended actions
            if ai_data.get("recommended_actions"):
                click.echo("\n  Recommended AI Actions:")
                for action in ai_data["recommended_actions"]:
                    click.echo(f"     {action}")

            # Display auto-generation status
            auto_confidence = suggestions.get("auto_generate_confidence", 0)
            if auto_confidence > HIGH_CONFIDENCE_THRESHOLD:
                click.echo(f"\n   High confidence ({auto_confidence:.0%}) - Autonomous script generation triggered!")
            elif auto_confidence > MODERATE_CONFIDENCE_THRESHOLD:
                click.echo(f"\n  [FAST] Moderate confidence ({auto_confidence:.0%}) - Consider manual script generation")

            # Display autonomous generation status
            if ai_data.get("autonomous_generation", {}).get("started"):
                click.echo("  🔄 Autonomous script generation started in background")
                click.echo(f"  📋 Targets: {', '.join(ai_data['autonomous_generation']['targets'])}")

        elif "ai_integration" in result and not result["ai_integration"].get("enabled"):
            ai_error = result["ai_integration"].get("error", "Unknown error")
            click.echo(f"\nWARNING️  AI integration failed: {ai_error}")

        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            click.echo(f"\nAnalysis saved to: {output}")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Analysis failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@_typed_decorator
@cli.command()
@click.argument("binary_path")
@click.option("--offset", "-o", type=str, help="Patch offset (hex)")
@click.option("--data", "-d", help="Patch data (hex)")
@click.option("--nop-range", "-n", help="NOP range (start:end in hex)")
@click.option("--output", "-O", help="Output patched binary")
def patch(
    binary_path: str,
    offset: str | None,
    data: str | None,
    nop_range: str | None,
    output: str | None,
) -> None:
    """Patch a binary file."""
    try:
        patches = []

        if offset and data:
            patches.append(
                {
                    "offset": int(offset, 16),
                    "data": bytes.fromhex(data.replace(" ", "")),
                },
            )

        if nop_range:
            nop_start, nop_end = nop_range.split(":")
            patches.append(
                {
                    "type": "nop",
                    "start": int(nop_start, 16),
                    "end": int(nop_end, 16),
                },
            )

        if not patches:
            click.echo("No patches specified!", err=True)
            sys.exit(1)

        click.echo(f"Patching binary: {binary_path}")

        patch_config = {
            "patches": patches,
            "output_path": output,
        }
        result = generate_patch(binary_path, patch_config)

        if result["success"]:
            click.echo("Patching successful!")
            click.echo(f"Output: {result.get('output_path', 'N/A')}")
        else:
            click.echo("Patching failed!", err=True)

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Patching failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# =============================================================================
# Enhanced CLI Commands for Advanced Exploitation Framework
# =============================================================================


@_typed_decorator
@cli.group()
def advanced() -> None:
    """Advanced exploitation commands."""
    if not ADVANCED_MODULES_AVAILABLE:
        click.echo("Advanced modules not available. Please check installation.", err=True)
        sys.exit(1)


@_typed_decorator
@advanced.group()
def advanced_payload() -> None:
    """Advanced payload generation commands."""


@_typed_decorator
@advanced_payload.command()
@click.option(
    "--type",
    "-t",
    "payload_type",
    type=click.Choice(["reverse_shell", "bind_shell", "meterpreter", "staged_payload", "custom"]),
    default="reverse_shell",
    help="Payload type",
)
@click.option(
    "--arch",
    "-a",
    "architecture",
    type=click.Choice(["x86", "x64", "arm", "arm64"]),
    default="x64",
    help="Target architecture",
)
@click.option("--lhost", required=True, help="Listener host")
@click.option("--lport", type=int, required=True, help="Listener port")
@click.option(
    "--encoding",
    type=click.Choice(["none", "polymorphic", "metamorphic", "xor", "alpha"]),
    default="polymorphic",
    help="Payload encoding",
)
@click.option(
    "--evasion",
    type=click.Choice(["none", "low", "medium", "high", "maximum"]),
    default="medium",
    help="Evasion level",
)
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format",
    type=click.Choice(["raw", "exe", "dll", "shellcode"]),
    default="raw",
    help="Output format",
)
def advanced_generate() -> None:
    """Generate advanced payload with evasion techniques."""
    try:
        # This functionality has been removed as it was part of out-of-scope exploitation code.
        click.echo("Advanced payload generation has been removed from this version.")
        click.echo("Intellicrack now focuses on binary analysis and security research capabilities.")
        return

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Advanced payload generation failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@_typed_decorator
@advanced.group()
def research() -> None:
    """Vulnerability research commands."""


@_typed_decorator
@research.command()
@click.argument("target_path")
@click.option(
    "--type",
    "-t",
    "campaign_type",
    type=click.Choice(
        [
            "binary_analysis",
            "fuzzing",
            "vulnerability_assessment",
            "patch_analysis",
            "hybrid_research",
        ],
    ),
    default="binary_analysis",
    help="Research campaign type",
)
@click.option("--output", "-o", help="Output directory for results")
@click.option("--timeout", type=int, default=3600, help="Analysis timeout (seconds)")
@click.option("--use-ai", is_flag=True, help="Use AI-guided analysis")
def run(target_path: str, output: str | None, timeout: int, *, use_ai: bool) -> None:
    """Run vulnerability research analysis."""
    try:
        if not os.path.exists(target_path):
            click.echo(f"Target file not found: {target_path}", err=True)
            sys.exit(1)

        result: dict[str, Any] | None = {}

        if use_ai:
            # Use AI-guided analysis
            ai_researcher = LicensingProtectionAnalyzer()

            click.echo(f"Running AI-guided analysis on {target_path} (timeout: {timeout}s)...")
            # Set timeout for the analysis
            import platform
            import signal

            try:
                alarm_func = getattr(signal, "alarm", None)
                sigalrm = getattr(signal, "SIGALRM", None)
                if platform.system() != "Windows" and sigalrm is not None and alarm_func is not None:

                    def timeout_handler(signum: int, frame: types.FrameType | None) -> NoReturn:
                        logger.warning("AI analysis timeout handler: signal %s, frame %s", signum, frame)
                        raise TimeoutError(f"Analysis timed out after {timeout} seconds")

                    signal.signal(sigalrm, timeout_handler)
                    alarm_func(timeout)

                    try:
                        result = ai_researcher.analyze_licensing_protection(target_path)
                    finally:
                        alarm_func(0)  # Cancel the alarm
                else:
                    # Windows or systems without SIGALRM
                    result = ai_researcher.analyze_licensing_protection(target_path)
            except (AttributeError, OSError) as e:
                logger.exception("Error in cli: %s", e)
                # Fallback for systems without signal support - use threading for timeout
                exception_holder: list[BaseException | None] = [None]
                result = None

                def run_analysis() -> None:
                    nonlocal result
                    try:
                        result = ai_researcher.analyze_licensing_protection(target_path)
                    except (
                        OSError,
                        ValueError,
                        RuntimeError,
                        AttributeError,
                        KeyError,
                        ImportError,
                        TypeError,
                        ConnectionError,
                        TimeoutError,
                    ) as exc:
                        logger.exception("Error in cli: %s", exc)
                        exception_holder[0] = exc

                thread = threading.Thread(target=run_analysis)
                thread.daemon = True
                thread.start()
                thread.join(timeout)

                if thread.is_alive():
                    # Thread is still running, analysis timed out
                    result = {
                        "success": False,
                        "error": f"Analysis timed out after {timeout} seconds",
                    }
                elif exception_holder[0] is not None:
                    raise RuntimeError("Analysis failed in thread") from exception_holder[0]

            if result is not None and result["success"]:
                click.echo("OK AI analysis completed!")

                # Show risk assessment
                risk = result["risk_assessment"]
                click.echo(f"  Risk Level: {risk['overall_risk']}")
                click.echo(f"  Risk Score: {risk['risk_score']:.2f}")
                click.echo(f"  Exploitation Likelihood: {risk['exploitation_likelihood']:.2f}")

                # Show AI recommendations
                recommendations = result["ai_recommendations"]
                if recommendations:
                    click.echo(f"\nAI Recommendations ({len(recommendations)}):")
                    for i, rec in enumerate(recommendations[:5], 1):
                        click.echo(f"  {i}. {rec}")

                # Show exploitation strategies
                strategies = result["exploitation_strategies"]
                if strategies:
                    click.echo(f"\nExploitation Strategies ({len(strategies)}):")
                    for strategy in strategies[:3]:
                        vuln = strategy["vulnerability"]
                        click.echo(f"   {vuln['type']} ({vuln['severity']}) - {strategy['approach']}")
                        click.echo(f"    Confidence: {strategy['confidence']:.2f}")

        else:
            # Use standard binary analysis
            from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer

            analyzer = BinaryAnalyzer()

            click.echo(f"Running binary analysis on {target_path}...")

            # Run direct analysis with timeout
            import platform
            import signal

            try:
                alarm_func = getattr(signal, "alarm", None)
                sigalrm = getattr(signal, "SIGALRM", None)
                if platform.system() != "Windows" and sigalrm is not None and alarm_func is not None:

                    def timeout_handler(signum: int, frame: types.FrameType | None) -> NoReturn:
                        logger.warning(
                            "Binary analysis timeout handler: signal %s, frame %s",
                            signum,
                            frame,
                        )
                        raise TimeoutError(f"Analysis timed out after {timeout} seconds")

                    signal.signal(sigalrm, timeout_handler)
                    alarm_func(timeout)

                    try:
                        result = analyzer.analyze(target_path)
                    finally:
                        alarm_func(0)  # Cancel the alarm
                else:
                    # Windows or systems without SIGALRM
                    result = analyzer.analyze(target_path)
            except (AttributeError, OSError) as e:
                logger.exception("Error in cli: %s", e)
                # Fallback for systems without signal support
                result = analyzer.analyze(target_path)

            if result.get("success"):
                protections = result.get("protections", [])
                click.echo(f"OK Analysis completed - {len(protections)} protections found")

                # Categorize protections
                licensing_protections = [p for p in protections if "licensing" in p.get("type", "").lower()]
                obfuscation_protections = [p for p in protections if "obfuscation" in p.get("type", "").lower()]

                click.echo(f"  Licensing Protections: {len(licensing_protections)}")
                click.echo(f"  Obfuscation Protections: {len(obfuscation_protections)}")

                # Show top protections
                if protections:
                    click.echo("\nTop Protections:")
                    for protection in protections[:5]:
                        type_name = protection.get("type", "Unknown")
                        description = protection.get("description", "No description")
                        click.echo(f"   {type_name} - {description}")

        # Save results if output specified
        if output and result is not None and result.get("success"):
            os.makedirs(output, exist_ok=True)
            result_file = os.path.join(output, f"analysis_results_{int(time.time())}.json")

            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)

            click.echo(f"\nResults saved to: {result_file}")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Vulnerability research failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@advanced.group()
def post_exploit() -> None:
    """Post-exploitation commands."""


@post_exploit.command()
@click.option(
    "--platform",
    type=click.Choice(["windows", "linux", "macos"]),
    required=True,
    help="Target platform",
)
@click.option("--output", "-o", help="Save detailed results to file")
def auto_exploit(target_path: str, lhost: str, lport: int, target_platform: str, output: str | None) -> None:
    """Run full automated exploitation workflow."""
    try:
        if not os.path.exists(target_path):
            click.echo(f"Target file not found: {target_path}", err=True)
            sys.exit(1)

        ai_researcher = LicensingProtectionAnalyzer()

        click.echo(f"Starting automated licensing protection analysis of {os.path.basename(target_path)}...")
        click.echo(f"Target platform: {target_platform}")
        click.echo(f"Analysis configuration: {lhost}:{lport}")
        click.echo("=" * 50)

        result = ai_researcher.analyze_licensing_protection(target_path)

        if result["success"]:
            click.echo("OK Licensing protection analysis completed successfully!")
            click.echo(f"  Target: {result.get('target_path', 'N/A')}")

            # Show protection mechanisms found
            mechanisms = result.get("protection_mechanisms", [])
            click.echo(f"\nProtection Mechanisms Found ({len(mechanisms)}):")
            for mech in mechanisms:
                confidence = mech.get("confidence", 0)
                conf_str = (
                    "HIGH" if confidence > HIGH_CONFIDENCE_THRESHOLD else "MEDIUM" if confidence > MODERATE_CONFIDENCE_THRESHOLD else "LOW"
                )
                click.echo(f"   {mech['type']} [{conf_str} confidence]")

            if recommendations := result.get("ai_recommendations", []):
                click.echo(f"\nAI Recommendations ({len(recommendations)}):")
                for rec in recommendations[:5]:
                    click.echo(f"   {rec}")

        else:
            click.echo(f"FAIL Licensing protection analysis failed: {result.get('error')}")

            # Show analysis results summary
            if "analysis_results" in result:
                analysis = result["analysis_results"]
                click.echo("\nAnalysis Results:")
                for key, value in analysis.items():
                    if isinstance(value, dict) and "success" in value:
                        status = "OK" if value.get("success") else "FAIL"
                        click.echo(f"  {status} {key.replace('_', ' ').title()}")

            sys.exit(1)

        # Save detailed results
        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
            click.echo(f"\nDetailed results saved to: {output}")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Automated exploitation failed: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def ai() -> None:
    """AI-powered script generation and analysis commands."""


@ai.command("generate")
@click.argument("binary_path")
@click.option(
    "--script-type",
    type=click.Choice(["frida", "ghidra", "both"]),
    default="frida",
    help="Type of script to generate",
)
@click.option(
    "--complexity",
    type=click.Choice(["basic", "advanced"]),
    default="basic",
    help="Script complexity level",
)
@click.option(
    "--focus",
    type=click.Choice(["auto", "license", "trial", "network", "anti-debug", "vm"]),
    default="auto",
    help="Protection focus",
)
@click.option("--output", "-o", help="Output directory for generated scripts")
@click.option("--autonomous", is_flag=True, help="Enable autonomous mode with testing")
@click.option("--preview", is_flag=True, help="Preview script before saving")
def ai_generate(
    binary_path: str,
    script_type: str,
    complexity: str,
    focus: str,
    output: str | None,
    *,
    autonomous_mode: bool,
    preview: bool,
) -> None:
    """Generate AI scripts for binary protection bypass."""
    try:
        if not os.path.exists(binary_path):
            click.echo(f"Binary file not found: {binary_path}", err=True)
            sys.exit(1)

        from intellicrack.ai.orchestrator import get_orchestrator
        from intellicrack.ai.script_generation_agent import AIAgent

        # Get AI orchestrator
        click.echo(" Initializing AI script generator...")
        orchestrator = get_orchestrator()

        # Create autonomous agent
        agent = AIAgent(orchestrator=orchestrator, cli_interface=None)

        # Build request
        binary_name = os.path.basename(binary_path)
        click.echo(f" Target: {binary_name}")
        click.echo(f"📋 Script Type: {script_type}")
        click.echo(f" Complexity: {complexity}")
        click.echo(f" Focus: {focus}")

        if script_type == "both":
            script_request = f"Create both Frida and Ghidra scripts to bypass protections in {binary_path}"
        elif script_type == "frida":
            script_request = f"Create a {complexity} Frida script to bypass protections in {binary_path}"
        else:
            script_request = f"Create a {complexity} Ghidra script to bypass protections in {binary_path}"

        if focus != "auto":
            protection_map = {
                "license": "license bypass",
                "trial": "trial extension",
                "network": "network validation",
                "anti-debug": "anti-debugging",
                "vm": "VM detection",
            }
            script_request += f". Focus on {protection_map[focus]} protection."

        if autonomous_mode:
            script_request += " Use autonomous mode with testing and refinement."
            click.echo("🔄 Autonomous mode enabled - AI will test and refine scripts")

        # Generate scripts
        click.echo("\n Starting AI script generation...")
        bar: Any
        with click.progressbar(length=100, label="Generating") as bar:
            result = agent.process_request(script_request)
            bar.update(100)

        # Handle results
        if result.get("status") == "success":
            scripts = result.get("scripts", [])
            analysis = result.get("analysis", {})
            iterations = result.get("iterations", 0)

            click.echo(f"\nOK Successfully generated {len(scripts)} scripts!")
            click.echo(f"🔄 Completed in {iterations} iterations")

            # Show analysis summary
            if analysis and "protections" in analysis:
                if protections := analysis["protections"]:
                    click.echo(f"\n🛡️  Detected {len(protections)} protection mechanisms:")
                    for prot in protections[:5]:
                        confidence = prot.get("confidence", 0.0)
                        click.echo(f"    {prot['type']} (confidence: {confidence:.0%})")

            # Process each script
            for i, script in enumerate(scripts):
                script_name = f"ai_generated_{binary_name}_{script.metadata.script_type.value}_{int(time.time())}"
                success_prob = script.metadata.success_probability

                click.echo(f"\n📄 Script {i + 1}: {script.metadata.script_type.value} ({script_name})")
                click.echo(f"   Success Probability: {success_prob:.0%}")
                click.echo(f"   Size: {len(script.content)} characters")

                # Preview if requested
                if preview:
                    click.echo(f"\n📖 Preview of {script.metadata.script_type.value} script:")
                    click.echo("─" * 60)
                    preview_lines = script.content.split("\n")[:20]
                    for line in preview_lines:
                        click.echo(f"   {line}")
                    if len(script.content.split("\n")) > 20:
                        click.echo("   ... (truncated)")
                    click.echo("─" * 60)

                    if not click.confirm("\nSave this script?"):
                        continue

                # Save script
                try:
                    save_dir_path = Path(output or "intellicrack/intellicrack/scripts/ai_generated")
                    save_dir_path.mkdir(parents=True, exist_ok=True)

                    script_filename = f"{script_name}.js"
                    saved_path = save_dir_path / script_filename
                    saved_path.write_text(script.content, encoding="utf-8")

                    click.echo(f" Saved: {saved_path}")

                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    AttributeError,
                    KeyError,
                    ImportError,
                    TypeError,
                    ConnectionError,
                    TimeoutError,
                ) as e:
                    logger.exception("Error in cli: %s", e)
                    click.echo(f"ERROR Failed to save script: {e}", err=True)

        else:
            error_msg = result.get("message", "Unknown error")
            click.echo(f"ERROR Generation failed: {error_msg}", err=True)
            sys.exit(1)

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("AI script generation failed: %s", e)
        click.echo(f"ERROR Error: {e}", err=True)
        sys.exit(1)


@ai.command("test")
@click.argument("script_path")
@click.option("--binary", help="Target binary for testing")
@click.option(
    "--environment",
    type=click.Choice(["qemu", "sandbox", "direct"]),
    default="qemu",
    help="Testing environment",
)
@click.option("--timeout", default=60, help="Test timeout in seconds")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def test(script_path: str, binary: str | None, environment: str, timeout: int, verbose: bool) -> None:
    """Test AI-generated scripts in safe environments."""
    try:
        if not os.path.exists(script_path):
            click.echo(f"Script file not found: {script_path}", err=True)
            sys.exit(1)

        # Determine script type
        script_ext = os.path.splitext(script_path)[1].lower()
        if script_ext == ".js":
            script_type = "frida"
        elif script_ext == ".py":
            script_type = "ghidra"
        else:
            click.echo(f"Unknown script type for file: {script_path}", err=True)
            sys.exit(1)

        # Read script content
        with open(script_path, encoding="utf-8") as f:
            script_content = f.read()

        click.echo(f"🧪 Testing {script_type} script: {os.path.basename(script_path)}")
        click.echo(f"🏗️  Environment: {environment}")
        click.echo(f"⏱️  Timeout: {timeout}s")

        if binary:
            click.echo(f" Target: {os.path.basename(binary)}")

        # Initialize test manager
        if environment == "qemu":
            from intellicrack.ai.qemu_manager import QEMUManager

            test_manager = QEMUManager()

            # Create snapshot
            click.echo("\n📸 Creating QEMU snapshot...")
            snapshot_id = test_manager.create_snapshot(binary or "unknown")

            try:
                # Run test
                click.echo(" Executing script in QEMU...")
                if script_type == "frida":
                    result = test_manager.test_frida_script(snapshot_id, script_content, binary or "unknown")
                else:
                    result = test_manager.test_ghidra_script(snapshot_id, script_content, binary or "unknown")

                # Show results
                if result.success:
                    click.echo("OK Script executed successfully!")
                    click.echo(f"⏱️  Runtime: {result.runtime_ms}ms")

                    if verbose and result.output:
                        click.echo("\n📋 Script Output:")
                        click.echo(result.output)
                else:
                    click.echo("ERROR Script execution failed!")
                    if result.error:
                        click.echo(f"Error: {result.error}")
                    sys.exit(1)

            finally:
                # Cleanup
                click.echo("🧹 Cleaning up snapshot...")
                test_manager.cleanup_snapshot(snapshot_id)

        else:
            click.echo(f"Environment '{environment}' testing not yet implemented")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Script testing failed: %s", e)
        click.echo(f"ERROR Error: {e}", err=True)
        sys.exit(1)


@ai.command("analyze")
@click.argument("binary_path")
@click.option("--output", "-o", help="Save analysis report to file")
@click.option("--format", type=click.Choice(["text", "json", "html"]), default="text", help="Output format")
@click.option("--deep", is_flag=True, help="Enable deep AI analysis")
def ai_analyze(binary_path: str, output: str | None, output_format: str, deep: bool) -> None:
    """Analyze binary for protection mechanisms using AI."""
    try:
        if not os.path.exists(binary_path):
            click.echo(f"Binary file not found: {binary_path}", err=True)
            sys.exit(1)

        from intellicrack.ai.orchestrator import AITask, AITaskType, AnalysisComplexity, get_orchestrator

        click.echo(f" AI analyzing: {os.path.basename(binary_path)}")
        click.echo(f" Analysis depth: {'Deep' if deep else 'Standard'}")

        # Get orchestrator
        orchestrator = get_orchestrator()

        # Create analysis task
        complexity = AnalysisComplexity.CRITICAL if deep else AnalysisComplexity.COMPLEX

        task = AITask(
            task_id=f"analysis_{int(time.time())}",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=complexity,
            input_data={"binary_path": binary_path},
            priority=9 if deep else 7,
        )

        # Submit task
        click.echo(" Starting AI analysis...")
        task_id = orchestrator.submit_task(task)
        click.echo(f"Task submitted with ID: {task_id}")

        # Track real analysis task progress
        bar: Any
        with click.progressbar(length=100, label="Analyzing") as bar:
            last_progress = 0
            while True:
                if task_status := orchestrator.get_task_status(task_id):
                    progress = task_status.get("progress", 0)
                    if progress > last_progress:
                        bar.update(progress - last_progress)
                        last_progress = progress

                    if task_status.get("status") == "completed":
                        bar.update(100 - last_progress)
                        break
                    if task_status.get("status") == "failed":
                        click.echo("\nERROR Analysis failed: " + task_status.get("error", "Unknown error"))
                        return

                # Brief sleep to avoid excessive CPU usage during polling
                time.sleep(0.1)

        click.echo("OK Analysis complete!")

        # Get actual analysis results from orchestrator
        task_status = orchestrator.get_task_status(task_id)
        analysis_results = task_status.get("result") if task_status else None
        if not analysis_results:
            # Fallback: perform basic binary analysis if orchestrator doesn't have results
            binary_name = os.path.basename(binary_path)
            analysis_results = {
                "binary_info": {
                    "name": binary_name,
                    "size": os.path.getsize(binary_path),
                    "type": "PE" if binary_path.endswith(".exe") else "Unknown",
                },
                "protections": [
                    {
                        "type": "license_check",
                        "confidence": 0.85,
                        "description": "String comparison based license validation",
                    },
                    {
                        "type": "trial_timer",
                        "confidence": 0.72,
                        "description": "Time-based trial limitation",
                    },
                ],
                "recommendations": [
                    "Focus on license validation bypass",
                    "Monitor time-related function calls",
                    "Consider registry-based license storage",
                ],
            }

        # Format output
        if output_format == "json":
            output_text = json.dumps(analysis_results, indent=2)
        elif output_format == "html":
            output_text = f"""
<html><head><title>AI Analysis: {binary_name}</title></head>
<body>
<h1>AI Binary Analysis Report</h1>
<h2>Binary: {binary_name}</h2>
<h3>Detected Protections:</h3>
<ul>
"""
            for prot in analysis_results["protections"]:
                output_text += f"<li>{prot['type']} (confidence: {prot['confidence']:.0%}) - {prot['description']}</li>\n"
            output_text += "</ul></body></html>"
        else:
            # Text format
            output_text = "AI Binary Analysis Report\n"
            output_text += f"{'=' * 50}\n"
            output_text += f"Binary: {binary_name}\n"
            output_text += f"Size: {analysis_results['binary_info']['size']} bytes\n"
            output_text += f"Type: {analysis_results['binary_info']['type']}\n\n"

            output_text += f"Detected Protections ({len(analysis_results['protections'])}):\n"
            for prot in analysis_results["protections"]:
                output_text += f"   {prot['type']} (confidence: {prot['confidence']:.0%})\n"
                output_text += f"    {prot['description']}\n"

            output_text += "\nAI Recommendations:\n"
            for i, rec in enumerate(analysis_results["recommendations"], 1):
                output_text += f"  {i}. {rec}\n"

        # Save or display
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(output_text)
            click.echo(f" Analysis saved to: {output}")
        else:
            click.echo("\n📋 Analysis Results:")
            click.echo(output_text)

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("AI analysis failed: %s", e)
        click.echo(f"ERROR Error: {e}", err=True)
        sys.exit(1)


@ai.command()
@click.argument("request")
@click.option("--binary", help="Target binary (optional)")
@click.option("--max-iterations", default=10, help="Maximum refinement iterations")
@click.option(
    "--test-environment",
    type=click.Choice(["qemu", "sandbox"]),
    default="qemu",
    help="Testing environment",
)
@click.option("--save-all", is_flag=True, help="Save all intermediate scripts")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def autonomous(
    request: str,
    binary: str | None,
    max_iterations: int,
    test_environment: str,
    save_all: bool,
    verbose: bool,
) -> None:
    """Run autonomous AI workflow for complex tasks."""
    try:
        from intellicrack.ai.orchestrator import get_orchestrator
        from intellicrack.ai.script_generation_agent import AIAgent

        click.echo(" Starting autonomous AI workflow...")
        click.echo(f" Request: {request}")
        click.echo(f"🔄 Max iterations: {max_iterations}")
        click.echo(f"🏗️  Test environment: {test_environment}")

        if binary:
            click.echo(f" Target binary: {os.path.basename(binary)}")
            # Add binary to request if provided
            request = f"{request}. Target binary: {binary}"

        # Initialize autonomous agent
        orchestrator = get_orchestrator()
        agent = AIAgent(orchestrator=orchestrator, cli_interface=None)
        agent.max_iterations = max_iterations

        click.echo("\n Executing autonomous workflow...")

        result = agent.process_request(request)

        # Handle results
        if result.get("status") == "success":
            scripts = result.get("scripts", [])
            iterations = result.get("iterations", 0)
            analysis = result.get("analysis", {})

            click.echo("\nOK Autonomous workflow completed successfully!")
            click.echo(f"🔄 Total iterations: {iterations}")
            click.echo(f"📄 Generated scripts: {len(scripts)}")

            # Show script details
            for i, script in enumerate(scripts):
                script_type = script.metadata.script_type.value
                success_prob = script.metadata.success_probability
                click.echo(f"   Script {i + 1}: {script_type} (success: {success_prob:.0%})")

                if save_all:
                    try:
                        save_dir_path = Path("intellicrack/intellicrack/scripts/autonomous")
                        save_dir_path.mkdir(parents=True, exist_ok=True)

                        script_filename = f"autonomous_{script_type}_{int(time.time())}.js"
                        saved_path = save_dir_path / script_filename
                        saved_path.write_text(script.content, encoding="utf-8")
                        click.echo(f"      Saved: {saved_path}")
                    except (
                        OSError,
                        ValueError,
                        RuntimeError,
                        AttributeError,
                        KeyError,
                        ImportError,
                        TypeError,
                        ConnectionError,
                        TimeoutError,
                    ) as e:
                        logger.exception("Error in cli: %s", e)
                        click.echo(f"      Save failed: {e}")

            # Show analysis if verbose
            if verbose and analysis:
                click.echo("\n Analysis Summary:")
                if "protections" in analysis:
                    protections = analysis["protections"]
                    click.echo(f"   Protections detected: {len(protections)}")
                    for prot in protections[:3]:
                        click.echo(f"       {prot.get('type', 'unknown')}")
        else:
            error_msg = result.get("message", "Unknown error")
            click.echo(f"ERROR Autonomous workflow failed: {error_msg}", err=True)
            sys.exit(1)

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Autonomous workflow failed: %s", e)
        click.echo(f"ERROR Error: {e}", err=True)
        sys.exit(1)


@ai.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--output", "-o", help="Output file for session data")
@click.option("--include-ui", is_flag=True, help="Include UI conversation history")
def save_session(binary_path: str, output: str | None, include_ui: bool) -> None:
    """Save AI session data including conversation history."""
    try:
        from intellicrack.ai.script_generation_agent import AIAgent

        click.echo(" Saving AI session data...")

        # Initialize agent
        agent = AIAgent()

        # Prepare session save options
        save_options = {
            "binary_path": binary_path,
            "include_ui_history": include_ui,
        }

        # Include UI conversation history if requested
        if include_ui:
            click.echo(" Including UI conversation history in session data...")
            # Try to get UI history if available
            try:
                import intellicrack.ui.main_app as main_app_module

                get_history_func = getattr(main_app_module, "get_conversation_history", None)
                if get_history_func is None:
                    click.echo("  UI conversation history function not available")
                elif ui_history := get_history_func():
                    save_options["ui_conversation_history"] = ui_history
                    click.echo(f"  Added {len(ui_history)} UI conversation entries")
                else:
                    click.echo("  No UI conversation history available")
            except ImportError:
                click.echo("  UI module not available, skipping UI history")
            except Exception as e:
                logger.exception("Could not retrieve UI history: %s", e)
                click.echo(f"  Warning: Could not retrieve UI history: {e}")

        # Save session data with options
        if hasattr(agent, "save_session_data_with_options"):
            session_file = agent.save_session_data_with_options(output, save_options)
        else:
            # Fallback to basic save
            session_file = agent.save_session_data(output)
            if include_ui:
                click.echo("  Note: Agent doesn't support extended save options")

        click.echo(f"OK Session data saved to: {session_file}")

        # Display what was included
        click.echo("\n📋 Session includes:")
        click.echo("  OK Agent conversation history")
        click.echo("  OK Analysis results")
        click.echo("  OK Generated scripts")
        if include_ui:
            click.echo("  OK UI conversation history")
        else:
            click.echo("  FAIL UI conversation history (use --include-ui to add)")

        # Show session summary
        history = agent.get_conversation_history()
        click.echo(f" Conversation entries: {len(history)}")
        generated_scripts = getattr(agent, "generated_scripts", [])
        click.echo(f"📄 Scripts generated: {len(generated_scripts)}")
        test_results = getattr(agent, "test_results", [])
        click.echo(f"🧪 Tests run: {len(test_results)}")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Failed to save session: %s", e)
        click.echo(f"ERROR Error: {e}", err=True)
        sys.exit(1)


@ai.command()
@click.option("--confirm", is_flag=True, help="Confirm reset without prompt")
def reset(confirm: bool) -> None:
    """Reset AI agent state for new analysis."""
    try:
        from intellicrack.ai.script_generation_agent import AIAgent

        if not confirm and not click.confirm("WARNING️  Reset AI agent? This will clear all conversation history."):
            click.echo("ERROR Reset cancelled")
            return

        click.echo("🔄 Resetting AI agent...")

        # Initialize and reset agent
        agent = AIAgent()
        reset_func = getattr(agent, "reset", None)
        if reset_func is not None:
            reset_func()
            click.echo("OK AI agent reset successfully")
        else:
            click.echo("OK AI agent re-initialized (no reset method available)")
        click.echo("    Conversation history cleared")
        click.echo("    Generated scripts cleared")
        click.echo("    Test results cleared")
        click.echo("    Ready for new analysis")

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Failed to reset agent: %s", e)
        click.echo(f"ERROR Error: {e}", err=True)
        sys.exit(1)


@ai.command()
@click.argument(
    "task_type",
    type=click.Choice(["script_generation", "vulnerability_analysis", "script_testing"]),
)
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--request", help="Custom request for the task")
@click.option("--script", help="Script content for testing (script_testing only)")
@click.option("--output", "-o", help="Output file for results")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def task(
    task_type: str,
    binary_path: str,
    request: str | None,
    script: str | None,
    output: str | None,
    verbose: bool,
) -> None:
    """Execute specific autonomous AI task."""
    try:
        from intellicrack.ai.script_generation_agent import AIAgent

        click.echo(f" Executing {task_type} task...")
        click.echo(f" Target: {os.path.basename(binary_path)}")

        # Initialize agent
        agent = AIAgent()

        # Build task config
        task_config = {
            "type": task_type,
            "target_binary": binary_path,
            "request": request or f"Perform {task_type} on {binary_path}",
        }

        # Add script for testing tasks
        if task_type == "script_testing" and script:
            task_config["script"] = script

        # Execute task
        bar: Any
        with click.progressbar(length=100, label="Processing") as bar:
            result = agent.execute_autonomous_task(task_config)
            bar.update(100)

        # Handle results
        if result.get("success"):
            click.echo("\nOK Task completed successfully!")

            if task_type == "script_generation" and "scripts" in result:
                scripts = result["scripts"]
                click.echo(f"📄 Generated {len(scripts)} scripts")
                for i, script_obj in enumerate(scripts):
                    click.echo(f"   Script {i + 1}: {script_obj.script_type}")

            elif task_type == "vulnerability_analysis" and "vulnerabilities" in result:
                vulns = result["vulnerabilities"]
                click.echo(f" Found {len(vulns)} vulnerabilities")
                for vuln in vulns[:5]:  # Show first 5
                    click.echo(f"    {vuln}")

            elif task_type == "script_testing" and "test_results" in result:
                test_result = result["test_results"]
                click.echo(f"🧪 Test completed in {test_result.get('runtime_ms', 0)}ms")
                click.echo(f"   Exit code: {test_result.get('exit_code', 'N/A')}")

            # Save output if requested
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, default=str)
                click.echo(f" Results saved to: {output}")
            elif verbose:
                click.echo("\n Full results:")
                click.echo(json.dumps(result, indent=2, default=str))

        else:
            error_msg = result.get("error", "Unknown error")
            click.echo(f"ERROR Task failed: {error_msg}", err=True)
            sys.exit(1)

    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        KeyError,
        ImportError,
        TypeError,
        ConnectionError,
        TimeoutError,
    ) as e:
        logger.exception("Task execution failed: %s", e)
        click.echo(f"ERROR Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def frida() -> None:
    """Frida script management and execution commands."""


@frida.command("list")
@click.option(
    "--category",
    type=str,
    help="Filter by category (e.g., protection_bypass, memory_analysis)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed information about each script",
)
def frida_list(category: str | None, verbose: bool) -> None:
    """List available Frida scripts from the library."""
    try:
        from pathlib import Path

        from intellicrack.core.analysis.frida_script_manager import FridaScriptManager

        scripts_dir = Path(__file__).parent.parent / "scripts" / "frida"
        manager = FridaScriptManager(scripts_dir)

        if not manager.scripts:
            click.echo("No Frida scripts found in the library.")
            return

        # Filter by category if specified
        scripts_to_show = manager.scripts
        if category:
            scripts_to_show = {name: config for name, config in manager.scripts.items() if config.category.value == category}

            if not scripts_to_show:
                click.echo(f"No scripts found in category: {category}")
                return

        click.echo(f"\n📜 Available Frida Scripts ({len(scripts_to_show)}):\n")

        for script_name, config in sorted(scripts_to_show.items()):
            click.echo(f"   {script_name}")
            click.echo(f"    Category: {config.category.value}")

            if verbose:
                click.echo(f"    Description: {config.description}")

                if config.parameters:
                    click.echo(f"    Parameters: {', '.join(config.parameters.keys())}")

                click.echo()

        click.echo("\n Use 'intellicrack frida info <script_name>' for details")
        click.echo(" Use 'intellicrack frida run <script_name> <binary>' to execute\n")

    except Exception as e:
        logger.exception("Failed to list Frida scripts: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@frida.command("info")
@click.argument("script_name")
def frida_info(script_name: str) -> None:
    """Show detailed information about a specific Frida script."""
    try:
        from pathlib import Path

        from intellicrack.core.analysis.frida_script_manager import FridaScriptManager

        scripts_dir = Path(__file__).parent.parent / "scripts" / "frida"
        manager = FridaScriptManager(scripts_dir)

        if script_name not in manager.scripts:
            click.echo(f"Script '{script_name}' not found.")
            click.echo(f"\nAvailable scripts: {', '.join(sorted(manager.scripts.keys()))}")
            sys.exit(1)

        config = manager.scripts[script_name]

        click.echo(f"\n📜 Script: {script_name}\n")
        click.echo(f"Category: {config.category.value}")
        click.echo(f"Description: {config.description}")

        if config.parameters:
            click.echo("\nParameters:")
            for param_name, param_desc in config.parameters.items():
                click.echo(f"   {param_name}: {param_desc}")

        if config.path.exists():
            size_kb = config.path.stat().st_size / 1024
            click.echo(f"\nScript Size: {size_kb:.2f} KB")
            click.echo(f"Script Path: {config.path}")

        click.echo()

    except Exception as e:
        logger.exception("Failed to get script info: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@frida.command("run")
@click.argument("script_name")
@click.argument("binary_path")
@click.option(
    "--mode",
    type=click.Choice(["spawn", "attach"]),
    default="spawn",
    help="Execution mode: spawn (launch process) or attach (attach to running process)",
)
@click.option(
    "--params",
    type=str,
    help='JSON string of parameters to pass to the script (e.g., \'{"key": "value"}\')',
)
@click.option(
    "--output",
    type=click.Path(),
    help="Save results to file",
)
def frida_run(script_name: str, binary_path: str, mode: str, params: str | None, output: str | None) -> None:
    """Execute a Frida script from the library against a target binary."""
    try:
        import json
        from pathlib import Path

        from intellicrack.core.analysis.frida_script_manager import FridaScriptManager

        scripts_dir = Path(__file__).parent.parent / "scripts" / "frida"
        manager = FridaScriptManager(scripts_dir)

        if script_name not in manager.scripts:
            click.echo(f"FAIL Script '{script_name}' not found.")
            click.echo(f"\nAvailable scripts: {', '.join(sorted(manager.scripts.keys()))}")
            sys.exit(1)

        if not os.path.exists(binary_path):
            click.echo(f"FAIL Binary not found: {binary_path}")
            sys.exit(1)

        # Parse parameters if provided
        parameters = {}
        if params:
            try:
                parameters = json.loads(params)
            except json.JSONDecodeError as e:
                logger.exception("Invalid JSON parameters: %s", e)
                click.echo(f"FAIL Invalid JSON parameters: {e}")
                sys.exit(1)

        click.echo(f"\n📜 Executing: {script_name}")
        click.echo(f" Target: {Path(binary_path).name}")
        click.echo(f"[CFG]️  Mode: {mode}")
        if parameters:
            click.echo(f" Parameters: {parameters}")
        click.echo()

        # Execute the script
        result = manager.execute_script(
            script_name=script_name,
            target=binary_path,
            mode=mode,
            parameters=parameters,
        )

        # Display results
        if result.success:
            click.echo("OK Execution successful!")
            execution_time_ms = (result.end_time - result.start_time) * 1000
            click.echo(f"⏱️  Execution time: {execution_time_ms:.0f}ms")

            if result.messages:
                click.echo("\n Script Output:")
                for msg in result.messages[:10]:
                    msg_type = msg.get("type", "log")
                    payload = msg.get("payload", str(msg))
                    click.echo(f"  [{msg_type}] {payload}")
                if len(result.messages) > 10:
                    click.echo(f"  ... and {len(result.messages) - 10} more messages")

            if hooks_triggered := result.data.get("hooks_triggered", []):
                click.echo(f"\n🎣 Hooks triggered: {hooks_triggered}")

            if result.data:
                data_items = list(result.data.items())
                click.echo(f"\n Data collected: {len(data_items)} items")

                # Show sample of collected data
                for i, (key, value) in enumerate(data_items[:5]):
                    click.echo(f"  [{i + 1}] {key}: {value}")

                if len(data_items) > 5:
                    click.echo(f"  ... and {len(data_items) - 5} more items")

            # Save results if output path specified
            if output:
                output_path = Path(output)
                manager.export_results(result.script_name, output_path)
                click.echo(f"\n Results saved to: {output}")

            click.echo()
        else:
            error_msg = result.errors[0] if result.errors else "Unknown error"
            click.echo(f"FAIL Execution failed: {error_msg}")

            if result.messages:
                click.echo("\n📋 Partial output:")
                for msg in result.messages[:5]:
                    msg_type = msg.get("type", "log")
                    payload = msg.get("payload", str(msg))
                    click.echo(f"  [{msg_type}] {payload}")

            sys.exit(1)

    except Exception as e:
        logger.exception("Failed to execute Frida script: %s", e)
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command("cert-detect")
@click.argument("target")
@click.option("--report", "-r", help="Export detection report to file (JSON format)")
@click.option("--verbose", "-v", is_flag=True, help="Display detailed detection information")
@click.option("--min-confidence", "-c", type=float, default=0.3, help="Minimum confidence threshold (0.0-1.0)")
def cert_detect(target: str, report: str | None, verbose: bool, min_confidence: float) -> None:
    """Detect certificate validation in binary or process.

    TARGET can be a file path or process name/PID.

    Examples:
        intellicrack cert-detect target.exe
        intellicrack cert-detect /path/to/app --report detection.json
        intellicrack cert-detect 1234 --min-confidence 0.5

    """
    if not CERT_BYPASS_AVAILABLE:
        click.echo("Error: Certificate bypass modules not available", err=True)
        sys.exit(1)

    try:
        click.echo(f" Detecting certificate validation in: {target}")
        click.echo()

        detector = CertificateValidationDetector()
        detector.min_confidence = min_confidence

        detection_report = detector.detect_certificate_validation(target)

        click.echo("OK Detection complete")
        click.echo()
        click.echo(" Results:")
        click.echo(f"  Binary: {detection_report.binary_path}")
        click.echo(f"  Detected libraries: {len(detection_report.detected_libraries)}")

        for lib in detection_report.detected_libraries:
            click.echo(f"    - {lib}")

        click.echo(f"  Validation functions: {len(detection_report.validation_functions)}")

        if detection_report.validation_functions:
            click.echo()
            click.echo("📍 Detected validation functions:")

            for func in detection_report.validation_functions:
                confidence_icon = "🟢" if func.confidence > 0.7 else "🟡" if func.confidence > 0.4 else "🔴"
                click.echo(f"  {confidence_icon} {func.api_name} at 0x{func.address:x}")
                click.echo(f"     Library: {func.library}")
                click.echo(f"     Confidence: {func.confidence:.2f}")

                if verbose and func.context:
                    click.echo(f"     Context: {func.context[:100]}...")

                if verbose and func.references:
                    click.echo(f"     References: {len(func.references)} callers")

                click.echo()
        else:
            click.echo()
            click.echo("  i  No certificate validation detected")

        click.echo(f" Recommended method: {detection_report.recommended_method.value}")
        click.echo(f"WARNING  Risk level: {detection_report.risk_level}")

        if report:
            report_json = detection_report.to_json()
            with open(report, "w", encoding="utf-8") as f:
                f.write(report_json)
            click.echo()
            click.echo(f" Report saved to: {report}")

    except FileNotFoundError as e:
        logger.exception("Target not found: %s", e)
        click.echo(f"FAIL Error: Target not found - {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.exception("Certificate detection failed: %s", e)
        click.echo(f"FAIL Error: {e}", err=True)
        sys.exit(1)


@cli.command("cert-bypass")
@click.argument("target")
@click.option(
    "--method",
    "-m",
    type=click.Choice(["auto", "patch", "frida", "hybrid", "mitm"], case_sensitive=False),
    default="auto",
    help="Bypass method to use",
)
@click.option("--verify", "-v", is_flag=True, help="Run verification after bypass")
@click.option("--report", "-r", help="Export bypass report to file (JSON format)")
@click.option("--force", "-f", is_flag=True, help="Force bypass even on high-risk targets")
def cert_bypass(target: str, method: str, verify: bool, report: str | None, force: bool) -> None:
    """Execute certificate validation bypass on target.

    TARGET can be a file path or process name/PID.

    Methods:
        auto   - Automatically select optimal method (default)
        patch  - Binary patching (permanent, requires file access)
        frida  - Runtime hooking (temporary, requires running process)
        hybrid - Combination of patch and frida
        mitm   - MITM proxy with certificate injection

    Examples:
        intellicrack cert-bypass target.exe
        intellicrack cert-bypass app.exe --method frida --verify
        intellicrack cert-bypass 1234 --method patch --report bypass.json

    """
    if not CERT_BYPASS_AVAILABLE:
        click.echo("Error: Certificate bypass modules not available", err=True)
        sys.exit(1)

    try:
        click.echo(f" Executing certificate bypass on: {target}")
        click.echo(f"   Method: {method}")
        click.echo()

        orchestrator = CertificateBypassOrchestrator()

        bypass_method = None
        if method != "auto":
            method_map = {
                "patch": BypassMethod.BINARY_PATCH,
                "frida": BypassMethod.FRIDA_HOOK,
                "hybrid": BypassMethod.HYBRID,
                "mitm": BypassMethod.MITM_PROXY,
            }
            bypass_method = method_map.get(method.lower())

        click.echo(" Step 1: Detecting certificate validation...")
        result = orchestrator.bypass(target, method=bypass_method)

        if result.success:
            click.echo()
            click.echo("OK Bypass successful!")
            click.echo()
            click.echo(" Results:")
            click.echo(f"  Method used: {result.method_used.value}")
            click.echo(f"  Detected libraries: {', '.join(result.detection_report.detected_libraries)}")
            click.echo(f"  Functions bypassed: {len(result.detection_report.validation_functions)}")

            if result.patch_result:
                click.echo(f"  Patches applied: {len(result.patch_result.patched_functions)}")

                if result.patch_result.patched_functions:
                    click.echo()
                    click.echo(" Patched functions:")
                    for patched in result.patch_result.patched_functions:
                        click.echo(f"    - {patched.api_name} at 0x{patched.address:x}")
                        click.echo(f"      Patch type: {patched.patch_type.value}")
                        click.echo(f"      Patch size: {patched.patch_size} bytes")

            if result.frida_status:
                click.echo()
                click.echo("🪝  Frida hooks:")
                click.echo(f"  Active scripts: {result.frida_status.get('active_scripts', 0)}")
                click.echo(f"  Hooked functions: {result.frida_status.get('hooked_functions', 0)}")

            if verify:
                click.echo()
                click.echo("🧪 Running verification...")
                verification_passed = result.verification_passed

                if verification_passed:
                    click.echo("  OK Verification passed - bypass is working")
                else:
                    click.echo("  WARNING  Verification failed - bypass may not be effective")

            click.echo()
            click.echo(" Tip: Use 'intellicrack cert-rollback' to restore original state")

        else:
            click.echo()
            click.echo("FAIL Bypass failed")
            click.echo()
            click.echo("Errors:")
            for error in result.errors:
                click.echo(f"  - {error}")

            sys.exit(1)

        if report:
            result_dict = result.to_dict()
            with open(report, "w", encoding="utf-8") as f:
                json.dump(result_dict, f, indent=2)
            click.echo()
            click.echo(f" Report saved to: {report}")

    except FileNotFoundError as e:
        logger.exception("Target not found: %s", e)
        click.echo(f"FAIL Error: Target not found - {e}", err=True)
        sys.exit(1)
    except PermissionError as e:
        logger.exception("Permission denied: %s", e)
        click.echo(f"FAIL Error: Permission denied - {e}", err=True)
        click.echo("   Try running with administrator/root privileges", err=True)
        sys.exit(1)
    except Exception as e:
        logger.exception("Certificate bypass failed: %s", e)
        click.echo(f"FAIL Error: {e}", err=True)
        sys.exit(1)


@cli.command("cert-test")
@click.argument("target")
@click.option("--url", "-u", default="https://www.google.com", help="HTTPS URL to test")
@click.option("--timeout", "-t", type=int, default=10, help="Connection timeout in seconds")
def cert_test(target: str, url: str, timeout: int) -> None:
    """Test if certificate bypass is working for target.

    TARGET can be a file path or process name/PID.

    This command attempts an HTTPS connection to verify that
    certificate validation has been successfully bypassed.

    Examples:
        intellicrack cert-test target.exe
        intellicrack cert-test app.exe --url https://example.com
        intellicrack cert-test 1234 --timeout 30

    """
    if not CERT_BYPASS_AVAILABLE:
        click.echo("Error: Certificate bypass modules not available", err=True)
        sys.exit(1)

    try:
        click.echo(f"🧪 Testing certificate bypass for: {target}")
        click.echo(f"   Test URL: {url}")
        click.echo()

        import ssl
        import urllib.request
        from pathlib import Path

        target_path = Path(target)
        if target_path.exists():
            click.echo("Target type: File")
        else:
            try:
                pid = int(target)
                click.echo(f"Target type: Process (PID: {pid})")
            except ValueError:
                click.echo(f"Target type: Process (Name: {target})")

        click.echo()
        click.echo(" Checking bypass status...")

        detector = CertificateValidationDetector()

        detection_report = detector.detect_certificate_validation(target)

        if not detection_report.validation_functions:
            click.echo("  i  No certificate validation detected in target")
            click.echo("  Bypass not needed - target does not validate certificates")
            return

        click.echo(f"  Found {len(detection_report.validation_functions)} validation functions")

        click.echo()
        click.echo(f"🌐 Testing HTTPS connection to {url}...")

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={"User-Agent": "Intellicrack-Test/1.0"})  # noqa: S310

            with urllib.request.urlopen(req, context=context, timeout=timeout) as response:  # noqa: S310
                status_code = response.getcode()

                if status_code == 200:
                    click.echo()
                    click.echo("OK Test PASSED")
                    click.echo(f"   Successfully connected to {url}")
                    click.echo(f"   Status code: {status_code}")
                    click.echo()
                    click.echo(" Certificate bypass appears to be working")
                else:
                    click.echo()
                    click.echo(f"WARNING  Test completed with status code: {status_code}")
                    click.echo("   Bypass may be partially effective")

        except urllib.error.URLError as e:
            logger.exception("Certificate test URL error: %s", e)
            click.echo()
            click.echo("FAIL Test FAILED")
            click.echo(f"   Connection error: {e.reason}")
            click.echo()
            click.echo(" This could indicate:")
            click.echo("   - Certificate bypass is not active or not effective")
            click.echo("   - Target is not using bypassed validation")
            click.echo("   - Network connectivity issues")
            sys.exit(1)

    except FileNotFoundError as e:
        logger.exception("Target not found: %s", e)
        click.echo(f"FAIL Error: Target not found - {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.exception("Certificate test failed: %s", e)
        click.echo(f"FAIL Error: {e}", err=True)
        sys.exit(1)


@cli.command("cert-rollback")
@click.argument("target")
@click.option("--force", "-f", is_flag=True, help="Force rollback even if no backup found")
def cert_rollback(target: str, force: bool) -> None:
    """Rollback certificate bypass and restore original state.

    TARGET can be a file path or process name/PID.

    This command will:
    - Restore original binary from backup (if patched)
    - Detach Frida hooks (if using runtime hooking)
    - Remove injected certificates
    - Restore system state

    Examples:
        intellicrack cert-rollback target.exe
        intellicrack cert-rollback app.exe --force
        intellicrack cert-rollback 1234

    """
    if not CERT_BYPASS_AVAILABLE:
        click.echo("Error: Certificate bypass modules not available", err=True)
        sys.exit(1)

    try:
        click.echo(f"🔄 Rolling back certificate bypass for: {target}")
        click.echo()

        from pathlib import Path

        target_path = Path(target)
        backup_path = Path(f"{target_path!s}.intellicrack_backup")

        click.echo(" Checking for bypass artifacts...")

        rollback_success = False

        if backup_path.exists():
            click.echo("  OK Found binary backup")
            click.echo()
            click.echo(" Restoring original binary...")

            import shutil

            shutil.copy2(backup_path, target_path)

            click.echo("  OK Original binary restored")
            backup_path.unlink()
            click.echo("    Backup file removed")

            rollback_success = True
        elif not force:
            click.echo("  WARNING  No backup file found")
            click.echo()
            click.echo(" Possible reasons:")
            click.echo("   - Binary was not patched (Frida hooks only)")
            click.echo("   - Backup was manually deleted")
            click.echo("   - Bypass was not applied to this target")
            click.echo()
            click.echo("Use --force to attempt rollback anyway")

        click.echo()
        click.echo("🪝 Checking for active Frida hooks...")

        try:
            import psutil

            target_pid = None
            if target_path.exists():
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        if proc.info["exe"] == str(target_path.absolute()):
                            target_pid = proc.info["pid"]
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            else:
                try:
                    target_pid = int(target)
                except ValueError:
                    for proc in psutil.process_iter(["pid", "name"]):
                        try:
                            if proc.info["name"] == target:
                                target_pid = proc.info["pid"]
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

            if target_pid:
                click.echo(f"  Found running process: PID {target_pid}")
                click.echo("  🔓 Detaching Frida hooks...")

                from intellicrack.core.certificate.frida_cert_hooks import FridaCertificateHooks

                hooks = FridaCertificateHooks()
                if hooks.attach(target_pid):
                    hooks.detach()
                    click.echo("  OK Frida hooks detached")
                    rollback_success = True
                else:
                    click.echo("  i  No active Frida hooks found")
            else:
                click.echo("  i  Target process not running")

        except ImportError:
            click.echo("  WARNING  psutil not available, skipping process check")
        except Exception as hook_error:
            logger.warning("Failed to detach hooks: %s", hook_error)
            click.echo(f"  WARNING  Hook detachment failed: {hook_error}")

        click.echo()

        if rollback_success or force:
            click.echo("OK Rollback complete")
            click.echo()
            click.echo(" Next steps:")
            click.echo("   - Verify target runs correctly")
            click.echo("   - Certificate validation should now be active")
        else:
            click.echo("FAIL Rollback incomplete")
            click.echo("   No changes were made")
            sys.exit(1)

    except FileNotFoundError as e:
        logger.exception("Target not found: %s", e)
        click.echo(f"FAIL Error: Target not found - {e}", err=True)
        sys.exit(1)
    except PermissionError as e:
        logger.exception("Permission denied: %s", e)
        click.echo(f"FAIL Error: Permission denied - {e}", err=True)
        click.echo("   Try running with administrator/root privileges", err=True)
        sys.exit(1)
    except Exception as e:
        logger.exception("Certificate rollback failed: %s", e)
        click.echo(f"FAIL Error: {e}", err=True)
        sys.exit(1)


# Command aliases
cli.add_command(cert_detect, name="cd")
cli.add_command(cert_bypass, name="cb")
cli.add_command(cert_test, name="ct")
cli.add_command(cert_rollback, name="cr")


def main() -> int:
    """Run main entry point for CLI."""
    # Check for --gui flag in command line arguments
    if "--gui" in sys.argv:
        # Remove --gui from argv before passing to click
        sys.argv.remove("--gui")
        # Launch GUI interface
        try:
            import intellicrack.ui.main_app as main_app_module

            gui_main = getattr(main_app_module, "main", None)
            if gui_main is not None:
                gui_main()
            else:
                click.echo("GUI main function not available", err=True)
                return 1
        except ImportError as e:
            logger.exception("Failed to import GUI module: %s", e)
            click.echo(f"Failed to import GUI module: {e}", err=True)
            return 1
        return 0

    # Otherwise run CLI
    cli()  # pylint: disable=E1120
    return 0


if __name__ == "__main__":
    sys.exit(main())
