#!/usr/bin/env python3
"""Pipeline support for Intellicrack CLI.

Enables Unix-style command chaining and data flow between operations.

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

import argparse
import csv
import json
import logging
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)


@dataclass
class PipelineData:
    """Data passed between pipeline stages.

    Attributes:
        content: The actual data payload being processed through the pipeline.
        metadata: Dictionary containing metadata about the data and processing stages.
        format: Format of the content (json, binary, text, or csv). Defaults to "json".

    """

    content: Any
    metadata: dict[str, Any]
    format: str = "json"

    def to_json(self) -> str:
        """Convert PipelineData to JSON string representation.

        Returns:
            str: JSON string containing serialized content, metadata, and
                format.

        """
        return json.dumps(
            {
                "content": self.content,
                "metadata": self.metadata,
                "format": self.format,
            },
            default=str,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "PipelineData":
        """Create PipelineData instance from JSON string.

        Args:
            json_str: JSON string containing serialized pipeline data with
                content, metadata, and format keys.

        Returns:
            PipelineData: Instance deserialized from JSON string containing
                original content, metadata, and format.

        """
        data: dict[str, Any] = json.loads(json_str)
        return cls(
            content=data.get("content"),
            metadata=data.get("metadata", {}),
            format=data.get("format", "json"),
        )


class PipelineStage(ABC):
    """Base class for pipeline stages.

    Attributes:
        name: Name identifier for the pipeline stage.
        console: Rich console instance for output.

    """

    def __init__(self, name: str) -> None:
        """Initialize pipeline stage with name and console.

        Args:
            name: Name identifier for the pipeline stage, used for logging
                and stage identification.

        """
        self.name = name
        self.console: Console = Console()

    @abstractmethod
    def process(self, input_data: PipelineData) -> PipelineData:
        """Process input data and return transformed output data.

        Args:
            input_data: PipelineData to process containing content, metadata,
                and format information.

        Returns:
            PipelineData: Processed output with transformed content,
                updated metadata, and format designation.

        """
        pass

    # pylint: disable=too-many-branches
    def validate_input(self, input_data: PipelineData) -> bool:
        """Validate input data format and content integrity.

        Args:
            input_data: PipelineData to validate against format-specific
                constraints and security checks.

        Returns:
            bool: True if data format is valid and passes security checks,
                False if validation fails.

        """
        if input_data.format == "json":
            if input_data.content is None:
                return False
            try:
                json.dumps(input_data.content)
            except (TypeError, ValueError):
                return False
        elif input_data.format == "binary":
            if isinstance(input_data.content, (bytes, bytearray)):
                pass
            elif isinstance(input_data.content, (str, Path)):
                path: Path = Path(input_data.content)
                if not path.exists() or not path.is_file():
                    return False
            else:
                return False
        elif input_data.format == "text":
            if not isinstance(input_data.content, (str, bytes)):
                return False
        elif input_data.format == "csv":
            if not isinstance(input_data.content, (list, dict, str)):
                return False

        if not isinstance(input_data.metadata, dict):
            return False

        if isinstance(input_data.content, (str, Path)):
            try:
                path_str: str = str(input_data.content)
                if ".." in path_str or path_str.startswith("/etc/") or path_str.startswith("/root/"):
                    return False
            except (AttributeError, TypeError):
                pass

        return True


class AnalysisStage(PipelineStage):
    """Run binary analysis."""

    def __init__(self) -> None:
        """Initialize analysis stage for binary analysis processing.

        Calls parent PipelineStage.__init__ with stage name "analysis".

        """
        super().__init__("analysis")

    def process(self, input_data: PipelineData) -> PipelineData:
        """Process binary analysis stage.

        Args:
            input_data: PipelineData containing binary file path to analyze
                for licensing protections and vulnerabilities.

        Returns:
            PipelineData: Analysis results in JSON format with vulnerability
                data, imports, and protection detection information.

        """
        from intellicrack.utils.analysis.binary_analysis import analyze_binary

        # Extract binary path
        binary_path: str | Any
        if input_data.format == "text":
            binary_path = input_data.content.strip()
        elif input_data.format == "json":
            binary_path = input_data.content.get("path", input_data.content)
        else:
            binary_path = str(input_data.content)

        # Run analysis
        try:
            results: Any = analyze_binary(binary_path)

            return PipelineData(
                content=results,
                metadata={
                    "stage": self.name,
                    "binary_path": binary_path,
                    "success": True,
                },
                format="json",
            )
        except Exception as e:
            logger.exception("Analysis stage failed for %s: %s", binary_path, e, exc_info=True)
            return PipelineData(
                content={"error": str(e)},
                metadata={
                    "stage": self.name,
                    "binary_path": binary_path,
                    "success": False,
                },
                format="json",
            )


class FilterStage(PipelineStage):
    """Filter data based on criteria.

    Attributes:
        filter_expr: Filter expression string to apply during processing.

    """

    def __init__(self, filter_expr: str) -> None:
        """Initialize filter stage with filter expression for data processing.

        Args:
            filter_expr: Filter expression string containing keywords to match
                against data items for filtering operations.

        """
        super().__init__("filter")
        self.filter_expr: str = filter_expr

    def process(self, input_data: PipelineData) -> PipelineData:
        """Process filter stage to apply filtering criteria.

        Args:
            input_data: PipelineData to filter based on expression keywords
                and severity levels.

        Returns:
            PipelineData: Filtered content with only matching items retained
                and filtered flag set in metadata.

        """
        if input_data.format != "json":
            return input_data

        content: Any = input_data.content

        # Simple filter expressions
        if "vulnerability" in self.filter_expr:
            # Filter for vulnerabilities
            if isinstance(content, dict) and "vulnerabilities" in content:
                filtered: list[Any] = [v for v in content["vulnerabilities"] if self._matches_filter(v)]
                content["vulnerabilities"] = filtered

        elif "imports" in self.filter_expr:
            # Filter imports
            if isinstance(content, dict) and "imports" in content:
                filtered = [i for i in content["imports"] if self._matches_filter(i)]
                content["imports"] = filtered

        elif "high_severity" in self.filter_expr:
            # Filter high severity items
            if isinstance(content, list):
                content = [item for item in content if self._is_high_severity(item)]

        return PipelineData(
            content=content,
            metadata={**input_data.metadata, "filtered": True},
            format=input_data.format,
        )

    def _matches_filter(self, item: object) -> bool:
        """Check if item matches filter.

        Args:
            item: Item to check against filter expression.

        Returns:
            True if item matches filter keywords, False otherwise.

        """
        keywords: list[str] = self.filter_expr.split()
        item_str: str = str(item).lower()

        return any(keyword.lower() in item_str for keyword in keywords)

    def _is_high_severity(self, item: object) -> bool:
        """Check if item is high severity.

        Args:
            item: Item to check for high severity status.

        Returns:
            True if item has high or critical severity, False otherwise.

        """
        if isinstance(item, dict):
            severity: str = item.get("severity", "").lower()
            return severity in ["high", "critical"]
        return False


class TransformStage(PipelineStage):
    """Transform data format.

    Attributes:
        output_format: Target format for transformation (csv, table, summary, json, xml).

    """

    def __init__(self, output_format: str) -> None:
        """Initialize transform stage with output format for data transformation.

        Args:
            output_format: Target format for transformation including csv, table,
                summary, json, or xml.

        """
        super().__init__("transform")
        self.output_format: str = output_format

    def process(self, input_data: PipelineData) -> PipelineData:
        """Process transform stage to convert data format.

        Args:
            input_data: PipelineData to transform into target output format
                specified at initialization.

        Returns:
            PipelineData: Content converted to specified output format with
                appropriate format designation.

        """
        content: Any = input_data.content

        if self.output_format == "csv":
            # Convert to CSV format
            csv_content: str = self._to_csv(content)
            return PipelineData(
                content=csv_content,
                metadata=input_data.metadata,
                format="csv",
            )

        if self.output_format == "table":
            # Convert to table format
            table_content: str = self._to_table(content)
            return PipelineData(
                content=table_content,
                metadata=input_data.metadata,
                format="text",
            )

        if self.output_format == "summary":
            # Create summary
            summary: str = self._create_summary(content)
            return PipelineData(
                content=summary,
                metadata=input_data.metadata,
                format="text",
            )

        return input_data

    def _to_csv(self, content: object) -> str:
        """Convert to CSV format.

        Args:
            content: Data to convert to CSV format (dict or list).

        Returns:
            CSV-formatted string representation of content.

        """
        import io

        output: io.StringIO = io.StringIO()

        if isinstance(content, list) and content:
            # List of dicts
            if isinstance(content[0], dict):
                dict_writer: csv.DictWriter[str] = csv.DictWriter(output, fieldnames=content[0].keys())
                dict_writer.writeheader()
                dict_writer.writerows(content)
            else:
                # List of values
                writer: Any = csv.writer(output)
                for item in content:
                    writer.writerow([str(item)])

        elif isinstance(content, dict):
            # Single dict
            dict_writer_2: csv.DictWriter[str] = csv.DictWriter(output, fieldnames=content.keys())
            dict_writer_2.writeheader()
            dict_writer_2.writerow(content)

        return output.getvalue()

    def _to_table(self, content: object) -> str:
        """Convert to table format.

        Args:
            content: Data to convert to table format (dict or list).

        Returns:
            Rendered table as string.

        """
        table: Table = Table(box=box.SIMPLE)

        if isinstance(content, dict):
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")

            for key, value in content.items():
                table.add_row(str(key), str(value))

        elif isinstance(content, list) and content:
            if isinstance(content[0], dict):
                # List of dicts
                for key in content[0]:
                    table.add_column(str(key))

                for item in content:
                    table.add_row(*[str(item.get(k, "")) for k in content[0]])

        # Render table to string
        import io

        string_io: io.StringIO = io.StringIO()
        console: Console = Console(file=string_io)
        console.print(table)
        return string_io.getvalue()

    def _create_summary(self, content: object) -> str:
        """Create a summary of the content.

        Args:
            content: Data to summarize (dict or list).

        Returns:
            String summary of content structure and contents.

        """
        lines: list[str] = []

        if isinstance(content, dict):
            lines.append(f"Data Type: Dictionary with {len(content)} keys")

            # Summarize lists
            for key, value in content.items():
                if isinstance(value, list):
                    lines.append(f"  {key}: {len(value)} items")
                elif isinstance(value, dict):
                    lines.append(f"  {key}: Dictionary with {len(value)} keys")
                else:
                    lines.append(f"  {key}: {value}")

        elif isinstance(content, list):
            lines.append(f"Data Type: List with {len(content)} items")

            if content and isinstance(content[0], dict):
                lines.extend((
                    "  Item type: Dictionary",
                    f"  Keys: {', '.join(content[0].keys())}",
                ))
        return "\n".join(lines)


class OutputStage(PipelineStage):
    """Output data to file or stdout.

    Attributes:
        output_path: Optional file path for output; if None, writes to stdout.

    """

    def __init__(self, output_path: str | None = None) -> None:
        """Initialize output stage with optional output path for data export.

        Args:
            output_path: Optional file path for output destination; if None,
                writes formatted output to stdout using Rich console.

        """
        super().__init__("output")
        self.output_path: str | None = output_path

    def process(self, input_data: PipelineData) -> PipelineData:
        """Process output stage to write data to file or stdout.

        Args:
            input_data: PipelineData to output with content formatted based
                on data type and destination.

        Returns:
            PipelineData: Unmodified input data after writing to file or
                stdout destination.

        """
        if self.output_path:
            # Write to file
            with open(self.output_path, "w") as f:
                if input_data.format == "json":
                    json.dump(input_data.content, f, indent=2, default=str)
                else:
                    f.write(str(input_data.content))

            logger.info("Output written to %s", self.output_path)
        # Print to stdout
        elif input_data.format == "json":
            syntax: Syntax = Syntax(
                json.dumps(input_data.content, indent=2, default=str),
                "json",
                theme="monokai",
            )
            self.console.print(syntax)
        else:
            self.console.print(input_data.content)

        return input_data


class Pipeline:
    """Pipeline executor."""

    def __init__(self) -> None:
        """Initialize pipeline with empty stages list and console."""
        self.stages: list[PipelineStage] = []
        self.console: Console = Console()

    def add_stage(self, stage: PipelineStage) -> "Pipeline":
        """Add a stage to the pipeline execution chain.

        Args:
            stage: PipelineStage to append to pipeline for sequential execution.

        Returns:
            Pipeline: Self reference enabling method chaining for fluent
                configuration.

        """
        self.stages.append(stage)
        return self

    def execute(self, initial_input: str | dict[str, Any] | PipelineData) -> PipelineData:
        """Execute all stages in the pipeline sequentially.

        Args:
            initial_input: Initial data to process as string, dict, or
                PipelineData object for pipeline input.

        Returns:
            PipelineData: Final result after all stages complete containing
                processed content and metadata.

        Raises:
            ValueError: If input validation fails for any stage in the
                pipeline execution chain.

        """
        # Convert initial input to PipelineData
        data: PipelineData
        if isinstance(initial_input, PipelineData):
            data = initial_input
        elif isinstance(initial_input, str):
            data = PipelineData(content=initial_input, metadata={}, format="text")
        else:
            data = PipelineData(content=initial_input, metadata={}, format="json")

        # Execute each stage
        for i, stage in enumerate(self.stages):
            logger.info("Executing stage %d/%d: %s", i + 1, len(self.stages), stage.name)

            try:
                # Validate input
                if not stage.validate_input(data):
                    raise ValueError(f"Invalid input for stage {stage.name}")

                # Process
                data = stage.process(data)

                # Check for errors
                if isinstance(data.content, dict) and "error" in data.content:
                    logger.exception("Error in stage %s: %s", stage.name, data.content["error"])
                    if not data.metadata.get("continue_on_error", False):
                        break

            except Exception as e:
                logger.exception("Failed at stage %s: %s", stage.name, e, exc_info=True)
                break

        return data


# pylint: disable=too-many-branches,too-many-statements
def parse_pipeline_command(command: str) -> Pipeline:
    """Parse a pipeline command string into executable Pipeline object.

    Args:
        command: Pipeline command string with stages separated by pipes,
            containing valid analyze, filter, transform, and output commands.

    Returns:
        Pipeline: Configured Pipeline object with parsed stages ready for
            sequential execution.

    Raises:
        ValueError: If command is invalid, malicious, too long, has invalid
            syntax, contains suspicious patterns, or exceeds limits.

    """
    # Validate command string
    if not command or not isinstance(command, str):
        raise ValueError("Invalid pipeline command")

    # Security check - limit command length
    if len(command) > 1000:
        raise ValueError("Pipeline command too long")

    # Check for suspicious patterns
    suspicious_patterns: list[str] = ["exec", "eval", "__import__", "compile", "globals", "locals"]
    command_lower: str = command.lower()
    for pattern in suspicious_patterns:
        if pattern in command_lower:
            raise ValueError(f"Suspicious pattern '{pattern}' detected in command")

    pipeline: Pipeline = Pipeline()

    # Split by pipe character
    stages: list[str] = command.split("|")

    # Limit number of stages
    if len(stages) > 10:
        raise ValueError("Too many pipeline stages (max: 10)")

    for stage_str in stages:
        stage_str = stage_str.strip()
        parts: list[str] = stage_str.split()

        if not parts:
            continue

        cmd: str = parts[0]
        args: list[str] = parts[1:] if len(parts) > 1 else []

        # Validate command name
        allowed_commands: list[str] = ["analyze", "filter", "transform", "output"]
        if cmd not in allowed_commands:
            raise ValueError(f"Unknown command: {cmd}")

        # Create appropriate stage
        if cmd == "analyze":
            pipeline.add_stage(AnalysisStage())

        elif cmd == "filter":
            filter_expr: str = " ".join(args)
            # Validate filter expression
            if len(filter_expr) > 200:
                raise ValueError("Filter expression too long")
            pipeline.add_stage(FilterStage(filter_expr))

        elif cmd == "transform":
            if args:
                # Validate transform type
                allowed_transforms: list[str] = ["json", "table", "summary", "csv", "xml"]
                if args[0] not in allowed_transforms:
                    raise ValueError(f"Invalid transform type: {args[0]}")
                pipeline.add_stage(TransformStage(args[0]))

        elif cmd == "output":
            if args:
                output_path: str = args[0]
                # Validate output path
                try:
                    path: Path = Path(output_path).resolve()
                    # Prevent writing to sensitive locations
                    sensitive_dirs: list[str] = ["/etc", "/root", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]
                    path_str: str = str(path)
                    for sensitive_dir in sensitive_dirs:
                        if path_str.startswith(sensitive_dir):
                            raise ValueError(f"Cannot write to sensitive directory: {sensitive_dir}")
                except Exception as e:
                    raise ValueError(f"Invalid output path: {e}") from e
                pipeline.add_stage(OutputStage(output_path))
            else:
                pipeline.add_stage(OutputStage(None))

    return pipeline


# pylint: disable=too-many-branches,too-many-statements
def main() -> None:
    """Execute CLI entry point for pipeline operations.

    Parses command-line arguments, validates pipeline configuration,
    and executes the specified pipeline with provided input data.

    """
    parser = argparse.ArgumentParser(
        description="Intellicrack Pipeline Processor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze and filter vulnerabilities
  intellicrack-pipeline "analyze | filter vulnerability | output vulns.json"

  # Transform analysis to CSV
  intellicrack-pipeline "analyze | transform csv | output results.csv"

  # Create summary report
  intellicrack-pipeline "analyze | transform summary"

  # Filter high severity issues
  intellicrack-pipeline "analyze | filter high_severity | transform table"
        """,
    )

    parser.add_argument("pipeline", help="Pipeline command string")
    parser.add_argument("-i", "--input", help="Input file or binary path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args: argparse.Namespace = parser.parse_args()

    Console()

    # Parse pipeline with validation
    try:
        pipeline: Pipeline = parse_pipeline_command(args.pipeline)
    except ValueError as e:
        logger.exception("Invalid pipeline command: %s", e, exc_info=True)
        return
    except Exception as e:
        logger.exception("Error parsing pipeline: %s", e, exc_info=True)
        return

    # Determine input
    initial_input: str | None = None
    if args.input:
        # Validate input file path
        try:
            input_path: Path = Path(args.input).resolve()
            # Check if path exists and is accessible
            if not input_path.exists():
                logger.exception("Input file not found: %s", args.input)
                return
            if not input_path.is_file():
                logger.exception("Input path is not a file: %s", args.input)
                return
            # Check file size to prevent memory issues
            if input_path.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
                logger.exception("Input file too large (max 100MB)")
                return
            initial_input = str(input_path)
        except Exception as e:
            logger.exception("Invalid input path: %s", e, exc_info=True)
            return
    elif not sys.stdin.isatty():
        # Read from stdin with size limit
        try:
            max_stdin_size: int = 10 * 1024 * 1024  # 10MB limit for stdin
            initial_input = ""
            bytes_read: int = 0

            while True:
                chunk: str = sys.stdin.read(1024)  # Read in chunks
                if not chunk:
                    break
                bytes_read += len(chunk.encode("utf-8"))
                if bytes_read > max_stdin_size:
                    logger.exception("Stdin input too large (max 10MB)")
                    return
                initial_input += chunk
        except Exception as e:
            logger.exception("Error reading from stdin: %s", e, exc_info=True)
            return
    else:
        logger.exception("No input provided. Use -i flag or pipe data to stdin.")
        return

    # Execute pipeline
    if args.verbose:
        logger.info("Executing pipeline: %s", args.pipeline)

    result: PipelineData = pipeline.execute(initial_input)

    if args.verbose:
        logger.info("Pipeline completed!")
        if result:
            logger.debug("Result type: %s", type(result).__name__)


# Alias for easier importing
PipelineProcessor = Pipeline


if __name__ == "__main__":
    main()
