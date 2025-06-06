#!/usr/bin/env python3
"""
Pipeline Support for Intellicrack CLI
Enables Unix-style command chaining and data flow between operations
"""

import sys
import json
import os
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass
from abc import ABC, abstractmethod
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich import box


@dataclass
class PipelineData:
    """Data passed between pipeline stages"""
    content: Any
    metadata: Dict[str, Any]
    format: str = "json"  # json, binary, text, csv
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps({
            "content": self.content,
            "metadata": self.metadata,
            "format": self.format
        }, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'PipelineData':
        """Create from JSON string"""
        data = json.loads(json_str)
        return cls(
            content=data.get("content"),
            metadata=data.get("metadata", {}),
            format=data.get("format", "json")
        )


class PipelineStage(ABC):
    """Base class for pipeline stages"""
    
    def __init__(self, name: str):
        self.name = name
        self.console = Console()
    
    @abstractmethod
    def process(self, input_data: PipelineData) -> PipelineData:
        """Process input data and return output data"""
        pass
    
    def validate_input(self, input_data: PipelineData) -> bool:
        """Validate input data format"""
        return True


class AnalysisStage(PipelineStage):
    """Run binary analysis"""
    
    def __init__(self):
        super().__init__("analysis")
    
    def process(self, input_data: PipelineData) -> PipelineData:
        from intellicrack.utils.binary_analysis import analyze_binary
        
        # Extract binary path
        if input_data.format == "text":
            binary_path = input_data.content.strip()
        elif input_data.format == "json":
            binary_path = input_data.content.get("path", input_data.content)
        else:
            binary_path = str(input_data.content)
        
        # Run analysis
        try:
            results = analyze_binary(binary_path)
            
            return PipelineData(
                content=results,
                metadata={
                    "stage": self.name,
                    "binary_path": binary_path,
                    "success": True
                },
                format="json"
            )
        except Exception as e:
            return PipelineData(
                content={"error": str(e)},
                metadata={
                    "stage": self.name,
                    "binary_path": binary_path,
                    "success": False
                },
                format="json"
            )


class FilterStage(PipelineStage):
    """Filter data based on criteria"""
    
    def __init__(self, filter_expr: str):
        super().__init__("filter")
        self.filter_expr = filter_expr
    
    def process(self, input_data: PipelineData) -> PipelineData:
        if input_data.format != "json":
            return input_data
        
        content = input_data.content
        
        # Simple filter expressions
        if "vulnerability" in self.filter_expr:
            # Filter for vulnerabilities
            if isinstance(content, dict) and "vulnerabilities" in content:
                filtered = [v for v in content["vulnerabilities"] 
                           if self._matches_filter(v)]
                content["vulnerabilities"] = filtered
        
        elif "imports" in self.filter_expr:
            # Filter imports
            if isinstance(content, dict) and "imports" in content:
                filtered = [i for i in content["imports"] 
                           if self._matches_filter(i)]
                content["imports"] = filtered
        
        elif "high_severity" in self.filter_expr:
            # Filter high severity items
            if isinstance(content, list):
                content = [item for item in content 
                          if self._is_high_severity(item)]
        
        return PipelineData(
            content=content,
            metadata={**input_data.metadata, "filtered": True},
            format=input_data.format
        )
    
    def _matches_filter(self, item: Any) -> bool:
        """Check if item matches filter"""
        # Simple keyword matching for now
        keywords = self.filter_expr.split()
        item_str = str(item).lower()
        
        return any(keyword.lower() in item_str for keyword in keywords)
    
    def _is_high_severity(self, item: Any) -> bool:
        """Check if item is high severity"""
        if isinstance(item, dict):
            severity = item.get("severity", "").lower()
            return severity in ["high", "critical"]
        return False


class TransformStage(PipelineStage):
    """Transform data format"""
    
    def __init__(self, output_format: str):
        super().__init__("transform")
        self.output_format = output_format
    
    def process(self, input_data: PipelineData) -> PipelineData:
        content = input_data.content
        
        if self.output_format == "csv":
            # Convert to CSV format
            csv_content = self._to_csv(content)
            return PipelineData(
                content=csv_content,
                metadata=input_data.metadata,
                format="csv"
            )
        
        elif self.output_format == "table":
            # Convert to table format
            table_content = self._to_table(content)
            return PipelineData(
                content=table_content,
                metadata=input_data.metadata,
                format="text"
            )
        
        elif self.output_format == "summary":
            # Create summary
            summary = self._create_summary(content)
            return PipelineData(
                content=summary,
                metadata=input_data.metadata,
                format="text"
            )
        
        return input_data
    
    def _to_csv(self, content: Any) -> str:
        """Convert to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        
        if isinstance(content, list) and content:
            # List of dicts
            if isinstance(content[0], dict):
                writer = csv.DictWriter(output, fieldnames=content[0].keys())
                writer.writeheader()
                writer.writerows(content)
            else:
                # List of values
                writer = csv.writer(output)
                for item in content:
                    writer.writerow([str(item)])
        
        elif isinstance(content, dict):
            # Single dict
            writer = csv.DictWriter(output, fieldnames=content.keys())
            writer.writeheader()
            writer.writerow(content)
        
        return output.getvalue()
    
    def _to_table(self, content: Any) -> str:
        """Convert to table format"""
        table = Table(box=box.SIMPLE)
        
        if isinstance(content, dict):
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")
            
            for key, value in content.items():
                table.add_row(str(key), str(value))
        
        elif isinstance(content, list) and content:
            if isinstance(content[0], dict):
                # List of dicts
                for key in content[0].keys():
                    table.add_column(str(key))
                
                for item in content:
                    table.add_row(*[str(item.get(k, "")) for k in content[0].keys()])
        
        # Render table to string
        console = Console(file=io.StringIO())
        console.print(table)
        return console.file.getvalue()
    
    def _create_summary(self, content: Any) -> str:
        """Create a summary of the content"""
        lines = []
        
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
                lines.append(f"  Item type: Dictionary")
                lines.append(f"  Keys: {', '.join(content[0].keys())}")
        
        return "\n".join(lines)


class OutputStage(PipelineStage):
    """Output data to file or stdout"""
    
    def __init__(self, output_path: Optional[str] = None):
        super().__init__("output")
        self.output_path = output_path
    
    def process(self, input_data: PipelineData) -> PipelineData:
        if self.output_path:
            # Write to file
            with open(self.output_path, 'w') as f:
                if input_data.format == "json":
                    json.dump(input_data.content, f, indent=2, default=str)
                else:
                    f.write(str(input_data.content))
            
            self.console.print(f"[green]Output written to {self.output_path}[/green]")
        else:
            # Print to stdout
            if input_data.format == "json":
                syntax = Syntax(
                    json.dumps(input_data.content, indent=2, default=str),
                    "json",
                    theme="monokai"
                )
                self.console.print(syntax)
            else:
                self.console.print(input_data.content)
        
        return input_data


class Pipeline:
    """Pipeline executor"""
    
    def __init__(self):
        self.stages: List[PipelineStage] = []
        self.console = Console()
    
    def add_stage(self, stage: PipelineStage) -> 'Pipeline':
        """Add a stage to the pipeline"""
        self.stages.append(stage)
        return self
    
    def execute(self, initial_input: Union[str, Dict, PipelineData]) -> PipelineData:
        """Execute the pipeline"""
        # Convert initial input to PipelineData
        if isinstance(initial_input, PipelineData):
            data = initial_input
        elif isinstance(initial_input, str):
            data = PipelineData(content=initial_input, metadata={}, format="text")
        else:
            data = PipelineData(content=initial_input, metadata={}, format="json")
        
        # Execute each stage
        for i, stage in enumerate(self.stages):
            self.console.print(f"[cyan]Executing stage {i+1}/{len(self.stages)}: {stage.name}[/cyan]")
            
            try:
                # Validate input
                if not stage.validate_input(data):
                    raise ValueError(f"Invalid input for stage {stage.name}")
                
                # Process
                data = stage.process(data)
                
                # Check for errors
                if isinstance(data.content, dict) and "error" in data.content:
                    self.console.print(f"[red]Error in stage {stage.name}: {data.content['error']}[/red]")
                    if not data.metadata.get("continue_on_error", False):
                        break
                        
            except Exception as e:
                self.console.print(f"[red]Failed at stage {stage.name}: {e}[/red]")
                break
        
        return data


def parse_pipeline_command(command: str) -> Pipeline:
    """Parse a pipeline command string"""
    pipeline = Pipeline()
    
    # Split by pipe character
    stages = command.split("|")
    
    for stage_str in stages:
        stage_str = stage_str.strip()
        parts = stage_str.split()
        
        if not parts:
            continue
        
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Create appropriate stage
        if cmd == "analyze":
            pipeline.add_stage(AnalysisStage())
        
        elif cmd == "filter":
            filter_expr = " ".join(args)
            pipeline.add_stage(FilterStage(filter_expr))
        
        elif cmd == "transform":
            if args:
                pipeline.add_stage(TransformStage(args[0]))
        
        elif cmd == "output":
            output_path = args[0] if args else None
            pipeline.add_stage(OutputStage(output_path))
    
    return pipeline


def main():
    """CLI entry point for pipeline operations"""
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
        """
    )
    
    parser.add_argument("pipeline", help="Pipeline command string")
    parser.add_argument("-i", "--input", help="Input file or binary path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    console = Console()
    
    # Parse pipeline
    pipeline = parse_pipeline_command(args.pipeline)
    
    # Determine input
    if args.input:
        initial_input = args.input
    elif not sys.stdin.isatty():
        # Read from stdin
        initial_input = sys.stdin.read()
    else:
        console.print("[red]No input provided. Use -i flag or pipe data to stdin.[/red]")
        return
    
    # Execute pipeline
    if args.verbose:
        console.print(f"[bold]Executing pipeline:[/bold] {args.pipeline}")
    
    result = pipeline.execute(initial_input)
    
    if args.verbose:
        console.print("\n[bold green]Pipeline completed![/bold green]")


if __name__ == "__main__":
    main()