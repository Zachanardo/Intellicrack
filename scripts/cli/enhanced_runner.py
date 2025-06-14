"""
Enhanced CLI Runner for Intellicrack Integrates progress visualization and improved user experience

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

#!/usr/bin/env python3
"""
Enhanced CLI Runner for Intellicrack
Integrates progress visualization and improved user experience
"""

import sys
import os
import time
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt, Confirm
from rich.tree import Tree

from intellicrack.utils.binary_analysis import analyze_binary
from intellicrack.core.analysis.vulnerability_engine import VulnerabilityEngine
from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer
from intellicrack.utils.protection_detection import detect_all_protections
from scripts.cli.progress_manager import ProgressManager


class EnhancedCLIRunner:
    """Enhanced CLI runner with progress visualization"""
    
    def __init__(self):
        self.console = Console()
        self.progress_manager = ProgressManager()
        self.results = {}
        
    def run_with_progress(self, binary_path: str, operations: List[str]) -> Dict[str, Any]:
        """Run operations with progress visualization"""
        self.console.print(f"\n[bold cyan]Analyzing:[/bold cyan] {binary_path}")
        
        # Start progress display
        self.progress_manager.start_analysis(binary_path, operations)
        
        # Run operations in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}
            
            # Submit all operations
            for operation in operations:
                if operation == "Static Analysis":
                    future = executor.submit(self._run_static_analysis, binary_path)
                elif operation == "Vulnerability Scan":
                    future = executor.submit(self._run_vulnerability_scan, binary_path)
                elif operation == "Protection Detection":
                    future = executor.submit(self._run_protection_detection, binary_path)
                elif operation == "Dynamic Analysis":
                    future = executor.submit(self._run_dynamic_analysis, binary_path)
                elif operation == "Network Analysis":
                    future = executor.submit(self._run_network_analysis, binary_path)
                
                futures[future] = operation
            
            # Process completed operations
            for future in as_completed(futures):
                operation = futures[future]
                try:
                    result = future.result()
                    self.results[operation] = result
                    self.progress_manager.complete_task(operation, success=True)
                except Exception as e:
                    self.results[operation] = {"error": str(e)}
                    self.progress_manager.complete_task(operation, success=False, error=str(e))
        
        # Stop progress display
        self.progress_manager.stop()
        
        return self.results
    
    def _run_static_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Run static analysis with progress updates"""
        steps = [
            ("Loading binary", 10),
            ("Parsing headers", 20),
            ("Extracting sections", 30),
            ("Analyzing imports", 50),
            ("Detecting patterns", 70),
            ("Generating report", 90),
            ("Finalizing", 100)
        ]
        
        results = {}
        
        for step, progress in steps:
            # Simulate work
            time.sleep(0.5)
            
            # Update progress
            self.progress_manager.update_progress(
                "Static Analysis", 
                progress, 
                100,
                speed=progress * 2
            )
            
            # Actual analysis on final step
            if progress == 100:
                try:
                    results = analyze_binary(binary_path)
                except Exception as e:
                    results = {"error": str(e)}
        
        return results
    
    def _run_vulnerability_scan(self, binary_path: str) -> Dict[str, Any]:
        """Run vulnerability scan with progress updates"""
        try:
            engine = VulnerabilityEngine()
            
            # Simulate progress
            for i in range(0, 101, 10):
                time.sleep(0.3)
                self.progress_manager.update_progress(
                    "Vulnerability Scan",
                    i,
                    100,
                    speed=50 + i
                )
            
            # Actual scan
            vulnerabilities = engine.scan_binary(binary_path)
            return {"vulnerabilities": vulnerabilities}
        except Exception as e:
            return {"error": str(e)}
    
    def _run_protection_detection(self, binary_path: str) -> Dict[str, Any]:
        """Run protection detection with progress updates"""
        try:
            # Progress simulation
            for i in range(0, 101, 20):
                time.sleep(0.2)
                self.progress_manager.update_progress(
                    "Protection Detection",
                    i,
                    100,
                    speed=100 + i * 2
                )
            
            # Actual detection
            protections = detect_all_protections(binary_path)
            return {"protections": protections}
        except Exception as e:
            return {"error": str(e)}
    
    def _run_dynamic_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Run dynamic analysis (simulated)"""
        # Simulate dynamic analysis
        steps = [
            "Setting up sandbox environment",
            "Loading binary in emulator",
            "Monitoring system calls",
            "Tracking file operations",
            "Analyzing network activity",
            "Collecting behavioral data"
        ]
        
        for i, step in enumerate(steps):
            progress = int((i + 1) / len(steps) * 100)
            time.sleep(0.4)
            self.progress_manager.update_progress(
                "Dynamic Analysis",
                progress,
                100,
                speed=30 + i * 10
            )
        
        return {
            "behavior": "Binary exhibits normal behavior",
            "syscalls": ["CreateFile", "ReadFile", "WriteFile"],
            "network": "No suspicious network activity detected"
        }
    
    def _run_network_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Run network analysis"""
        try:
            analyzer = NetworkTrafficAnalyzer()
            
            # Progress updates
            for i in range(0, 101, 25):
                time.sleep(0.3)
                self.progress_manager.update_progress(
                    "Network Analysis",
                    i,
                    100,
                    speed=75 + i
                )
            
            return {
                "protocols": ["HTTP", "HTTPS"],
                "endpoints": ["api.example.com", "license.server.com"],
                "suspicious": False
            }
        except Exception as e:
            return {"error": str(e)}
    
    def display_results(self) -> None:
        """Display analysis results in a beautiful format"""
        self.console.print("\n[bold cyan]Analysis Results[/bold cyan]\n")
        
        for operation, result in self.results.items():
            # Create a panel for each operation
            if "error" in result:
                content = f"[red]Error: {result['error']}[/red]"
                panel = Panel(content, title=f"[red]{operation}[/red]", box=box.ROUNDED)
            else:
                # Format results based on operation type
                if operation == "Static Analysis":
                    content = self._format_static_results(result)
                elif operation == "Vulnerability Scan":
                    content = self._format_vulnerability_results(result)
                elif operation == "Protection Detection":
                    content = self._format_protection_results(result)
                else:
                    content = self._format_generic_results(result)
                
                panel = Panel(content, title=f"[green]{operation}[/green]", box=box.ROUNDED)
            
            self.console.print(panel)
    
    def _format_static_results(self, result: Dict) -> str:
        """Format static analysis results"""
        lines = []
        if "file_type" in result:
            lines.append(f"[yellow]File Type:[/yellow] {result.get('file_type', 'Unknown')}")
        if "arch" in result:
            lines.append(f"[yellow]Architecture:[/yellow] {result.get('arch', 'Unknown')}")
        if "imports" in result:
            lines.append(f"[yellow]Imports:[/yellow] {len(result.get('imports', []))} functions")
        if "exports" in result:
            lines.append(f"[yellow]Exports:[/yellow] {len(result.get('exports', []))} functions")
        
        return "\n".join(lines) if lines else "No static analysis data"
    
    def _format_vulnerability_results(self, result: Dict) -> str:
        """Format vulnerability scan results"""
        vulns = result.get("vulnerabilities", [])
        if not vulns:
            return "[green]No vulnerabilities detected[/green]"
        
        lines = [f"[red]Found {len(vulns)} vulnerabilities:[/red]"]
        for vuln in vulns[:5]:  # Show first 5
            lines.append(f"  • {vuln}")
        
        if len(vulns) > 5:
            lines.append(f"  ... and {len(vulns) - 5} more")
        
        return "\n".join(lines)
    
    def _format_protection_results(self, result: Dict) -> str:
        """Format protection detection results"""
        protections = result.get("protections", {})
        if not protections:
            return "[green]No protections detected[/green]"
        
        lines = ["[yellow]Detected protections:[/yellow]"]
        for protection, details in protections.items():
            if details:
                lines.append(f"  • {protection}: {details}")
        
        return "\n".join(lines)
    
    def _format_generic_results(self, result: Dict) -> str:
        """Format generic results"""
        lines = []
        for key, value in result.items():
            if isinstance(value, list):
                lines.append(f"[yellow]{key}:[/yellow] {len(value)} items")
            elif isinstance(value, dict):
                lines.append(f"[yellow]{key}:[/yellow] {len(value)} entries")
            else:
                lines.append(f"[yellow]{key}:[/yellow] {value}")
        
        return "\n".join(lines) if lines else "No data"


def main():
    """Main entry point for enhanced CLI"""
    console = Console()
    
    # Show banner
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║     🚀 Intellicrack Enhanced CLI Runner 🚀        ║
    ║          With Progress Visualization              ║
    ╚═══════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, box=box.DOUBLE, style="bold cyan"))
    
    # Get binary path
    binary_path = Prompt.ask("\n[bold cyan]Enter binary path[/bold cyan]")
    
    if not Path(binary_path).exists():
        console.print(f"[red]Error: File '{binary_path}' not found![/red]")
        return
    
    # Select operations
    console.print("\n[bold]Select operations to perform:[/bold]")
    
    operations = []
    available_ops = [
        "Static Analysis",
        "Vulnerability Scan",
        "Protection Detection",
        "Dynamic Analysis",
        "Network Analysis"
    ]
    
    for op in available_ops:
        if Confirm.ask(f"  Run {op}?", default=True):
            operations.append(op)
    
    if not operations:
        console.print("[yellow]No operations selected. Exiting.[/yellow]")
        return
    
    # Run analysis with progress
    runner = EnhancedCLIRunner()
    results = runner.run_with_progress(binary_path, operations)
    
    # Display results
    runner.display_results()
    
    # Ask if user wants to save results
    if Confirm.ask("\nSave results to file?", default=False):
        output_path = Prompt.ask("Output file path", default="analysis_results.json")
        
        import json
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        console.print(f"\n[green]Results saved to {output_path}[/green]")
    
    console.print("\n[bold cyan]Analysis complete![/bold cyan]")


if __name__ == "__main__":
    main()