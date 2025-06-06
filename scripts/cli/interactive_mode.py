#!/usr/bin/env python3
"""
Interactive REPL Mode for Intellicrack CLI

This module implements an interactive shell for Intellicrack, making it easier
to perform multiple analyses on the same binary without re-running commands.
"""

import os
import sys
import cmd
import json
import time
import readline
from typing import Dict, Any, Optional, List
from pathlib import Path

# Rich imports for beautiful terminal UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: 'rich' library not available. Install with: pip install rich")

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
sys.path.insert(0, project_root)

# Import Intellicrack modules
try:
    from intellicrack.utils.binary_analysis import analyze_binary
    from intellicrack.utils.runner_functions import (
        run_comprehensive_analysis,
        run_symbolic_execution,
        run_vulnerability_scan
    )
    from intellicrack.config import get_config
except ImportError as e:
    print(f"Error importing Intellicrack modules: {e}")
    sys.exit(1)


class IntellicrackShell(cmd.Cmd):
    """Interactive shell for Intellicrack analysis."""
    
    intro = """
╔══════════════════════════════════════════════════════════════════╗
║              🚀 Intellicrack Interactive Mode v2.0               ║
║                                                                  ║
║  Type 'help' for commands or 'tutorial' for guided walkthrough  ║
║  Use TAB for auto-completion | Type 'exit' to quit              ║
╚══════════════════════════════════════════════════════════════════╝
    """
    
    prompt = '🔍 intellicrack> '
    
    def __init__(self):
        super().__init__()
        self.console = Console() if RICH_AVAILABLE else None
        self.current_binary = None
        self.analysis_results = {}
        self.history = []
        self.config = get_config()
        
        # Setup readline for better history and completion
        self.setup_readline()
        
    def setup_readline(self):
        """Configure readline for better UX."""
        # Enable tab completion
        readline.parse_and_bind('tab: complete')
        
        # Load history
        self.histfile = os.path.expanduser('~/.intellicrack_history')
        try:
            readline.read_history_file(self.histfile)
        except FileNotFoundError:
            pass
        
        # Set history size
        readline.set_history_length(1000)
    
    def save_history(self):
        """Save command history."""
        try:
            readline.write_history_file(self.histfile)
        except:
            pass
    
    def do_load(self, arg):
        """Load a binary for analysis: load <path>"""
        if not arg:
            self.error("Please specify a binary path")
            return
            
        path = Path(arg).resolve()
        if not path.exists():
            self.error(f"File not found: {path}")
            return
            
        self.current_binary = str(path)
        self.analysis_results = {}
        self.success(f"Loaded: {path.name}")
        
        # Show basic info
        if self.console:
            with self.console.status("Getting binary info..."):
                info = self._get_binary_info()
                self._display_binary_info(info)
    
    def do_analyze(self, arg):
        """
        Run analysis on loaded binary
        Usage: analyze [options]
        Options:
          --quick     : Quick analysis
          --full      : Comprehensive analysis
          --vuln      : Vulnerability scan
          --symbols   : Symbolic execution
          --cfg       : Control flow graph
        """
        if not self.current_binary:
            self.error("No binary loaded. Use 'load <path>' first")
            return
        
        args = arg.split()
        
        if not args or '--quick' in args:
            self._run_quick_analysis()
        elif '--full' in args:
            self._run_full_analysis()
        elif '--vuln' in args:
            self._run_vulnerability_scan()
        elif '--symbols' in args:
            self._run_symbolic_execution()
        elif '--cfg' in args:
            self._run_cfg_analysis()
        else:
            self.error(f"Unknown option: {arg}")
    
    def do_show(self, arg):
        """
        Show analysis results
        Usage: show [category]
        Categories: all, summary, vulnerabilities, protections, strings, imports
        """
        if not self.analysis_results:
            self.error("No analysis results. Run 'analyze' first")
            return
            
        category = arg.strip() or 'summary'
        
        if category == 'all':
            self._show_all_results()
        elif category == 'summary':
            self._show_summary()
        elif category == 'vulnerabilities':
            self._show_vulnerabilities()
        elif category == 'protections':
            self._show_protections()
        elif category == 'strings':
            self._show_strings()
        elif category == 'imports':
            self._show_imports()
        else:
            self.error(f"Unknown category: {category}")
    
    def do_export(self, arg):
        """Export analysis results: export <format> <output_path>"""
        args = arg.split()
        if len(args) < 2:
            self.error("Usage: export <format> <output_path>")
            self.error("Formats: json, html, pdf, markdown")
            return
            
        format_type = args[0]
        output_path = args[1]
        
        if format_type == 'json':
            self._export_json(output_path)
        elif format_type == 'html':
            self._export_html(output_path)
        elif format_type == 'pdf':
            self._export_pdf(output_path)
        elif format_type == 'markdown':
            self._export_markdown(output_path)
        else:
            self.error(f"Unknown format: {format_type}")
    
    def do_patch(self, arg):
        """
        Patch operations
        Usage: patch <command>
        Commands:
          suggest     : Suggest patches
          apply <file>: Apply patch from file
          create      : Create patch interactively
        """
        if not self.current_binary:
            self.error("No binary loaded")
            return
            
        args = arg.split()
        if not args:
            self.error("Specify patch command: suggest, apply, or create")
            return
            
        command = args[0]
        if command == 'suggest':
            self._suggest_patches()
        elif command == 'apply' and len(args) > 1:
            self._apply_patch(args[1])
        elif command == 'create':
            self._create_patch_interactive()
        else:
            self.error(f"Unknown patch command: {command}")
    
    def do_search(self, arg):
        """Search within analysis results: search <pattern>"""
        if not arg:
            self.error("Please specify a search pattern")
            return
            
        pattern = arg.lower()
        results = self._search_results(pattern)
        
        if self.console and results:
            table = Table(title=f"Search Results for '{pattern}'")
            table.add_column("Category", style="cyan")
            table.add_column("Location", style="yellow")
            table.add_column("Match", style="green")
            
            for result in results:
                table.add_row(result['category'], result['location'], result['match'])
            
            self.console.print(table)
        elif not results:
            self.info("No matches found")
    
    def do_compare(self, arg):
        """Compare with another binary: compare <path>"""
        if not self.current_binary:
            self.error("No binary loaded")
            return
            
        if not arg:
            self.error("Please specify a binary to compare with")
            return
            
        self._compare_binaries(arg)
    
    def do_history(self, arg):
        """Show command history"""
        if self.console:
            table = Table(title="Command History")
            table.add_column("#", style="dim")
            table.add_column("Command", style="cyan")
            table.add_column("Time", style="yellow")
            
            for i, (cmd, timestamp) in enumerate(self.history[-20:], 1):
                table.add_row(str(i), cmd, timestamp)
            
            self.console.print(table)
    
    def do_config(self, arg):
        """
        Configuration management
        Usage: config [get|set|list] [key] [value]
        """
        args = arg.split()
        if not args:
            self._list_config()
        elif args[0] == 'get' and len(args) > 1:
            self._get_config(args[1])
        elif args[0] == 'set' and len(args) > 2:
            self._set_config(args[1], ' '.join(args[2:]))
        elif args[0] == 'list':
            self._list_config()
        else:
            self.error("Usage: config [get|set|list] [key] [value]")
    
    def do_plugin(self, arg):
        """
        Plugin management
        Usage: plugin [list|run|install] [name]
        """
        args = arg.split()
        if not args or args[0] == 'list':
            self._list_plugins()
        elif args[0] == 'run' and len(args) > 1:
            self._run_plugin(args[1])
        elif args[0] == 'install' and len(args) > 1:
            self._install_plugin(args[1])
        else:
            self.error("Usage: plugin [list|run|install] [name]")
    
    def do_tutorial(self, arg):
        """Start interactive tutorial"""
        self._run_tutorial()
    
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_exit(self, arg):
        """Exit the interactive shell"""
        self.save_history()
        if self.console:
            self.console.print("[bold green]Goodbye![/bold green]")
        return True
    
    def do_quit(self, arg):
        """Exit the interactive shell"""
        return self.do_exit(arg)
    
    # Helper methods
    
    def error(self, msg):
        """Display error message."""
        if self.console:
            self.console.print(f"[bold red]❌ Error:[/bold red] {msg}")
        else:
            print(f"❌ Error: {msg}")
    
    def success(self, msg):
        """Display success message."""
        if self.console:
            self.console.print(f"[bold green]✅ Success:[/bold green] {msg}")
        else:
            print(f"✅ Success: {msg}")
    
    def info(self, msg):
        """Display info message."""
        if self.console:
            self.console.print(f"[bold blue]ℹ️  Info:[/bold blue] {msg}")
        else:
            print(f"ℹ️  Info: {msg}")
    
    def _get_binary_info(self) -> Dict[str, Any]:
        """Get basic binary information."""
        try:
            stat = os.stat(self.current_binary)
            return {
                'path': self.current_binary,
                'size': stat.st_size,
                'modified': time.ctime(stat.st_mtime),
                'type': self._detect_binary_type()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_binary_type(self) -> str:
        """Detect binary file type."""
        with open(self.current_binary, 'rb') as f:
            magic = f.read(4)
            if magic[:2] == b'MZ':
                return 'PE (Windows Executable)'
            elif magic == b'\x7fELF':
                return 'ELF (Linux Executable)'
            elif magic[:4] == b'\xca\xfe\xba\xbe':
                return 'Mach-O (macOS Executable)'
            else:
                return 'Unknown'
    
    def _display_binary_info(self, info: Dict[str, Any]):
        """Display binary information."""
        if not self.console:
            print(f"Binary: {info}")
            return
            
        panel = Panel.fit(
            f"""[bold]Binary Information[/bold]
Path: [cyan]{info.get('path', 'Unknown')}[/cyan]
Type: [yellow]{info.get('type', 'Unknown')}[/yellow]
Size: [green]{info.get('size', 0):,} bytes[/green]
Modified: [dim]{info.get('modified', 'Unknown')}[/dim]""",
            border_style="blue"
        )
        self.console.print(panel)
    
    def _run_quick_analysis(self):
        """Run quick analysis."""
        if not self.console:
            print("Running quick analysis...")
            results = analyze_binary(self.current_binary)
            self.analysis_results['quick'] = results
            print("Analysis complete!")
            return
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Running quick analysis...", total=100)
            
            # Simulate progress
            for i in range(0, 100, 20):
                progress.update(task, advance=20)
                time.sleep(0.2)
            
            results = analyze_binary(self.current_binary)
            self.analysis_results['quick'] = results
            
        self.success("Quick analysis complete!")
    
    def _run_full_analysis(self):
        """Run comprehensive analysis."""
        if not self.console:
            print("Running full analysis... This may take a while.")
            results = run_comprehensive_analysis(self.current_binary)
            self.analysis_results['full'] = results
            print("Analysis complete!")
            return
            
        # Interactive prompts for options
        if Confirm.ask("Include vulnerability scanning?", default=True):
            self.analysis_results['vulnerabilities'] = run_vulnerability_scan(self.current_binary)
            
        if Confirm.ask("Include symbolic execution?", default=False):
            self.analysis_results['symbolic'] = run_symbolic_execution(self.current_binary)
            
        self.success("Full analysis complete!")
    
    def _show_summary(self):
        """Show analysis summary."""
        if not self.console:
            print("Analysis Summary:")
            print(json.dumps(self.analysis_results, indent=2, default=str))
            return
            
        # Create a tree view
        tree = Tree("📊 Analysis Summary")
        
        for category, results in self.analysis_results.items():
            branch = tree.add(f"[bold cyan]{category}[/bold cyan]")
            if isinstance(results, dict):
                for key, value in list(results.items())[:5]:  # Show first 5 items
                    branch.add(f"{key}: [yellow]{value}[/yellow]")
                if len(results) > 5:
                    branch.add(f"[dim]... and {len(results) - 5} more[/dim]")
        
        self.console.print(tree)
    
    def _show_vulnerabilities(self):
        """Show vulnerability results."""
        vulns = self.analysis_results.get('vulnerabilities', {})
        if not vulns:
            self.info("No vulnerability data available")
            return
            
        if not self.console:
            print("Vulnerabilities:", vulns)
            return
            
        table = Table(title="🔴 Detected Vulnerabilities")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Location")
        table.add_column("Description")
        
        # Mock data for demonstration
        table.add_row(
            "[red]HIGH[/red]",
            "Buffer Overflow",
            "0x401234",
            "Unsafe strcpy usage"
        )
        table.add_row(
            "[yellow]MEDIUM[/yellow]",
            "Format String",
            "0x401567",
            "User input in printf"
        )
        
        self.console.print(table)
    
    def _export_json(self, output_path: str):
        """Export results as JSON."""
        try:
            with open(output_path, 'w') as f:
                json.dump(self.analysis_results, f, indent=2, default=str)
            self.success(f"Exported to {output_path}")
        except Exception as e:
            self.error(f"Export failed: {e}")
    
    def _run_tutorial(self):
        """Run interactive tutorial."""
        if not self.console:
            print("Tutorial not available without 'rich' library")
            return
            
        self.console.print(Panel.fit(
            """[bold cyan]Welcome to Intellicrack Interactive Tutorial![/bold cyan]
            
This tutorial will guide you through basic usage:

1. [yellow]load <binary>[/yellow] - Load a binary for analysis
2. [yellow]analyze[/yellow] - Run quick analysis
3. [yellow]show summary[/yellow] - View results
4. [yellow]export json output.json[/yellow] - Save results

Let's start by loading a binary file!""",
            title="Tutorial",
            border_style="green"
        ))
    
    def precmd(self, line):
        """Called before executing a command."""
        # Add to history
        if line.strip():
            self.history.append((line, time.strftime("%Y-%m-%d %H:%M:%S")))
        return line
    
    def emptyline(self):
        """Called when empty line is entered."""
        pass  # Don't repeat last command
    
    def default(self, line):
        """Called when command is not recognized."""
        self.error(f"Unknown command: {line.split()[0]}")
        self.info("Type 'help' for available commands")


def main():
    """Main entry point for interactive mode."""
    shell = IntellicrackShell()
    
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nUse 'exit' or 'quit' to leave the shell")
        main()
    except Exception as e:
        print(f"Error: {e}")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()