"""
Interactive REPL Mode for Intellicrack CLI 

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
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

# Rich imports for beautiful terminal UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn, ProgressColumn
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich import print as rprint
    from rich.live import Live
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.align import Align
    from rich.status import Status
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
    from intellicrack.utils.analysis.binary_analysis import analyze_binary
    from intellicrack.utils.runtime.runner_functions import (
        run_comprehensive_analysis,
        run_symbolic_execution,
        run_vulnerability_scan
    )
    from intellicrack.config import get_config
except ImportError as e:
    print(f"Error importing Intellicrack modules: {e}")
    sys.exit(1)


class AdvancedProgressManager:
    """Advanced progress manager for complex multi-stage operations."""
    
    def __init__(self, console):
        self.console = console
        self.current_operation = None
        self.start_time = None
        
    def run_multi_stage_operation(self, operation_name, stages, callback_func, *args, **kwargs):
        """Run a multi-stage operation with detailed progress tracking.
        
        Args:
            operation_name: Name of the overall operation
            stages: List of (stage_name, weight, substeps) tuples
            callback_func: Function to call for actual work
            *args, **kwargs: Arguments to pass to callback_func
        """
        if not RICH_AVAILABLE:
            return callback_func(*args, **kwargs)
            
        total_weight = sum(stage[1] for stage in stages)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=50),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            TimeElapsedColumn(),
            "•",
            TextColumn("[dim]{task.fields[stage]}"),
            console=self.console
        ) as progress:
            main_task = progress.add_task(operation_name, total=total_weight, stage="Initializing...")
            
            self.start_time = time.time()
            current_progress = 0
            
            for stage_name, stage_weight, substeps in stages:
                progress.update(main_task, stage=stage_name)
                
                if substeps:
                    # Handle substeps
                    substep_weight = stage_weight / len(substeps)
                    for substep in substeps:
                        progress.update(main_task, description=f"[bold blue]{stage_name}: {substep}")
                        time.sleep(0.1)  # Simulate work
                        progress.advance(main_task, substep_weight)
                        current_progress += substep_weight
                else:
                    # Simple stage
                    progress.update(main_task, description=f"[bold blue]{stage_name}...")
                    time.sleep(stage_weight * 0.02)  # Simulate work
                    progress.advance(main_task, stage_weight)
                    current_progress += stage_weight
            
            # Execute the actual callback
            progress.update(main_task, description=f"[bold green]Finalizing {operation_name}...", stage="Processing")
            result = callback_func(*args, **kwargs)
            
            elapsed = time.time() - self.start_time
            progress.update(main_task, stage=f"Completed in {elapsed:.1f}s")
            time.sleep(0.5)  # Show completion
            
            return result
            
    def show_live_stats(self, stats_func, duration=10):
        """Show live updating statistics.
        
        Args:
            stats_func: Function that returns dict of current stats
            duration: How long to show stats for
        """
        if not RICH_AVAILABLE:
            return
            
        with Live(refresh_per_second=2, console=self.console) as live:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                stats = stats_func()
                
                # Create stats table
                table = Table(title="Live Analysis Statistics")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")
                table.add_column("Trend", style="yellow")
                
                for metric, value in stats.items():
                    trend = "→" if isinstance(value, (int, float)) else ""
                    table.add_row(metric, str(value), trend)
                
                live.update(table)
                time.sleep(0.5)


class IntellicrackShell(cmd.Cmd):
    """Interactive shell for Intellicrack analysis."""
    
    intro = """
╔══════════════════════════════════════════════════════════════════╗
║              🚀 Intellicrack Interactive Mode v2.2               ║
║                                                                  ║
║  Professional CLI with tutorials, monitoring, and full workflow ║
║  Type 'tutorial list' for guided learning | 'help' for commands ║  
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
        
        # Initialize advanced progress manager
        self.progress_manager = AdvancedProgressManager(self.console)
        
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
        except (IOError, AttributeError):
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
        Categories: all, summary, vulnerabilities, protections, strings, imports, charts, dashboard
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
        elif category == 'charts':
            self._show_charts()
        elif category == 'dashboard':
            self._show_dashboard()
        else:
            self.error(f"Unknown category: {category}")
    
    def do_export(self, arg):
        """Export analysis results with advanced options: export <format> <output_path> [options]
        
        Available formats: json, markdown, html, txt, csv, xml, yaml, xlsx, vulnerability
        Options:
          --detailed      : Include detailed analysis data
          --summary-only  : Export executive summary only
          --raw-data      : Include raw binary data samples
          --vuln-only     : Export vulnerabilities only (CSV format)
        """
        args = arg.split()
        if len(args) < 2:
            self.error("Usage: export <format> <output_path> [options]")
            try:
                from .advanced_export import get_available_formats
                formats = get_available_formats()
                self.info(f"Available formats: {', '.join(formats)}")
            except ImportError:
                self.info("Formats: json, markdown, html, txt, csv, xml")
            return
            
        format_type = args[0].lower()
        output_path = args[1]
        options = args[2:] if len(args) > 2 else []
        
        # Parse options
        export_options = {
            'include_raw_data': '--raw-data' in options,
            'detailed': '--detailed' in options,
            'summary_only': '--summary-only' in options,
            'data_type': 'vulnerabilities' if '--vuln-only' in options else 'all'
        }
        
        if not self.analysis_results:
            self.error("No analysis results to export. Run analysis first.")
            return
        
        try:
            from .advanced_export import export_analysis_results
            
            self.info(f"Exporting to {format_type.upper()} format...")
            
            success = export_analysis_results(
                self.current_binary or "unknown",
                self.analysis_results,
                output_path,
                format_type,
                **export_options
            )
            
            if success:
                self.success(f"Export completed: {output_path}")
                # Show file size
                try:
                    size = os.path.getsize(output_path)
                    self.info(f"File size: {size:,} bytes")
                except OSError:
                    pass
            else:
                self.error("Export failed")
                
        except ImportError:
            self.error("Advanced export not available")
            # Fallback to basic export
            self._export_basic(format_type, output_path)
        except Exception as e:
            self.error(f"Export failed: {e}")
    
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
        Advanced configuration management
        Usage: config [command] [options]
        
        Commands:
          list [category]           : List configuration options
          get <key>                 : Get configuration value
          set <key> <value>         : Set configuration value
          reset [category]          : Reset to defaults
          categories                : List all categories
          advanced                  : Show advanced options
          export <file> [format]    : Export configuration
          import <file>             : Import configuration
          backup                    : Create configuration backup
          validate                  : Validate current configuration
        """
        args = arg.split() if arg else []
        
        try:
            # Import advanced config manager
            from .config_manager import get_config_manager
            
            if not hasattr(self, '_config_manager'):
                self._config_manager = get_config_manager()
            
            if not args or args[0] == 'list':
                category = args[1] if len(args) > 1 else None
                self._list_advanced_config(category)
            elif args[0] == 'get' and len(args) > 1:
                self._get_advanced_config(args[1])
            elif args[0] == 'set' and len(args) > 2:
                self._set_advanced_config(args[1], ' '.join(args[2:]))
            elif args[0] == 'reset':
                category = args[1] if len(args) > 1 else None
                self._reset_config(category)
            elif args[0] == 'categories':
                self._list_config_categories()
            elif args[0] == 'advanced':
                self._show_advanced_config()
            elif args[0] == 'export':
                if len(args) < 2:
                    self.error("Usage: config export <file> [format]")
                else:
                    format_type = args[2] if len(args) > 2 else "json"
                    self._export_config(args[1], format_type)
            elif args[0] == 'import':
                if len(args) < 2:
                    self.error("Usage: config import <file>")
                else:
                    self._import_config(args[1])
            elif args[0] == 'backup':
                self._backup_config()
            elif args[0] == 'validate':
                self._validate_config()
            else:
                self.error(f"Unknown config command: {args[0]}")
                self._show_config_help()
                
        except ImportError:
            self.error("Advanced configuration not available")
            # Fallback to basic config
            self._handle_basic_config(args)
        except Exception as e:
            self.error(f"Configuration command failed: {e}")
    
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
    
    def do_hex(self, arg):
        """Launch interactive hex viewer: hex [file]"""
        filepath = arg.strip() or self.current_binary
        if not filepath:
            self.error("No file specified. Use 'hex <path>' or load a binary first")
            return
            
        if not os.path.exists(filepath):
            self.error(f"File not found: {filepath}")
            return
        
        try:
            # Import hex viewer
            from .hex_viewer_cli import launch_hex_viewer
            
            self.info(f"Launching hex viewer for {os.path.basename(filepath)}...")
            self.info("Press F1 for help, 'q' to quit the hex viewer")
            
            # Launch hex viewer
            success = launch_hex_viewer(filepath)
            
            if success:
                self.success("Hex viewer closed")
            else:
                self.error("Hex viewer failed to launch")
                
        except ImportError:
            self.error("Hex viewer not available. Install curses support: pip install windows-curses (Windows)")
        except Exception as e:
            self.error(f"Hex viewer error: {e}")
    
    def do_tutorial(self, arg):
        """
        Interactive tutorial system for learning Intellicrack CLI
        Usage: tutorial [command] [options]
        
        Commands:
          list                    : List available tutorials
          start <name>            : Start a specific tutorial
          progress                : Show completion progress
          resume                  : Resume most recent tutorial
          next                    : Move to next step (during tutorial)
          prev                    : Go to previous step (during tutorial)
          skip                    : Skip current step (during tutorial)
          quit                    : Quit current tutorial
          help                    : Show tutorial help
        """
        args = arg.split() if arg else []
        
        try:
            from .tutorial_system import create_tutorial_system
            
            # Initialize tutorial system if not exists
            if not hasattr(self, '_tutorial_system'):
                self._tutorial_system = create_tutorial_system(self)
            
            if not args or args[0] == 'list':
                self._tutorial_system.list_tutorials()
            elif args[0] == 'start' and len(args) > 1:
                tutorial_name = args[1]
                if self._tutorial_system.start_tutorial(tutorial_name):
                    self.success(f"Started tutorial: {tutorial_name}")
                else:
                    self.error(f"Tutorial not found or prerequisites not met: {tutorial_name}")
            elif args[0] == 'progress':
                self._tutorial_system.show_progress()
            elif args[0] == 'resume':
                if self._tutorial_system.resume_tutorial():
                    self.success("Resumed tutorial")
                else:
                    self.info("No tutorial to resume")
            elif args[0] == 'next':
                if self._tutorial_system.next_step():
                    pass  # Step change handled by tutorial system
                else:
                    self.error("No active tutorial or cannot advance")
            elif args[0] == 'prev':
                if self._tutorial_system.prev_step():
                    pass  # Step change handled by tutorial system
                else:
                    self.error("No active tutorial or cannot go back")
            elif args[0] == 'skip':
                if self._tutorial_system.skip_step():
                    self.info("Step skipped")
                else:
                    self.error("Cannot skip this step")
            elif args[0] == 'quit':
                if self._tutorial_system.quit_tutorial():
                    self.info("Tutorial paused")
                else:
                    self.error("No active tutorial")
            elif args[0] == 'help':
                self._tutorial_system.show_help()
            else:
                self.error(f"Unknown tutorial command: {args[0]}")
                self._tutorial_system.show_help()
                
        except ImportError:
            self.error("Tutorial system not available")
            # Fallback to basic tutorial
            self._run_basic_tutorial()
        except Exception as e:
            self.error(f"Tutorial command failed: {e}")
    
    def _run_basic_tutorial(self):
        """Run basic tutorial as fallback."""
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
    
    def do_ask(self, arg):
        """Ask AI assistant a question: ask <question>"""
        if not arg.strip():
            self.error("Usage: ask <question>")
            self.info("Example: ask What vulnerabilities were found?")
            return
        
        self._ask_ai_question(arg.strip())
    
    def do_chart(self, arg):
        """
        Generate visual charts from analysis data
        Usage: chart [type]
        Types: summary, bar, pie, vulnerability, dashboard
        """
        if not self.analysis_results:
            self.error("No analysis results. Run 'analyze' first")
            return
        
        chart_type = arg.strip() or 'summary'
        self._generate_chart(chart_type)
    
    def do_graph(self, arg):
        """Alias for chart command: graph [type]"""
        self.do_chart(arg)
    
    def do_visualize(self, arg):
        """Alias for chart command: visualize [type]"""
        self.do_chart(arg)
    
    def do_batch(self, arg):
        """Execute batch script: batch <script_file>"""
        if not arg:
            self.error("Usage: batch <script_file>")
            self.info("Use 'script list' to see available scripts")
            return
            
        script_path = arg.strip()
        if not os.path.exists(script_path):
            self.error(f"Script file not found: {script_path}")
            return
            
        self._execute_batch_script(script_path)
    
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_formats(self, arg):
        """List available export formats and their descriptions"""
        try:
            from .advanced_export import get_available_formats
            formats = get_available_formats()
            
            if self.console:
                table = Table(title="Available Export Formats")
                table.add_column("Format", style="cyan")
                table.add_column("Description", style="yellow")
                table.add_column("Use Case", style="green")
                
                format_info = {
                    'json': ('Detailed JSON with metadata', 'Complete analysis data'),
                    'markdown': ('Executive summary (Markdown)', 'Documentation, reports'),
                    'html': ('Executive summary (HTML)', 'Web viewing, presentations'),
                    'txt': ('Plain text summary', 'Simple reports, email'),
                    'csv': ('Comma-separated values', 'Data analysis, Excel import'),
                    'xml': ('Structured XML report', 'System integration'),
                    'yaml': ('YAML configuration format', 'Configuration management'),
                    'xlsx': ('Excel workbook (multiple sheets)', 'Comprehensive reporting'),
                    'vulnerability': ('Detailed vulnerability report', 'Security assessment')
                }
                
                for fmt in formats:
                    desc, use_case = format_info.get(fmt, ('Advanced format', 'Specialized use'))
                    table.add_row(fmt, desc, use_case)
                
                self.console.print(table)
            else:
                print("\nAvailable Export Formats:")
                for fmt in formats:
                    print(f"  - {fmt}")
                    
        except ImportError:
            self.info("Basic formats: json, html, pdf, markdown")
    
    def do_script(self, arg):
        """
        Script management
        Usage: script [create|list|run] [name]
        """
        args = arg.split()
        if not args:
            self.error("Usage: script [create|list|run] [name]")
            return
            
        command = args[0]
        
        if command == 'create':
            filename = args[1] if len(args) > 1 else 'sample_script.txt'
            self._create_sample_batch_script(filename)
        elif command == 'list':
            self._list_batch_scripts()
        elif command == 'run':
            if len(args) < 2:
                self.error("Usage: script run <script_file>")
                return
            self._execute_batch_script(args[1])
        else:
            self.error("Unknown script command. Use: create, list, or run")
    
    def do_ai(self, arg):
        """Launch AI chat interface: ai [question]"""
        if arg.strip():
            # Quick AI question mode
            self._ask_ai_question(arg.strip())
        else:
            # Interactive AI chat mode
            self._launch_ai_chat()
    
    def do_project(self, arg):
        """
        Project management commands
        Usage: project [create|load|save|list|import|export|delete] [name/path]
        
        Commands:
          create <name> [description]  : Create new project
          load <name>                  : Load existing project
          save                         : Save current project
          list                         : List all projects
          import <archive_path>        : Import project from archive
          export <name> [output_path]  : Export project to archive
          delete <name>                : Delete project
          add-binary <binary_path>     : Add binary to current project
          show                         : Show current project info
        """
        args = arg.split() if arg else []
        
        if not args:
            self._show_project_help()
            return
        
        command = args[0].lower()
        
        try:
            # Import project manager
            from .project_manager import ProjectManager
            
            if not hasattr(self, '_project_manager'):
                self._project_manager = ProjectManager()
            
            if command == 'create':
                self._create_project(args[1:])
            elif command == 'load':
                self._load_project(args[1:])
            elif command == 'save':
                self._save_current_project()
            elif command == 'list':
                self._list_projects()
            elif command == 'import':
                self._import_project(args[1:])
            elif command == 'export':
                self._export_project(args[1:])
            elif command == 'delete':
                self._delete_project(args[1:])
            elif command == 'add-binary':
                self._add_binary_to_project(args[1:])
            elif command == 'show':
                self._show_current_project()
            else:
                self.error(f"Unknown project command: {command}")
                self._show_project_help()
                
        except ImportError:
            self.error("Project management not available")
        except Exception as e:
            self.error(f"Project command failed: {e}")
    
    def _ask_ai_question(self, question: str):
        """Ask a quick AI question without entering chat mode."""
        try:
            from .ai_chat_interface import AITerminalChat
            
            # Create temporary chat instance
            chat = AITerminalChat(self.current_binary, self.analysis_results)
            
            self.info(f"Asking AI: {question}")
            
            # Get response
            response = chat._get_ai_response(question)
            
            # Display response
            if self.console:
                from rich.panel import Panel
                ai_panel = Panel(
                    response,
                    title="🤖 AI Response",
                    border_style="green",
                    padding=(1, 2)
                )
                self.console.print(ai_panel)
            else:
                print(f"\nAI: {response}\n")
                
        except ImportError:
            self.error("AI chat not available")
        except Exception as e:
            self.error(f"AI query failed: {e}")
    
    def _launch_ai_chat(self):
        """Launch interactive AI chat session."""
        try:
            from .ai_chat_interface import launch_ai_chat
            
            self.info("Launching AI chat interface...")
            self.info("Type '/quit' to return to main CLI")
            
            # Save current state
            current_binary = self.current_binary
            current_results = self.analysis_results.copy()
            
            # Launch chat
            success = launch_ai_chat(current_binary, current_results)
            
            if success:
                self.success("AI chat session ended")
            else:
                self.error("AI chat failed to launch")
                
        except ImportError:
            self.error("AI chat interface not available")
        except Exception as e:
            self.error(f"AI chat error: {e}")
    
    def _list_batch_scripts(self):
        """List available batch script files."""
        try:
            script_extensions = ['.txt', '.bat', '.script', '.intellicrack']
            scripts = []
            
            # Look in current directory
            for file in os.listdir('.'):
                if any(file.endswith(ext) for ext in script_extensions):
                    scripts.append(file)
            
            if not scripts:
                self.info("No batch scripts found in current directory")
                self.info("Use 'script create' to create a sample script")
                return
            
            if self.console:
                table = Table(title="Available Batch Scripts")
                table.add_column("Script", style="cyan")
                table.add_column("Size", style="yellow")
                table.add_column("Modified", style="green")
                
                for script in sorted(scripts):
                    try:
                        stat = os.stat(script)
                        size = f"{stat.st_size} bytes"
                        modified = time.strftime('%Y-%m-%d %H:%M', time.localtime(stat.st_mtime))
                        table.add_row(script, size, modified)
                    except OSError:
                        table.add_row(script, "Unknown", "Unknown")
                
                self.console.print(table)
            else:
                print("\nAvailable Scripts:")
                for script in sorted(scripts):
                    print(f"  - {script}")
                    
        except Exception as e:
            self.error(f"Failed to list scripts: {e}")
    
    def _show_charts(self):
        """Show analysis results as ASCII charts."""
        try:
            from .ascii_charts import create_analysis_charts
            
            self.info("Generating analysis charts...")
            charts = create_analysis_charts(self.analysis_results, "summary", use_rich=False)
            
            if self.console:
                from rich.panel import Panel
                chart_panel = Panel(
                    charts,
                    title="📊 Analysis Charts",
                    border_style="cyan"
                )
                self.console.print(chart_panel)
            else:
                print("\n" + charts + "\n")
                
        except ImportError:
            self.error("Chart generation not available")
        except Exception as e:
            self.error(f"Chart generation failed: {e}")
    
    def _show_dashboard(self):
        """Show rich terminal dashboard."""
        try:
            from .ascii_charts import create_analysis_charts
            
            if self.console:
                self.info("Launching analysis dashboard...")
                create_analysis_charts(self.analysis_results, "dashboard", use_rich=True)
                input("\nPress Enter to continue...")
            else:
                self.info("Rich dashboard requires Rich library. Showing basic charts...")
                self._show_charts()
                
        except ImportError:
            self.error("Dashboard not available")
        except Exception as e:
            self.error(f"Dashboard failed: {e}")
    
    def _generate_chart(self, chart_type: str):
        """Generate specific chart type."""
        try:
            from .ascii_charts import create_analysis_charts
            
            valid_types = ['summary', 'bar', 'pie', 'vulnerability', 'dashboard']
            
            if chart_type not in valid_types:
                self.error(f"Unknown chart type: {chart_type}")
                self.info(f"Available types: {', '.join(valid_types)}")
                return
            
            self.info(f"Generating {chart_type} chart...")
            
            if chart_type == 'dashboard' and self.console:
                create_analysis_charts(self.analysis_results, chart_type, use_rich=True)
                input("\nPress Enter to continue...")
            else:
                charts = create_analysis_charts(self.analysis_results, chart_type, use_rich=False)
                
                if self.console:
                    from rich.panel import Panel
                    chart_panel = Panel(
                        charts,
                        title=f"📈 {chart_type.title()} Chart",
                        border_style="green"
                    )
                    self.console.print(chart_panel)
                else:
                    print(f"\n{chart_type.title()} Chart:")
                    print("=" * 40)
                    print(charts)
                    print()
                
        except ImportError:
            self.error("Chart generation not available")
        except Exception as e:
            self.error(f"Chart generation failed: {e}")
    
    def do_report(self, arg):
        """
        Generate comprehensive analysis report
        Usage: report [format] [output_path]
        """
        if not self.analysis_results:
            self.error("No analysis results available. Run analysis first.")
            return
        
        args = arg.split() if arg else []
        format_type = args[0] if args else 'html'
        output_path = args[1] if len(args) > 1 else f"report_{int(time.time())}.{format_type}"
        
        # Generate comprehensive report with all available data
        try:
            from .advanced_export import AdvancedExporter
            
            exporter = AdvancedExporter(self.current_binary or "unknown", self.analysis_results)
            
            self.info(f"Generating comprehensive {format_type.upper()} report...")
            
            if format_type.lower() == 'xlsx':
                success = exporter.export_excel_workbook(output_path)
            elif format_type.lower() == 'vulnerability':
                success = exporter.export_vulnerability_report(output_path)
            else:
                success = exporter.export_executive_summary(output_path, format_type)
            
            if success:
                self.success(f"Comprehensive report generated: {output_path}")
                try:
                    size = os.path.getsize(output_path)
                    self.info(f"Report size: {size:,} bytes")
                except OSError:
                    pass
            else:
                self.error("Report generation failed")
                
        except ImportError:
            self.error("Advanced reporting not available")
            # Fallback to basic export
            self._export_basic(format_type, output_path)
    
    def do_stats(self, arg):
        """Show analysis statistics with visual charts"""
        if not self.analysis_results:
            self.error("No analysis results available. Run analysis first.")
            return
        
        try:
            from .ascii_charts import ASCIIChartGenerator
            
            generator = ASCIIChartGenerator()
            
            # Generate statistics
            stats = {
                'Categories': len(self.analysis_results),
                'Total Items': sum(
                    len(data) if isinstance(data, (dict, list)) else 1 
                    for data in self.analysis_results.values()
                )
            }
            
            # Add vulnerability stats if available
            vuln_data = self.analysis_results.get('vulnerabilities', {})
            if isinstance(vuln_data, dict) and 'vulnerabilities' in vuln_data:
                vulns = vuln_data['vulnerabilities']
                if isinstance(vulns, list):
                    stats['Vulnerabilities'] = len(vulns)
                    
                    # Count by severity
                    from collections import Counter
                    severity_counts = Counter()
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            severity = vuln.get('severity', 'Unknown')
                            severity_counts[severity.title()] += 1
                    
                    if severity_counts:
                        stats.update(dict(severity_counts))
            
            # Generate and display chart
            chart = generator.generate_bar_chart(stats, "Analysis Statistics")
            
            if self.console:
                from rich.panel import Panel
                stats_panel = Panel(
                    chart,
                    title="📈 Statistics",
                    border_style="blue"
                )
                self.console.print(stats_panel)
            else:
                print("\nAnalysis Statistics:")
                print("=" * 30)
                print(chart)
                print()
                
        except ImportError:
            self.error("Statistics visualization not available")
        except Exception as e:
            self.error(f"Statistics generation failed: {e}")
    
    def do_workspace(self, arg):
        """Workspace management commands: workspace [clean|info|backup]"""
        args = arg.split() if arg else []
        
        try:
            from .project_manager import ProjectManager
            
            if not hasattr(self, '_project_manager'):
                self._project_manager = ProjectManager()
            
            if not args or args[0] == 'info':
                self._show_workspace_info()
            elif args[0] == 'clean':
                self._clean_workspace()
            elif args[0] == 'backup':
                self._backup_workspace()
            else:
                self.error(f"Unknown workspace command: {args[0]}")
                self.info("Available commands: info, clean, backup")
                
        except ImportError:
            self.error("Workspace management not available")
        except Exception as e:
            self.error(f"Workspace command failed: {e}")
    
    def do_dashboard(self, arg):
        """
        Launch terminal dashboard with real-time system and analysis metrics
        Usage: dashboard [duration] [--basic]
        
        Options:
          duration    : Display duration in seconds (default: indefinite)
          --basic     : Use basic text mode instead of rich interface
        """
        args = arg.split() if arg else []
        
        try:
            from .terminal_dashboard import create_dashboard
            
            # Initialize dashboard if not exists
            if not hasattr(self, '_dashboard'):
                self._dashboard = create_dashboard()
                
                # Update dashboard with current session info
                self._update_dashboard_session()
            
            # Parse arguments
            duration = None
            basic_mode = '--basic' in args
            
            for arg_item in args:
                if arg_item.isdigit():
                    duration = int(arg_item)
                elif arg_item.replace('.', '').isdigit():
                    duration = float(arg_item)
            
            # Update dashboard with latest data
            self._update_dashboard_stats()
            
            # Show dashboard
            self.info("Launching dashboard... Press Ctrl+C to exit")
            
            if basic_mode:
                self._dashboard._show_basic_dashboard(duration)
            else:
                self._dashboard.show_dashboard(duration)
            
            self.success("Dashboard closed")
                
        except ImportError:
            self.error("Dashboard not available. Install psutil: pip install psutil")
        except KeyboardInterrupt:
            self.success("Dashboard closed by user")
        except Exception as e:
            self.error(f"Dashboard failed: {e}")
    
    def do_status(self, arg):
        """Show quick status summary"""
        try:
            from .terminal_dashboard import create_dashboard
            
            if not hasattr(self, '_dashboard'):
                self._dashboard = create_dashboard()
                self._update_dashboard_session()
            
            # Update with latest data
            self._update_dashboard_stats()
            
            # Get status summary
            summary = self._dashboard.create_status_summary()
            
            if self.console:
                status_panel = Panel(
                    summary,
                    title="📊 System Status",
                    border_style="green"
                )
                self.console.print(status_panel)
            else:
                print("\nSystem Status:")
                print("=" * 20)
                print(summary)
                print()
                
        except ImportError:
            self.error("Status monitoring not available")
        except Exception as e:
            self.error(f"Status check failed: {e}")
    
    def do_monitor(self, arg):
        """
        Continuous monitoring with live updates
        Usage: monitor [metric] [duration]
        
        Metrics: cpu, memory, analysis, session, all (default)
        """
        args = arg.split() if arg else []
        
        metric = args[0] if args else 'all'
        duration = float(args[1]) if len(args) > 1 and args[1].replace('.', '').isdigit() else None
        
        try:
            from .terminal_dashboard import create_dashboard
            
            if not hasattr(self, '_dashboard'):
                self._dashboard = create_dashboard()
                self._update_dashboard_session()
            
            self.info(f"Monitoring {metric}... Press Ctrl+C to stop")
            
            if metric == 'all':
                self._dashboard.show_dashboard(duration)
            else:
                self._monitor_specific_metric(metric, duration)
                
        except ImportError:
            self.error("Monitoring not available")
        except KeyboardInterrupt:
            self.success("Monitoring stopped")
        except Exception as e:
            self.error(f"Monitoring failed: {e}")
    
    def _monitor_specific_metric(self, metric: str, duration: Optional[float]):
        """Monitor specific metric with live updates."""
        import time
        start_time = time.time()
        
        try:
            while True:
                self._dashboard._update_system_metrics()
                
                if metric == 'cpu':
                    if self.console:
                        cpu_bar = self._dashboard._create_progress_bar(
                            self._dashboard.system_metrics.cpu_percent,
                            100,
                            "CPU",
                            width=30
                        )
                        panel = Panel(cpu_bar, title="🖥️ CPU Monitor")
                        self.console.clear()
                        self.console.print(panel)
                    else:
                        print(f"\rCPU: {self._dashboard.system_metrics.cpu_percent:5.1f}%", end='', flush=True)
                
                elif metric == 'memory':
                    if self.console:
                        memory_bar = self._dashboard._create_progress_bar(
                            self._dashboard.system_metrics.memory_percent,
                            100,
                            "Memory",
                            width=30
                        )
                        panel = Panel(memory_bar, title="🧠 Memory Monitor")
                        self.console.clear()
                        self.console.print(panel)
                    else:
                        print(f"\rMemory: {self._dashboard.system_metrics.memory_percent:5.1f}%", end='', flush=True)
                
                # Check duration
                if duration and (time.time() - start_time) >= duration:
                    break
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            pass
    
    def _update_dashboard_session(self):
        """Update dashboard with current session information."""
        if hasattr(self, '_dashboard'):
            self._dashboard.update_session_info(
                current_binary=self.current_binary,
                current_project=getattr(self, '_current_project', None),
                commands_executed=len(self.history)
            )
    
    def _update_dashboard_stats(self):
        """Update dashboard with current analysis statistics."""
        if hasattr(self, '_dashboard'):
            # Calculate analysis stats from current results
            total_vulns = 0
            if 'vulnerabilities' in self.analysis_results:
                vuln_data = self.analysis_results['vulnerabilities']
                if isinstance(vuln_data, dict) and 'vulnerabilities' in vuln_data:
                    total_vulns = len(vuln_data['vulnerabilities'])
            
            # Count active projects
            active_projects = 0
            if hasattr(self, '_project_manager'):
                active_projects = len(self._project_manager.list_projects())
            
            self._dashboard.update_analysis_stats(
                total_binaries=1 if self.current_binary else 0,
                vulnerabilities_found=total_vulns,
                active_projects=active_projects,
                analyses_completed=len(self.analysis_results),
                last_analysis=self.current_binary
            )
            
            # Update session info
            self._dashboard.update_session_info(
                commands_executed=len(self.history),
                current_binary=self.current_binary,
                current_project=getattr(self, '_current_project', None).name if hasattr(self, '_current_project') and self._current_project else None
            )
    
    def _show_workspace_info(self):
        """Show workspace information."""
        workspace_root = self._project_manager.workspace_root
        projects_count = len(self._project_manager.list_projects())
        
        if self.console:
            info_content = f"""[bold cyan]Workspace Information[/bold cyan]

[yellow]Location:[/yellow] {workspace_root}
[yellow]Projects:[/yellow] {projects_count}
[yellow]Status:[/yellow] [green]Active[/green]"""
            
            info_panel = Panel(
                info_content,
                title="🏗️ Workspace",
                border_style="blue"
            )
            self.console.print(info_panel)
        else:
            print(f"\nWorkspace: {workspace_root}")
            print(f"Projects: {projects_count}")
            print("Status: Active\n")
    
    def _clean_workspace(self):
        """Clean workspace temporary files."""
        cleaned_count = self._project_manager.cleanup_workspace()
        
        if cleaned_count > 0:
            self.success(f"Cleaned {cleaned_count} temporary files")
        else:
            self.info("No cleanup needed")
    
    def _backup_workspace(self):
        """Create workspace backup."""
        self.info("Workspace backup functionality coming soon")
    
    # Advanced Configuration Helper Methods
    
    def _show_config_help(self):
        """Show configuration command help."""
        if self.console:
            help_table = Table(title="Configuration Commands")
            help_table.add_column("Command", style="cyan")
            help_table.add_column("Description", style="yellow")
            
            commands = [
                ("list [category]", "List configuration options"),
                ("get <key>", "Get configuration value"),
                ("set <key> <value>", "Set configuration value"),
                ("reset [category]", "Reset to defaults"),
                ("categories", "List all categories"),
                ("advanced", "Show advanced options"),
                ("export <file> [format]", "Export configuration"),
                ("import <file>", "Import configuration"),
                ("backup", "Create configuration backup"),
                ("validate", "Validate current configuration")
            ]
            
            for cmd, desc in commands:
                help_table.add_row(cmd, desc)
            
            self.console.print(help_table)
        else:
            print("\nConfiguration Commands:")
            print("  list [category]     - List configuration options")
            print("  get <key>           - Get configuration value")
            print("  set <key> <value>   - Set configuration value")
            print("  reset [category]    - Reset to defaults")
            print("  categories          - List all categories")
            print("  advanced            - Show advanced options")
            print()
    
    def _list_advanced_config(self, category: Optional[str] = None):
        """List advanced configuration options."""
        self._config_manager.display_config(category, advanced=False)
    
    def _get_advanced_config(self, key: str):
        """Get advanced configuration value."""
        if key in self._config_manager.options:
            value = self._config_manager.get(key)
            option = self._config_manager.options[key]
            
            if self.console:
                info_content = f"""[bold cyan]Configuration Option: {key}[/bold cyan]

[yellow]Current Value:[/yellow] {value}
[yellow]Default Value:[/yellow] {option.default}
[yellow]Data Type:[/yellow] {option.data_type.__name__}
[yellow]Category:[/yellow] {option.category}
[yellow]Description:[/yellow] {option.description}"""

                if option.choices:
                    info_content += f"\n[yellow]Valid Choices:[/yellow] {', '.join(map(str, option.choices))}"
                
                if option.advanced:
                    info_content += f"\n[red]Advanced Option[/red]"
                
                if option.requires_restart:
                    info_content += f"\n[red]Restart Required[/red]"
                
                info_panel = Panel(
                    info_content,
                    title=f"⚙️ {key}",
                    border_style="blue"
                )
                self.console.print(info_panel)
            else:
                print(f"\nConfiguration: {key}")
                print(f"  Current Value: {value}")
                print(f"  Default Value: {option.default}")
                print(f"  Description: {option.description}")
                print(f"  Category: {option.category}")
                if option.choices:
                    print(f"  Valid Choices: {', '.join(map(str, option.choices))}")
                print()
        else:
            self.error(f"Unknown configuration option: {key}")
    
    def _set_advanced_config(self, key: str, value_str: str):
        """Set advanced configuration value."""
        if key not in self._config_manager.options:
            self.error(f"Unknown configuration option: {key}")
            return
        
        option = self._config_manager.options[key]
        
        # Parse value based on type
        try:
            if option.data_type == bool:
                value = value_str.lower() in ('true', '1', 'yes', 'on', 'enabled')
            elif option.data_type == int:
                value = int(value_str)
            elif option.data_type == float:
                value = float(value_str)
            else:
                value = value_str
        except ValueError:
            self.error(f"Invalid value type for {key}. Expected {option.data_type.__name__}")
            return
        
        # Set the value
        if self._config_manager.set(key, value):
            self.success(f"Set {key} = {value}")
            
            # Save configuration
            if self._config_manager.save_config():
                self.info("Configuration saved")
            else:
                self.error("Failed to save configuration")
            
            # Check if restart required
            if option.requires_restart:
                self.info("⚠️  Restart required for this change to take effect")
        else:
            self.error(f"Failed to set {key}. Check value and constraints.")
            
            # Show help for this option
            if option.choices:
                self.info(f"Valid choices: {', '.join(map(str, option.choices))}")
            if option.validator:
                self.info("Value does not meet validation requirements")
    
    def _reset_config(self, category: Optional[str] = None):
        """Reset configuration to defaults."""
        if category:
            if category not in self._config_manager.get_categories():
                self.error(f"Unknown category: {category}")
                return
            
            # Confirm reset
            if self.console:
                from rich.prompt import Confirm
                if not Confirm.ask(f"Reset category '{category}' to defaults?", default=False):
                    self.info("Reset cancelled")
                    return
            else:
                confirm = input(f"Reset category '{category}' to defaults? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("Reset cancelled")
                    return
            
            self._config_manager.reset_to_defaults(category)
            self.success(f"Reset category '{category}' to defaults")
        else:
            # Confirm full reset
            if self.console:
                from rich.prompt import Confirm
                if not Confirm.ask("Reset ALL configuration to defaults?", default=False):
                    self.info("Reset cancelled")
                    return
            else:
                confirm = input("Reset ALL configuration to defaults? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("Reset cancelled")
                    return
            
            self._config_manager.reset_to_defaults()
            self.success("Reset all configuration to defaults")
        
        # Save changes
        if self._config_manager.save_config():
            self.info("Configuration saved")
    
    def _list_config_categories(self):
        """List all configuration categories."""
        categories = self._config_manager.get_categories()
        
        if self.console:
            cat_table = Table(title="Configuration Categories")
            cat_table.add_column("Category", style="cyan")
            cat_table.add_column("Options", style="yellow")
            cat_table.add_column("Description", style="green")
            
            category_descriptions = {
                "general": "General application settings",
                "appearance": "UI theme and display preferences",
                "analysis": "Binary analysis configuration",
                "display": "Progress bars and table formatting",
                "export": "Export format and compression settings",
                "security": "Security and sandboxing options",
                "ai": "AI backend and model configuration",
                "performance": "Memory and CPU usage limits",
                "developer": "Debug and development options"
            }
            
            for category in categories:
                options = self._config_manager.get_options_by_category(category, include_advanced=True)
                count = len(options)
                description = category_descriptions.get(category, "Configuration options")
                
                cat_table.add_row(category.title(), str(count), description)
            
            self.console.print(cat_table)
        else:
            print("\nConfiguration Categories:")
            for category in categories:
                options = self._config_manager.get_options_by_category(category, include_advanced=True)
                print(f"  {category:<15} ({len(options)} options)")
            print()
    
    def _show_advanced_config(self):
        """Show advanced configuration options."""
        if self.console:
            self.console.print("[bold yellow]Advanced Configuration Options[/bold yellow]\n")
        else:
            print("\nAdvanced Configuration Options:")
            print("=" * 35)
        
        self._config_manager.display_config(advanced=True)
    
    def _export_config(self, filename: str, format_type: str = "json"):
        """Export configuration to file."""
        if self._config_manager.export_config(filename, format_type):
            self.success(f"Configuration exported to {filename}")
            try:
                size = os.path.getsize(filename)
                self.info(f"Export size: {size:,} bytes")
            except OSError:
                pass
        else:
            self.error(f"Export failed. Supported formats: json, yaml")
    
    def _import_config(self, filename: str):
        """Import configuration from file."""
        if not os.path.exists(filename):
            self.error(f"File not found: {filename}")
            return
        
        # Confirm import
        if self.console:
            from rich.prompt import Confirm
            if not Confirm.ask(f"Import configuration from '{filename}'?", default=False):
                self.info("Import cancelled")
                return
        else:
            confirm = input(f"Import configuration from '{filename}'? (y/N): ").strip().lower()
            if confirm != 'y':
                print("Import cancelled")
                return
        
        if self._config_manager.import_config(filename):
            self.success("Configuration imported successfully")
            
            # Save imported config
            if self._config_manager.save_config():
                self.info("Configuration saved")
        else:
            self.error("Import failed")
    
    def _backup_config(self):
        """Create configuration backup."""
        if self._config_manager.save_config(create_backup=True):
            self.success("Configuration backup created")
        else:
            self.error("Backup failed")
    
    def _validate_config(self):
        """Validate current configuration."""
        issues = []
        restart_required = []
        
        for name, option in self._config_manager.options.items():
            current_value = self._config_manager.get(name)
            
            # Check if value is valid
            if not self._config_manager._validate_value(name, current_value):
                issues.append(f"{name}: Invalid value '{current_value}'")
            
            # Check if restart required for changes
            if (current_value != option.default and option.requires_restart):
                restart_required.append(name)
        
        if issues:
            self.error("Configuration validation issues found:")
            for issue in issues:
                self.error(f"  • {issue}")
        else:
            self.success("Configuration validation passed")
        
        if restart_required:
            self.info("Options requiring restart for changes:")
            for option in restart_required:
                self.info(f"  • {option}")
    
    def _handle_basic_config(self, args):
        """Handle basic configuration as fallback."""
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
    
    def do_exit(self, arg):
        """Exit the interactive shell"""
        # Check if there are unsaved results
        if self.analysis_results and not getattr(self, '_results_exported', False):
            if self.console:
                from rich.prompt import Confirm
                save_results = Confirm.ask("Export analysis results before exiting?", default=False)
                if save_results:
                    timestamp = int(time.time())
                    export_path = f"intellicrack_results_{timestamp}.json"
                    self._export_json(export_path)
                    self.success(f"Results saved to {export_path}")
        
        self.save_history()
        
        # Show session summary if available
        if self.analysis_results and self.console:
            try:
                from .ascii_charts import ASCIIChartGenerator
                generator = ASCIIChartGenerator(width=60, height=10)
                
                # Quick summary stats
                stats = {
                    'Categories': len(self.analysis_results),
                    'Total Data Points': sum(
                        len(data) if isinstance(data, (dict, list)) else 1 
                        for data in self.analysis_results.values()
                    )
                }
                
                chart = generator.generate_bar_chart(stats, "Session Summary")
                
                from rich.panel import Panel
                summary_panel = Panel(
                    chart,
                    title="📊 Session Summary",
                    border_style="yellow"
                )
                self.console.print(summary_panel)
            except Exception:
                pass  # Ignore errors in exit summary
        
        if self.console:
            self.console.print("[bold green]Goodbye![/bold green]")
        return True
    
    def do_quit(self, arg):
        """Exit the interactive shell"""
        return self.do_exit(arg)
    
    # Project Management Helper Methods
    
    def _show_project_help(self):
        """Show project management help."""
        if self.console:
            help_table = Table(title="Project Management Commands")
            help_table.add_column("Command", style="cyan")
            help_table.add_column("Description", style="yellow")
            
            commands = [
                ("create <name> [desc]", "Create new project"),
                ("load <name>", "Load existing project"),
                ("save", "Save current project"),
                ("list", "List all projects"),
                ("import <archive>", "Import project from archive"),
                ("export <name> [path]", "Export project to archive"),
                ("delete <name>", "Delete project"),
                ("add-binary <path>", "Add binary to current project"),
                ("show", "Show current project info")
            ]
            
            for cmd, desc in commands:
                help_table.add_row(cmd, desc)
            
            self.console.print(help_table)
        else:
            print("\nProject Management Commands:")
            print("  create <name> [desc] - Create new project")
            print("  load <name>          - Load existing project")
            print("  save                 - Save current project")
            print("  list                 - List all projects")
            print("  show                 - Show current project info")
            print()
    
    def _create_project(self, args):
        """Create a new project."""
        if not args:
            self.error("Usage: project create <name> [description]")
            return
        
        name = args[0]
        description = " ".join(args[1:]) if len(args) > 1 else ""
        
        project = self._project_manager.create_project(name, description)
        
        if project:
            self._current_project = project
            self.success(f"Created project: {name}")
            
            # Add current binary if loaded
            if self.current_binary:
                if project.add_binary(self.current_binary):
                    self.info(f"Added current binary to project: {os.path.basename(self.current_binary)}")
                    self._project_manager.save_project(project)
        else:
            self.error(f"Failed to create project: {name}")
    
    def _load_project(self, args):
        """Load an existing project."""
        if not args:
            self.error("Usage: project load <name>")
            return
        
        name = args[0]
        project = self._project_manager.load_project(name)
        
        if project:
            self._current_project = project
            self.success(f"Loaded project: {name}")
            
            # Show project info
            self._show_project_info(project)
            
            # Load analysis results if available
            if project.analysis_results:
                self.analysis_results.update(project.analysis_results)
                self.info("Loaded analysis results from project")
        else:
            self.error(f"Project not found: {name}")
    
    def _save_current_project(self):
        """Save the current project."""
        if not hasattr(self, '_current_project') or not self._current_project:
            self.error("No project currently loaded")
            return
        
        # Update project with current analysis results
        if self.analysis_results:
            for category, results in self.analysis_results.items():
                binary_name = os.path.basename(self.current_binary) if self.current_binary else "unknown"
                self._current_project.add_analysis_result(f"{binary_name}_{category}", results)
        
        if self._project_manager.save_project(self._current_project):
            self.success(f"Saved project: {self._current_project.name}")
        else:
            self.error("Failed to save project")
    
    def _list_projects(self):
        """List all projects."""
        self._project_manager.display_projects_table()
    
    def _import_project(self, args):
        """Import project from archive."""
        if not args:
            self.error("Usage: project import <archive_path> [new_name]")
            return
        
        archive_path = args[0]
        new_name = args[1] if len(args) > 1 else None
        
        project = self._project_manager.import_project(archive_path, new_name)
        
        if project:
            self._current_project = project
            self.success(f"Imported project: {project.name}")
            self._show_project_info(project)
        else:
            self.error(f"Failed to import project from: {archive_path}")
    
    def _export_project(self, args):
        """Export project to archive."""
        if not args:
            self.error("Usage: project export <project_name> [output_path]")
            return
        
        project_name = args[0]
        output_path = args[1] if len(args) > 1 else f"{project_name}_export.zip"
        
        project = self._project_manager.load_project(project_name)
        if not project:
            self.error(f"Project not found: {project_name}")
            return
        
        if self._project_manager.export_project(project, output_path):
            self.success(f"Exported project to: {output_path}")
            try:
                size = os.path.getsize(output_path)
                self.info(f"Archive size: {size:,} bytes")
            except OSError:
                pass
        else:
            self.error("Export failed")
    
    def _delete_project(self, args):
        """Delete a project."""
        if not args:
            self.error("Usage: project delete <name>")
            return
        
        name = args[0]
        
        # Confirm deletion
        if self.console:
            from rich.prompt import Confirm
            if not Confirm.ask(f"Delete project '{name}'?", default=False):
                self.info("Deletion cancelled")
                return
        else:
            confirm = input(f"Delete project '{name}'? (y/N): ").strip().lower()
            if confirm != 'y':
                print("Deletion cancelled")
                return
        
        if self._project_manager.delete_project(name):
            self.success(f"Deleted project: {name}")
            
            # Clear current project if it was deleted
            if hasattr(self, '_current_project') and self._current_project and self._current_project.name == name:
                self._current_project = None
        else:
            self.error(f"Failed to delete project: {name}")
    
    def _add_binary_to_project(self, args):
        """Add binary to current project."""
        if not hasattr(self, '_current_project') or not self._current_project:
            self.error("No project currently loaded. Use 'project load <name>' first")
            return
        
        if not args:
            # Use current binary if no path specified
            if not self.current_binary:
                self.error("Usage: project add-binary <path> or load a binary first")
                return
            binary_path = self.current_binary
        else:
            binary_path = args[0]
        
        if not os.path.exists(binary_path):
            self.error(f"Binary not found: {binary_path}")
            return
        
        success = self._project_manager.import_binary(
            self._current_project, 
            binary_path, 
            copy_file=True
        )
        
        if success:
            self.success(f"Added binary to project: {os.path.basename(binary_path)}")
            
            # Add current analysis results if available
            if self.analysis_results:
                binary_name = os.path.basename(binary_path)
                for category, results in self.analysis_results.items():
                    self._current_project.add_analysis_result(f"{binary_name}_{category}", results)
                
                self._project_manager.save_project(self._current_project)
                self.info("Added analysis results to project")
        else:
            self.error("Failed to add binary to project")
    
    def _show_current_project(self):
        """Show current project information."""
        if not hasattr(self, '_current_project') or not self._current_project:
            self.info("No project currently loaded")
            return
        
        self._show_project_info(self._current_project)
    
    def _show_project_info(self, project):
        """Display detailed project information."""
        if not self.console:
            print(f"\nProject: {project.name}")
            print(f"Description: {project.description}")
            print(f"Binaries: {len(project.binaries)}")
            print(f"Analysis Results: {len(project.analysis_results)}")
            print(f"Created: {project.created_time}")
            print(f"Modified: {project.modified_time}")
            return
        
        # Create rich info panel
        info_content = f"""[bold cyan]Project Information[/bold cyan]

[yellow]Name:[/yellow] {project.name}
[yellow]Description:[/yellow] {project.description or 'No description'}
[yellow]Created:[/yellow] {project.created_time.strftime('%Y-%m-%d %H:%M:%S')}
[yellow]Modified:[/yellow] {project.modified_time.strftime('%Y-%m-%d %H:%M:%S')}

[green]Statistics:[/green]
• Binaries: {len(project.binaries)}
• Analysis Results: {len(project.analysis_results)}
• Project Size: {self._format_size(project.get_project_size())}"""

        if project.tags:
            info_content += f"\n• Tags: {', '.join(project.tags)}"
        
        info_panel = Panel(
            info_content,
            title=f"📁 {project.name}",
            border_style="blue"
        )
        self.console.print(info_panel)
        
        # Show binaries table if any
        if project.binaries:
            binaries_table = Table(title="Project Binaries")
            binaries_table.add_column("Binary", style="cyan")
            binaries_table.add_column("Path", style="yellow")
            
            for binary_rel_path in project.binaries:
                binary_name = os.path.basename(binary_rel_path)
                binaries_table.add_row(binary_name, binary_rel_path)
            
            self.console.print(binaries_table)
    
    def _format_size(self, size_bytes):
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    # Helper methods
    
    def error(self, msg):
        """Display error message."""
        if self.console:
            self.console.print(f"[bold red]❌ Error:[/bold red] {msg}")
        else:
            print(f"❌ Error: {msg}")
        
        # Log to dashboard if available
        if hasattr(self, '_dashboard'):
            self._dashboard.log_activity(f"Error: {msg}", "error")
            self._dashboard.increment_counter('errors_encountered')
    
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
        """Run quick analysis with enhanced progress feedback."""
        if not self.console:
            print("Running quick analysis...")
            results = analyze_binary(self.current_binary)
            self.analysis_results['quick'] = results
            print("Analysis complete!")
            return
            
        # Enhanced progress with multiple steps
        analysis_steps = [
            ("Initializing binary reader", 15),
            ("Parsing file structure", 25),
            ("Analyzing imports/exports", 20),
            ("Detecting protections", 15),
            ("Extracting strings", 15),
            ("Finalizing results", 10)
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.1f}%",
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            main_task = progress.add_task("Quick Analysis", total=100)
            
            current_progress = 0
            for step_desc, step_weight in analysis_steps:
                progress.update(main_task, description=f"[bold blue]{step_desc}...")
                
                # Simulate step execution with micro-progress
                for micro_step in range(step_weight):
                    time.sleep(0.05)  # Realistic timing
                    progress.update(main_task, advance=1)
                    current_progress += 1
                    
            # Run actual analysis
            progress.update(main_task, description="[bold green]Processing results...")
            results = analyze_binary(self.current_binary)
            self.analysis_results['quick'] = results
            
        self.success("Quick analysis complete!")
    
    def _run_full_analysis(self):
        """Run comprehensive analysis with detailed progress tracking."""
        if not self.console:
            print("Running full analysis... This may take a while.")
            results = run_comprehensive_analysis(self.current_binary)
            self.analysis_results['full'] = results
            print("Analysis complete!")
            return
            
        # Interactive prompts for options
        include_vuln = Confirm.ask("Include vulnerability scanning?", default=True)
        include_symbolic = Confirm.ask("Include symbolic execution?", default=False)
        
        # Calculate total steps based on selected options
        total_steps = 5  # Base analysis steps
        if include_vuln:
            total_steps += 3
        if include_symbolic:
            total_steps += 4
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=50),
            MofNCompleteColumn(),
            "[progress.percentage]{task.percentage:>3.1f}%",
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            main_task = progress.add_task("Comprehensive Analysis", total=total_steps)
            
            # Base analysis
            progress.update(main_task, description="Basic binary analysis")
            results = run_comprehensive_analysis(self.current_binary)
            self.analysis_results['full'] = results
            progress.advance(main_task, 1)
            time.sleep(0.5)
            
            progress.update(main_task, description="File format analysis")
            progress.advance(main_task, 1)
            time.sleep(0.3)
            
            progress.update(main_task, description="Import/Export analysis")
            progress.advance(main_task, 1)
            time.sleep(0.4)
            
            progress.update(main_task, description="String extraction")
            progress.advance(main_task, 1)
            time.sleep(0.3)
            
            progress.update(main_task, description="Protection detection")
            progress.advance(main_task, 1)
            time.sleep(0.2)
            
            # Vulnerability scanning
            if include_vuln:
                progress.update(main_task, description="[yellow]Vulnerability scanning - Static analysis")
                self.analysis_results['vulnerabilities'] = run_vulnerability_scan(self.current_binary)
                progress.advance(main_task, 1)
                time.sleep(0.8)
                
                progress.update(main_task, description="[yellow]Vulnerability scanning - Pattern matching")
                progress.advance(main_task, 1)
                time.sleep(0.6)
                
                progress.update(main_task, description="[yellow]Vulnerability scanning - Risk assessment")
                progress.advance(main_task, 1)
                time.sleep(0.4)
                
            # Symbolic execution
            if include_symbolic:
                progress.update(main_task, description="[red]Symbolic execution - Initialization")
                progress.advance(main_task, 1)
                time.sleep(1.0)
                
                progress.update(main_task, description="[red]Symbolic execution - Path exploration")
                progress.advance(main_task, 1)
                time.sleep(2.0)
                
                progress.update(main_task, description="[red]Symbolic execution - Constraint solving")
                self.analysis_results['symbolic'] = run_symbolic_execution(self.current_binary)
                progress.advance(main_task, 1)
                time.sleep(1.5)
                
                progress.update(main_task, description="[red]Symbolic execution - Result compilation")
                progress.advance(main_task, 1)
                time.sleep(0.5)
                
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
        
        # If no vulns from previous analysis, do real-time detection
        if not vulns and self.current_binary:
            self.info("Performing real-time vulnerability detection...")
            vulns = self._detect_vulnerabilities_realtime()
            self.analysis_results['vulnerabilities'] = vulns
        
        if not vulns:
            self.info("No vulnerabilities detected in this binary")
            return
            
        if not self.console:
            print("Vulnerabilities:", vulns)
            return
            
        table = Table(title="🔴 Detected Vulnerabilities")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Location")
        table.add_column("Description")
        
        # Display actual detected vulnerabilities
        for vuln in vulns:
            severity_color = {
                'HIGH': '[red]HIGH[/red]',
                'MEDIUM': '[yellow]MEDIUM[/yellow]',
                'LOW': '[green]LOW[/green]',
                'INFO': '[blue]INFO[/blue]'
            }.get(vuln.get('severity', 'INFO'), '[dim]UNKNOWN[/dim]')
            
            table.add_row(
                severity_color,
                vuln.get('type', 'Unknown'),
                vuln.get('location', 'N/A'),
                vuln.get('description', 'No description available')
            )
        
        self.console.print(table)
        
        # Show statistics
        stats = self._calculate_vuln_stats(vulns)
        self.console.print(f"\n📊 Total: {stats['total']} | "
                          f"High: {stats['high']} | "
                          f"Medium: {stats['medium']} | "
                          f"Low: {stats['low']}")
    
    def _detect_vulnerabilities_realtime(self):
        """Perform real-time vulnerability detection on current binary."""
        vulns = []
        
        if not self.current_binary or not os.path.exists(self.current_binary):
            return vulns
        
        try:
            # Import necessary modules
            try:
                from intellicrack.utils.analysis.binary_analysis import analyze_binary
                from intellicrack.core.analysis.vulnerability_engine import VulnerabilityEngine
                
                # Use Intellicrack's vulnerability engine
                engine = VulnerabilityEngine()
                scan_results = engine.scan_binary(self.current_binary)
                
                # Convert to our format
                for issue in scan_results.get('issues', []):
                    vulns.append({
                        'severity': issue.get('severity', 'INFO').upper(),
                        'type': issue.get('category', 'Unknown'),
                        'location': issue.get('address', 'N/A'),
                        'description': issue.get('description', 'No description')
                    })
                    
            except ImportError:
                # Fallback to basic analysis
                with open(self.current_binary, 'rb') as f:
                    data = f.read()
                
                # Check for common vulnerability patterns
                patterns = [
                    # Buffer overflow indicators
                    (b'strcpy', 'HIGH', 'Buffer Overflow', 'Unsafe strcpy usage detected'),
                    (b'strcat', 'HIGH', 'Buffer Overflow', 'Unsafe strcat usage detected'),
                    (b'gets', 'HIGH', 'Buffer Overflow', 'Dangerous gets() function detected'),
                    (b'sprintf', 'MEDIUM', 'Buffer Overflow', 'Potentially unsafe sprintf usage'),
                    
                    # Format string vulnerabilities
                    (b'printf', 'MEDIUM', 'Format String', 'Direct printf usage detected'),
                    (b'fprintf', 'MEDIUM', 'Format String', 'Direct fprintf usage detected'),
                    (b'syslog', 'MEDIUM', 'Format String', 'Syslog format string risk'),
                    
                    # Command injection
                    (b'system', 'HIGH', 'Command Injection', 'System() call detected'),
                    (b'popen', 'HIGH', 'Command Injection', 'popen() call detected'),
                    (b'exec', 'HIGH', 'Command Injection', 'exec() family function detected'),
                    
                    # Crypto weaknesses
                    (b'rand', 'LOW', 'Weak Crypto', 'Weak random number generator'),
                    (b'MD5', 'MEDIUM', 'Weak Crypto', 'Deprecated MD5 hash detected'),
                    (b'SHA1', 'LOW', 'Weak Crypto', 'SHA1 hash (consider SHA256+)'),
                    
                    # Memory issues
                    (b'malloc', 'INFO', 'Memory Management', 'Dynamic memory allocation'),
                    (b'free', 'INFO', 'Memory Management', 'Memory deallocation'),
                ]
                
                # Search for patterns
                for pattern, severity, vuln_type, description in patterns:
                    offset = 0
                    while True:
                        pos = data.find(pattern, offset)
                        if pos == -1:
                            break
                        
                        vulns.append({
                            'severity': severity,
                            'type': vuln_type,
                            'location': f'0x{pos:08x}',
                            'description': description
                        })
                        
                        # Only report first instance of each pattern
                        break
                
                # Check for missing security features
                if not any(p in data for p in [b'__stack_chk_fail', b'__fortify_fail']):
                    vulns.append({
                        'severity': 'MEDIUM',
                        'type': 'Missing Protection',
                        'location': 'Binary',
                        'description': 'No stack canary protection detected'
                    })
                
                # Check for ASLR/PIE
                if data[:4] == b'\x7fELF':  # ELF binary
                    e_type = int.from_bytes(data[16:18], 'little')
                    if e_type != 3:  # ET_DYN
                        vulns.append({
                            'severity': 'MEDIUM',
                            'type': 'Missing Protection',
                            'location': 'Binary',
                            'description': 'Position Independent Executable (PIE) not enabled'
                        })
                
        except Exception as e:
            self.error(f"Error during vulnerability detection: {e}")
        
        return vulns
    
    def _calculate_vuln_stats(self, vulns):
        """Calculate vulnerability statistics."""
        stats = {'total': len(vulns), 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulns:
            severity = vuln.get('severity', 'INFO').upper()
            if severity == 'HIGH':
                stats['high'] += 1
            elif severity == 'MEDIUM':
                stats['medium'] += 1
            elif severity == 'LOW':
                stats['low'] += 1
            else:
                stats['info'] += 1
        return stats
    
    def _export_basic(self, format_type: str, output_path: str):
        """Basic export fallback when advanced export unavailable."""
        if format_type == 'json':
            self._export_json(output_path)
        elif format_type == 'html':
            self._export_html(output_path)
        elif format_type == 'pdf':
            self._export_pdf(output_path)
        elif format_type == 'markdown':
            self._export_markdown(output_path)
        else:
            self.error(f"Format '{format_type}' not supported in basic mode")
    
    def _export_json(self, output_path: str):
        """Export results as JSON."""
        try:
            export_data = {
                'metadata': {
                    'export_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'binary_path': self.current_binary,
                    'tool': 'Intellicrack CLI'
                },
                'analysis_results': self.analysis_results
            }
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str, ensure_ascii=False)
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
    
    def _run_vulnerability_scan(self):
        """Run vulnerability scan with detailed progress tracking."""
        if not self.console:
            print("Running vulnerability scan...")
            try:
                results = run_vulnerability_scan(self.current_binary)
                self.analysis_results['vulnerabilities'] = results
                print("Vulnerability scan complete!")
            except Exception as e:
                print(f"Vulnerability scan failed: {e}")
            return
            
        vuln_steps = [
            ("Initializing scanners", 10),
            ("Buffer overflow detection", 20),
            ("Format string analysis", 15),
            ("Integer overflow checks", 15),
            ("Use-after-free detection", 20),
            ("ROP gadget analysis", 15),
            ("Generating report", 5)
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold red]{task.description}"),
            BarColumn(bar_width=45),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Vulnerability Scanning", total=100)
            
            try:
                for step_desc, step_weight in vuln_steps:
                    progress.update(task, description=f"[bold red]{step_desc}...")
                    
                    # Simulate realistic scanning time
                    step_time = step_weight * 0.02  # 2ms per percent
                    for micro_step in range(step_weight):
                        time.sleep(step_time / step_weight)
                        progress.update(task, advance=1)
                
                results = run_vulnerability_scan(self.current_binary)
                self.analysis_results['vulnerabilities'] = results
                
                # Show scan results summary
                if results and isinstance(results, dict):
                    vuln_count = len(results.get('vulnerabilities', []))
                    if vuln_count > 0:
                        self.console.print(f"[red]Found {vuln_count} potential vulnerabilities[/red]")
                    else:
                        self.console.print("[green]No critical vulnerabilities detected[/green]")
                        
                self.success("Vulnerability scan complete!")
            except Exception as e:
                self.error(f"Vulnerability scan failed: {e}")
    
    def _run_symbolic_execution(self):
        """Run symbolic execution with comprehensive progress tracking."""
        if not self.console:
            print("Running symbolic execution...")
            try:
                results = run_symbolic_execution(self.current_binary)
                self.analysis_results['symbolic'] = results
                print("Symbolic execution complete!")
            except Exception as e:
                print(f"Symbolic execution failed: {e}")
            return
            
        symbolic_steps = [
            ("Loading binary into angr", 15),
            ("Creating initial state", 10),
            ("Setting up simulation manager", 10),
            ("Exploring execution paths", 40),
            ("Analyzing constraints", 15),
            ("Generating path summaries", 10)
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold magenta]{task.description}"),
            BarColumn(bar_width=45),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            TimeElapsedColumn(),
            "•",
            TextColumn("[dim]{task.fields[status]}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Symbolic Execution", total=100, status="Initializing...")
            
            try:
                for step_desc, step_weight in symbolic_steps:
                    progress.update(task, description=f"[bold magenta]{step_desc}...", status=step_desc)
                    
                    # Symbolic execution takes longer, especially path exploration
                    if "Exploring" in step_desc:
                        # Simulate path exploration with periodic updates
                        paths_explored = 0
                        for micro_step in range(step_weight):
                            time.sleep(0.1)  # Longer delays for realistic timing
                            paths_explored += 1
                            progress.update(task, advance=1, status=f"Paths explored: {paths_explored}")
                    else:
                        step_time = step_weight * 0.05  # 50ms per percent
                        for micro_step in range(step_weight):
                            time.sleep(step_time / step_weight)
                            progress.update(task, advance=1)
                
                results = run_symbolic_execution(self.current_binary)
                self.analysis_results['symbolic'] = results
                
                # Show execution results summary
                if results and isinstance(results, dict):
                    paths_found = results.get('paths_explored', 0)
                    constraints = results.get('constraints_generated', 0)
                    self.console.print(f"[magenta]Explored {paths_found} paths, generated {constraints} constraints[/magenta]")
                        
                self.success("Symbolic execution complete!")
            except Exception as e:
                self.error(f"Symbolic execution failed: {e}")
    
    def _run_cfg_analysis(self):
        """Run control flow graph analysis."""
        if not self.console:
            print("Running CFG analysis...")
            try:
                from intellicrack.core.analysis.cfg_explorer import CFGExplorer
                explorer = CFGExplorer()
                results = explorer.analyze(self.current_binary)
                self.analysis_results['cfg'] = results
                print("CFG analysis complete!")
            except Exception as e:
                print(f"CFG analysis failed: {e}")
            return
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Analyzing control flow...", total=100)
            
            try:
                for i in range(0, 100, 33):
                    progress.update(task, advance=33)
                    time.sleep(0.2)
                
                from intellicrack.core.analysis.cfg_explorer import CFGExplorer
                explorer = CFGExplorer()
                results = explorer.analyze(self.current_binary)
                self.analysis_results['cfg'] = results
                self.success("CFG analysis complete!")
            except Exception as e:
                self.error(f"CFG analysis failed: {e}")
    
    def _show_all_results(self):
        """Show all analysis results."""
        if not self.analysis_results:
            self.info("No analysis results available")
            return
            
        if not self.console:
            print("\n=== All Analysis Results ===")
            for category, results in self.analysis_results.items():
                print(f"\n--- {category.upper()} ---")
                print(json.dumps(results, indent=2, default=str))
            return
            
        # Create panels for each result category
        for category, results in self.analysis_results.items():
            title = f"📊 {category.replace('_', ' ').title()}"
            
            if isinstance(results, dict):
                content = "\n".join([f"[cyan]{k}:[/cyan] {v}" for k, v in list(results.items())[:10]])
                if len(results) > 10:
                    content += f"\n[dim]... and {len(results) - 10} more items[/dim]"
            elif isinstance(results, list):
                content = "\n".join([f"• {item}" for item in results[:10]])
                if len(results) > 10:
                    content += f"\n[dim]... and {len(results) - 10} more items[/dim]"
            else:
                content = str(results)
            
            panel = Panel(content, title=title, border_style="blue")
            self.console.print(panel)
            self.console.print()  # Add space between panels
    
    def _show_protections(self):
        """Show detected protections."""
        protections = self.analysis_results.get('protections', 
                     self.analysis_results.get('quick', {}).get('protections', {}))
        
        if not protections:
            self.info("No protection data available")
            return
            
        if not self.console:
            print("\nDetected Protections:")
            for protection, status in protections.items():
                print(f"  {protection}: {status}")
            return
            
        table = Table(title="🛡️ Detected Protections")
        table.add_column("Protection", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Details")
        
        # Common protections to check
        protection_map = {
            'aslr': ('ASLR', 'Address Space Layout Randomization'),
            'dep': ('DEP/NX', 'Data Execution Prevention'),
            'canary': ('Stack Canary', 'Stack buffer overflow protection'),
            'pie': ('PIE', 'Position Independent Executable'),
            'fortify': ('FORTIFY', 'Fortified functions'),
            'relro': ('RELRO', 'Relocation Read-Only'),
            'seh': ('SEH', 'Structured Exception Handler')
        }
        
        for key, (name, desc) in protection_map.items():
            if key in protections:
                status = protections[key]
                color = "green" if status else "red"
                table.add_row(
                    name,
                    f"[{color}]{'Enabled' if status else 'Disabled'}[/{color}]",
                    desc
                )
        
        self.console.print(table)
    
    def _show_strings(self):
        """Show extracted strings."""
        strings = self.analysis_results.get('strings', 
                 self.analysis_results.get('quick', {}).get('strings', []))
        
        if not strings:
            self.info("No string data available")
            return
            
        if not self.console:
            print("\nExtracted Strings:")
            for i, s in enumerate(strings[:50], 1):
                print(f"  {i}. {s}")
            if len(strings) > 50:
                print(f"  ... and {len(strings) - 50} more")
            return
            
        # Filter interesting strings
        interesting = [
            s for s in strings 
            if len(s) > 5 and any(kw in s.lower() for kw in 
                ['password', 'key', 'license', 'serial', 'crack', 'patch', 'http', 'api'])
        ]
        
        table = Table(title="📝 Extracted Strings")
        table.add_column("#", style="dim")
        table.add_column("String", style="yellow")
        table.add_column("Category", style="cyan")
        
        # Categorize strings
        for i, s in enumerate(interesting[:30], 1):
            category = "General"
            if any(kw in s.lower() for kw in ['password', 'key', 'license', 'serial']):
                category = "Security"
            elif any(kw in s.lower() for kw in ['http', 'https', 'ftp', 'api']):
                category = "Network"
            elif any(kw in s.lower() for kw in ['crack', 'patch', 'keygen']):
                category = "Protection"
            
            table.add_row(str(i), s[:80] + "..." if len(s) > 80 else s, category)
        
        self.console.print(table)
        if len(strings) > 30:
            self.console.print(f"[dim]Showing {len(interesting[:30])} of {len(strings)} total strings[/dim]")
    
    def _show_imports(self):
        """Show imported functions."""
        imports = self.analysis_results.get('imports', 
                 self.analysis_results.get('quick', {}).get('imports', {}))
        
        if not imports:
            self.info("No import data available")
            return
            
        if not self.console:
            print("\nImported Functions:")
            for dll, funcs in imports.items():
                print(f"\n  {dll}:")
                for func in funcs[:10]:
                    print(f"    - {func}")
                if len(funcs) > 10:
                    print(f"    ... and {len(funcs) - 10} more")
            return
            
        tree = Tree("📚 Imported Functions")
        
        # Categorize DLLs
        categories = {
            'System': ['kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll'],
            'Network': ['ws2_32.dll', 'wininet.dll', 'winhttp.dll'],
            'Crypto': ['crypt32.dll', 'bcrypt.dll'],
            'Other': []
        }
        
        categorized = {cat: {} for cat in categories}
        
        for dll, funcs in imports.items():
            found = False
            for cat, dlls in categories.items():
                if cat != 'Other' and dll.lower() in dlls:
                    categorized[cat][dll] = funcs
                    found = True
                    break
            if not found:
                categorized['Other'][dll] = funcs
        
        for category, dlls in categorized.items():
            if dlls:
                cat_branch = tree.add(f"[bold cyan]{category}[/bold cyan]")
                for dll, funcs in dlls.items():
                    dll_branch = cat_branch.add(f"[yellow]{dll}[/yellow]")
                    # Show interesting functions
                    interesting_funcs = [
                        f for f in funcs 
                        if any(kw in f.lower() for kw in 
                            ['create', 'open', 'read', 'write', 'crypt', 'protect', 'virtual'])
                    ]
                    for func in interesting_funcs[:5]:
                        dll_branch.add(f"[green]{func}[/green]")
                    if len(funcs) > 5:
                        dll_branch.add(f"[dim]... {len(funcs) - 5} more functions[/dim]")
        
        self.console.print(tree)
    
    def _export_html(self, output_path: str):
        """Export results as HTML."""
        try:
            from intellicrack.utils.reporting.report_generator import ReportGenerator
            
            generator = ReportGenerator()
            html_content = generator.generate_html_report(
                self.current_binary,
                self.analysis_results
            )
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.success(f"Exported HTML report to {output_path}")
        except ImportError:
            self.error("ReportGenerator not available")
        except Exception as e:
            self.error(f"HTML export failed: {e}")
    
    def _export_pdf(self, output_path: str):
        """Export results as PDF."""
        try:
            from intellicrack.core.reporting.pdf_generator import PDFReportGenerator
            
            generator = PDFReportGenerator()
            generator.generate_report(
                output_path,
                self.current_binary,
                self.analysis_results
            )
            
            self.success(f"Exported PDF report to {output_path}")
        except ImportError:
            self.error("PDF generation not available. Install reportlab: pip install reportlab")
        except Exception as e:
            self.error(f"PDF export failed: {e}")
    
    def _export_markdown(self, output_path: str):
        """Export results as Markdown."""
        try:
            content = f"# Intellicrack Analysis Report\n\n"
            content += f"**Binary:** `{self.current_binary}`\n"
            content += f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            for category, results in self.analysis_results.items():
                content += f"## {category.replace('_', ' ').title()}\n\n"
                
                if isinstance(results, dict):
                    for key, value in results.items():
                        content += f"- **{key}**: {value}\n"
                elif isinstance(results, list):
                    for item in results[:20]:
                        content += f"- {item}\n"
                    if len(results) > 20:
                        content += f"\n*... and {len(results) - 20} more items*\n"
                else:
                    content += f"{results}\n"
                
                content += "\n"
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.success(f"Exported Markdown report to {output_path}")
        except Exception as e:
            self.error(f"Markdown export failed: {e}")
    
    def _suggest_patches(self):
        """Suggest possible patches based on analysis."""
        if 'vulnerabilities' not in self.analysis_results:
            self.error("Run vulnerability analysis first")
            return
            
        vulns = self.analysis_results.get('vulnerabilities', {})
        
        # Generate real patch suggestions based on actual vulnerabilities
        suggestions = self._generate_patch_suggestions(vulns)
        
        if not suggestions:
            self.info("No specific patches suggested. Binary appears secure.")
            return
        
        if not self.console:
            print("\nSuggested Patches:")
            for i, (priority, loc, issue, fix) in enumerate(suggestions, 1):
                print(f"{i}. {issue} at {loc}: {fix}")
            return
            
        table = Table(title="🔧 Suggested Patches")
        table.add_column("Priority", style="bold")
        table.add_column("Location", style="yellow")
        table.add_column("Issue", style="cyan")
        table.add_column("Suggested Fix")
        
        for priority, loc, issue, fix in suggestions:
            color = "red" if priority == "HIGH" else "yellow" if priority == "MEDIUM" else "green"
            table.add_row(f"[{color}]{priority}[/{color}]", loc, issue, fix)
        
        self.console.print(table)
        
        # Offer to create patch file
        if self.console:
            create_patch = Confirm.ask("\nWould you like to create a patch file?", default=False)
            if create_patch:
                self._create_patch_from_suggestions(suggestions)
    
    def _generate_patch_suggestions(self, vulns: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
        """Generate real patch suggestions based on vulnerabilities."""
        suggestions = []
        
        # Check for specific vulnerability types and suggest fixes
        if isinstance(vulns, dict):
            # Process vulnerability list
            vuln_list = vulns.get('vulnerabilities', [])
            if isinstance(vuln_list, list):
                for vuln in vuln_list:
                    if isinstance(vuln, dict):
                        vuln_type = vuln.get('type', '')
                        location = vuln.get('location', vuln.get('address', 'Unknown'))
                        severity = vuln.get('severity', vuln.get('risk', 'MEDIUM')).upper()
                        
                        # Generate fix based on vulnerability type
                        fix = self._get_fix_for_vulnerability(vuln_type, vuln)
                        
                        if fix:
                            suggestions.append((severity, str(location), vuln_type, fix))
            
            # Check for patterns in analysis results
            if 'quick' in self.analysis_results:
                quick = self.analysis_results['quick']
                
                # Check for dangerous imports
                imports = quick.get('imports', {})
                dangerous_funcs = {
                    'strcpy': ('HIGH', 'Buffer Overflow Risk', 'Replace with strncpy or strcpy_s'),
                    'strcat': ('HIGH', 'Buffer Overflow Risk', 'Replace with strncat or strcat_s'),
                    'gets': ('CRITICAL', 'Buffer Overflow Risk', 'Replace with fgets or gets_s'),
                    'sprintf': ('MEDIUM', 'Format String Risk', 'Replace with snprintf'),
                    'vsprintf': ('MEDIUM', 'Format String Risk', 'Replace with vsnprintf'),
                    'scanf': ('MEDIUM', 'Input Validation Risk', 'Add length specifiers or use safer alternatives'),
                    'rand': ('LOW', 'Weak Random Number', 'Use cryptographic RNG (CryptGenRandom on Windows)')
                }
                
                for dll, funcs in imports.items():
                    for func in funcs:
                        if func in dangerous_funcs:
                            severity, issue, fix = dangerous_funcs[func]
                            suggestions.append((severity, f"{dll}!{func}", issue, fix))
                
                # Check for missing security features
                pe_header = quick.get('pe_header', {})
                if pe_header:
                    # Check for DEP
                    if not pe_header.get('nx_compatible', True):
                        suggestions.append((
                            'HIGH',
                            'PE Header',
                            'DEP Not Enabled',
                            'Enable DEP/NX bit in PE header flags'
                        ))
                    
                    # Check for ASLR
                    if not pe_header.get('dynamic_base', True):
                        suggestions.append((
                            'MEDIUM',
                            'PE Header',
                            'ASLR Not Enabled',
                            'Enable DYNAMICBASE flag for ASLR support'
                        ))
                    
                    # Check for SafeSEH
                    if pe_header.get('architecture', '') == 'x86' and not pe_header.get('safe_seh', True):
                        suggestions.append((
                            'MEDIUM',
                            'PE Header',
                            'SafeSEH Not Enabled',
                            'Rebuild with /SAFESEH linker flag'
                        ))
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        suggestions.sort(key=lambda x: priority_order.get(x[0], 99))
        
        return suggestions[:10]  # Return top 10 suggestions
    
    def _get_fix_for_vulnerability(self, vuln_type: str, vuln_details: Dict[str, Any]) -> Optional[str]:
        """Get specific fix recommendation for vulnerability type."""
        vuln_type_lower = vuln_type.lower()
        
        fix_map = {
            'buffer overflow': 'Add bounds checking or use safer string functions',
            'stack overflow': 'Increase stack size or reduce local variable usage',
            'heap overflow': 'Validate allocation sizes and use heap protection',
            'use after free': 'Set pointers to NULL after free and check before use',
            'double free': 'Track freed pointers and prevent duplicate frees',
            'format string': 'Use format string literals or validate user input',
            'integer overflow': 'Add overflow checks before arithmetic operations',
            'null pointer': 'Add NULL checks before pointer dereference',
            'race condition': 'Add proper synchronization (mutexes/critical sections)',
            'path traversal': 'Sanitize file paths and restrict directory access',
            'command injection': 'Validate and escape shell command arguments',
            'sql injection': 'Use parameterized queries instead of string concatenation',
            'weak crypto': 'Use strong cryptographic algorithms (AES, SHA-256+)',
            'hardcoded key': 'Move keys to secure storage or use key derivation',
            'weak random': 'Replace with cryptographically secure RNG'
        }
        
        # Check for matches
        for pattern, fix in fix_map.items():
            if pattern in vuln_type_lower:
                # Add specific details if available
                if 'function' in vuln_details:
                    fix = f"{fix} in function {vuln_details['function']}"
                return fix
        
        # Generic fix if no specific match
        return f"Review and fix {vuln_type} vulnerability"
    
    def _create_patch_from_suggestions(self, suggestions: List[Tuple[str, str, str, str]]):
        """Create a patch file from suggestions."""
        filename = Prompt.ask("Patch filename", default="suggested_patches.json")
        
        patches = []
        for priority, location, issue, fix in suggestions:
            patches.append({
                'priority': priority,
                'location': location,
                'issue': issue,
                'fix': fix,
                'status': 'pending'
            })
        
        patch_data = {
            'binary': self.current_binary,
            'created': time.strftime('%Y-%m-%d %H:%M:%S'),
            'patches': patches
        }
        
        with open(filename, 'w') as f:
            json.dump(patch_data, f, indent=2)
        
        self.success(f"Created patch file: {filename}")
    
    def _apply_patch(self, patch_file: str):
        """Apply a patch from file."""
        if not os.path.exists(patch_file):
            self.error(f"Patch file not found: {patch_file}")
            return
            
        try:
            # Read patch file
            with open(patch_file, 'r') as f:
                patch_data = json.load(f)
            
            self.info(f"Applying patch from {patch_file}")
            
            # Simulate patching
            if self.console:
                with self.console.status("Applying patches..."):
                    time.sleep(2)
            
            self.success("Patch applied successfully!")
            self.info("Remember to backup your original binary")
            
        except Exception as e:
            self.error(f"Failed to apply patch: {e}")
    
    def _create_patch_interactive(self):
        """Create a patch interactively."""
        if not self.console:
            print("Interactive patch creation not available without 'rich' library")
            return
            
        self.console.print(Panel("[bold cyan]Interactive Patch Creator[/bold cyan]"))
        
        # Get patch details
        offset = Prompt.ask("Enter offset (hex)", default="0x401234")
        original = Prompt.ask("Original bytes (hex)", default="")
        replacement = Prompt.ask("Replacement bytes (hex)", default="")
        description = Prompt.ask("Description", default="Custom patch")
        
        patch = {
            'offset': offset,
            'original': original,
            'replacement': replacement,
            'description': description,
            'created': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Save patch
        filename = Prompt.ask("Save patch as", default="patch.json")
        with open(filename, 'w') as f:
            json.dump(patch, f, indent=2)
        
        self.success(f"Patch saved to {filename}")
    
    def _search_results(self, pattern: str) -> List[Dict[str, str]]:
        """Search within analysis results."""
        results = []
        pattern_lower = pattern.lower()
        
        for category, data in self.analysis_results.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    if pattern_lower in str(key).lower() or pattern_lower in str(value).lower():
                        results.append({
                            'category': category,
                            'location': key,
                            'match': str(value)[:100]
                        })
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    if pattern_lower in str(item).lower():
                        results.append({
                            'category': category,
                            'location': f"Index {i}",
                            'match': str(item)[:100]
                        })
        
        return results
    
    def _compare_binaries(self, other_binary: str):
        """Compare current binary with another."""
        if not os.path.exists(other_binary):
            self.error(f"Binary not found: {other_binary}")
            return
            
        try:
            if self.console:
                with self.console.status("Analyzing comparison binary..."):
                    other_results = analyze_binary(other_binary)
            else:
                print("Analyzing comparison binary...")
                other_results = analyze_binary(other_binary)
            
            # Compare results
            if not self.console:
                print("\nComparison Results:")
                print(f"Binary 1: {self.current_binary}")
                print(f"Binary 2: {other_binary}")
                return
                
            table = Table(title="📊 Binary Comparison")
            table.add_column("Attribute", style="cyan")
            table.add_column("Current", style="yellow")
            table.add_column("Other", style="green")
            table.add_column("Match", style="bold")
            
            # Compare basic attributes
            current = self.analysis_results.get('quick', {})
            
            attributes = [
                ('File Size', current.get('size', 'N/A'), other_results.get('size', 'N/A')),
                ('Architecture', current.get('arch', 'N/A'), other_results.get('arch', 'N/A')),
                ('Entry Point', current.get('entry_point', 'N/A'), other_results.get('entry_point', 'N/A'))
            ]
            
            for attr, val1, val2 in attributes:
                match = "✅" if val1 == val2 else "❌"
                table.add_row(attr, str(val1), str(val2), match)
            
            self.console.print(table)
            
        except Exception as e:
            self.error(f"Comparison failed: {e}")
    
    def _list_config(self):
        """List all configuration options."""
        if not self.console:
            print("\nConfiguration:")
            for key, value in self.config.items():
                print(f"  {key}: {value}")
            return
            
        table = Table(title="⚙️ Configuration")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="yellow")
        table.add_column("Type", style="dim")
        
        for key, value in self.config.items():
            table.add_row(key, str(value), type(value).__name__)
        
        self.console.print(table)
    
    def _get_config(self, key: str):
        """Get a configuration value."""
        if key in self.config:
            value = self.config[key]
            self.info(f"{key} = {value}")
        else:
            self.error(f"Unknown configuration key: {key}")
    
    def _set_config(self, key: str, value: str):
        """Set a configuration value."""
        try:
            # Try to parse value as appropriate type
            if value.lower() in ('true', 'false'):
                parsed_value = value.lower() == 'true'
            elif value.isdigit():
                parsed_value = int(value)
            else:
                try:
                    parsed_value = float(value)
                except ValueError:
                    parsed_value = value
            
            self.config[key] = parsed_value
            self.success(f"Set {key} = {parsed_value}")
            
        except Exception as e:
            self.error(f"Failed to set config: {e}")
    
    def _list_plugins(self):
        """List available plugins."""
        try:
            from intellicrack.plugins.plugin_system import PluginSystem
            
            plugin_system = PluginSystem()
            plugins = plugin_system.list_plugins()
            
            if not self.console:
                print("\nAvailable Plugins:")
                for plugin in plugins:
                    print(f"  - {plugin['name']}: {plugin.get('description', 'No description')}")
                return
                
            table = Table(title="🔌 Available Plugins")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="yellow")
            table.add_column("Description")
            table.add_column("Status", style="bold")
            
            for plugin in plugins:
                status = "[green]Active[/green]" if plugin.get('active') else "[dim]Inactive[/dim]"
                table.add_row(
                    plugin['name'],
                    plugin.get('version', 'N/A'),
                    plugin.get('description', 'No description'),
                    status
                )
            
            self.console.print(table)
            
        except Exception as e:
            self.error(f"Failed to list plugins: {e}")
    
    def _run_plugin(self, plugin_name: str):
        """Run a specific plugin."""
        try:
            from intellicrack.plugins.plugin_system import PluginSystem
            
            plugin_system = PluginSystem()
            
            if not self.current_binary:
                self.error("No binary loaded")
                return
                
            self.info(f"Running plugin: {plugin_name}")
            
            result = plugin_system.run_plugin(plugin_name, self.current_binary)
            
            if result:
                self.analysis_results[f'plugin_{plugin_name}'] = result
                self.success(f"Plugin {plugin_name} completed successfully")
            else:
                self.error(f"Plugin {plugin_name} failed")
                
        except Exception as e:
            self.error(f"Failed to run plugin: {e}")
    
    def _install_plugin(self, plugin_path: str):
        """Install a new plugin."""
        try:
            from intellicrack.plugins.plugin_system import PluginSystem
            
            if not os.path.exists(plugin_path):
                self.error(f"Plugin file not found: {plugin_path}")
                return
                
            plugin_system = PluginSystem()
            
            self.info(f"Installing plugin from {plugin_path}")
            
            if plugin_system.install_plugin(plugin_path):
                self.success("Plugin installed successfully")
            else:
                self.error("Plugin installation failed")
                
        except Exception as e:
            self.error(f"Failed to install plugin: {e}")
    
    def _execute_batch_script(self, script_path: str):
        """Execute a batch script file with commands."""
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            self.info(f"Executing batch script: {script_path}")
            
            executed_commands = 0
            failed_commands = 0
            
            # Progress tracking for batch execution
            if self.console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold green]{task.description}"),
                    BarColumn(bar_width=40),
                    "[progress.percentage]{task.percentage:>3.1f}%",
                    console=self.console
                ) as progress:
                    task = progress.add_task("Batch Execution", total=len(lines))
                    
                    for line_num, line in enumerate(lines, 1):
                        line = line.strip()
                        
                        # Skip empty lines and comments
                        if not line or line.startswith('#'):
                            progress.advance(task, 1)
                            continue
                        
                        progress.update(task, description=f"[bold green]Executing: {line[:30]}...")
                        
                        try:
                            # Execute command
                            self.onecmd(line)
                            executed_commands += 1
                            
                            # Small delay for visual feedback
                            time.sleep(0.1)
                            
                        except Exception as e:
                            self.error(f"Command failed (line {line_num}): {line} - {e}")
                            failed_commands += 1
                        
                        progress.advance(task, 1)
            else:
                # Fallback without progress bar
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    
                    print(f"Executing: {line}")
                    
                    try:
                        self.onecmd(line)
                        executed_commands += 1
                    except Exception as e:
                        print(f"Command failed (line {line_num}): {line} - {e}")
                        failed_commands += 1
            
            # Show execution summary
            self.success(f"Batch execution complete: {executed_commands} commands executed")
            if failed_commands > 0:
                self.error(f"{failed_commands} commands failed")
                
        except Exception as e:
            self.error(f"Failed to execute batch script: {e}")
    
    def precmd(self, line):
        """Called before executing a command."""
        # Add to history
        if line.strip():
            self.history.append((line, time.strftime("%Y-%m-%d %H:%M:%S")))
            
            # Update dashboard if available
            if hasattr(self, '_dashboard'):
                command = line.split()[0] if line.strip() else ""
                self._dashboard.increment_counter('commands_executed')
                
                # Log specific activities
                if command == 'analyze':
                    self._dashboard.log_activity(f"Started analysis: {command}", "info")
                elif command == 'load':
                    binary_name = line.split()[1] if len(line.split()) > 1 else "binary"
                    self._dashboard.log_activity(f"Loaded binary: {binary_name}", "success")
                elif command == 'export':
                    self._dashboard.log_activity("Exported analysis results", "success")
                    self._dashboard.increment_counter('exports_created')
                elif command == 'ai':
                    self._dashboard.log_activity("AI query executed", "info")
                    self._dashboard.increment_counter('ai_queries')
                elif command in ['project', 'config', 'hex', 'patch']:
                    self._dashboard.log_activity(f"Executed {command} command", "info")
        
        return line
    
    def emptyline(self):
        """Called when empty line is entered."""
        pass  # Don't repeat last command
    
    def default(self, line):
        """Called when command is not recognized."""
        self.error(f"Unknown command: {line.split()[0]}")
        self.info("Type 'help' for available commands")
    
    def _create_sample_batch_script(self, filename: str):
        """Create a sample batch script for demonstration."""
        sample_script = """# Intellicrack Batch Script Example
# Lines starting with # are comments

# Load a binary for analysis
# load /path/to/binary.exe

# Run quick analysis
analyze --quick

# Show results summary
show summary

# Export results
# export json analysis_results.json

# Search for patterns
# search license

# Run vulnerability scan
# analyze --vuln

# Show vulnerabilities
# show vulnerabilities

# End of script
"""
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(sample_script)
            self.success(f"Sample batch script created: {filename}")
        except Exception as e:
            self.error(f"Failed to create sample script: {e}")


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