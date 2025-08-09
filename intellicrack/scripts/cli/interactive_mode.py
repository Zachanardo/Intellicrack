"""Interactive CLI mode for Intellicrack.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import cmd
import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from intellicrack.utils.logger import get_logger
from intellicrack.utils.runner_functions import run_comprehensive_analysis

logger = get_logger(__name__)


class IntellicrackShell(cmd.Cmd):
    """Interactive command shell for Intellicrack."""
    
    intro = """
    ╔══════════════════════════════════════════════════════════════╗
    ║           Intellicrack Interactive Shell v1.0.0              ║
    ║     Advanced Binary Analysis & Security Research Platform    ║
    ╚══════════════════════════════════════════════════════════════╝
    
    Type 'help' for available commands or 'exit' to quit.
    """
    
    prompt = "intellicrack> "
    
    def __init__(self):
        """Initialize the interactive shell."""
        super().__init__()
        self.current_file = None
        self.analysis_results = None
    
    def do_load(self, arg):
        """Load a binary file for analysis: load <filepath>"""
        if not arg:
            print("Usage: load <filepath>")
            return
        
        filepath = Path(arg)
        if not filepath.exists():
            print(f"Error: File not found: {arg}")
            return
        
        self.current_file = filepath
        print(f"Loaded: {filepath}")
    
    def do_analyze(self, arg):
        """Analyze the currently loaded file"""
        if not self.current_file:
            print("Error: No file loaded. Use 'load' command first.")
            return
        
        try:
            print(f"Analyzing {self.current_file}...")
            self.analysis_results = run_comprehensive_analysis(
                str(self.current_file),
                verbose=True
            )
            print("Analysis complete!")
        except Exception as e:
            print(f"Analysis failed: {e}")
    
    def do_status(self, arg):
        """Show current status"""
        print(f"Current file: {self.current_file or 'None'}")
        print(f"Analysis results: {'Available' if self.analysis_results else 'None'}")
    
    def do_clear(self, arg):
        """Clear current session"""
        self.current_file = None
        self.analysis_results = None
        print("Session cleared")
    
    def do_exit(self, arg):
        """Exit the interactive shell"""
        print("Goodbye!")
        return True
    
    def do_quit(self, arg):
        """Exit the interactive shell"""
        return self.do_exit(arg)
    
    def do_help(self, arg):
        """Show help for commands"""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            print("\nAvailable commands:")
            print("  load <file>  - Load a binary file for analysis")
            print("  analyze      - Analyze the loaded file")
            print("  status       - Show current status")
            print("  clear        - Clear current session")
            print("  help [cmd]   - Show help")
            print("  exit/quit    - Exit the shell")
            print()


def main():
    """Launch interactive mode."""
    shell = IntellicrackShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Use 'exit' to quit properly.")
        return main()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())