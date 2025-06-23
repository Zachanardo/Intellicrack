#!/usr/bin/env python3
"""
AI Chat Interface - Terminal-based AI interaction for Intellicrack CLI

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
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# Rich imports for beautiful terminal UI
try:
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Add parent directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
sys.path.insert(0, project_root)


class AITerminalChat:
    """Terminal-based AI chat interface with rich formatting."""

    def __init__(self, binary_path: Optional[str] = None, analysis_results: Optional[Dict[str, Any]] = None):
        """Initialize AI chat interface.

        Args:
            binary_path: Path to current binary being analyzed
            analysis_results: Current analysis results for context
        """
        self.console = Console() if RICH_AVAILABLE else None
        self.binary_path = binary_path
        self.analysis_results = analysis_results or {}
        self.conversation_history = []
        self.ai_backend = None
        self.logger = logging.getLogger(__name__)
        self.session_start = datetime.now()

        # Chat configuration
        self.max_history = 50
        self.typing_delay = 0.02  # Simulated typing speed
        self.auto_save = True

        # Available commands
        self.commands = {
            '/help': self._show_help,
            '/clear': self._clear_history,
            '/save': self._save_conversation,
            '/load': self._load_conversation,
            '/export': self._export_conversation,
            '/analyze': self._analyze_current_binary,
            '/context': self._show_context,
            '/backend': self._switch_backend,
            '/quit': self._quit_chat,
            '/exit': self._quit_chat
        }

        # Initialize AI backend
        self._initialize_ai_backend()

    def _initialize_ai_backend(self):
        """Initialize AI backend connection."""
        try:
            # Try to import and initialize AI coordination layer
            from intellicrack.ai.coordination_layer import CoordinationLayer
            self.ai_backend = CoordinationLayer()

            if self.console:
                self.console.print("[green]AI backend initialized successfully[/green]")
            else:
                print("AI backend initialized successfully")

        except ImportError:
            if self.console:
                self.console.print("[yellow]AI backend not available - using mock responses[/yellow]")
            else:
                print("AI backend not available - using mock responses")
            self.ai_backend = None

    def start_chat_session(self):
        """Start interactive chat session."""
        if self.console:
            self._start_rich_chat()
        else:
            self._start_basic_chat()

    def _start_rich_chat(self):
        """Start rich terminal chat interface."""
        self.console.clear()

        # Welcome message
        welcome_panel = Panel(
            "[bold cyan]Intellicrack AI Assistant[/bold cyan]\n\n"
            "I can help you analyze binaries, understand security vulnerabilities,\n"
            "and provide insights about your analysis results.\n\n"
            "[dim]Type '/help' for commands or just ask me anything![/dim]",
            title="🤖 AI Chat Interface",
            border_style="blue"
        )
        self.console.print(welcome_panel)

        if self.binary_path:
            self.console.print(f"[dim]Current binary: {os.path.basename(self.binary_path)}[/dim]")

        self.console.print()

        try:
            while True:
                # Get user input
                user_input = Prompt.ask("[bold blue]You[/bold blue]", default="").strip()

                if not user_input:
                    continue

                # Check for commands
                if user_input.startswith('/'):
                    command = user_input.split()[0]
                    args = user_input.split()[1:] if len(user_input.split()) > 1 else []

                    if command in self.commands:
                        result = self.commands[command](args)
                        if result == 'quit':
                            break
                        continue
                    else:
                        self.console.print(f"[red]Unknown command: {command}[/red]")
                        self.console.print("[dim]Type '/help' for available commands[/dim]")
                        continue

                # Process AI query
                self._process_ai_query(user_input)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Chat session ended[/yellow]")
        except EOFError:
            self.console.print("\n[yellow]Chat session ended[/yellow]")

    def _start_basic_chat(self):
        """Start basic terminal chat interface."""
        print("Intellicrack AI Assistant")
        print("=" * 25)
        print("Type '/help' for commands or ask me anything!")
        print("Type '/quit' to exit\n")

        if self.binary_path:
            print(f"Current binary: {os.path.basename(self.binary_path)}\n")

        try:
            while True:
                user_input = input("You: ").strip()

                if not user_input:
                    continue

                # Check for commands
                if user_input.startswith('/'):
                    command = user_input.split()[0]
                    args = user_input.split()[1:] if len(user_input.split()) > 1 else []

                    if command in self.commands:
                        result = self.commands[command](args)
                        if result == 'quit':
                            break
                        continue
                    else:
                        print(f"Unknown command: {command}")
                        print("Type '/help' for available commands")
                        continue

                # Process AI query
                self._process_ai_query_basic(user_input)

        except KeyboardInterrupt:
            print("\nChat session ended")
        except EOFError:
            print("\nChat session ended")

    def _process_ai_query(self, user_input: str):
        """Process AI query with rich formatting."""
        # Add to conversation history
        self.conversation_history.append({
            'timestamp': datetime.now().isoformat(),
            'type': 'user',
            'content': user_input
        })

        # Show thinking indicator
        with self.console.status("[bold green]AI is thinking...", spinner="dots") as status:
            response = self._get_ai_response(user_input)

        # Display response with typing effect
        self._display_ai_response(response)

        # Add response to history
        self.conversation_history.append({
            'timestamp': datetime.now().isoformat(),
            'type': 'ai',
            'content': response
        })

        # Trim history if too long
        if len(self.conversation_history) > self.max_history * 2:
            self.conversation_history = self.conversation_history[-self.max_history:]

    def _process_ai_query_basic(self, user_input: str):
        """Process AI query with basic formatting."""
        # Add to conversation history
        self.conversation_history.append({
            'timestamp': datetime.now().isoformat(),
            'type': 'user',
            'content': user_input
        })

        print("AI: Thinking...")
        response = self._get_ai_response(user_input)

        print(f"AI: {response}\n")

        # Add response to history
        self.conversation_history.append({
            'timestamp': datetime.now().isoformat(),
            'type': 'ai',
            'content': response
        })

    def _get_ai_response(self, user_input: str) -> str:
        """Get AI response from backend or mock."""
        context = self._build_context()

        if self.ai_backend:
            try:
                # Use real AI backend
                response = self.ai_backend.analyze_with_llm(
                    user_input,
                    context=context,
                    analysis_type="chat"
                )

                if isinstance(response, dict):
                    return response.get('analysis', response.get('response', str(response)))
                else:
                    return str(response)

            except Exception as e:
                return f"AI backend error: {e}. Using fallback response."

        # Fallback to mock responses
        return self._get_mock_response(user_input, context)

    def _get_mock_response(self, user_input: str, context: Dict[str, Any]) -> str:
        """Generate mock AI responses based on input patterns."""
        self.logger.debug(f"Generating mock response with context keys: {list(context.keys()) if context else 'none'}")
        user_lower = user_input.lower()

        # Binary analysis questions
        if any(word in user_lower for word in ['analyze', 'analysis', 'binary', 'file']):
            if self.binary_path:
                return f"""I can see you're working with {os.path.basename(self.binary_path)}. 

Based on the analysis results, here's what I found:
• File type detection and format analysis
• Security protections and vulnerabilities
• String extraction and pattern analysis

Would you like me to focus on any specific aspect of the analysis?"""
            else:
                return "To analyze a binary, please load one first using the 'load' command in the main interface."

        # Vulnerability questions
        elif any(word in user_lower for word in ['vulnerability', 'vuln', 'security', 'exploit']):
            vuln_count = len(self.analysis_results.get('vulnerabilities', {}).get('vulnerabilities', []))
            if vuln_count > 0:
                return f"""I found {vuln_count} potential vulnerabilities in your binary:

• Buffer overflow risks in unsafe string functions
• Potential integer overflow conditions
• Missing security mitigations (ASLR, DEP, Stack Canaries)

I recommend addressing the high-severity issues first. Would you like specific remediation advice?"""
            else:
                return "No critical vulnerabilities detected in the current analysis. The binary appears to have good security protections."

        # Protection questions
        elif any(word in user_lower for word in ['protection', 'aslr', 'dep', 'canary', 'mitigation']):
            protections = self.analysis_results.get('protections', {})
            if protections:
                enabled = [k for k, v in protections.items() if v]
                disabled = [k for k, v in protections.items() if not v]

                response = "Security protections analysis:\n\n"
                if enabled:
                    response += f"✅ Enabled: {', '.join(enabled)}\n"
                if disabled:
                    response += f"❌ Disabled: {', '.join(disabled)}\n"

                response += "\nI recommend enabling all available protections for better security."
                return response
            else:
                return "No protection information available. Run a comprehensive analysis to check security mitigations."

        # String analysis questions
        elif any(word in user_lower for word in ['string', 'text', 'password', 'key']):
            strings = self.analysis_results.get('strings', [])
            if strings:
                interesting_strings = [s for s in strings if any(keyword in s.lower()
                                     for keyword in ['password', 'key', 'license', 'admin', 'secret'])]

                if interesting_strings:
                    return f"""Found {len(interesting_strings)} potentially interesting strings:

{chr(10).join(['• ' + s[:50] + ('...' if len(s) > 50 else '') for s in interesting_strings[:5]])}

These strings might indicate authentication mechanisms or sensitive data."""
                else:
                    return f"Found {len(strings)} strings total, but none appear particularly sensitive."
            else:
                return "No string analysis data available. Run string extraction first."

        # Help questions
        elif any(word in user_lower for word in ['help', 'what', 'how', 'explain']):
            return """I'm here to help you understand your binary analysis results!

I can assist with:
• Explaining vulnerability findings
• Recommending security improvements
• Interpreting analysis data
• Suggesting next steps

Just ask me about any aspect of your analysis, or use commands like:
/analyze - Quick analysis overview
/context - Show current analysis context
/help - Show all available commands"""

        # General conversation
        else:
            return f"""I understand you're asking about: "{user_input}"

I'm specialized in binary analysis and security research. I can help you:
• Understand analysis results
• Identify security issues
• Recommend improvements
• Explain technical findings

Could you be more specific about what aspect of the analysis you'd like to explore?"""

    def _build_context(self) -> Dict[str, Any]:
        """Build context for AI responses."""
        context = {
            'session_info': {
                'start_time': self.session_start.isoformat(),
                'conversation_length': len(self.conversation_history)
            }
        }

        if self.binary_path:
            context['binary_info'] = {
                'name': os.path.basename(self.binary_path),
                'path': self.binary_path,
                'size': os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0
            }

        if self.analysis_results:
            # Summarize analysis results for context
            context['analysis_summary'] = {
                'categories': list(self.analysis_results.keys()),
                'vulnerability_count': len(self.analysis_results.get('vulnerabilities', {}).get('vulnerabilities', [])),
                'string_count': len(self.analysis_results.get('strings', [])),
                'has_protections': 'protections' in self.analysis_results
            }

        return context

    def _display_ai_response(self, response: str):
        """Display AI response with typing effect."""
        ai_panel = Panel(
            response,
            title="🤖 AI Assistant",
            border_style="green",
            padding=(1, 2)
        )

        # Simple display without typing effect for now
        self.console.print(ai_panel)
        self.console.print()

    def _show_help(self, args: List[str]) -> Optional[str]:
        """Show help information."""
        self.logger.debug(f"Help command called with args: {args}")
        if self.console:
            help_table = Table(title="AI Chat Commands")
            help_table.add_column("Command", style="cyan")
            help_table.add_column("Description", style="yellow")

            help_table.add_row("/help", "Show this help message")
            help_table.add_row("/clear", "Clear conversation history")
            help_table.add_row("/save [file]", "Save conversation to file")
            help_table.add_row("/load [file]", "Load conversation from file")
            help_table.add_row("/export [format]", "Export conversation (json, txt, md)")
            help_table.add_row("/analyze", "Get analysis overview of current binary")
            help_table.add_row("/context", "Show current analysis context")
            help_table.add_row("/backend", "Switch AI backend")
            help_table.add_row("/quit, /exit", "Exit chat session")

            self.console.print(help_table)
            self.console.print()
        else:
            print("\nAI Chat Commands:")
            print("/help - Show this help message")
            print("/clear - Clear conversation history")
            print("/save [file] - Save conversation")
            print("/analyze - Analysis overview")
            print("/context - Show context")
            print("/quit - Exit chat\n")

        return None

    def _clear_history(self, args: List[str]) -> Optional[str]:
        """Clear conversation history."""
        self.logger.debug(f"Clear history called with args: {args}")
        self.conversation_history.clear()

        if self.console:
            self.console.print("[green]Conversation history cleared[/green]")
        else:
            print("Conversation history cleared")

        return None

    def _save_conversation(self, args: List[str]) -> Optional[str]:
        """Save conversation to file."""
        filename = args[0] if args else f"ai_chat_{int(time.time())}.json"

        try:
            conversation_data = {
                'session_info': {
                    'start_time': self.session_start.isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'binary_path': self.binary_path
                },
                'conversation': self.conversation_history
            }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(conversation_data, f, indent=2, ensure_ascii=False)

            if self.console:
                self.console.print(f"[green]Conversation saved to {filename}[/green]")
            else:
                print(f"Conversation saved to {filename}")

        except Exception as e:
            if self.console:
                self.console.print(f"[red]Save failed: {e}[/red]")
            else:
                print(f"Save failed: {e}")

        return None

    def _analyze_current_binary(self, args: List[str]) -> Optional[str]:
        """Provide analysis overview of current binary."""
        self.logger.debug(f"Analyze current binary called with args: {args}")
        if not self.binary_path:
            if self.console:
                self.console.print("[yellow]No binary currently loaded[/yellow]")
            else:
                print("No binary currently loaded")
            return None

        # Generate analysis overview
        overview = f"Analysis Overview for {os.path.basename(self.binary_path)}:\n\n"

        if self.analysis_results:
            for category, data in self.analysis_results.items():
                if isinstance(data, dict):
                    count = len(data)
                elif isinstance(data, list):
                    count = len(data)
                else:
                    count = 1
                overview += f"• {category.replace('_', ' ').title()}: {count} items\n"
        else:
            overview += "No analysis results available. Run analysis first."

        # Simulate AI response
        response = {
            'timestamp': datetime.now().isoformat(),
            'type': 'ai',
            'content': overview
        }

        self.conversation_history.append(response)

        if self.console:
            self._display_ai_response(overview)
        else:
            print(f"AI: {overview}")

        return None

    def _show_context(self, args: List[str]) -> Optional[str]:
        """Show current analysis context."""
        self.logger.debug(f"Show context called with args: {args}")
        context = self._build_context()

        if self.console:
            context_panel = Panel(
                json.dumps(context, indent=2),
                title="Current Context",
                border_style="blue"
            )
            self.console.print(context_panel)
        else:
            print("\nCurrent Context:")
            print(json.dumps(context, indent=2))
            print()

        return None

    def _switch_backend(self, args: List[str]) -> Optional[str]:
        """Switch AI backend."""
        self.logger.debug(f"Switch backend called with args: {args}")
        if self.console:
            self.console.print("[yellow]Backend switching not implemented yet[/yellow]")
        else:
            print("Backend switching not implemented yet")

        return None

    def _quit_chat(self, args: List[str]) -> str:
        """Exit chat session."""
        self.logger.debug(f"Quit chat called with args: {args}")
        if self.auto_save and self.conversation_history:
            self._save_conversation([f"auto_save_{int(time.time())}.json"])

        if self.console:
            self.console.print("[green]Thanks for using Intellicrack AI Assistant![/green]")
        else:
            print("Thanks for using Intellicrack AI Assistant!")

        return 'quit'

    def _load_conversation(self, args: List[str]) -> Optional[str]:
        """Load conversation from file."""
        if not args:
            if self.console:
                self.console.print("[red]Usage: /load <filename>[/red]")
            else:
                print("Usage: /load <filename>")
            return None

        filename = args[0]

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.conversation_history = data.get('conversation', [])

            if self.console:
                self.console.print(f"[green]Conversation loaded from {filename}[/green]")
            else:
                print(f"Conversation loaded from {filename}")

        except Exception as e:
            if self.console:
                self.console.print(f"[red]Load failed: {e}[/red]")
            else:
                print(f"Load failed: {e}")

        return None

    def _export_conversation(self, args: List[str]) -> Optional[str]:
        """Export conversation in various formats."""
        format_type = args[0] if args else 'txt'
        filename = f"conversation_export_{int(time.time())}.{format_type}"

        try:
            if format_type == 'json':
                self._save_conversation([filename])
            elif format_type == 'txt':
                self._export_text(filename)
            elif format_type == 'md':
                self._export_markdown(filename)
            else:
                if self.console:
                    self.console.print(f"[red]Unsupported format: {format_type}[/red]")
                else:
                    print(f"Unsupported format: {format_type}")
                return None

            if self.console:
                self.console.print(f"[green]Conversation exported to {filename}[/green]")
            else:
                print(f"Conversation exported to {filename}")

        except Exception as e:
            if self.console:
                self.console.print(f"[red]Export failed: {e}[/red]")
            else:
                print(f"Export failed: {e}")

        return None

    def _export_text(self, filename: str):
        """Export conversation as plain text."""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Intellicrack AI Chat Session\n")
            f.write(f"Started: {self.session_start}\n")
            if self.binary_path:
                f.write(f"Binary: {self.binary_path}\n")
            f.write("\n" + "="*50 + "\n\n")

            for entry in self.conversation_history:
                timestamp = entry.get('timestamp', '')
                entry_type = entry.get('type', 'unknown')
                content = entry.get('content', '')

                speaker = "You" if entry_type == 'user' else "AI"
                f.write(f"[{timestamp}] {speaker}: {content}\n\n")

    def _export_markdown(self, filename: str):
        """Export conversation as Markdown."""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("# Intellicrack AI Chat Session\n\n")
            f.write(f"**Started:** {self.session_start}\n")
            if self.binary_path:
                f.write(f"**Binary:** `{self.binary_path}`\n")
            f.write("\n---\n\n")

            for entry in self.conversation_history:
                timestamp = entry.get('timestamp', '')
                entry_type = entry.get('type', 'unknown')
                content = entry.get('content', '')

                if entry_type == 'user':
                    f.write(f"## 👤 User\n\n{content}\n\n")
                else:
                    f.write(f"## 🤖 AI Assistant\n\n{content}\n\n")

                f.write(f"*{timestamp}*\n\n---\n\n")


def launch_ai_chat(binary_path: Optional[str] = None, analysis_results: Optional[Dict[str, Any]] = None):
    """Launch AI chat interface.

    Args:
        binary_path: Path to current binary
        analysis_results: Current analysis results
    """
    try:
        chat = AITerminalChat(binary_path, analysis_results)
        chat.start_chat_session()
    except Exception as e:
        print(f"AI chat error: {e}")
        return False
    return True


if __name__ == "__main__":
    # Test the chat interface
    launch_ai_chat()
