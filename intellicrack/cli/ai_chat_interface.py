#!/usr/bin/env python3
"""AI Chat Interface - Terminal-based AI interaction for Intellicrack CLI

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

import json
import os
import sys
import time
from datetime import datetime
from typing import Any

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
project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
sys.path.insert(0, project_root)


class AITerminalChat:
    """Terminal-based AI chat interface with rich formatting."""

    def __init__(
        self, binary_path: str | None = None, analysis_results: dict[str, Any] | None = None
    ):
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
        self.session_start = datetime.now()

        # Chat configuration
        self.max_history = 50
        self.typing_delay = 0.02  # Simulated typing speed
        self.auto_save = True

        # Available commands
        self.commands = {
            "/help": self._show_help,
            "/clear": self._clear_history,
            "/save": self._save_conversation,
            "/load": self._load_conversation,
            "/export": self._export_conversation,
            "/analyze": self._analyze_current_binary,
            "/context": self._show_context,
            "/backend": self._switch_backend,
            "/quit": self._quit_chat,
            "/exit": self._quit_chat,
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
                self.console.print(
                    "[yellow]AI backend not available - using mock responses[/yellow]"
                )
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
            border_style="blue",
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
                if user_input.startswith("/"):
                    command = user_input.split()[0]
                    args = user_input.split()[1:] if len(user_input.split()) > 1 else []

                    if command in self.commands:
                        result = self.commands[command](args)
                        if result == "quit":
                            break
                        continue
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
                if user_input.startswith("/"):
                    command = user_input.split()[0]
                    args = user_input.split()[1:] if len(user_input.split()) > 1 else []

                    if command in self.commands:
                        result = self.commands[command](args)
                        if result == "quit":
                            break
                        continue
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
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "user",
                "content": user_input,
            }
        )

        # Show thinking indicator with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True,
        ) as progress:
            # Add tasks for different AI processing stages
            thinking_task = progress.add_task("[green]AI is analyzing your query...", total=100)
            progress.update(thinking_task, advance=25)

            response = self._get_ai_response(user_input)
            progress.update(thinking_task, advance=50, description="[blue]Generating response...")

            # Check if response contains code and prepare syntax highlighting
            if "```" in response:
                progress.update(
                    thinking_task, advance=15, description="[yellow]Formatting code blocks..."
                )

            progress.update(thinking_task, advance=10, description="[green]Finalizing response...")

        # Display response with typing effect
        self._display_ai_response(response)

        # Add response to history
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "ai",
                "content": response,
            }
        )

        # Trim history if too long
        if len(self.conversation_history) > self.max_history * 2:
            self.conversation_history = self.conversation_history[-self.max_history :]

    def _process_ai_query_basic(self, user_input: str):
        """Process AI query with basic formatting."""
        # Add to conversation history
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "user",
                "content": user_input,
            }
        )

        print("AI: Thinking...")
        response = self._get_ai_response(user_input)

        print(f"AI: {response}\n")

        # Add response to history
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "ai",
                "content": response,
            }
        )

    def _get_ai_response(self, user_input: str) -> str:
        """Get AI response from backend or mock."""
        context = self._build_context()

        # Try using AI tools ask_question method first
        try:
            from intellicrack.ai.ai_tools import AIAssistant

            ai_tools = AIAssistant()

            # Build contextual question with binary and analysis info
            contextual_question = user_input
            if self.binary_path:
                contextual_question = f"Binary: {os.path.basename(self.binary_path)}\n{user_input}"

            if self.analysis_results:
                # Add key analysis findings to context
                vuln_count = len(
                    self.analysis_results.get("vulnerabilities", {}).get("vulnerabilities", [])
                )
                if vuln_count > 0:
                    contextual_question = (
                        f"Context: Found {vuln_count} vulnerabilities\n{contextual_question}"
                    )

            response = ai_tools.ask_question(contextual_question)
            return response

        except Exception:
            # Log the error but continue to fallback methods
            pass

        if self.ai_backend:
            try:
                # Use real AI backend
                response = self.ai_backend.analyze_with_llm(
                    user_input,
                    context=context,
                    analysis_type="chat",
                )

                if isinstance(response, dict):
                    return response.get("analysis", response.get("response", str(response)))
                return str(response)

            except Exception as e:
                return f"AI backend error: {e}. Using fallback response."

        # Fallback to offline responses
        return self._get_fallback_response(user_input, context)

    def _get_fallback_response(self, user_input: str, context: dict[str, Any]) -> str:
        """Generate intelligent fallback AI responses when backend is unavailable."""
        user_lower = user_input.lower()

        # Binary analysis questions
        if any(word in user_lower for word in ["analyze", "analysis", "binary", "file"]):
            if self.binary_path:
                # Generate detailed analysis response based on actual results
                binary_name = os.path.basename(self.binary_path)
                file_type = self.analysis_results.get("file_type", "Unknown")
                arch = self.analysis_results.get("architecture", "Unknown")
                size = self.analysis_results.get("size", 0)

                response = f"""Analyzing {binary_name}:

📊 File Information:
• Type: {file_type}
• Architecture: {arch}
• Size: {size:,} bytes

🔍 Analysis Results:"""

                # Add protection information if available
                protections = self.analysis_results.get("protections", {})
                if protections:
                    enabled_protections = [p for p, enabled in protections.items() if enabled]
                    disabled_protections = [p for p, enabled in protections.items() if not enabled]

                    if enabled_protections:
                        response += f"\n• Enabled Protections: {', '.join(enabled_protections)}"
                    if disabled_protections:
                        response += f"\n• Missing Protections: {', '.join(disabled_protections)}"

                # Add vulnerability summary
                vulns = self.analysis_results.get("vulnerabilities", {}).get("vulnerabilities", [])
                if vulns:
                    critical = sum(1 for v in vulns if v.get("severity") == "critical")
                    high = sum(1 for v in vulns if v.get("severity") == "high")
                    response += f"\n• Vulnerabilities: {critical} critical, {high} high severity"

                response += "\n\nWhat specific aspect would you like me to explain further?"
                return response

            return "Please load a binary file first. Use the main interface to select a file for analysis."

        # Vulnerability questions with detailed responses
        if any(word in user_lower for word in ["vulnerability", "vuln", "security", "exploit"]):
            vulns = self.analysis_results.get("vulnerabilities", {}).get("vulnerabilities", [])

            if vulns:
                # Group vulnerabilities by severity
                critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
                high_vulns = [v for v in vulns if v.get("severity") == "high"]
                medium_vulns = [v for v in vulns if v.get("severity") == "medium"]

                response = f"""Security Analysis Results - {len(vulns)} vulnerabilities detected:

🔴 Critical ({len(critical_vulns)}):"""
                for vuln in critical_vulns[:3]:
                    response += f"\n• {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}"

                if high_vulns:
                    response += f"\n\n🟠 High ({len(high_vulns)}):"
                    for vuln in high_vulns[:3]:
                        response += (
                            f"\n• {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}"
                        )

                response += "\n\n💡 Recommendations:\n1. Address critical vulnerabilities immediately\n2. Implement missing security protections\n3. Consider code review for affected components"

                return response

            return "✅ No critical vulnerabilities detected. The binary implements standard security protections."

        # Protection questions
        if any(
            word in user_lower for word in ["protection", "aslr", "dep", "canary", "mitigation"]
        ):
            protections = self.analysis_results.get("protections", {})
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
            return "No protection information available. Run a comprehensive analysis to check security mitigations."

        # String analysis questions
        if any(word in user_lower for word in ["string", "text", "password", "key"]):
            strings = self.analysis_results.get("strings", [])
            if strings:
                interesting_strings = [
                    s
                    for s in strings
                    if any(
                        keyword in s.lower()
                        for keyword in ["password", "key", "license", "admin", "secret"]
                    )
                ]

                if interesting_strings:
                    return f"""Found {len(interesting_strings)} potentially interesting strings:

{chr(10).join(['• ' + s[:50] + ('...' if len(s) > 50 else '') for s in interesting_strings[:5]])}

These strings might indicate authentication mechanisms or sensitive data."""
                return (
                    f"Found {len(strings)} strings total, but none appear particularly sensitive."
                )
            return "No string analysis data available. Run string extraction first."

        # Help questions
        if any(word in user_lower for word in ["help", "what", "how", "explain"]):
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
        return f"""I understand you're asking about: "{user_input}"

I'm specialized in binary analysis and security research. I can help you:
• Understand analysis results
• Identify security issues
• Recommend improvements
• Explain technical findings

Could you be more specific about what aspect of the analysis you'd like to explore?"""

    def _build_context(self) -> dict[str, Any]:
        """Build context for AI responses."""
        context = {
            "session_info": {
                "start_time": self.session_start.isoformat(),
                "conversation_length": len(self.conversation_history),
            },
        }

        if self.binary_path:
            context["binary_info"] = {
                "name": os.path.basename(self.binary_path),
                "path": self.binary_path,
                "size": os.path.getsize(self.binary_path)
                if os.path.exists(self.binary_path)
                else 0,
            }

        if self.analysis_results:
            # Summarize analysis results for context
            context["analysis_summary"] = {
                "categories": list(self.analysis_results.keys()),
                "vulnerability_count": len(
                    self.analysis_results.get("vulnerabilities", {}).get("vulnerabilities", [])
                ),
                "string_count": len(self.analysis_results.get("strings", [])),
                "has_protections": "protections" in self.analysis_results,
            }

        return context

    def _display_ai_response(self, response: str):
        """Display AI response with typing effect."""
        if not RICH_AVAILABLE:
            print(f"\nAI: {response}")
            return

        # Create layout with centered content
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=1),
        )

        # Header with centered title
        header_content = Align.center(Text("🤖 AI Assistant Response", style="bold green"))
        layout["header"].update(Panel(header_content, border_style="green"))

        # Body with response content - check for code blocks and markdown
        if "```" in response:
            # Process code blocks with syntax highlighting
            response_content = self._process_code_blocks(response)
        elif response.startswith("#") or "*" in response or "**" in response:
            # Render as markdown for formatted text
            response_content = Markdown(response)
        else:
            # Plain text response
            response_content = response

        ai_panel = Panel(
            response_content,
            title="Response",
            border_style="green",
            padding=(1, 2),
        )
        layout["body"].update(ai_panel)

        # Footer with timestamp
        footer_content = Align.center(f"Generated at {datetime.now().strftime('%H:%M:%S')}")
        layout["footer"].update(footer_content)

        # Display with live update for typing effect
        with Live(layout, refresh_per_second=10, console=self.console) as live:
            import time

            # Simulate typing effect by updating the display
            for _i in range(5):  # 5 refresh cycles
                live.update(layout)
                time.sleep(0.1)  # Brief display effect

        self.console.print()

    def _process_code_blocks(self, response: str):
        """Process response with code blocks and apply syntax highlighting."""
        if not RICH_AVAILABLE:
            return response

        import re

        # Pattern to match code blocks with optional language specification
        pattern = r"```(\w+)?\n(.*?)\n```"

        def replace_code_block(match):
            language = match.group(1) or "python"  # Default to python if no language specified
            code = match.group(2)

            # Create syntax highlighted code block
            syntax = Syntax(code, language, theme="monokai", line_numbers=True)
            return syntax

        # Replace code blocks with syntax-highlighted versions
        parts = re.split(pattern, response, flags=re.DOTALL)

        if len(parts) > 1:
            # If we found code blocks, create a composite with alternating text and code
            result_parts = []
            for i, part in enumerate(parts):
                if i % 3 == 0:  # Regular text parts
                    if part.strip():
                        result_parts.append(part)
                elif i % 3 == 2:  # Code content parts
                    lang = parts[i - 1] or "python"
                    syntax = Syntax(part, lang, theme="monokai", line_numbers=True)
                    result_parts.append(syntax)

            # Return first part as text if available, or the syntax object
            return result_parts[0] if result_parts else response

        return response

    def _display_analysis_summary(self):
        """Display analysis summary using columns layout."""
        if not RICH_AVAILABLE or not self.analysis_results:
            print("Analysis results not available or Rich not installed")
            return

        # Create summary panels for different analysis types
        panels = []

        if "vulnerabilities" in self.analysis_results:
            vuln_data = self.analysis_results["vulnerabilities"]
            vuln_count = (
                len(vuln_data.get("vulnerabilities", [])) if isinstance(vuln_data, dict) else 0
            )
            panels.append(
                Panel(
                    f"[red]{vuln_count}[/red] vulnerabilities found",
                    title="Security",
                    border_style="red",
                )
            )

        if "strings" in self.analysis_results:
            string_count = len(self.analysis_results["strings"])
            panels.append(
                Panel(
                    f"[blue]{string_count}[/blue] strings extracted",
                    title="Strings",
                    border_style="blue",
                )
            )

        if "protections" in self.analysis_results:
            protection_data = self.analysis_results["protections"]
            protection_count = (
                len(protection_data) if isinstance(protection_data, (list, dict)) else 1
            )
            panels.append(
                Panel(
                    f"[yellow]{protection_count}[/yellow] protections detected",
                    title="Protections",
                    border_style="yellow",
                )
            )

        if panels:
            # Display in columns for better layout
            columns = Columns(panels, equal=True, expand=True)
            self.console.print("\n")
            self.console.print(Panel(columns, title="Analysis Summary", border_style="cyan"))
            self.console.print("\n")

    def _show_help(self, args: list[str]) -> str | None:
        """Show help information."""
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

    def _clear_history(self, args: list[str]) -> str | None:
        """Clear conversation history."""
        self.conversation_history.clear()

        if self.console:
            self.console.print("[green]Conversation history cleared[/green]")
        else:
            print("Conversation history cleared")

        return None

    def _save_conversation(self, args: list[str]) -> str | None:
        """Save conversation to file."""
        filename = args[0] if args else f"ai_chat_{int(time.time())}.json"

        try:
            conversation_data = {
                "session_info": {
                    "start_time": self.session_start.isoformat(),
                    "end_time": datetime.now().isoformat(),
                    "binary_path": self.binary_path,
                },
                "conversation": self.conversation_history,
            }

            with open(filename, "w", encoding="utf-8") as f:
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

    def _analyze_current_binary(self, args: list[str]) -> str | None:
        """Provide analysis overview of current binary."""
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
                if isinstance(data, dict) or isinstance(data, list):
                    count = len(data)
                else:
                    count = 1
                overview += f"• {category.replace('_', ' ').title()}: {count} items\n"
        else:
            overview += "No analysis results available. Run analysis first."

        # Simulate AI response
        response = {
            "timestamp": datetime.now().isoformat(),
            "type": "ai",
            "content": overview,
        }

        self.conversation_history.append(response)

        if self.console:
            self._display_ai_response(overview)
        else:
            print(f"AI: {overview}")

        return None

    def _show_context(self, args: list[str]) -> str | None:
        """Show current analysis context."""
        context = self._build_context()

        if self.console:
            context_panel = Panel(
                json.dumps(context, indent=2),
                title="Current Context",
                border_style="blue",
            )
            self.console.print(context_panel)
        else:
            print("\nCurrent Context:")
            print(json.dumps(context, indent=2))
            print()

        return None

    def _switch_backend(self, args: list[str]) -> str | None:
        """Switch AI backend."""
        # Try to get available backends from AI assistant if available
        try:
            if hasattr(self, "ai_assistant") and hasattr(self.ai_assistant, "llm_manager"):
                available_backends = self.ai_assistant.llm_manager.list_backends()
                current_backend = self.ai_assistant.llm_manager.current_backend
            else:
                # Fallback list of backends
                available_backends = ["openai", "anthropic", "google", "local", "ollama"]
                current_backend = getattr(self, "current_backend", "openai")
        except AttributeError:
            available_backends = ["openai", "anthropic", "google", "local", "ollama"]
            current_backend = "openai"

        if not args:
            # Show available backends
            if self.console:
                self.console.print("\n[bold cyan]Available AI Backends:[/bold cyan]")
                for backend in available_backends:
                    if backend == current_backend:
                        self.console.print(f"  • {backend} [green](current)[/green]")
                    else:
                        self.console.print(f"  • {backend}")
                self.console.print("\n[dim]Usage: /backend <name>[/dim]")
            else:
                print("\nAvailable AI Backends:")
                for backend in available_backends:
                    if backend == current_backend:
                        print(f"  • {backend} (current)")
                    else:
                        print(f"  • {backend}")
                print("\nUsage: /backend <name>")

            return None

        # Switch to specified backend
        backend_name = args[0].lower()

        try:
            # Attempt to switch backend
            if hasattr(self, "ai_assistant") and hasattr(self.ai_assistant, "llm_manager"):
                success = self.ai_assistant.llm_manager.switch_backend(backend_name)
            else:
                # Direct backend switching for production use
                from intellicrack.ai.llm_config_manager import LLMConfigManager

                llm_manager = LLMConfigManager()
                success = llm_manager.switch_backend(backend_name)

                if success:
                    self.current_backend = backend_name
                    # Re-initialize AI with new backend
                    self._reinitialize_ai_with_backend(backend_name)

            if success:
                msg = f"Switched to {backend_name} backend successfully!"
                if self.console:
                    self.console.print(f"[green]{msg}[/green]")
                else:
                    print(msg)

                # Update context with new backend info
                self.context["ai_backend"] = backend_name
                self.context["backend_capabilities"] = (
                    self.ai_assistant.llm_manager.get_backend_capabilities(backend_name)
                )

            else:
                msg = f"Failed to switch to {backend_name} backend. Check configuration."
                if self.console:
                    self.console.print(f"[red]{msg}[/red]")
                else:
                    print(msg)

        except Exception as e:
            error_msg = f"Error switching backend: {e!s}"
            if self.console:
                self.console.print(f"[red]{error_msg}[/red]")
            else:
                print(error_msg)

        return None

    def _reinitialize_ai_with_backend(self, backend_name: str):
        """Reinitialize AI assistant with new backend."""
        try:
            from intellicrack.ai.ai_assistant import AIAssistant
            from intellicrack.ai.llm_config_manager import LLMConfigManager

            # Create new LLM manager with specified backend
            llm_manager = LLMConfigManager()
            llm_manager.switch_backend(backend_name)

            # Initialize new AI assistant
            self.ai_assistant = AIAssistant(llm_manager=llm_manager)

            # Update context
            self.context = {
                "ai_backend": backend_name,
                "backend_capabilities": llm_manager.get_backend_capabilities(backend_name),
            }

            if self.console:
                self.console.print(
                    f"[green]AI assistant reinitialized with {backend_name} backend[/green]"
                )
        except Exception as e:
            if self.console:
                self.console.print(f"[yellow]Failed to reinitialize AI: {e}[/yellow]")
            self.ai_assistant = None

    def _quit_chat(self, args: list[str]) -> str:
        """Exit chat session."""
        if self.auto_save and self.conversation_history:
            self._save_conversation([f"auto_save_{int(time.time())}.json"])

        if self.console:
            self.console.print("[green]Thanks for using Intellicrack AI Assistant![/green]")
        else:
            print("Thanks for using Intellicrack AI Assistant!")

        return "quit"

    def _load_conversation(self, args: list[str]) -> str | None:
        """Load conversation from file."""
        if not args:
            if self.console:
                self.console.print("[red]Usage: /load <filename>[/red]")
            else:
                print("Usage: /load <filename>")
            return None

        filename = args[0]

        try:
            with open(filename, encoding="utf-8") as f:
                data = json.load(f)

            self.conversation_history = data.get("conversation", [])

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

    def _export_conversation(self, args: list[str]) -> str | None:
        """Export conversation in various formats."""
        format_type = args[0] if args else "txt"
        filename = f"conversation_export_{int(time.time())}.{format_type}"

        try:
            if format_type == "json":
                self._save_conversation([filename])
            elif format_type == "txt":
                self._export_text(filename)
            elif format_type == "md":
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
        with open(filename, "w", encoding="utf-8") as f:
            f.write("Intellicrack AI Chat Session\n")
            f.write(f"Started: {self.session_start}\n")
            if self.binary_path:
                f.write(f"Binary: {self.binary_path}\n")
            f.write("\n" + "=" * 50 + "\n\n")

            for entry in self.conversation_history:
                timestamp = entry.get("timestamp", "")
                entry_type = entry.get("type", "unknown")
                content = entry.get("content", "")

                speaker = "You" if entry_type == "user" else "AI"
                f.write(f"[{timestamp}] {speaker}: {content}\n\n")

    def _export_markdown(self, filename: str):
        """Export conversation as Markdown."""
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# Intellicrack AI Chat Session\n\n")
            f.write(f"**Started:** {self.session_start}\n")
            if self.binary_path:
                f.write(f"**Binary:** `{self.binary_path}`\n")
            f.write("\n---\n\n")

            for entry in self.conversation_history:
                timestamp = entry.get("timestamp", "")
                entry_type = entry.get("type", "unknown")
                content = entry.get("content", "")

                if entry_type == "user":
                    f.write(f"## 👤 User\n\n{content}\n\n")
                else:
                    f.write(f"## 🤖 AI Assistant\n\n{content}\n\n")

                f.write(f"*{timestamp}*\n\n---\n\n")


def launch_ai_chat(binary_path: str | None = None, analysis_results: dict[str, Any] | None = None):
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
