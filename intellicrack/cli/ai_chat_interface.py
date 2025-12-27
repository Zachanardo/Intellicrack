#!/usr/bin/env python3
"""AI Chat Interface - Terminal-based AI interaction for Intellicrack CLI.

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
import logging
import os
import sys
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any


logger = logging.getLogger(__name__)


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

    def __init__(self, binary_path: str | None = None, analysis_results: dict[str, Any] | None = None) -> None:
        """Initialize AI chat interface.

        Args:
            binary_path: Path to current binary being analyzed
            analysis_results: Current analysis results for context

        """
        self.console: Console | None = Console() if RICH_AVAILABLE else None
        self.binary_path = binary_path
        self.analysis_results = analysis_results or {}
        self.conversation_history: list[dict[str, Any]] = []
        self.ai_backend: Any = None
        self.llm_manager: Any = None
        self.orchestrator: Any = None
        self.session_start = datetime.now()

        # Chat configuration
        self.max_history = 50
        self.response_buffer_size = 4096
        self.auto_save = True

        # Available commands - using Any for callable type due to method compatibility
        self.commands: dict[str, Any] = {
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

    def _initialize_ai_backend(self) -> None:
        """Initialize AI backend connection."""
        self.ai_backend = None
        self.llm_manager = None
        self.orchestrator = None

        try:
            # Initialize LLM configuration manager
            from intellicrack.ai.llm_config_manager import LLMConfigManager

            self.llm_manager = LLMConfigManager()

            # Initialize AI orchestrator for complex tasks
            from intellicrack.ai.orchestrator import AIOrchestrator

            self.orchestrator = AIOrchestrator()

            # Try to initialize the coordination layer as primary backend
            try:
                from intellicrack.ai.coordination_layer import AICoordinationLayer

                self.ai_backend = AICoordinationLayer()
            except (ImportError, AttributeError):
                # Use orchestrator as fallback
                self.ai_backend = self.orchestrator

            # Verify backend functionality
            if hasattr(self.ai_backend, "health_check"):
                health_status = self.ai_backend.health_check()
                if not health_status.get("healthy", False):
                    raise RuntimeError(f"Backend health check failed: {health_status.get('error', 'Unknown error')}")

            backend_name = type(self.ai_backend).__name__
            logger.info("AI backend (%s) initialized successfully", backend_name)
            if self.console:
                self.console.print(f"[green]AI backend ({backend_name}) initialized successfully[/green]")

        except Exception as e:
            # Initialize minimal AI tools as final fallback
            try:
                from intellicrack.ai.code_analysis_tools import AIAssistant

                self.ai_backend = AIAssistant()
                logger.info("Using AI tools fallback due to: %s", e)

                if self.console:
                    self.console.print(f"[yellow]Using AI tools fallback: {e}[/yellow]")

            except Exception as fallback_error:
                logger.exception("All AI backends failed: %s", fallback_error)
                if self.console:
                    self.console.print(f"[red]All AI backends failed: {fallback_error}[/red]")
                self.ai_backend = None

    def start_chat_session(self) -> None:
        """Start interactive chat session."""
        if self.console:
            self._start_rich_chat()
        else:
            self._start_basic_chat()

    def _start_rich_chat(self) -> None:
        """Start rich terminal chat interface."""
        if not self.console:
            return
        self.console.clear()

        # Welcome message
        welcome_panel = Panel(
            "[bold cyan]Intellicrack AI Assistant[/bold cyan]\n\n"
            "I can help you analyze binaries, understand security vulnerabilities,\n"
            "and provide insights about your analysis results.\n\n"
            "[dim]Type '/help' for commands or just ask me anything![/dim]",
            title=" AI Chat Interface",
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
                        command_func = self.commands[command]
                        result = command_func(args)
                        if result == "quit":
                            break
                        continue
                    self.console.print(f"[red]Unknown command: {command}[/red]")
                    self.console.print("[dim]Type '/help' for available commands[/dim]")
                    continue

                # Process AI query
                self._process_ai_query(user_input)

        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[yellow]Chat session ended[/yellow]")

    def _start_basic_chat(self) -> None:
        """Start basic terminal chat interface."""
        logger.info("Starting basic chat interface")
        sys.stdout.write("Intellicrack AI Assistant\n")
        sys.stdout.write("=" * 25 + "\n")
        sys.stdout.write("Type '/help' for commands or ask me anything!\n")
        sys.stdout.write("Type '/quit' to exit\n\n")
        sys.stdout.flush()

        if self.binary_path:
            logger.debug("Binary loaded for chat: %s", self.binary_path)
            sys.stdout.write(f"Current binary: {os.path.basename(self.binary_path)}\n\n")
            sys.stdout.flush()

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
                        command_func = self.commands[command]
                        result = command_func(args)
                        if result == "quit":
                            break
                        continue
                    logger.debug("Unknown command attempted: %s", command)
                    sys.stdout.write(f"Unknown command: {command}\n")
                    sys.stdout.write("Type '/help' for available commands\n")
                    sys.stdout.flush()
                    continue

                # Process AI query
                self._process_ai_query_basic(user_input)

        except (KeyboardInterrupt, EOFError):
            logger.info("Basic chat session ended by user interrupt")
            sys.stdout.write("\nChat session ended\n")
            sys.stdout.flush()

    def _process_ai_query(self, user_input: str) -> None:
        """Process AI query with rich formatting."""
        # Add to conversation history
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "user",
                "content": user_input,
            },
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
                progress.update(thinking_task, advance=15, description="[yellow]Formatting code blocks...")

            progress.update(thinking_task, advance=10, description="[green]Finalizing response...")

        # Display response with typing effect
        self._display_ai_response(response)

        # Add response to history
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "ai",
                "content": response,
            },
        )

        # Trim history if too long
        if len(self.conversation_history) > self.max_history * 2:
            self.conversation_history = self.conversation_history[-self.max_history :]

    def _process_ai_query_basic(self, user_input: str) -> None:
        """Process AI query with basic formatting."""
        # Add to conversation history
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "user",
                "content": user_input,
            },
        )

        logger.debug("Processing AI query in basic mode")
        sys.stdout.write("AI: Thinking...\n")
        sys.stdout.flush()
        response = self._get_ai_response(user_input)
        logger.debug("AI response generated, length: %d", len(response))

        sys.stdout.write(f"AI: {response}\n\n")
        sys.stdout.flush()

        # Add response to history
        self.conversation_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "ai",
                "content": response,
            },
        )

    def _get_ai_response(self, user_input: str) -> str:
        """Get AI response from backend."""
        context = self._build_context()

        if not self.ai_backend:
            return "AI backend not available. Please check your AI configuration and ensure required dependencies are installed."

        try:
            # Prepare enriched context for AI
            enriched_context = self._prepare_enriched_context(user_input, context)

            # Try using the primary AI backend (orchestrator/coordination layer)
            if hasattr(self.ai_backend, "chat_with_context"):
                response = self.ai_backend.chat_with_context(
                    user_input=user_input,
                    context=enriched_context,
                    session_history=self.conversation_history[-10:],  # Last 10 exchanges for context
                )

                if isinstance(response, dict):
                    return str(response.get("response", response.get("analysis", str(response))))
                return str(response)

            # Try using analyze_with_llm method
            if hasattr(self.ai_backend, "analyze_with_llm"):
                response = self.ai_backend.analyze_with_llm(
                    user_input,
                    context=enriched_context,
                    analysis_type="conversational_analysis",
                )

                if isinstance(response, dict):
                    return str(response.get("analysis", response.get("response", str(response))))
                return str(response)

            # Try using ask_question method (AIAssistant fallback)
            if hasattr(self.ai_backend, "ask_question"):
                # Build contextual question with binary and analysis info
                contextual_question = user_input
                if self.binary_path:
                    contextual_question = f"Binary: {os.path.basename(self.binary_path)}\n{user_input}"

                if self.analysis_results:
                    # Add key analysis findings to context
                    vuln_count = len(self.analysis_results.get("vulnerabilities", {}).get("vulnerabilities", []))
                    if vuln_count > 0:
                        contextual_question = f"Context: Found {vuln_count} vulnerabilities\n{contextual_question}"

                response = self.ai_backend.ask_question(contextual_question)
                return str(response)

            # Try generic query method
            if hasattr(self.ai_backend, "query"):
                response = self.ai_backend.query(prompt=user_input, context=enriched_context)
                return str(response)

            # Direct LLM manager usage as final attempt
            if self.llm_manager and hasattr(self.llm_manager, "generate_response"):
                response = self.llm_manager.generate_response(
                    prompt=user_input,
                    context=enriched_context.get("binary_analysis", {}),
                    max_tokens=1500,
                )

                if isinstance(response, dict):
                    return str(response.get("content", response.get("text", str(response))))
                return str(response)

            return "AI backend is available but doesn't support the required methods for chat functionality."

        except Exception as e:
            # Attempt direct LLM call as last resort
            if self.llm_manager:
                try:
                    fallback_response = self.llm_manager.generate_response(
                        prompt=f"Binary Analysis Chat - User Question: {user_input}",
                        context={"error": str(e), "fallback": True},
                        max_tokens=800,
                    )

                    if isinstance(fallback_response, dict):
                        content = fallback_response.get("content", fallback_response.get("text", str(fallback_response)))
                        return f"{content}\n\n[Note: Primary AI backend encountered an error, using fallback response]"

                    return f"{fallback_response!s}\n\n[Note: Primary AI backend encountered an error, using fallback response]"

                except Exception as fallback_error:
                    return f"AI backend error: {e}\nFallback error: {fallback_error}\n\nPlease check your AI configuration and ensure all required services are running."

            return f"AI backend error: {e}\n\nPlease check your AI configuration and try again."

    def _prepare_enriched_context(self, user_input: str, base_context: dict[str, Any]) -> dict[str, Any]:
        """Prepare enriched context for AI responses."""
        enriched_context = base_context.copy()

        # Add binary analysis context
        if self.binary_path and self.analysis_results:
            enriched_context["binary_analysis"] = {
                "binary_name": os.path.basename(self.binary_path),
                "binary_path": self.binary_path,
                "file_type": self.analysis_results.get("file_type", "Unknown"),
                "architecture": self.analysis_results.get("architecture", "Unknown"),
                "size": self.analysis_results.get("size", 0),
            }

            # Add security analysis summary
            if "vulnerabilities" in self.analysis_results:
                vulns = self.analysis_results.get("vulnerabilities", {})
                if isinstance(vulns, dict):
                    vuln_list = vulns.get("vulnerabilities", [])
                else:
                    vuln_list = vulns if isinstance(vulns, list) else []

                severity_counts: dict[str, int] = {}
                for vuln in vuln_list:
                    severity = vuln.get("severity", "unknown")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                enriched_context["security_analysis"] = {
                    "total_vulnerabilities": len(vuln_list),
                    "severity_breakdown": severity_counts,
                    "has_critical": severity_counts.get("critical", 0) > 0,
                    "has_high": severity_counts.get("high", 0) > 0,
                }

            # Add protection status
            if "protections" in self.analysis_results:
                protections = self.analysis_results["protections"]
                if isinstance(protections, dict):
                    enabled_protections = [name for name, enabled in protections.items() if enabled]
                    disabled_protections = [name for name, enabled in protections.items() if not enabled]

                    enriched_context["protection_analysis"] = {
                        "enabled_protections": enabled_protections,
                        "disabled_protections": disabled_protections,
                        "protection_score": len(enabled_protections) / len(protections) if protections else 0,
                    }

            # Add interesting strings context
            if "strings" in self.analysis_results:
                strings = self.analysis_results["strings"]
                if isinstance(strings, list) and len(strings) > 0:
                    # Identify potentially interesting strings
                    interesting_keywords = [
                        "password",
                        "key",
                        "license",
                        "admin",
                        "secret",
                        "token",
                        "api",
                    ]
                    interesting_strings = [
                        s
                        for s in strings[:100]  # Limit to first 100 strings
                        if any(keyword in s.lower() for keyword in interesting_keywords)
                    ]

                    enriched_context["string_analysis"] = {
                        "total_strings": len(strings),
                        "interesting_strings_found": len(interesting_strings),
                        "sample_interesting": interesting_strings[:5],  # First 5 interesting strings
                    }

        # Add conversation context
        if self.conversation_history:
            recent_topics = []
            for entry in self.conversation_history[-5:]:  # Last 5 exchanges
                if entry.get("type") == "user":
                    content = entry.get("content", "").lower()
                    if any(topic in content for topic in ["vulnerability", "security", "exploit", "protection"]):
                        recent_topics.append("security_analysis")
                    elif any(topic in content for topic in ["string", "text", "data"]):
                        recent_topics.append("string_analysis")
                    elif any(topic in content for topic in ["analyze", "analysis", "report"]):
                        recent_topics.append("general_analysis")

            enriched_context["conversation_context"] = {
                "recent_topics": list(set(recent_topics)),
                "conversation_length": len(self.conversation_history),
                "user_expertise_level": self._infer_user_expertise(),
            }

        return enriched_context

    def _infer_user_expertise(self) -> str:
        """Infer user expertise level from conversation history."""
        if not self.conversation_history:
            return "beginner"

        user_messages = [entry.get("content", "").lower() for entry in self.conversation_history if entry.get("type") == "user"]

        # Count technical terms
        advanced_terms = [
            "rop",
            "gadget",
            "shellcode",
            "heap",
            "stack",
            "assembly",
            "disassembly",
            "reverse engineering",
        ]
        intermediate_terms = [
            "vulnerability",
            "exploit",
            "buffer overflow",
            "injection",
            "authentication",
            "encryption",
        ]

        advanced_count = sum(1 for msg in user_messages for term in advanced_terms if term in msg)
        intermediate_count = sum(1 for msg in user_messages for term in intermediate_terms if term in msg)

        ADVANCED_THRESHOLD = 2
        if advanced_count > ADVANCED_THRESHOLD:
            return "advanced"
        INTERMEDIATE_THRESHOLD = 1
        return "intermediate" if intermediate_count > INTERMEDIATE_THRESHOLD or advanced_count > 0 else "beginner"

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
                "size": os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0,
            }

        if self.analysis_results:
            # Summarize analysis results for context
            context["analysis_summary"] = {
                "categories": list(self.analysis_results.keys()),
                "vulnerability_count": len(self.analysis_results.get("vulnerabilities", {}).get("vulnerabilities", [])),
                "string_count": len(self.analysis_results.get("strings", [])),
                "has_protections": "protections" in self.analysis_results,
            }

        return context

    def _display_ai_response(self, response: str) -> None:
        """Display AI response with typing effect."""
        if not RICH_AVAILABLE:
            logger.debug("Displaying AI response in basic mode, length: %d", len(response))
            sys.stdout.write(f"\nAI: {response}\n")
            sys.stdout.flush()
            return

        # Create layout with centered content
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=1),
        )

        # Header with centered title
        header_content = Align.center(Text(" AI Assistant Response", style="bold green"))
        layout["header"].update(Panel(header_content, border_style="green"))

        # Body with response content - check for code blocks and markdown
        processed_response = self._process_code_blocks(response) if "```" in response else response

        if isinstance(processed_response, str):
            if processed_response.startswith("#") or "*" in processed_response or "**" in processed_response:
                response_content: Any = Markdown(processed_response)
            else:
                response_content = processed_response
        else:
            response_content = processed_response

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

        # Display with streaming update for real-time response rendering
        if self.console:
            with Live(layout, refresh_per_second=10, console=self.console) as live:
                # Stream response chunks as they arrive from the AI backend
                # This provides real-time display of AI processing results
                live.update(layout)
                # Allow brief time for console to render complex layouts
                time.sleep(0.05)

            self.console.print()

    @staticmethod
    def _process_code_blocks(response: str) -> str | object:
        """Process response with code blocks and apply syntax highlighting.

        Args:
            response: The AI response text potentially containing code blocks.

        Returns:
            The processed response with syntax highlighting applied, or the original
            response string if no code blocks are found or Rich is unavailable.
            May return a Syntax object or string depending on content.

        """
        if not RICH_AVAILABLE:
            return response

        import re

        # Pattern to match code blocks with optional language specification
        pattern = r"```(\w+)?\n(.*?)\n```"

        def replace_code_block(match: re.Match[str]) -> Syntax:
            """Replace code block with syntax highlighted version.

            Args:
                match: The regex match object containing code block and language.

            Returns:
                A Syntax object with highlighted code.

            """
            language = match.group(1) or "python"
            code = match.group(2)

            syntax = Syntax(code, language, theme="monokai", line_numbers=True)
            return syntax

        result_parts: list[str | Syntax] = []
        last_end = 0

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            text_before = response[last_end : match.start()]
            if text_before.strip():
                result_parts.append(text_before)

            result_parts.append(replace_code_block(match))
            last_end = match.end()

        text_after = response[last_end:]
        if text_after.strip():
            result_parts.append(text_after)

        return result_parts[0] if result_parts else response

    def _display_analysis_summary(self) -> None:
        """Display analysis summary using columns layout."""
        if not RICH_AVAILABLE or not self.analysis_results:
            logger.debug("Cannot display analysis summary: RICH_AVAILABLE=%s, has_results=%s", RICH_AVAILABLE, bool(self.analysis_results))
            logger.warning("Analysis results not available or Rich not installed")
            return

        # Create summary panels for different analysis types
        panels = []

        if "vulnerabilities" in self.analysis_results:
            vuln_data = self.analysis_results["vulnerabilities"]
            vuln_count = len(vuln_data.get("vulnerabilities", [])) if isinstance(vuln_data, dict) else 0
            panels.append(
                Panel(
                    f"[red]{vuln_count}[/red] vulnerabilities found",
                    title="Security",
                    border_style="red",
                ),
            )

        if "strings" in self.analysis_results:
            string_count = len(self.analysis_results["strings"])
            panels.append(
                Panel(
                    f"[blue]{string_count}[/blue] strings extracted",
                    title="Strings",
                    border_style="blue",
                ),
            )

        if "protections" in self.analysis_results:
            protection_data = self.analysis_results["protections"]
            protection_count = len(protection_data) if isinstance(protection_data, (list, dict)) else 1
            panels.append(
                Panel(
                    f"[yellow]{protection_count}[/yellow] protections detected",
                    title="Protections",
                    border_style="yellow",
                ),
            )

        if panels and self.console:
            # Display in columns for better layout
            columns = Columns(panels, equal=True, expand=True)
            self.console.print("\n")
            self.console.print(Panel(columns, title="Analysis Summary", border_style="cyan"))
            self.console.print("\n")

    def _show_help(self) -> str | None:
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
            logger.debug("Displaying help in basic mode")
            sys.stdout.write("\nAI Chat Commands:\n")
            sys.stdout.write("/help - Show this help message\n")
            sys.stdout.write("/clear - Clear conversation history\n")
            sys.stdout.write("/save [file] - Save conversation\n")
            sys.stdout.write("/analyze - Analysis overview\n")
            sys.stdout.write("/context - Show context\n")
            sys.stdout.write("/quit - Exit chat\n\n")
            sys.stdout.flush()

        return None

    def _clear_history(self) -> str | None:
        """Clear conversation history."""
        self.conversation_history.clear()
        logger.info("Conversation history cleared")

        if self.console:
            self.console.print("[green]Conversation history cleared[/green]")
        else:
            sys.stdout.write("Conversation history cleared\n")
            sys.stdout.flush()

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

            logger.info("Conversation saved to %s", filename)
            if self.console:
                self.console.print(f"[green]Conversation saved to {filename}[/green]")
            else:
                sys.stdout.write(f"Conversation saved to {filename}\n")
                sys.stdout.flush()

        except Exception as e:
            logger.exception("Save failed: %s", e)
            if self.console:
                self.console.print(f"[red]Save failed: {e}[/red]")
            else:
                sys.stdout.write(f"Save failed: {e}\n")
                sys.stdout.flush()

        return None

    def _analyze_current_binary(self) -> str | None:
        """Provide analysis overview of current binary."""
        if not self.binary_path:
            logger.warning("Analyze command called but no binary loaded")
            if self.console:
                self.console.print("[yellow]No binary currently loaded[/yellow]")
            else:
                sys.stdout.write("No binary currently loaded\n")
                sys.stdout.flush()
            return None

        # Generate analysis overview
        overview = f"Analysis Overview for {os.path.basename(self.binary_path)}:\n\n"

        if self.analysis_results:
            for category, data in self.analysis_results.items():
                count = len(data) if isinstance(data, (dict, list)) else 1
                overview += f" {category.replace('_', ' ').title()}: {count} items\n"
        else:
            overview += "No analysis results available. Run analysis first."

        # Generate structured AI response with analysis metadata
        response = {
            "timestamp": datetime.now().isoformat(),
            "type": "ai",
            "content": overview,
            "metadata": {
                "source": "analysis_context",
                "results_included": bool(self.analysis_results),
            },
        }

        self.conversation_history.append(response)

        logger.debug("Analysis overview generated for %s", os.path.basename(self.binary_path))
        if self.console:
            self._display_ai_response(overview)
        else:
            sys.stdout.write(f"AI: {overview}\n")
            sys.stdout.flush()

        return None

    def _show_context(self) -> str | None:
        """Show current analysis context."""
        context = self._build_context()

        logger.debug("Displaying current context with %d keys", len(context))
        if self.console:
            context_panel = Panel(
                json.dumps(context, indent=2),
                title="Current Context",
                border_style="blue",
            )
            self.console.print(context_panel)
        else:
            sys.stdout.write("\nCurrent Context:\n")
            sys.stdout.write(json.dumps(context, indent=2))
            sys.stdout.write("\n\n")
            sys.stdout.flush()

        return None

    def _switch_backend(self, args: list[str]) -> str | None:
        """Switch AI backend."""
        try:
            available_backends, current_backend = self._get_available_backends()

            if not args:
                self._display_available_backends(available_backends, current_backend)
                return None

            backend_name = args[0].lower()
            return self._handle_backend_switch_logic(backend_name, available_backends)

        except Exception as e:
            error_msg = f"Error in backend switching: {e}"
            logger.exception("Error in backend switching: %s", e)
            if self.console:
                self.console.print(f"[red]{error_msg}[/red]")
            else:
                sys.stdout.write(f"{error_msg}\n")
                sys.stdout.flush()
            return None

    def _get_available_backends(self) -> tuple[list[str], str]:
        """Helper to get available backends and current backend."""
        available_backends: list[str]
        current_backend: str
        if self.llm_manager and hasattr(self.llm_manager, "list_model_configs"):
            available_backends = list(self.llm_manager.list_model_configs())
            loaded_configs = self.llm_manager.configs if hasattr(self.llm_manager, "configs") else {}
            current_backend = next(iter(loaded_configs.keys())) if loaded_configs else "default"
        else:
            available_backends = ["openai", "anthropic", "google", "local", "ollama"]
            current_backend = "openai"
        return available_backends, current_backend

    def _display_available_backends(self, available_backends: list[str], current_backend: str) -> None:
        """Helper to display available AI backends."""
        if self.console:
            self.console.print("\n[bold cyan]Available AI Backends:[/bold cyan]")
            for backend in available_backends:
                status = ""
                if backend == current_backend:
                    status = " [green](current)[/green]"

                if self.llm_manager and hasattr(self.llm_manager, "is_backend_configured"):
                    if self.llm_manager.is_backend_configured(backend):
                        status += " [blue](configured)[/blue]"
                    else:
                        status += " [yellow](not configured)[/yellow]"

                self.console.print(f"   {backend}{status}")
            self.console.print("\n[dim]Usage: /backend <name>[/dim]")
        else:
            logger.debug("Displaying available backends in basic mode")
            sys.stdout.write("\nAvailable AI Backends:\n")
            for backend in available_backends:
                status = " (current)" if backend == current_backend else ""
                sys.stdout.write(f"   {backend}{status}\n")
            sys.stdout.write("\nUsage: /backend <name>\n")
            sys.stdout.flush()

    def _handle_backend_switch_logic(self, backend_name: str, available_backends: list[str]) -> str | None:
        """Helper to handle the logic for switching AI backend."""
        if backend_name not in available_backends:
            error_msg = f"""Backend '{backend_name}' not available. Available backends: {", ".join(available_backends)}"""
            logger.warning("Invalid backend requested: %s", backend_name)
            if self.console:
                self.console.print(f"[red]{error_msg}[/red]")
            else:
                sys.stdout.write(f"{error_msg}\n")
                sys.stdout.flush()
            return None

        try:
            if not self.llm_manager:
                from intellicrack.ai.llm_config_manager import LLMConfigManager

                self.llm_manager = LLMConfigManager()

            if success := self.llm_manager.switch_backend(backend_name):
                self._reinitialize_ai_with_backend(backend_name)
                msg = f"Successfully switched to {backend_name} backend (status: {success})!"
                logger.info("Backend switched to %s", backend_name)
                if self.console:
                    self.console.print(f"[green]{msg}[/green]")
                else:
                    sys.stdout.write(f"{msg}\n")
                    sys.stdout.flush()
            else:
                msg = f"Failed to switch to {backend_name} backend. Check configuration and API keys."
                logger.error("Failed to switch to backend: %s", backend_name)
                if self.console:
                    self.console.print(f"[red]{msg}[/red]")
                else:
                    sys.stdout.write(f"{msg}\n")
                    sys.stdout.flush()
            return None

        except Exception as e:
            error_msg = f"Error switching to {backend_name}: {e}"
            logger.exception("Error switching to backend %s: %s", backend_name, e)
            if self.console:
                self.console.print(f"[red]{error_msg}[/red]")
            else:
                sys.stdout.write(f"{error_msg}\n")
                sys.stdout.flush()
            return None

    def _reinitialize_ai_with_backend(self, backend_name: str) -> None:
        """Reinitialize AI backend systems with new backend configuration."""
        try:
            # Reinitialize orchestrator with new LLM manager
            from intellicrack.ai.orchestrator import AIOrchestrator

            self.orchestrator = AIOrchestrator()

            # Try to reinitialize coordination layer
            try:
                from intellicrack.ai.coordination_layer import AICoordinationLayer

                self.ai_backend = AICoordinationLayer()
            except (ImportError, AttributeError):
                # Use orchestrator as backend
                self.ai_backend = self.orchestrator

            # Verify new backend functionality
            if hasattr(self.ai_backend, "health_check"):
                health_status = self.ai_backend.health_check()
                if not health_status.get("healthy", False):
                    raise RuntimeError(f"New backend health check failed: {health_status.get('error', 'Unknown error')}")

            backend_class_name = type(self.ai_backend).__name__
            logger.info("AI backend (%s) reinitialized with %s", backend_class_name, backend_name)
            if self.console:
                self.console.print(f"[green]AI backend ({backend_class_name}) reinitialized with {backend_name}[/green]")
            else:
                sys.stdout.write(f"AI backend ({backend_class_name}) reinitialized with {backend_name}\n")
                sys.stdout.flush()

        except Exception as e:
            # Fall back to AIAssistant if available
            logger.warning("Backend reinitialization failed, attempting fallback: %s", e, exc_info=True)
            try:
                from intellicrack.ai.code_analysis_tools import AIAssistant

                self.ai_backend = AIAssistant()
                logger.info("Fell back to AIAssistant due to: %s", e)

                if self.console:
                    self.console.print(f"[yellow]Fell back to AIAssistant due to: {e}[/yellow]")
                else:
                    sys.stdout.write(f"Fell back to AIAssistant due to: {e}\n")
                    sys.stdout.flush()

            except Exception as fallback_error:
                logger.exception("Failed to reinitialize AI backend: %s", fallback_error)
                if self.console:
                    self.console.print(f"[red]Failed to reinitialize AI backend: {fallback_error}[/red]")
                else:
                    sys.stdout.write(f"Failed to reinitialize AI backend: {fallback_error}\n")
                    sys.stdout.flush()
                self.ai_backend = None

    def _quit_chat(self, args: list[str]) -> str:
        """Exit chat session."""
        if self.auto_save and self.conversation_history:
            self._save_conversation([f"auto_save_{int(time.time())}.json"])

        logger.info("Chat session ended by user")
        if self.console:
            self.console.print("[green]Thanks for using Intellicrack AI Assistant![/green]")
        else:
            sys.stdout.write("Thanks for using Intellicrack AI Assistant!\n")
            sys.stdout.flush()

        return "quit"

    def _load_conversation(self, args: list[str]) -> str | None:
        """Load conversation from file."""
        if not args:
            logger.debug("Load command called without filename argument")
            if self.console:
                self.console.print("[red]Usage: /load <filename>[/red]")
            else:
                sys.stdout.write("Usage: /load <filename>\n")
                sys.stdout.flush()
            return None

        filename = args[0]

        try:
            with open(filename, encoding="utf-8") as f:
                data = json.load(f)

            self.conversation_history = data.get("conversation", [])
            logger.info("Conversation loaded from %s", filename)

            if self.console:
                self.console.print(f"[green]Conversation loaded from {filename}[/green]")
            else:
                sys.stdout.write(f"Conversation loaded from {filename}\n")
                sys.stdout.flush()

        except Exception as e:
            logger.exception("Failed to load conversation from %s: %s", filename, e)
            if self.console:
                self.console.print(f"[red]Load failed: {e}[/red]")
            else:
                sys.stdout.write(f"Load failed: {e}\n")
                sys.stdout.flush()

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
                logger.warning("Unsupported export format requested: %s", format_type)
                if self.console:
                    self.console.print(f"[red]Unsupported format: {format_type}[/red]")
                else:
                    sys.stdout.write(f"Unsupported format: {format_type}\n")
                    sys.stdout.flush()
                return None

            logger.info("Conversation exported to %s", filename)
            if self.console:
                self.console.print(f"[green]Conversation exported to {filename}[/green]")
            else:
                sys.stdout.write(f"Conversation exported to {filename}\n")
                sys.stdout.flush()

        except Exception as e:
            logger.exception("Failed to export conversation: %s", e)
            if self.console:
                self.console.print(f"[red]Export failed: {e}[/red]")
            else:
                sys.stdout.write(f"Export failed: {e}\n")
                sys.stdout.flush()

        return None

    def _export_text(self, filename: str) -> None:
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

    def _export_markdown(self, filename: str) -> None:
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
                    f.write(f"##  AI Assistant\n\n{content}\n\n")

                f.write(f"*{timestamp}*\n\n---\n\n")


def launch_ai_chat(binary_path: str | None = None, analysis_results: dict[str, Any] | None = None) -> bool:
    """Launch AI chat interface.

    Args:
        binary_path: Path to current binary
        analysis_results: Current analysis results

    """
    try:
        chat = AITerminalChat(binary_path, analysis_results)
        chat.start_chat_session()
    except Exception as e:
        logger.exception("AI chat error: %s", e)
        return False
    return True


if __name__ == "__main__":
    # Test the chat interface
    launch_ai_chat()
