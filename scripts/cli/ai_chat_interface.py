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

import os
import sys
import time
import json
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

# Rich imports for beautiful terminal UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.align import Align
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
                
        except KeyboardInterrupt:\n            self.console.print(\"\\n[yellow]Chat session ended[/yellow]\")\n        except EOFError:\n            self.console.print(\"\\n[yellow]Chat session ended[/yellow]\")\n    \n    def _start_basic_chat(self):\n        \"\"\"Start basic terminal chat interface.\"\"\"\n        print(\"Intellicrack AI Assistant\")\n        print(\"=\" * 25)\n        print(\"Type '/help' for commands or ask me anything!\")\n        print(\"Type '/quit' to exit\\n\")\n        \n        if self.binary_path:\n            print(f\"Current binary: {os.path.basename(self.binary_path)}\\n\")\n        \n        try:\n            while True:\n                user_input = input(\"You: \").strip()\n                \n                if not user_input:\n                    continue\n                \n                # Check for commands\n                if user_input.startswith('/'):\n                    command = user_input.split()[0]\n                    args = user_input.split()[1:] if len(user_input.split()) > 1 else []\n                    \n                    if command in self.commands:\n                        result = self.commands[command](args)\n                        if result == 'quit':\n                            break\n                        continue\n                    else:\n                        print(f\"Unknown command: {command}\")\n                        print(\"Type '/help' for available commands\")\n                        continue\n                \n                # Process AI query\n                self._process_ai_query_basic(user_input)\n                \n        except KeyboardInterrupt:\n            print(\"\\nChat session ended\")\n        except EOFError:\n            print(\"\\nChat session ended\")\n    \n    def _process_ai_query(self, user_input: str):\n        \"\"\"Process AI query with rich formatting.\"\"\"\n        # Add to conversation history\n        self.conversation_history.append({\n            'timestamp': datetime.now().isoformat(),\n            'type': 'user',\n            'content': user_input\n        })\n        \n        # Show thinking indicator\n        with self.console.status(\"[bold green]AI is thinking...\", spinner=\"dots\") as status:\n            response = self._get_ai_response(user_input)\n        \n        # Display response with typing effect\n        self._display_ai_response(response)\n        \n        # Add response to history\n        self.conversation_history.append({\n            'timestamp': datetime.now().isoformat(),\n            'type': 'ai',\n            'content': response\n        })\n        \n        # Trim history if too long\n        if len(self.conversation_history) > self.max_history * 2:\n            self.conversation_history = self.conversation_history[-self.max_history:]\n    \n    def _process_ai_query_basic(self, user_input: str):\n        \"\"\"Process AI query with basic formatting.\"\"\"\n        # Add to conversation history\n        self.conversation_history.append({\n            'timestamp': datetime.now().isoformat(),\n            'type': 'user',\n            'content': user_input\n        })\n        \n        print(\"AI: Thinking...\")\n        response = self._get_ai_response(user_input)\n        \n        print(f\"AI: {response}\\n\")\n        \n        # Add response to history\n        self.conversation_history.append({\n            'timestamp': datetime.now().isoformat(),\n            'type': 'ai',\n            'content': response\n        })\n    \n    def _get_ai_response(self, user_input: str) -> str:\n        \"\"\"Get AI response from backend or mock.\"\"\"\n        context = self._build_context()\n        \n        if self.ai_backend:\n            try:\n                # Use real AI backend\n                response = self.ai_backend.analyze_with_llm(\n                    user_input,\n                    context=context,\n                    analysis_type=\"chat\"\n                )\n                \n                if isinstance(response, dict):\n                    return response.get('analysis', response.get('response', str(response)))\n                else:\n                    return str(response)\n                    \n            except Exception as e:\n                return f\"AI backend error: {e}. Using fallback response.\"\n        \n        # Fallback to mock responses\n        return self._get_mock_response(user_input, context)\n    \n    def _get_mock_response(self, user_input: str, context: Dict[str, Any]) -> str:\n        \"\"\"Generate mock AI responses based on input patterns.\"\"\"\n        user_lower = user_input.lower()\n        \n        # Binary analysis questions\n        if any(word in user_lower for word in ['analyze', 'analysis', 'binary', 'file']):\n            if self.binary_path:\n                return f\"\"\"I can see you're working with {os.path.basename(self.binary_path)}. \n                \nBased on the analysis results, here's what I found:\n                • File type detection and format analysis\n                • Security protections and vulnerabilities\n                • String extraction and pattern analysis\n                \nWould you like me to focus on any specific aspect of the analysis?\"\"\"\n            else:\n                return \"To analyze a binary, please load one first using the 'load' command in the main interface.\"\n        \n        # Vulnerability questions\n        elif any(word in user_lower for word in ['vulnerability', 'vuln', 'security', 'exploit']):\n            vuln_count = len(self.analysis_results.get('vulnerabilities', {}).get('vulnerabilities', []))\n            if vuln_count > 0:\n                return f\"\"\"I found {vuln_count} potential vulnerabilities in your binary:\n                \n                • Buffer overflow risks in unsafe string functions\n                • Potential integer overflow conditions\n                • Missing security mitigations (ASLR, DEP, Stack Canaries)\n                \n                I recommend addressing the high-severity issues first. Would you like specific remediation advice?\"\"\"\n            else:\n                return \"No critical vulnerabilities detected in the current analysis. The binary appears to have good security protections.\"\n        \n        # Protection questions\n        elif any(word in user_lower for word in ['protection', 'aslr', 'dep', 'canary', 'mitigation']):\n            protections = self.analysis_results.get('protections', {})\n            if protections:\n                enabled = [k for k, v in protections.items() if v]\n                disabled = [k for k, v in protections.items() if not v]\n                \n                response = \"Security protections analysis:\\n\\n\"\n                if enabled:\n                    response += f\"✅ Enabled: {', '.join(enabled)}\\n\"\n                if disabled:\n                    response += f\"❌ Disabled: {', '.join(disabled)}\\n\"\n                \n                response += \"\\nI recommend enabling all available protections for better security.\"\n                return response\n            else:\n                return \"No protection information available. Run a comprehensive analysis to check security mitigations.\"\n        \n        # String analysis questions\n        elif any(word in user_lower for word in ['string', 'text', 'password', 'key']):\n            strings = self.analysis_results.get('strings', [])\n            if strings:\n                interesting_strings = [s for s in strings if any(keyword in s.lower() \n                                     for keyword in ['password', 'key', 'license', 'admin', 'secret'])]\n                \n                if interesting_strings:\n                    return f\"\"\"Found {len(interesting_strings)} potentially interesting strings:\n                    \n                    {chr(10).join(['• ' + s[:50] + ('...' if len(s) > 50 else '') for s in interesting_strings[:5]])}\n                    \n                    These strings might indicate authentication mechanisms or sensitive data.\"\"\"\n                else:\n                    return f\"Found {len(strings)} strings total, but none appear particularly sensitive.\"\n            else:\n                return \"No string analysis data available. Run string extraction first.\"\n        \n        # Help questions\n        elif any(word in user_lower for word in ['help', 'what', 'how', 'explain']):\n            return \"\"\"I'm here to help you understand your binary analysis results!\n            \n            I can assist with:\n            • Explaining vulnerability findings\n            • Recommending security improvements\n            • Interpreting analysis data\n            • Suggesting next steps\n            \n            Just ask me about any aspect of your analysis, or use commands like:\n            /analyze - Quick analysis overview\n            /context - Show current analysis context\n            /help - Show all available commands\"\"\"\n        \n        # General conversation\n        else:\n            return f\"\"\"I understand you're asking about: \"{user_input}\"\n            \n            I'm specialized in binary analysis and security research. I can help you:\n            • Understand analysis results\n            • Identify security issues\n            • Recommend improvements\n            • Explain technical findings\n            \n            Could you be more specific about what aspect of the analysis you'd like to explore?\"\"\"\n    \n    def _build_context(self) -> Dict[str, Any]:\n        \"\"\"Build context for AI responses.\"\"\"\n        context = {\n            'session_info': {\n                'start_time': self.session_start.isoformat(),\n                'conversation_length': len(self.conversation_history)\n            }\n        }\n        \n        if self.binary_path:\n            context['binary_info'] = {\n                'name': os.path.basename(self.binary_path),\n                'path': self.binary_path,\n                'size': os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0\n            }\n        \n        if self.analysis_results:\n            # Summarize analysis results for context\n            context['analysis_summary'] = {\n                'categories': list(self.analysis_results.keys()),\n                'vulnerability_count': len(self.analysis_results.get('vulnerabilities', {}).get('vulnerabilities', [])),\n                'string_count': len(self.analysis_results.get('strings', [])),\n                'has_protections': 'protections' in self.analysis_results\n            }\n        \n        return context\n    \n    def _display_ai_response(self, response: str):\n        \"\"\"Display AI response with typing effect.\"\"\"\n        ai_panel = Panel(\n            response,\n            title=\"🤖 AI Assistant\",\n            border_style=\"green\",\n            padding=(1, 2)\n        )\n        \n        # Simple display without typing effect for now\n        self.console.print(ai_panel)\n        self.console.print()\n    \n    def _show_help(self, args: List[str]) -> Optional[str]:\n        \"\"\"Show help information.\"\"\"\n        if self.console:\n            help_table = Table(title=\"AI Chat Commands\")\n            help_table.add_column(\"Command\", style=\"cyan\")\n            help_table.add_column(\"Description\", style=\"yellow\")\n            \n            help_table.add_row(\"/help\", \"Show this help message\")\n            help_table.add_row(\"/clear\", \"Clear conversation history\")\n            help_table.add_row(\"/save [file]\", \"Save conversation to file\")\n            help_table.add_row(\"/load [file]\", \"Load conversation from file\")\n            help_table.add_row(\"/export [format]\", \"Export conversation (json, txt, md)\")\n            help_table.add_row(\"/analyze\", \"Get analysis overview of current binary\")\n            help_table.add_row(\"/context\", \"Show current analysis context\")\n            help_table.add_row(\"/backend\", \"Switch AI backend\")\n            help_table.add_row(\"/quit, /exit\", \"Exit chat session\")\n            \n            self.console.print(help_table)\n            self.console.print()\n        else:\n            print(\"\\nAI Chat Commands:\")\n            print(\"/help - Show this help message\")\n            print(\"/clear - Clear conversation history\")\n            print(\"/save [file] - Save conversation\")\n            print(\"/analyze - Analysis overview\")\n            print(\"/context - Show context\")\n            print(\"/quit - Exit chat\\n\")\n        \n        return None\n    \n    def _clear_history(self, args: List[str]) -> Optional[str]:\n        \"\"\"Clear conversation history.\"\"\"\n        self.conversation_history.clear()\n        \n        if self.console:\n            self.console.print(\"[green]Conversation history cleared[/green]\")\n        else:\n            print(\"Conversation history cleared\")\n        \n        return None\n    \n    def _save_conversation(self, args: List[str]) -> Optional[str]:\n        \"\"\"Save conversation to file.\"\"\"\n        filename = args[0] if args else f\"ai_chat_{int(time.time())}.json\"\n        \n        try:\n            conversation_data = {\n                'session_info': {\n                    'start_time': self.session_start.isoformat(),\n                    'end_time': datetime.now().isoformat(),\n                    'binary_path': self.binary_path\n                },\n                'conversation': self.conversation_history\n            }\n            \n            with open(filename, 'w', encoding='utf-8') as f:\n                json.dump(conversation_data, f, indent=2, ensure_ascii=False)\n            \n            if self.console:\n                self.console.print(f\"[green]Conversation saved to {filename}[/green]\")\n            else:\n                print(f\"Conversation saved to {filename}\")\n                \n        except Exception as e:\n            if self.console:\n                self.console.print(f\"[red]Save failed: {e}[/red]\")\n            else:\n                print(f\"Save failed: {e}\")\n        \n        return None\n    \n    def _analyze_current_binary(self, args: List[str]) -> Optional[str]:\n        \"\"\"Provide analysis overview of current binary.\"\"\"\n        if not self.binary_path:\n            if self.console:\n                self.console.print(\"[yellow]No binary currently loaded[/yellow]\")\n            else:\n                print(\"No binary currently loaded\")\n            return None\n        \n        # Generate analysis overview\n        overview = f\"Analysis Overview for {os.path.basename(self.binary_path)}:\\n\\n\"\n        \n        if self.analysis_results:\n            for category, data in self.analysis_results.items():\n                if isinstance(data, dict):\n                    count = len(data)\n                elif isinstance(data, list):\n                    count = len(data)\n                else:\n                    count = 1\n                overview += f\"• {category.replace('_', ' ').title()}: {count} items\\n\"\n        else:\n            overview += \"No analysis results available. Run analysis first.\"\n        \n        # Simulate AI response\n        response = {\n            'timestamp': datetime.now().isoformat(),\n            'type': 'ai',\n            'content': overview\n        }\n        \n        self.conversation_history.append(response)\n        \n        if self.console:\n            self._display_ai_response(overview)\n        else:\n            print(f\"AI: {overview}\")\n        \n        return None\n    \n    def _show_context(self, args: List[str]) -> Optional[str]:\n        \"\"\"Show current analysis context.\"\"\"\n        context = self._build_context()\n        \n        if self.console:\n            context_panel = Panel(\n                json.dumps(context, indent=2),\n                title=\"Current Context\",\n                border_style=\"blue\"\n            )\n            self.console.print(context_panel)\n        else:\n            print(\"\\nCurrent Context:\")\n            print(json.dumps(context, indent=2))\n            print()\n        \n        return None\n    \n    def _switch_backend(self, args: List[str]) -> Optional[str]:\n        \"\"\"Switch AI backend.\"\"\"\n        if self.console:\n            self.console.print(\"[yellow]Backend switching not implemented yet[/yellow]\")\n        else:\n            print(\"Backend switching not implemented yet\")\n        \n        return None\n    \n    def _quit_chat(self, args: List[str]) -> str:\n        \"\"\"Exit chat session.\"\"\"\n        if self.auto_save and self.conversation_history:\n            self._save_conversation([f\"auto_save_{int(time.time())}.json\"])\n        \n        if self.console:\n            self.console.print(\"[green]Thanks for using Intellicrack AI Assistant![/green]\")\n        else:\n            print(\"Thanks for using Intellicrack AI Assistant!\")\n        \n        return 'quit'\n    \n    def _load_conversation(self, args: List[str]) -> Optional[str]:\n        \"\"\"Load conversation from file.\"\"\"\n        if not args:\n            if self.console:\n                self.console.print(\"[red]Usage: /load <filename>[/red]\")\n            else:\n                print(\"Usage: /load <filename>\")\n            return None\n        \n        filename = args[0]\n        \n        try:\n            with open(filename, 'r', encoding='utf-8') as f:\n                data = json.load(f)\n            \n            self.conversation_history = data.get('conversation', [])\n            \n            if self.console:\n                self.console.print(f\"[green]Conversation loaded from {filename}[/green]\")\n            else:\n                print(f\"Conversation loaded from {filename}\")\n                \n        except Exception as e:\n            if self.console:\n                self.console.print(f\"[red]Load failed: {e}[/red]\")\n            else:\n                print(f\"Load failed: {e}\")\n        \n        return None\n    \n    def _export_conversation(self, args: List[str]) -> Optional[str]:\n        \"\"\"Export conversation in various formats.\"\"\"\n        format_type = args[0] if args else 'txt'\n        filename = f\"conversation_export_{int(time.time())}.{format_type}\"\n        \n        try:\n            if format_type == 'json':\n                self._save_conversation([filename])\n            elif format_type == 'txt':\n                self._export_text(filename)\n            elif format_type == 'md':\n                self._export_markdown(filename)\n            else:\n                if self.console:\n                    self.console.print(f\"[red]Unsupported format: {format_type}[/red]\")\n                else:\n                    print(f\"Unsupported format: {format_type}\")\n                return None\n            \n            if self.console:\n                self.console.print(f\"[green]Conversation exported to {filename}[/green]\")\n            else:\n                print(f\"Conversation exported to {filename}\")\n                \n        except Exception as e:\n            if self.console:\n                self.console.print(f\"[red]Export failed: {e}[/red]\")\n            else:\n                print(f\"Export failed: {e}\")\n        \n        return None\n    \n    def _export_text(self, filename: str):\n        \"\"\"Export conversation as plain text.\"\"\"\n        with open(filename, 'w', encoding='utf-8') as f:\n            f.write(f\"Intellicrack AI Chat Session\\n\")\n            f.write(f\"Started: {self.session_start}\\n\")\n            if self.binary_path:\n                f.write(f\"Binary: {self.binary_path}\\n\")\n            f.write(\"\\n\" + \"=\"*50 + \"\\n\\n\")\n            \n            for entry in self.conversation_history:\n                timestamp = entry.get('timestamp', '')\n                entry_type = entry.get('type', 'unknown')\n                content = entry.get('content', '')\n                \n                speaker = \"You\" if entry_type == 'user' else \"AI\"\n                f.write(f\"[{timestamp}] {speaker}: {content}\\n\\n\")\n    \n    def _export_markdown(self, filename: str):\n        \"\"\"Export conversation as Markdown.\"\"\"\n        with open(filename, 'w', encoding='utf-8') as f:\n            f.write(f\"# Intellicrack AI Chat Session\\n\\n\")\n            f.write(f\"**Started:** {self.session_start}\\n\")\n            if self.binary_path:\n                f.write(f\"**Binary:** `{self.binary_path}`\\n\")\n            f.write(\"\\n---\\n\\n\")\n            \n            for entry in self.conversation_history:\n                timestamp = entry.get('timestamp', '')\n                entry_type = entry.get('type', 'unknown')\n                content = entry.get('content', '')\n                \n                if entry_type == 'user':\n                    f.write(f\"## 👤 User\\n\\n{content}\\n\\n\")\n                else:\n                    f.write(f\"## 🤖 AI Assistant\\n\\n{content}\\n\\n\")\n                    \n                f.write(f\"*{timestamp}*\\n\\n---\\n\\n\")\n\n\ndef launch_ai_chat(binary_path: Optional[str] = None, analysis_results: Optional[Dict[str, Any]] = None):\n    \"\"\"Launch AI chat interface.\n    \n    Args:\n        binary_path: Path to current binary\n        analysis_results: Current analysis results\n    \"\"\"\n    try:\n        chat = AITerminalChat(binary_path, analysis_results)\n        chat.start_chat_session()\n    except Exception as e:\n        print(f\"AI chat error: {e}\")\n        return False\n    return True\n\n\nif __name__ == \"__main__\":\n    # Test the chat interface\n    launch_ai_chat()\n