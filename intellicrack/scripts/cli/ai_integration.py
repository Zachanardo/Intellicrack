"""AI Integration Module for Intellicrack.

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
AI Integration Module for Intellicrack.

This module provides integration points for various AI models (OpenAI, Anthropic, etc.)
to use Intellicrack capabilities safely.
"""

import json
import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import Any

from .ai_wrapper import ConfirmationManager, IntellicrackAIInterface

# Add parent directories to path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
sys.path.insert(0, project_root)


logger = logging.getLogger(__name__)


class AIModelAdapter(ABC):
    """Abstract base class for AI model adapters."""

    def __init__(self, intellicrack_interface: IntellicrackAIInterface):
        """Initialize AI model adapter with Intellicrack interface and tool definitions."""
        self.interface = intellicrack_interface
        self.tools = self._create_tool_definitions()

    @abstractmethod
    def _create_tool_definitions(self) -> list[dict[str, Any]]:
        """Create tool definitions in the model's expected format."""

    @abstractmethod
    def handle_tool_call(self, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call from the AI model."""


class ClaudeAdapter(AIModelAdapter):
    """Adapter for Anthropic Claude models."""

    def _create_tool_definitions(self) -> list[dict[str, Any]]:
        """Create tool definitions in Claude's format."""
        tools = []

        # Analyze binary tool
        tools.append({
            "name": "analyze_binary",
            "description": "Analyze a binary file to understand its structure, protections, and vulnerabilities",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file to analyze",
                    },
                    "analyses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Types of analysis to perform",
                        "default": ["comprehensive"],
                    },
                },
                "required": ["binary_path"],
            },
        })

        # Suggest patches tool
        tools.append({
            "name": "suggest_patches",
            "description": "Generate patch suggestions for bypassing protections in a binary",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file",
                    },
                },
                "required": ["binary_path"],
            },
        })

        # Apply patch tool
        tools.append({
            "name": "apply_patch",
            "description": "Apply a patch to modify a binary (requires user confirmation)",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file",
                    },
                    "patch_file": {
                        "type": "string",
                        "description": "Path to the patch definition file",
                    },
                },
                "required": ["binary_path", "patch_file"],
            },
        })

        # Generic CLI command tool
        tools.append({
            "name": "execute_cli_command",
            "description": "Execute any Intellicrack CLI command with full control",
            "input_schema": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "CLI arguments to pass",
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable description of the action",
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation of why this action is needed",
                    },
                },
                "required": ["args", "description"],
            },
        })

        return tools

    def handle_tool_call(self, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call from Claude."""
        try:
            if tool_name == "analyze_binary":
                return self.interface.analyze_binary(
                    parameters["binary_path"],
                    parameters.get("analyses", ["comprehensive"]),
                )

            if tool_name == "suggest_patches":
                return self.interface.suggest_patches(parameters["binary_path"])

            if tool_name == "apply_patch":
                return self.interface.apply_patch(
                    parameters["binary_path"],
                    parameters["patch_file"],
                )

            if tool_name == "execute_cli_command":
                return self.interface.execute_command(
                    parameters["args"],
                    parameters["description"],
                    parameters.get("reasoning"),
                )

            return {
                "status": "error",
                "message": f"Unknown tool: {tool_name}",
            }

        except Exception as e:
            logger.error(f"Error handling tool call: {e}")
            return {
                "status": "error",
                "message": str(e),
            }


class OpenAIAdapter(AIModelAdapter):
    """Adapter for OpenAI models."""

    def _create_tool_definitions(self) -> list[dict[str, Any]]:
        """Create tool definitions in OpenAI's format."""
        tools = []

        # Analyze binary function
        tools.append({
            "type": "function",
            "function": {
                "name": "analyze_binary",
                "description": "Analyze a binary file to understand its structure, protections, and vulnerabilities",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file",
                        },
                        "analyses": {
                            "type": "array",
                            "items": {"type": "string"},
                            "enum": ["comprehensive", "vulnerabilities", "protections", "license", "network"],
                            "description": "Types of analysis to perform",
                        },
                    },
                    "required": ["binary_path"],
                },
            },
        })

        # Suggest patches function
        tools.append({
            "type": "function",
            "function": {
                "name": "suggest_patches",
                "description": "Generate patch suggestions for bypassing protections",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file",
                        },
                    },
                    "required": ["binary_path"],
                },
            },
        })

        # Apply patch function
        tools.append({
            "type": "function",
            "function": {
                "name": "apply_patch",
                "description": "Apply a patch to modify a binary (requires confirmation)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file",
                        },
                        "patch_file": {
                            "type": "string",
                            "description": "Path to patch definition",
                        },
                    },
                    "required": ["binary_path", "patch_file"],
                },
            },
        })

        return tools

    def handle_tool_call(self, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call from OpenAI."""
        # Similar implementation to Claude adapter
        return self.handle_tool_call(tool_name, parameters)


class LangChainIntegration:
    """Integration for LangChain-based AI applications."""

    def __init__(self, intellicrack_interface: IntellicrackAIInterface):
        """Initialize LangChain integration with Intellicrack interface."""
        self.interface = intellicrack_interface

    def create_tools(self):
        """Create LangChain tool wrappers."""
        try:
            from langchain.tools import Tool

            tools = []

            # Analyze binary tool
            tools.append(Tool(
                name="analyze_binary",
                func=lambda input_str: self._handle_analyze(input_str),
                description="Analyze a binary file. Input: 'path/to/binary [analysis_types]'",
            ))

            # Suggest patches tool
            tools.append(Tool(
                name="suggest_patches",
                func=lambda input_str: self._handle_suggest_patches(input_str),
                description="Suggest patches for a binary. Input: 'path/to/binary'",
            ))

            # CLI command tool
            tools.append(Tool(
                name="intellicrack_cli",
                func=lambda input_str: self._handle_cli_command(input_str),
                description="Run Intellicrack CLI command. Input: 'description | command args'",
            ))

            return tools

        except ImportError:
            logger.error("LangChain not available")
            return []

    def _handle_analyze(self, input_str: str) -> str:
        """Handle analyze tool call."""
        parts = input_str.strip().split()
        binary_path = parts[0]
        analyses = parts[1:] if len(parts) > 1 else ["comprehensive"]

        result = self.interface.analyze_binary(binary_path, analyses)
        return json.dumps(result, indent=2)

    def _handle_suggest_patches(self, input_str: str) -> str:
        """Handle suggest patches tool call."""
        binary_path = input_str.strip()
        result = self.interface.suggest_patches(binary_path)
        return json.dumps(result, indent=2)

    def _handle_cli_command(self, input_str: str) -> str:
        """Handle CLI command tool call."""
        # Format: "description | command args"
        parts = input_str.split("|", 1)
        if len(parts) != 2:
            return json.dumps({"error": "Invalid format. Use: 'description | command args'"})

        description = parts[0].strip()
        args = parts[1].strip().split()

        result = self.interface.execute_command(args, description)
        return json.dumps(result, indent=2)


class IntellicrackAIServer:
    """Server for AI model interactions."""

    def __init__(self, auto_approve_low_risk: bool = False):
        """Initialize AI server with confirmation manager and multiple AI adapters."""
        self.confirmation_manager = ConfirmationManager(auto_approve_low_risk)
        self.interface = IntellicrackAIInterface(self.confirmation_manager)
        self.adapters = {
            "claude": ClaudeAdapter(self.interface),
            "openai": OpenAIAdapter(self.interface),
            "langchain": LangChainIntegration(self.interface),
        }

    def get_adapter(self, model_type: str) -> AIModelAdapter | None:
        """Get adapter for specific model type."""
        return self.adapters.get(model_type)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle an AI model request."""
        model_type = request.get("model_type", "claude")
        tool_name = request.get("tool")
        parameters = request.get("parameters", {})

        adapter = self.get_adapter(model_type)
        if not adapter:
            return {
                "status": "error",
                "message": f"Unknown model type: {model_type}",
            }

        return adapter.handle_tool_call(tool_name, parameters)


def create_ai_system_prompt() -> str:
    """Create a comprehensive system prompt for AI models."""
    return """You are an AI assistant integrated with Intellicrack, a powerful binary analysis and patching tool.

## Available Tools

1. **analyze_binary(binary_path, analyses)**
   - Performs comprehensive analysis on binary files
   - Analysis types: comprehensive, vulnerabilities, protections, license, network
   - Always start with this to understand the target

2. **suggest_patches(binary_path)**
   - Generates patch suggestions based on analysis
   - Identifies bypass points for protections and licenses
   - Returns actionable patch definitions

3. **apply_patch(binary_path, patch_file)**
   - Applies patches to modify binaries
   - Requires user confirmation for safety
   - Creates backups before modification

4. **execute_cli_command(args, description, reasoning)**
   - Full access to Intellicrack CLI capabilities
   - Use for advanced operations not covered by other tools
   - Always provide clear descriptions and reasoning

## Workflow Guidelines

1. **Analysis First**: Always analyze the binary before suggesting modifications
2. **Clear Communication**: Explain what you're doing and why
3. **Safety Considerations**: High-risk operations require user confirmation
4. **Progressive Approach**: Start with analysis, then patches, then application
5. **Error Handling**: Handle errors gracefully and suggest alternatives

## Example Workflow

```
1. User: "Help me analyze and bypass the protection in app.exe"
2. AI: Use analyze_binary("app.exe", ["comprehensive", "protections"])
3. AI: Review results and identify protection mechanisms
4. AI: Use suggest_patches("app.exe") to generate bypass strategies
5. AI: Explain findings and suggested patches to user
6. AI: With confirmation, apply_patch("app.exe", "patches.json")
```

## Important Notes

- User confirmation is required for modifications
- Always explain potential impacts of actions
- Create backups before applying patches
- Respect legal and ethical boundaries
- Focus on educational and research purposes

You have access to all 78 Intellicrack features through these tools. Use them wisely to help users understand and analyze binary programs."""


def main():
    """Example usage of AI integration."""
    # Initialize server
    server = IntellicrackAIServer(auto_approve_low_risk=False)

    # Example: Claude-style request
    request = {
        "model_type": "claude",
        "tool": "analyze_binary",
        "parameters": {
            "binary_path": "example.exe",
            "analyses": ["comprehensive", "protections"],
        },
    }

    response = server.handle_request(request)
    print("Response:", json.dumps(response, indent=2))

    # Get tool definitions for Claude
    claude_adapter = server.get_adapter("claude")
    tools = claude_adapter._create_tool_definitions()
    print("\nClaude Tools:")
    print(json.dumps(tools, indent=2))


if __name__ == "__main__":
    main()
