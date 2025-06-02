#!/usr/bin/env python3
"""
AI-Controllable CLI Wrapper for Intellicrack.

This wrapper provides a safe interface for AI models to control the Intellicrack CLI
with user confirmation safeguards.
"""

import os
import sys
import json
import subprocess
import logging
import time
import threading
import queue
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Add parent directories to path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of actions that require confirmation."""
    ANALYSIS = "analysis"
    PATCHING = "patching"
    FILE_MODIFICATION = "file_modification"
    NETWORK_OPERATION = "network_operation"
    SYSTEM_CHANGE = "system_change"
    BYPASS_OPERATION = "bypass_operation"
    MODEL_TRAINING = "model_training"
    PLUGIN_EXECUTION = "plugin_execution"


@dataclass
class PendingAction:
    """Represents an action pending user confirmation."""
    action_id: str
    action_type: ActionType
    command: List[str]
    description: str
    risk_level: str  # low, medium, high
    potential_impacts: List[str]
    timestamp: float
    ai_reasoning: Optional[str] = None


class ConfirmationManager:
    """Manages user confirmations for AI actions."""
    
    def __init__(self, auto_approve_low_risk: bool = False):
        self.pending_actions: Dict[str, PendingAction] = {}
        self.action_history: List[Dict[str, Any]] = []
        self.auto_approve_low_risk = auto_approve_low_risk
        self.confirmation_queue = queue.Queue()
        
    def request_confirmation(self, action: PendingAction) -> bool:
        """Request user confirmation for an action."""
        # Auto-approve low-risk actions if enabled
        if self.auto_approve_low_risk and action.risk_level == "low":
            logger.info(f"Auto-approving low-risk action: {action.description}")
            return True
            
        # Display action details
        print("\n" + "="*80)
        print("🤖 AI ACTION CONFIRMATION REQUEST")
        print("="*80)
        print(f"Action Type: {action.action_type.value}")
        print(f"Description: {action.description}")
        print(f"Risk Level: {action.risk_level.upper()}")
        print(f"Command: {' '.join(action.command)}")
        
        if action.potential_impacts:
            print("\nPotential Impacts:")
            for impact in action.potential_impacts:
                print(f"  • {impact}")
                
        if action.ai_reasoning:
            print(f"\nAI Reasoning: {action.ai_reasoning}")
            
        print("\n" + "-"*80)
        
        # Get user input
        while True:
            response = input("Allow this action? [y/N/d(etails)]: ").lower().strip()
            
            if response == 'd':
                # Show detailed command breakdown
                print("\nDetailed Command Breakdown:")
                for i, arg in enumerate(action.command):
                    print(f"  [{i}] {arg}")
                continue
                
            elif response == 'y':
                self.action_history.append({
                    "action": action,
                    "approved": True,
                    "timestamp": time.time()
                })
                return True
                
            else:  # Default to No
                self.action_history.append({
                    "action": action,
                    "approved": False,
                    "timestamp": time.time()
                })
                return False


class IntellicrackAIInterface:
    """AI-safe interface for Intellicrack CLI operations."""
    
    # Define risk levels for different operations
    RISK_LEVELS = {
        # Analysis operations - generally safe
        "--comprehensive": "low",
        "--cfg-analysis": "low",
        "--vulnerability-scan": "low",
        "--detect-protections": "low",
        "--license-analysis": "low",
        "--import-export": "low",
        "--section-analysis": "low",
        
        # Potentially modifying operations
        "--suggest-patches": "medium",
        "--generate-payload": "medium",
        "--memory-patch": "medium",
        "--frida-script": "medium",
        
        # High-risk operations
        "--apply-patch": "high",
        "--bypass-tpm": "high",
        "--bypass-vm-detection": "high",
        "--emulate-dongle": "high",
        "--hwid-spoof": "high",
        "--time-bomb-defuser": "high",
        "--telemetry-blocker": "high",
        "--plugin-run": "high",
        "--train-model": "high",
    }
    
    def __init__(self, confirmation_manager: Optional[ConfirmationManager] = None):
        self.confirmation_manager = confirmation_manager or ConfirmationManager()
        self.cli_path = os.path.join(script_dir, "main.py")
        self.current_analysis = {}
        self.session_id = self._generate_session_id()
        
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import uuid
        return str(uuid.uuid4())[:8]
        
    def _determine_action_type(self, args: List[str]) -> ActionType:
        """Determine the type of action based on arguments."""
        if any(arg in args for arg in ["--apply-patch", "--memory-patch"]):
            return ActionType.PATCHING
        elif any(arg in args for arg in ["--bypass-tpm", "--bypass-vm-detection", "--hwid-spoof"]):
            return ActionType.BYPASS_OPERATION
        elif any(arg in args for arg in ["--network-capture", "--ssl-intercept"]):
            return ActionType.NETWORK_OPERATION
        elif any(arg in args for arg in ["--plugin-run", "--plugin-remote"]):
            return ActionType.PLUGIN_EXECUTION
        elif any(arg in args for arg in ["--train-model"]):
            return ActionType.MODEL_TRAINING
        elif "--output" in args or "--apply-patch" in args:
            return ActionType.FILE_MODIFICATION
        else:
            return ActionType.ANALYSIS
            
    def _determine_risk_level(self, args: List[str]) -> str:
        """Determine risk level of the operation."""
        max_risk = "low"
        
        for arg in args:
            if arg in self.RISK_LEVELS:
                risk = self.RISK_LEVELS[arg]
                if risk == "high":
                    return "high"
                elif risk == "medium" and max_risk == "low":
                    max_risk = "medium"
                    
        return max_risk
        
    def _get_potential_impacts(self, args: List[str]) -> List[str]:
        """Determine potential impacts of the operation."""
        impacts = []
        
        if "--apply-patch" in args:
            impacts.append("Binary file will be modified (backup created)")
        if "--memory-patch" in args:
            impacts.append("Process memory will be modified")
        if "--network-capture" in args:
            impacts.append("Network traffic will be captured")
        if "--ssl-intercept" in args:
            impacts.append("SSL/TLS traffic will be intercepted")
        if "--train-model" in args:
            impacts.append("ML model will be trained and saved")
        if "--plugin-run" in args:
            impacts.append("External plugin code will be executed")
        if any(bypass in args for bypass in ["--bypass-tpm", "--bypass-vm-detection"]):
            impacts.append("System protection mechanisms will be bypassed")
            
        return impacts
        
    def _create_action(self, args: List[str], description: str, 
                      ai_reasoning: Optional[str] = None) -> PendingAction:
        """Create a pending action for confirmation."""
        import uuid
        
        return PendingAction(
            action_id=str(uuid.uuid4()),
            action_type=self._determine_action_type(args),
            command=["python3", self.cli_path] + args,
            description=description,
            risk_level=self._determine_risk_level(args),
            potential_impacts=self._get_potential_impacts(args),
            timestamp=time.time(),
            ai_reasoning=ai_reasoning
        )
        
    def execute_command(self, args: List[str], description: str, 
                       ai_reasoning: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute an Intellicrack CLI command with confirmation.
        
        Args:
            args: CLI arguments
            description: Human-readable description of the action
            ai_reasoning: Optional AI explanation for why this action is needed
            
        Returns:
            Dict containing execution results
        """
        # Create pending action
        action = self._create_action(args, description, ai_reasoning)
        
        # Request confirmation
        if not self.confirmation_manager.request_confirmation(action):
            return {
                "status": "cancelled",
                "message": "User declined the action",
                "action": action
            }
            
        # Execute the command
        try:
            logger.info(f"Executing: {' '.join(action.command)}")
            
            result = subprocess.run(
                action.command,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse output if JSON
            output = result.stdout
            try:
                if "--format json" in args:
                    output = json.loads(output)
            except:
                pass
                
            return {
                "status": "success",
                "exit_code": result.returncode,
                "stdout": output,
                "stderr": result.stderr,
                "action": action
            }
            
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": "Command timed out",
                "action": action
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "action": action
            }
            
    def analyze_binary(self, binary_path: str, analyses: List[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a binary.
        
        Args:
            binary_path: Path to the binary
            analyses: List of specific analyses to run
            
        Returns:
            Analysis results
        """
        if analyses is None:
            analyses = ["comprehensive"]
            
        args = [binary_path, "--format", "json"]
        
        # Add analysis flags
        for analysis in analyses:
            if analysis == "comprehensive":
                args.append("--comprehensive")
            elif analysis == "vulnerabilities":
                args.append("--vulnerability-scan")
            elif analysis == "protections":
                args.append("--detect-protections")
            elif analysis == "license":
                args.append("--license-analysis")
            elif analysis == "network":
                args.append("--protocol-fingerprint")
                
        description = f"Analyze binary: {os.path.basename(binary_path)}"
        reasoning = f"Performing {', '.join(analyses)} analysis to understand the binary"
        
        return self.execute_command(args, description, reasoning)
        
    def suggest_patches(self, binary_path: str) -> Dict[str, Any]:
        """Suggest patches for a binary."""
        args = [binary_path, "--suggest-patches", "--format", "json"]
        description = f"Generate patch suggestions for: {os.path.basename(binary_path)}"
        reasoning = "Analyzing binary to identify patchable locations"
        
        return self.execute_command(args, description, reasoning)
        
    def apply_patch(self, binary_path: str, patch_file: str) -> Dict[str, Any]:
        """Apply a patch to a binary."""
        args = [binary_path, "--apply-patch", "--patch-file", patch_file]
        description = f"Apply patch to: {os.path.basename(binary_path)}"
        reasoning = "Applying identified patches to bypass protections"
        
        return self.execute_command(args, description, reasoning)
        
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of the current session."""
        return {
            "session_id": self.session_id,
            "total_actions": len(self.confirmation_manager.action_history),
            "approved_actions": sum(1 for h in self.confirmation_manager.action_history if h["approved"]),
            "declined_actions": sum(1 for h in self.confirmation_manager.action_history if not h["approved"]),
            "action_history": self.confirmation_manager.action_history
        }


# Tool definitions for AI models (Claude Code style)
AI_TOOLS = {
    "analyze_binary": {
        "description": "Analyze a binary file to understand its structure, protections, and vulnerabilities",
        "parameters": {
            "binary_path": "Path to the binary file",
            "analyses": "List of analyses to perform (comprehensive, vulnerabilities, protections, license, network)"
        }
    },
    "suggest_patches": {
        "description": "Generate patch suggestions for bypassing protections in a binary",
        "parameters": {
            "binary_path": "Path to the binary file"
        }
    },
    "apply_patch": {
        "description": "Apply a patch to modify a binary (requires user confirmation)",
        "parameters": {
            "binary_path": "Path to the binary file",
            "patch_file": "Path to the patch definition file"
        }
    },
    "execute_command": {
        "description": "Execute any Intellicrack CLI command with full control",
        "parameters": {
            "args": "List of CLI arguments",
            "description": "Human-readable description of the action",
            "ai_reasoning": "Explanation of why this action is needed"
        }
    }
}


def create_ai_prompt() -> str:
    """Create prompt for AI models to use Intellicrack."""
    return """You are an AI assistant with access to Intellicrack, a comprehensive binary analysis and patching tool.

You can use the following tools:

1. analyze_binary(binary_path, analyses) - Analyze a binary file
2. suggest_patches(binary_path) - Generate patch suggestions
3. apply_patch(binary_path, patch_file) - Apply patches (requires confirmation)
4. execute_command(args, description, ai_reasoning) - Run any CLI command

When analyzing binaries:
- Start with comprehensive analysis to understand the target
- Look for protections, license mechanisms, and vulnerabilities
- Suggest appropriate patches based on findings
- Always explain your reasoning for actions

Remember:
- High-risk actions require user confirmation
- Provide clear descriptions for all actions
- Explain potential impacts of modifications
- Create backups before applying patches

Example workflow:
1. Analyze the binary comprehensively
2. Identify protection mechanisms
3. Suggest appropriate patches
4. Apply patches with user confirmation
"""


def main():
    """Example usage and testing."""
    # Initialize the AI interface
    manager = ConfirmationManager(auto_approve_low_risk=False)
    ai_interface = IntellicrackAIInterface(manager)
    
    print("Intellicrack AI Interface Initialized")
    print("This interface provides safe AI control with confirmation safeguards")
    print("-" * 80)
    
    # Example: Analyze a binary
    result = ai_interface.analyze_binary(
        "example.exe",
        analyses=["comprehensive", "protections"]
    )
    print(f"Analysis result: {result['status']}")
    
    # Show session summary
    summary = ai_interface.get_session_summary()
    print(f"\nSession Summary:")
    print(f"  Total actions: {summary['total_actions']}")
    print(f"  Approved: {summary['approved_actions']}")
    print(f"  Declined: {summary['declined_actions']}")


if __name__ == "__main__":
    main()