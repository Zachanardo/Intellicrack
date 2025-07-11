"""
AI Model Manager for Intellicrack

Manages AI/LLM models for script generation, code analysis, and intelligent assistance.
Supports multiple model providers including OpenAI, Anthropic, Groq, and local models.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import json
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from enum import Enum

from PyQt6.QtCore import QObject, pyqtSignal

from intellicrack.logger import get_logger

logger = get_logger(__name__)


class ModelProvider(Enum):
    """Supported AI model providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    GOOGLE = "google"
    LOCAL = "local"
    OLLAMA = "ollama"


@dataclass
class ModelConfig:
    """Configuration for an AI model"""
    name: str
    provider: ModelProvider
    model_id: str
    api_key: Optional[str] = None
    endpoint: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2000
    system_prompt: Optional[str] = None


class AIModelManager(QObject):
    """
    Manages AI models for intelligent code generation and analysis
    """
    
    # Signals
    model_loaded = pyqtSignal(str)  # model_name
    model_unloaded = pyqtSignal(str)  # model_name
    response_received = pyqtSignal(str, str)  # model_name, response
    error_occurred = pyqtSignal(str, str)  # model_name, error
    
    def __init__(self):
        super().__init__()
        self.models: Dict[str, ModelConfig] = {}
        self.active_models: Dict[str, Any] = {}
        self.providers: Dict[ModelProvider, Any] = {}
        self._initialize_providers()
        
    def _initialize_providers(self):
        """Initialize model provider interfaces"""
        # Try to import available providers
        try:
            import openai
            self.providers[ModelProvider.OPENAI] = openai
            logger.info("OpenAI provider initialized")
        except ImportError:
            logger.debug("OpenAI not available")
            
        try:
            import anthropic
            self.providers[ModelProvider.ANTHROPIC] = anthropic
            logger.info("Anthropic provider initialized")
        except ImportError:
            logger.debug("Anthropic not available")
            
        try:
            import groq
            self.providers[ModelProvider.GROQ] = groq
            logger.info("Groq provider initialized")
        except ImportError:
            logger.debug("Groq not available")
            
    def register_model(self, config: ModelConfig) -> bool:
        """
        Register a new AI model
        
        Args:
            config: Model configuration
            
        Returns:
            bool: Success status
        """
        try:
            self.models[config.name] = config
            logger.info(f"Model registered: {config.name} ({config.provider.value})")
            return True
        except Exception as e:
            logger.error(f"Failed to register model {config.name}: {e}")
            return False
            
    def load_model(self, model_name: str) -> bool:
        """
        Load and initialize a registered model
        
        Args:
            model_name: Name of the model to load
            
        Returns:
            bool: Success status
        """
        if model_name not in self.models:
            logger.error(f"Model not registered: {model_name}")
            return False
            
        config = self.models[model_name]
        
        try:
            if config.provider == ModelProvider.OPENAI:
                self._load_openai_model(config)
            elif config.provider == ModelProvider.ANTHROPIC:
                self._load_anthropic_model(config)
            elif config.provider == ModelProvider.GROQ:
                self._load_groq_model(config)
            elif config.provider == ModelProvider.LOCAL:
                self._load_local_model(config)
            else:
                logger.warning(f"Provider not implemented: {config.provider}")
                return False
                
            self.active_models[model_name] = config
            self.model_loaded.emit(model_name)
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            self.error_occurred.emit(model_name, str(e))
            return False            
    def _load_openai_model(self, config: ModelConfig):
        """Load OpenAI model"""
        if ModelProvider.OPENAI not in self.providers:
            raise ImportError("OpenAI library not installed")
            
        openai = self.providers[ModelProvider.OPENAI]
        if config.api_key:
            openai.api_key = config.api_key
        elif os.getenv('OPENAI_API_KEY'):
            openai.api_key = os.getenv('OPENAI_API_KEY')
        else:
            raise ValueError("OpenAI API key not provided")
            
    def _load_anthropic_model(self, config: ModelConfig):
        """Load Anthropic model"""
        if ModelProvider.ANTHROPIC not in self.providers:
            raise ImportError("Anthropic library not installed")
            
        anthropic = self.providers[ModelProvider.ANTHROPIC]
        api_key = config.api_key or os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("Anthropic API key not provided")
            
    def _load_groq_model(self, config: ModelConfig):
        """Load Groq model"""
        if ModelProvider.GROQ not in self.providers:
            raise ImportError("Groq library not installed")
            
        api_key = config.api_key or os.getenv('GROQ_API_KEY')
        if not api_key:
            raise ValueError("Groq API key not provided")            
    def _load_local_model(self, config: ModelConfig):
        """Load local model (placeholder for local model loading)"""
        logger.info(f"Loading local model: {config.model_id}")
        
    def generate_script(self, model_name: str, script_type: str, 
                       target: str, requirements: str) -> Optional[str]:
        """
        Generate a script using the specified model
        
        Args:
            model_name: Name of the model to use
            script_type: Type of script (frida, ghidra, etc.)
            target: Target binary or function
            requirements: Additional requirements
            
        Returns:
            Generated script or None on error
        """
        if model_name not in self.active_models:
            logger.error(f"Model not loaded: {model_name}")
            return None
            
        config = self.active_models[model_name]
        
        # Build prompt
        prompt = self._build_script_prompt(script_type, target, requirements)
        
        try:
            if config.provider == ModelProvider.OPENAI:
                response = self._generate_openai(config, prompt)
            elif config.provider == ModelProvider.ANTHROPIC:
                response = self._generate_anthropic(config, prompt)
            elif config.provider == ModelProvider.GROQ:
                response = self._generate_groq(config, prompt)
            else:
                response = self._generate_template(script_type, target, requirements)
                
            self.response_received.emit(model_name, response)
            return response            
        except Exception as e:
            logger.error(f"Script generation failed: {e}")
            self.error_occurred.emit(model_name, str(e))
            return None
            
    def _build_script_prompt(self, script_type: str, target: str, requirements: str) -> str:
        """Build prompt for script generation"""
        prompts = {
            "frida": f"""Generate a Frida hook script for the following:
Target: {target}
Requirements: {requirements}

The script should:
1. Hook the specified functions/methods
2. Log function calls and arguments
3. Allow modification of return values
4. Handle errors gracefully
5. Include comments explaining the hooks

Generate production-ready Frida JavaScript code.""",
            
            "ghidra": f"""Generate a Ghidra analysis script for:
Target: {target}
Requirements: {requirements}

The script should:
1. Analyze the binary structure
2. Identify functions and cross-references
3. Detect patterns and vulnerabilities
4. Generate meaningful comments
5. Export analysis results

Generate production-ready Ghidra Python script.""",
            
            "license_bypass": f"""Generate a license bypass script for:
Target: {target}
Requirements: {requirements}

The script should:
1. Identify license check mechanisms
2. Hook or patch validation functions
3. Bypass time-based restrictions
4. Handle multiple validation methods
5. Be stealthy and undetectable

Generate working bypass code with explanations.""",
            
            "api_hook": f"""Generate an API hooking script for:
Target: {target}
Requirements: {requirements}

The script should:
1. Hook specified API calls
2. Log parameters and return values
3. Allow modification of behavior
4. Support both user and kernel mode
5. Handle edge cases

Generate complete hooking implementation."""
        }
        
        return prompts.get(script_type.lower(), f"""Generate a {script_type} script for:
Target: {target}
Requirements: {requirements}

Generate complete, working code with proper error handling and documentation.""")
        
    def _generate_openai(self, config: ModelConfig, prompt: str) -> str:
        """Generate using OpenAI API"""
        if ModelProvider.OPENAI not in self.providers:
            raise ImportError("OpenAI not available")
            
        openai = self.providers[ModelProvider.OPENAI]
        
        system_prompt = config.system_prompt or "You are an expert reverse engineer and exploit developer. Generate working, production-ready code."
        
        try:
            response = openai.ChatCompletion.create(
                model=config.model_id,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=config.temperature,
                max_tokens=config.max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            raise
            
    def _generate_anthropic(self, config: ModelConfig, prompt: str) -> str:
        """Generate using Anthropic API"""
        if ModelProvider.ANTHROPIC not in self.providers:
            raise ImportError("Anthropic not available")
            
        anthropic = self.providers[ModelProvider.ANTHROPIC]
        api_key = config.api_key or os.getenv('ANTHROPIC_API_KEY')
        
        client = anthropic.Anthropic(api_key=api_key)
        
        system_prompt = config.system_prompt or "You are an expert reverse engineer and exploit developer. Generate working, production-ready code."
        
        try:
            response = client.messages.create(
                model=config.model_id,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.temperature,
                max_tokens=config.max_tokens
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic generation failed: {e}")
            raise
            
    def _generate_groq(self, config: ModelConfig, prompt: str) -> str:
        """Generate using Groq API"""
        # Similar implementation for Groq
        return self._generate_template("generic", "", prompt)
        
    def _generate_template(self, script_type: str, target: str, requirements: str) -> str:
        """Fallback template-based generation"""
        templates = {
            "frida": f"""// Frida Hook Script for {target}
// Requirements: {requirements}

Java.perform(function() {{
    console.log("[+] Starting hooks for {target}");
    
    // Add your hooks here
    
    console.log("[+] Hooks installed");
}});""",
            
            "ghidra": f"""# Ghidra Analysis Script for {target}
# Requirements: {requirements}

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function

def analyze():
    # Add analysis logic here
    pass

if __name__ == "__main__":
    analyze()"""
        }
        
        return templates.get(script_type.lower(), f"// Generated script for {target}\n// {requirements}")
        
    def analyze_binary(self, model_name: str, binary_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a binary using AI model
        
        Args:
            model_name: Name of the model to use
            binary_path: Path to the binary
            
        Returns:
            Analysis results or None on error
        """
        if model_name not in self.active_models:
            logger.error(f"Model not loaded: {model_name}")
            return None
            
        # TODO: Implement binary analysis with AI
        # This would involve extracting binary features and
        # sending them to the AI for analysis
        
        return {
            "model": model_name,
            "binary": binary_path,
            "analysis": "AI-powered analysis not yet implemented"
        }
        
    def get_available_models(self) -> List[str]:
        """Get list of registered models"""
        return list(self.models.keys())
        
    def get_loaded_models(self) -> List[str]:
        """Get list of currently loaded models"""
        return list(self.active_models.keys())
        
    def unload_model(self, model_name: str) -> bool:
        """Unload a model"""
        if model_name in self.active_models:
            del self.active_models[model_name]
            self.model_unloaded.emit(model_name)
            logger.info(f"Model unloaded: {model_name}")
            return True
        return False