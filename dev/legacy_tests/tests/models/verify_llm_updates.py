#!/usr/bin/env python3
"""Verify LLM configuration updates without GUI."""

import sys
import os
import ast
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def verify_tooltip_fix():
    """Verify tooltip formatting fix."""
    print("1. Checking tooltip formatting fix...")
    
    tooltip_file = Path(__file__).parent.parent / "intellicrack" / "ui" / "tooltip_helper.py"
    with open(tooltip_file, 'r') as f:
        content = f.read()
    
    if "value.replace('\\n', '<br>')" in content:
        print("   ✓ Tooltip newline replacement found")
        return True
    else:
        print("   ✗ Tooltip fix not found")
        return False

def verify_theme_fix():
    """Verify theme initialization fix."""
    print("\n2. Checking theme initialization fix...")
    
    main_app_file = Path(__file__).parent.parent / "intellicrack" / "ui" / "main_app.py"
    with open(main_app_file, 'r') as f:
        content = f.read()
    
    if 'CONFIG.get("ui_theme", "light")' in content:
        print("   ✓ Theme defaults to light")
        return True
    else:
        print("   ✗ Theme default not fixed")
        return False

def verify_dynamic_models():
    """Verify dynamic model discovery implementation."""
    print("\n3. Checking dynamic model discovery...")
    
    llm_backends_file = Path(__file__).parent.parent / "intellicrack" / "ai" / "llm_backends.py"
    with open(llm_backends_file, 'r') as f:
        content = f.read()
    
    checks = {
        "ModelDiscoveryCache class": "class ModelDiscoveryCache:",
        "ModelDiscovery class": "class ModelDiscovery:",
        "OpenAI list_models": "def list_models(self).*OpenAIBackend",
        "Anthropic list_models": "def list_models(self).*AnthropicBackend",
        "Ollama list_models": "def list_models(self).*OllamaBackend"
    }
    
    results = []
    for name, pattern in checks.items():
        if pattern in content or (pattern.count('.*') == 1 and all(p in content for p in pattern.split('.*'))):
            print(f"   ✓ {name} found")
            results.append(True)
        else:
            print(f"   ✗ {name} not found")
            results.append(False)
    
    return all(results)

def verify_local_models_ui():
    """Verify Local Models tab implementation."""
    print("\n4. Checking Local Models tab...")
    
    dialog_file = Path(__file__).parent.parent / "intellicrack" / "ui" / "dialogs" / "llm_config_dialog.py"
    with open(dialog_file, 'r') as f:
        content = f.read()
    
    checks = {
        "Local Models tab creation": 'tabs.addTab(tab, "🗂️ Local Models")',
        "ModelFetcherThread class": "class ModelFetcherThread(QThread):",
        "Import GGUF button": "local_import_gguf_btn",
        "Local models list": "local_models_list",
        "Direct model add methods": "def add_gguf_model_direct",
        "Local model registry": "def load_local_models",
        "Activate model method": "def activate_local_model"
    }
    
    results = []
    for name, pattern in checks.items():
        if pattern in content:
            print(f"   ✓ {name} found")
            results.append(True)
        else:
            print(f"   ✗ {name} not found")
            results.append(False)
    
    return all(results)

def main():
    """Run all verifications."""
    print("=== Intellicrack LLM Updates Verification ===\n")
    
    results = []
    results.append(verify_tooltip_fix())
    results.append(verify_theme_fix())
    results.append(verify_dynamic_models())
    results.append(verify_local_models_ui())
    
    print("\n=== Summary ===")
    if all(results):
        print("✅ All updates verified successfully!")
        return 0
    else:
        print("❌ Some updates are missing or incomplete")
        return 1

if __name__ == "__main__":
    sys.exit(main())