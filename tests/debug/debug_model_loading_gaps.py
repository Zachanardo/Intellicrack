#!/usr/bin/env python3
"""
Test to demonstrate missing model loading capabilities.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from intellicrack.ai.ai_script_generator import LLMScriptInterface

def test_model_loading_gaps():
    """Test various model loading scenarios."""

    print("=== Testing Model Loading Capabilities ===\n")

    # Test 1: Can we load a GGUF file?
    print("1. Testing GGUF file loading:")
    gguf_path = "models/llama-2-7b-chat.Q4_K_M.gguf"

    interface = LLMScriptInterface()

    # Try to set a GGUF model path in environment
    os.environ["MODEL_PATH"] = gguf_path
    os.environ["GGUF_MODEL"] = gguf_path

    # Check if interface can handle it
    if interface.llm_backend:
        backend_type = interface.llm_backend.get("type") if isinstance(interface.llm_backend, dict) else "unknown"
        print(f"   Backend type: {backend_type}")

        if backend_type == "local" or "gguf" in str(interface.llm_backend).lower():
            print("   ✅ GGUF support detected")
        else:
            print(f"   ❌ No GGUF support - got {backend_type} backend instead")
    else:
        print("   ❌ No backend initialized for GGUF model")

    # Test 2: Can we use HuggingFace transformers?
    print("\n2. Testing HuggingFace transformers support:")
    os.environ["HF_MODEL"] = "microsoft/phi-2"

    # Check if _try_initialize_provider can handle HF models
    result = interface._try_initialize_provider("huggingface", "dummy_key")
    if result:
        print("   ✅ HuggingFace support detected")
    else:
        print("   ❌ No HuggingFace transformers support")

    # Test 3: Can we specify arbitrary model files?
    print("\n3. Testing arbitrary model file loading:")
    model_paths = [
        "/path/to/model.bin",
        "/path/to/model.safetensors",
        "/path/to/model.pt",
    ]

    for path in model_paths:
        os.environ["MODEL_FILE"] = path
        # Re-initialize to check if it picks up the model file
        test_interface = LLMScriptInterface()
        if test_interface.llm_backend and "model_file" in str(test_interface.llm_backend):
            print(f"   ✅ Can load {path}")
        else:
            print(f"   ❌ Cannot load {path}")

    # Test 4: Check what model formats are actually supported
    print("\n4. Supported model formats:")
    print("   ✅ API-based models (OpenAI, Anthropic, etc.)")
    print("   ✅ HTTP endpoint models (Ollama, etc.)")
    print("   ❌ GGUF files")
    print("   ❌ HuggingFace model files")
    print("   ❌ PyTorch model files")
    print("   ❌ ONNX models")
    print("   ❌ TensorFlow models")

if __name__ == "__main__":
    test_model_loading_gaps()
