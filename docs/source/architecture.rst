Architecture
============

Intellicrack is built with a modular architecture designed for extensibility
and maintainability.

Overview
--------

.. code-block:: text

   intellicrack/
   ├── ai/              # AI integration (providers, prompts)
   ├── core/            # Core analysis engine
   ├── ui/              # PyQt6 GUI components
   ├── utils/           # Utility functions
   └── providers/       # External tool integrations

Core Components
---------------

AI Module
~~~~~~~~~

The AI module provides integration with multiple AI providers:

* OpenAI (GPT-4, GPT-3.5)
* Anthropic (Claude)
* Google (Gemini)
* Local models (Ollama, GGUF)

Core Analysis
~~~~~~~~~~~~~

The core module handles binary analysis:

* PE/ELF/Mach-O parsing
* Disassembly and decompilation
* Control flow analysis
* Protection detection

UI Layer
~~~~~~~~

The GUI is built with PyQt6:

* Modern dark theme (QDarkStyle)
* Syntax-highlighted code views
* Interactive hex editor
* Analysis result visualization

Provider Integrations
~~~~~~~~~~~~~~~~~~~~~

External tool integrations:

* **Ghidra**: Advanced decompilation
* **radare2**: Binary analysis framework
* **Frida**: Dynamic instrumentation
* **Capstone**: Disassembly engine
