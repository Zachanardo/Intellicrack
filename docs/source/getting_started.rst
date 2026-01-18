Getting Started
===============

This guide will help you get started with Intellicrack.

Prerequisites
-------------

* Python 3.13 or later
* Windows 10/11 (primary platform)
* Pixi package manager

Installation
------------

Clone the repository and install dependencies:

.. code-block:: bash

   git clone https://github.com/intellicrack/intellicrack.git
   cd intellicrack
   just install

This will:

1. Install Python dependencies via Pixi
2. Download and install Ghidra
3. Download and install radare2
4. Download and install QEMU

Running Intellicrack
--------------------

Command Line
~~~~~~~~~~~~

.. code-block:: bash

   pixi run dev

GUI Mode
~~~~~~~~

.. code-block:: bash

   pixi run gui

Configuration
-------------

Intellicrack uses environment variables and configuration files for settings.
Copy the example configuration:

.. code-block:: bash

   cp .env.example .env

Edit ``.env`` to configure:

* AI provider settings (OpenAI, Anthropic, etc.)
* Tool paths (Ghidra, radare2)
* Analysis options
