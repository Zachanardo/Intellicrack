Intellicrack Documentation
===========================

**Intellicrack** is an advanced binary analysis platform for analyzing software
licensing protections. This tool focuses on defeating software licensing mechanisms,
registration systems, trial limitations, and copy protection schemes for security
research purposes.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting_started
   architecture
   api/index
   development

Features
--------

* **Binary Analysis**: Deep analysis of PE, ELF, and Mach-O executables
* **Protection Detection**: Identify common protection schemes (VMProtect, Themida, etc.)
* **License Analysis**: Analyze licensing validation mechanisms
* **AI-Powered**: Integrated AI assistance for complex analysis tasks
* **GUI Interface**: Modern PyQt6-based graphical interface

Quick Start
-----------

Installation
~~~~~~~~~~~~

.. code-block:: bash

   pixi install
   pixi run dev

Running the GUI
~~~~~~~~~~~~~~~

.. code-block:: bash

   pixi run gui

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
