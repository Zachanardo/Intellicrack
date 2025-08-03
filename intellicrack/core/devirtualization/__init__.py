"""
Devirtualization Engine Module

Virtual machine code translation and devirtualization for
VMProtect and other virtualization-based protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from .vm_translator import VMTranslator

__all__ = ['VMTranslator']