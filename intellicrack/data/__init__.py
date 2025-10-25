"""Data package containing signatures, templates, and databases.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Get the data directory path
DATA_DIR = Path(__file__).parent

# Database paths
C2_SESSIONS_DB = DATA_DIR / "c2_sessions.db"
PROTOCOL_SIGNATURES = DATA_DIR / "protocol_signatures.json"

# Template and signature directories
SIGNATURES_DIR = DATA_DIR / "signatures"
TEMPLATES_DIR = DATA_DIR / "templates"
YARA_RULES_DIR = DATA_DIR / "yara_rules"

# Available YARA rule files
YARA_RULES = {
    'antidebug': YARA_RULES_DIR / "antidebug.yar",
    'compilers': YARA_RULES_DIR / "compilers.yar",
    'licensing': YARA_RULES_DIR / "licensing.yar",
    'packers': YARA_RULES_DIR / "packers.yar",
    'protections': YARA_RULES_DIR / "protections.yar",
}

def get_yara_rule_path(rule_name):
    """Get path to a specific YARA rule file.

    Args:
        rule_name (str): Name of the rule (antidebug, compilers, licensing, packers, protections)

    Returns:
        Path: Path to the YARA rule file, or None if not found

    """
    return YARA_RULES.get(rule_name)

def get_available_yara_rules():
    """Get list of available YARA rule files."""
    return [name for name, path in YARA_RULES.items() if path.exists()]

def get_data_file(filename):
    """Get path to a data file in the data directory.

    Args:
        filename (str): Name of the file

    Returns:
        Path: Full path to the file

    """
    return DATA_DIR / filename

# Import signature templates if available
try:
    from .signature_templates import *
    logger.debug("Signature templates loaded successfully")
    HAS_SIGNATURE_TEMPLATES = True
except ImportError as e:
    logger.debug("Signature templates not available: %s", e)
    HAS_SIGNATURE_TEMPLATES = False

__all__ = [
    'DATA_DIR',
    'C2_SESSIONS_DB',
    'PROTOCOL_SIGNATURES',
    'SIGNATURES_DIR',
    'TEMPLATES_DIR',
    'YARA_RULES_DIR',
    'YARA_RULES',
    'get_yara_rule_path',
    'get_available_yara_rules',
    'get_data_file',
    'HAS_SIGNATURE_TEMPLATES',
]
