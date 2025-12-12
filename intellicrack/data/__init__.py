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
from pathlib import Path


logger: logging.Logger = logging.getLogger(__name__)

DATA_DIR: Path = Path(__file__).parent

CERTIFICATES_DIR: Path = DATA_DIR / "certificates"
DATABASE_DIR: Path = DATA_DIR / "database"
OUTPUT_DIR: Path = DATA_DIR / "output"
SIGNATURES_DIR: Path = DATA_DIR / "signatures"
TEMPLATES_DIR: Path = DATA_DIR / "templates"
YARA_RULES_DIR: Path = DATA_DIR / "yara_rules"

C2_SESSIONS_DB: Path = DATA_DIR / "c2_sessions.db"
SUCCESS_RATES_DB: Path = DATABASE_DIR / "intellicrack_success_rates.db"
PROTECTION_SIGNATURES_DB: Path = DATABASE_DIR / "protection_signatures.db"

CA_CERT_PATH: Path = CERTIFICATES_DIR / "ca.crt"
CA_KEY_PATH: Path = CERTIFICATES_DIR / "ca.key"

PROTOCOL_SIGNATURES: Path = SIGNATURES_DIR / "protocol_signatures.json"

YARA_RULES: dict[str, Path] = {
    "antidebug": YARA_RULES_DIR / "antidebug.yar",
    "compilers": YARA_RULES_DIR / "compilers.yar",
    "licensing": YARA_RULES_DIR / "licensing.yar",
    "packers": YARA_RULES_DIR / "packers.yar",
    "protections": YARA_RULES_DIR / "protections.yar",
}


def get_yara_rule_path(rule_name: str) -> Path | None:
    """Get path to a specific YARA rule file.

    Retrieve the file path for a YARA rule by name. This is used to locate
    YARA rule files for binary analysis and protection detection.

    Args:
        rule_name: Name of the rule (antidebug, compilers, licensing, packers, protections).

    Returns:
        Path to the YARA rule file if found, None otherwise.

    """
    return YARA_RULES.get(rule_name)


def get_available_yara_rules() -> list[str]:
    """Get list of available YARA rule files.

    Retrieve a list of all YARA rule names that have corresponding files
    existing in the YARA rules directory.

    Returns:
        List of available YARA rule names.

    """
    return [name for name, path in YARA_RULES.items() if path.exists()]


def get_data_file(filename: str) -> Path:
    """Get path to a data file in the data directory.

    Construct the full path to a data file within the package data directory.
    This is used to access signature templates, databases, and other resources.

    Args:
        filename: Name of the file to locate.

    Returns:
        Full path to the file within the data directory.

    """
    return DATA_DIR / filename


HAS_SIGNATURE_TEMPLATES: bool

try:
    from .signature_templates import *

    logger.debug("Signature templates loaded successfully")
    HAS_SIGNATURE_TEMPLATES = True
except ImportError as e:
    logger.debug("Signature templates not available: %s", e)
    HAS_SIGNATURE_TEMPLATES = False

__all__ = [
    "C2_SESSIONS_DB",
    "CA_CERT_PATH",
    "CA_KEY_PATH",
    "CERTIFICATES_DIR",
    "DATA_DIR",
    "DATABASE_DIR",
    "HAS_SIGNATURE_TEMPLATES",
    "OUTPUT_DIR",
    "PROTECTION_SIGNATURES_DB",
    "PROTOCOL_SIGNATURES",
    "SIGNATURES_DIR",
    "SUCCESS_RATES_DB",
    "TEMPLATES_DIR",
    "YARA_RULES",
    "YARA_RULES_DIR",
    "get_available_yara_rules",
    "get_data_file",
    "get_yara_rule_path",
]
