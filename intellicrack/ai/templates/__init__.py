"""AI template files for script generation and analysis.

This package contains template files used by the AI system to generate
Frida scripts, Ghidra scripts, and other analysis tools.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Template directory path
TEMPLATES_DIR = Path(__file__).parent

# Available template files
TEMPLATE_FILES = {
    'frida_license_bypass': TEMPLATES_DIR / 'frida_license_bypass.js',
    'ghidra_analysis': TEMPLATES_DIR / 'ghidra_analysis.py',
}

def get_template_path(template_name):
    """Get path to a specific template file.

    Args:
        template_name (str): Name of the template

    Returns:
        Path: Path to the template file, or None if not found
    """
    return TEMPLATE_FILES.get(template_name)

def get_available_templates():
    """Get list of available template files."""
    return [name for name, path in TEMPLATE_FILES.items() if path.exists()]

def load_template(template_name):
    """Load contents of a template file.

    Args:
        template_name (str): Name of the template to load

    Returns:
        str: Template contents, or None if template not found
    """
    template_path = get_template_path(template_name)
    if template_path and template_path.exists():
        try:
            return template_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.error("Error loading template %s: %s", template_name, e)
            return None
    else:
        logger.warning("Template not found: %s", template_name)
        return None

def template_exists(template_name):
    """Check if a template file exists.

    Args:
        template_name (str): Name of the template to check

    Returns:
        bool: True if template exists, False otherwise
    """
    template_path = get_template_path(template_name)
    return template_path is not None and template_path.exists()

__all__ = [
    'TEMPLATES_DIR',
    'TEMPLATE_FILES',
    'get_template_path',
    'get_available_templates',
    'load_template',
    'template_exists',
]
