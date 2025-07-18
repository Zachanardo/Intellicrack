"""
Sphinx configuration for Intellicrack documentation.
"""

import os
import sys
from datetime import datetime

# Add project root to Python path
sys.path.insert(0, os.path.abspath('..'))

# Project information
project = 'Intellicrack'
copyright = f'{datetime.now().year}, Zachary Flint'
author = 'Zachary Flint'
version = '1.0.0'
release = '1.0.0'

# General configuration
extensions = [
    'sphinx.ext.autodoc',           # Auto-generate docs from docstrings
    'sphinx.ext.napoleon',          # Support Google/NumPy docstrings
    'sphinx.ext.viewcode',          # Add [source] links
    'sphinx.ext.intersphinx',       # Link to other project docs
    'sphinx.ext.todo',              # Support TODO directives
    'sphinx.ext.coverage',          # Coverage reports
    'sphinx.ext.autosummary',       # Generate summary tables
    'sphinx.ext.inheritance_diagram', # Class inheritance diagrams
    'sphinx_autodoc_typehints',     # Better type hint support
    'myst_parser',                  # Support Markdown files
]

# Autodoc settings
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'exclude-members': '__weakref__'
}

# Autosummary settings
autosummary_generate = True
autosummary_imported_members = True

# Napoleon settings (for Google/NumPy style docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_type_aliases = None

# MyST parser for Markdown support
myst_enable_extensions = [
    "deflist",
    "tasklist",
    "html_image",
    "colon_fence",
    "smartquotes",
    "replacements",
    "linkify",
    "strikethrough",
]

# Source file parsers
source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

# Master document
master_doc = 'index'

# Language
language = 'en'

# Exclude patterns
exclude_patterns = [
    '_build', 
    'Thumbs.db', 
    '.DS_Store',
    '**/__pycache__',
    '**/test_*',
    '**/tests/*',
]

# HTML output settings
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'includehidden': True,
    'titles_only': False,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
}

html_static_path = ['_static'] if os.path.exists('_static') else []
html_css_files = ['custom.css'] if os.path.exists('_static/custom.css') else []

# Output file base name
htmlhelp_basename = 'Intellicrackdoc'

# LaTeX output settings
latex_elements = {
    'papersize': 'letterpaper',
    'pointsize': '10pt',
    'preamble': '',
    'figure_align': 'htbp',
}

latex_documents = [
    (master_doc, 'Intellicrack.tex', 'Intellicrack Documentation',
     'Zachary Flint', 'manual'),
]

# Man page output
man_pages = [
    (master_doc, 'intellicrack', 'Intellicrack Documentation',
     [author], 1)
]

# Texinfo output
texinfo_documents = [
    (master_doc, 'Intellicrack', 'Intellicrack Documentation',
     author, 'Intellicrack', 'Advanced binary analysis framework.',
     'Miscellaneous'),
]

# Intersphinx mappings
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'numpy': ('https://numpy.org/doc/stable/', None),
    'PyQt6': ('https://www.riverbankcomputing.com/static/Docs/PyQt6/', None),
}

# TODO extension settings
todo_include_todos = True

# Type hints settings
typehints_fully_qualified = False
always_document_param_types = True
typehints_document_rtype = True

# Autodoc type hints
autodoc_typehints = 'description'
autodoc_type_aliases = {
    'ArrayLike': 'numpy.typing.ArrayLike',
}

# Mock imports for modules that might not be available
autodoc_mock_imports = [
    'capstone',
    'keystone',
    'unicorn',
    'pefile',
    'pyelftools',
    'frida',
    'r2pipe',
    'angr',
    'qiling',
    'scapy',
    'yara',
    'volatility3',
    'miasm',
]

# Suppress specific warnings
suppress_warnings = ['autosummary', 'autodoc.import_object']