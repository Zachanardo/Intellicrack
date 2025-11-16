#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sphinx documentation configuration for Intellicrack.
Production-ready configuration with comprehensive settings.
"""

# -- Path setup --------------------------------------------------------------

import os
import sys
from datetime import datetime
from pathlib import Path

# Disable pybind11 GIL assertions to prevent EnumType errors during Sphinx build
os.environ["PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF"] = "1"

# Add project root to Python path
project_root = Path(__file__).parents[2].resolve()
sys.path.insert(0, str(project_root))

# -- Project information -----------------------------------------------------

project = "Intellicrack"
copyright_info = f"{datetime.now().year}, Zachary Flint"
author = "Zachary Flint"

# Version info - read from package if available
try:
    from intellicrack import __version__

    version = __version__
    release = __version__
except ImportError:
    version = "1.0.0"
    release = "1.0.0"

# -- General configuration ---------------------------------------------------

# Extensions
extensions = [
    "sphinx.ext.autodoc",  # Auto-generate API docs from docstrings
    "sphinx.ext.napoleon",  # Support Google/NumPy style docstrings
    "sphinx.ext.viewcode",  # Add links to source code
    "sphinx.ext.intersphinx",  # Link to other project's documentation
    "sphinx.ext.todo",  # Support for TODO items
    "sphinx.ext.coverage",  # Coverage checking
    "sphinx.ext.githubpages",  # Create .nojekyll file for GitHub Pages
    "sphinx.ext.graphviz",  # Graphviz support for diagrams
    "sphinx.ext.inheritance_diagram",  # Class inheritance diagrams
    "sphinx.ext.autosummary",  # Generate autodoc summaries
    "sphinx.ext.doctest",  # Test snippets in documentation
    "sphinx.ext.duration",  # Measure durations of Sphinx processing
    "sphinx.ext.extlinks",  # Shorten external links
]

# Autosummary settings
autosummary_generate = True
autosummary_generate_overwrite = False
autosummary_imported_members = False

# Napoleon settings for Google/NumPy style docstrings
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
napoleon_use_keyword = True
napoleon_preprocess_types = True
napoleon_type_aliases = {
    "np.ndarray": "numpy.ndarray",
    "pd.DataFrame": "pandas.DataFrame",
}
napoleon_attr_annotations = True

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__,__dict__,__module__,__hash__,pyqtSignal",
    "show-inheritance": True,
    "private-members": False,
    "inherited-members": False,
}
autodoc_typehints = "both"
autodoc_typehints_format = "short"
autodoc_preserve_defaults = True
autodoc_type_aliases = {
    "Callable": "typing.Callable",
    "Iterable": "typing.Iterable",
    "Iterator": "typing.Iterator",
}

# Mock imports for libraries that might not be installed during doc build
autodoc_mock_imports = [
    # GUI frameworks
    "PyQt6",
    "PyQt5",
    "PySide6",
    "PySide2",
    "pyqtgraph",
    "matplotlib",
    # Binary analysis
    "capstone",
    "keystone",
    "unicorn",
    "pwntools",
    "angr",
    "z3",
    "triton",
    "miasm",
    # Reverse engineering tools
    "frida",
    "r2pipe",
    "radare2",
    "rizin",
    "ghidra",
    "ghidra_bridge",
    "binaryninja",
    "binja",
    # File format parsers
    "pefile",
    "pyelftools",
    "lief",
    "yara",
    # Emulation and virtualization
    "qiling",
    "speakeasy",
    "vtil",
    # Windows API
    "win32api",
    "win32com",
    "win32con",
    "win32file",
    "win32process",
    "win32security",
    "pythoncom",
    # Machine learning - EXPANDED LIST
    "torch",
    "tensorflow",
    "keras",
    "sklearn",
    "transformers",
    "intel_extension_for_pytorch",
    "ipex",
    "bitsandbytes",
    "peft",
    "accelerate",
    "datasets",
    "evaluate",
    "safetensors",
    "trl",
    "sentence_transformers",
    "huggingface_hub",
    "tokenizers",
    "torchaudio",
    "torchvision",
    # Networking
    "mitmproxy",
    "scapy",
    "dpkt",
    "pcapy",
    # System utilities
    "psutil",
    "wmi",
    "pyuac",
    # Data processing
    "numpy",
    "pandas",
    "scipy",
    # Cryptography
    "cryptography",
    "Crypto",
    "pycryptodome",
    # Web frameworks
    "requests",
    "aiohttp",
    "httpx",
    "urllib3",
    # Database
    "sqlalchemy",
    "peewee",
    "pymongo",
    # CLI and formatting
    "rich",
    "click",
    "typer",
    "colorama",
    "termcolor",
    # Serialization
    "joblib",
    "dill",
    "cloudpickle",
    # Testing
    "pytest",
    "hypothesis",
    # OpenCL and GPU
    "pyopencl",
    "opencl",
    # Additional heavy imports that cause timeouts
    "pyopengl",
    "moderngl",
    "pygame",
    # Problematic modules that cause Sphinx autosummary issues
    "intellicrack.core.task_manager",
]

# Template path
templates_path = ["_templates"]

# Source file suffixes
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

# The master toctree document
master_doc = "index"
root_doc = "index"  # New name in Sphinx 4.0+

# Patterns to exclude from documentation
exclude_patterns = [
    # Build directories
    "_build",
    "build",
    "dist",
    "*.egg-info",
    # Version control
    ".git",
    ".github",
    ".gitignore",
    # Virtual environments
    "venv",
    "env",
    ".venv",
    ".env",
    ".pixi",
    ".venv_windows",
    # Python cache
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
    ".ruff_cache",
    # System files
    "Thumbs.db",
    ".DS_Store",
    "desktop.ini",
    # IDE files
    ".vscode",
    ".idea",
    "*.swp",
    "*.swo",
    # Project specific
    "../../.pixi/**",
    "../../.venv/**",
    "../../.venv_windows/**",
    "../../__pycache__/**",
    "../../.pytest_cache/**",
    "../../.ruff_cache/**",
    "../../.benchmarks/**",
    "../../.serena/**",
    "../../.claude/**",
    "../../backups/**",
    "../../data/**",
    "../../reports/**",
    "../../visualizations/**",
    "../../dev/**",
    "../../setup/**",
    "../../tools/**",
    "../../tests/**",
    "../../examples/**",
    "../../requirements/**",
    "../../config/**",
    # Generic patterns
    "**/node_modules/**",
    "**/venv/**",
    "**/env/**",
    "**/.env/**",
    "**/dist/**",
    "**/build/**",
    "**/*.egg-info/**",
    "**/htmlcov/**",
    "**/.coverage/**",
    "**/site-packages/**",
    "**/.tox/**",
    "**/wheelhouse/**",
]

# Language for content autogenerated by Sphinx
language = "en"

# List of patterns to ignore when looking for source files
exclude_trees = []

# The name of the Pygments syntax highlighting style
pygments_style = "friendly"
pygments_dark_style = "monokai"

# -- Options for HTML output -------------------------------------------------

# HTML theme configuration
html_theme = "sphinx_rtd_theme"
html_theme_options = {
    # RTD theme options for better dark mode support
    "style_nav_header_background": "#2980B9",
    "collapse_navigation": False,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "includehidden": True,
    "titles_only": False,
    "prev_next_buttons_location": "bottom",
    "style_external_links": True,
    # Standard RTD options
    "canonical_url": "",
    "analytics_id": "",
    "logo_only": False,
}

# Paths for static files
html_static_path = ["_static"]
html_extra_path = []

# Custom CSS files
html_css_files = [
    "custom.css",  # Our dark mode CSS
]

# Custom JavaScript files
html_js_files = []

# HTML metadata
html_title = f"{project} {version} Documentation"
html_short_title = project
html_baseurl = ""
html_logo = None
html_favicon = None

# HTML sidebar configuration
html_sidebars = {
    "**": [
        "globaltoc.html",
        "sourcelink.html",
        "searchbox.html",
    ]
}

# Additional HTML options
html_last_updated_fmt = "%b %d, %Y"
html_use_smartypants = True
html_split_index = False
html_domain_indices = True
html_use_index = True
html_use_modindex = True
html_show_sourcelink = True
html_show_sphinx = False
html_show_copyright = True
html_copy_source = True

# HTML search options
html_search_language = "en"
html_search_options = {
    "type": "default",
}
html_search_scorer = ""

# -- Options for LaTeX/PDF output --------------------------------------------

latex_engine = "pdflatex"
latex_elements = {
    "papersize": "letterpaper",
    "pointsize": "10pt",
    "preamble": r"""
\usepackage{charter}
\usepackage[defaultsans]{lato}
\usepackage{inconsolata}
\setcounter{tocdepth}{3}
""",
    "figure_align": "htbp",
    "extraclassoptions": "openany,oneside",
    "sphinxsetup": "verbatimwithframe=false",
}

# Grouping the document tree into LaTeX files
latex_documents = [
    (master_doc, "Intellicrack.tex", f"{project} Documentation", author, "manual"),
]

latex_logo = None
latex_use_parts = False
latex_show_pagerefs = True
latex_show_urls = "footnote"
latex_appendices = []
latex_domain_indices = True

# -- Options for manual page output ------------------------------------------

man_pages = [(master_doc, "intellicrack", f"{project} Documentation", [author], 1)]

man_show_urls = False

# -- Options for Texinfo output ----------------------------------------------

texinfo_documents = [
    (
        master_doc,
        "Intellicrack",
        f"{project} Documentation",
        author,
        "Intellicrack",
        "Advanced Binary Analysis & Security Research Platform for defensive security research.",
        "Miscellaneous",
    ),
]

texinfo_appendices = []
texinfo_domain_indices = True
texinfo_show_urls = "footnote"
texinfo_no_detailmenu = False

# -- Options for Epub output -------------------------------------------------

epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright_info
epub_identifier = "com.intellicrack.docs"
epub_scheme = "URL"
epub_uid = "intellicrack-docs"
epub_cover = ()
epub_guide = ()
epub_pre_files = []
epub_post_files = []
epub_exclude_files = ["search.html"]
epub_tocdepth = 3
epub_tocdup = True
epub_tocscope = "default"
epub_fix_images = False
epub_max_image_width = 0
epub_show_urls = "inline"
epub_use_index = True

# -- Extension configuration -------------------------------------------------

# Intersphinx - link to other documentation
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "numpy": ("https://numpy.org/doc/stable/", None),
    "pandas": ("https://pandas.pydata.org/docs/", None),
    "requests": ("https://requests.readthedocs.io/en/latest/", None),
    "sqlalchemy": ("https://docs.sqlalchemy.org/en/latest/", None),
}

# External links configuration
extlinks = {
    "issue": ("https://github.com/Zachanardo/Intellicrack/issues/%s", "issue %s"),
    "pr": ("https://github.com/Zachanardo/Intellicrack/pull/%s", "PR %s"),
}

# TODO extension
todo_include_todos = True
todo_emit_warnings = True
todo_link_only = False

# Coverage extension
coverage_ignore_modules = []
coverage_ignore_functions = []
coverage_ignore_classes = []
coverage_ignore_pyobjects = []
coverage_write_headline = True
coverage_skip_undoc_in_source = False

# Graphviz configuration
graphviz_output_format = "svg"
graphviz_dot_args = [
    "-Grankdir=TB",
    "-Gfontsize=10",
    "-Gfontname=sans-serif",
    "-Nfontsize=10",
    "-Nfontname=sans-serif",
    "-Efontsize=10",
    "-Efontname=sans-serif",
]

# Suppress specific warnings
suppress_warnings = [
    "image.nonlocal_uri",
    "epub.unknown_project_files",
    "autosummary",
    "app.add_directive",
    "autodoc.import_object",
    "ref.python",
    "app.add_node",
]

# Nitpicky mode settings
nitpicky = False
nitpick_ignore = [
    ("py:class", "optional"),
    ("py:class", "type"),
]

# -- Custom setup ------------------------------------------------------------


def setup(app):
    """Custom Sphinx application setup."""
    # Add custom CSS if file exists
    css_file = Path(__file__).parent / "_static" / "css" / "custom.css"
    if css_file.exists():
        app.add_css_file("css/custom.css")

    # Add custom roles or directives here if needed
    app.add_config_value(
        "recommonmark_config",
        {
            "auto_toc_tree_section": "Contents",
            "enable_math": False,
            "enable_inline_math": False,
            "enable_eval_rst": True,
        },
        True,
    )

    # Custom handler for PyQt6 signals to avoid docstring warnings
    def process_docstring(app, what, name, obj, options, lines):
        """Process docstrings to fix PyQt6 signal documentation issues."""
        # Skip processing for PyQt6 signals
        if "pyqtSignal" in str(type(obj)):
            lines.clear()
            lines.append("PyQt6 signal object.")
            return

        # Fix common docstring formatting issues
        for i, line in enumerate(lines):
            # Fix inline emphasis issues by escaping problematic asterisks
            if "*" in line:
                # Escape asterisks in Qt logging rules patterns
                if "*.debug=" in line or "QT_LOGGING_RULES" in line:
                    lines[i] = line.replace("*.debug=", r"\*.debug=")
                # Replace single asterisks that aren't already part of **bold** or *italic*
                elif not "**" in line:
                    # Check if it's a properly closed emphasis
                    asterisk_count = line.count("*")
                    if asterisk_count == 1 or asterisk_count % 2 != 0:
                        # Escape single asterisks
                        lines[i] = line.replace("*", r"\*")

            # Fix common definition list formatting issues
            stripped = line.strip()
            if stripped and ":" in stripped and not stripped.endswith(":"):
                # Check for common Args:/Returns: patterns that need periods
                if (
                    stripped.startswith("Args:")
                    or stripped.startswith("Returns:")
                    or stripped.startswith("Note:")
                    or stripped.startswith("Example:")
                    or any(
                        param_pattern in stripped
                        for param_pattern in [
                            "operation:",
                            "details:",
                            "function_name:",
                            "module:",
                            "metric_name:",
                            "value:",
                            "protection_type:",
                            "technique:",
                            "output_dir:",
                            "category:",
                            "hook_spec:",
                            "importance:",
                            "process_identifier:",
                            "script_content:",
                            "script_name:",
                        ]
                    )
                ):
                    # Add period if missing and not already ending with punctuation
                    if not stripped.endswith((".", "!", "?", ":", ")", "}")):
                        lines[i] = line.rstrip() + "."

    # Custom handler to skip entire common_imports modules
    def autodoc_skip_module(app, what, name, obj, skip, options):
        """Skip entire common_imports modules from documentation."""
        # Skip entire common_imports modules
        if what == "module" and "common_imports" in name:
            return True
        return skip

    # Custom handler to prevent duplicate object descriptions
    def autodoc_skip_member(app, what, name, obj, skip, options):
        """Skip duplicate PyQt6 class definitions and common imports."""
        try:
            # Skip PyQt6 signal objects that would create duplicates
            if "pyqtSignal" in str(type(obj)):
                return True

            # Get module name safely
            module_name = None
            if hasattr(obj, "__module__"):
                module_name = getattr(obj, "__module__", None)

            # If module_name is None or not a string, return default skip value
            if module_name is None:
                return skip

            # Convert to string if it's not already
            if not isinstance(module_name, str):
                module_name = str(module_name)

            # Skip ALL PyQt6 imports that are re-exported from other modules
            # This prevents duplicate object descriptions warnings
            if module_name.startswith("PyQt6"):
                # Get the fully qualified name of where this is being documented
                doc_module = getattr(app.env, "temp_data", {}).get("autodoc:module", "")

                # If it's a PyQt6 object being documented outside of PyQt6 itself, skip it
                if doc_module and not doc_module.startswith("PyQt6"):
                    return True

            # Skip all objects from common_imports modules
            if "common_imports" in module_name:
                return True

            # Skip elftools objects in import_patterns
            if "elftools" in module_name:
                current_doc = getattr(app.env, "docname", "")
                if current_doc and "import_patterns" in current_doc:
                    return True

            # Skip duplicate SeverityLevel when re-exported
            if name == "SeverityLevel" and "severity_levels" not in module_name:
                return True

            # Skip Qt enums and other PyQt6 objects that commonly cause duplicates
            if what == "class" and ("Qt." in name or name.startswith("Qt.")):
                return True

        except Exception:
            # If any error occurs, just return the default skip value
            pass

        return skip

    # Connect event handlers
    app.connect("autodoc-process-docstring", process_docstring)
    app.connect("autodoc-skip-member", autodoc_skip_member)
    app.connect("autodoc-skip-member", autodoc_skip_module)
    app.connect("builder-inited", lambda app: print(f"Building {project} documentation..."))

    return {
        "version": "1.0",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
