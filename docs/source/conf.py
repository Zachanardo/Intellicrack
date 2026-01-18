"""Sphinx configuration for Intellicrack documentation."""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

project = "Intellicrack"
copyright = f"{datetime.now().year}, Intellicrack Team"
author = "Intellicrack Team"
release = "0.1.0"
version = "0.1"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "sphinx_autodoc_typehints",
    "myst_parser",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"
language = "en"
pygments_style = "sphinx"

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_theme_options = {
    "navigation_depth": 4,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "includehidden": True,
    "titles_only": False,
    "display_version": True,
    "prev_next_buttons_location": "both",
}

html_context = {
    "display_github": True,
    "github_user": "intellicrack",
    "github_repo": "intellicrack",
    "github_version": "main",
    "conf_py_path": "/docs/source/",
}

autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
    "show-inheritance": True,
    "inherited-members": False,
}

autodoc_typehints = "description"
autodoc_typehints_format = "short"
autodoc_class_signature = "separated"
autodoc_warningiserror = False
autodoc_inherit_docstrings = False

suppress_warnings = [
    "autodoc",
    "autodoc.import_object",
    "ref.python",
]

nitpicky = False
nitpick_ignore = [
    ("py:class", "PyQt6.QtGui.QPaintDevice.PaintDeviceMetric"),
    ("py:class", "PyQt6.QtWidgets.QWidget.RenderFlag"),
    ("py:class", "PyQt6.QtWidgets.QFrame.Shadow"),
    ("py:class", "PyQt6.QtWidgets.QFrame.Shape"),
    ("py:class", "PyQt6.QtWidgets.QFrame.StyleMask"),
]

nitpick_ignore_regex = [
    (r"py:.*", r"PyQt6\..*"),
    (r"py:.*", r"http\.server\..*"),
]

autosummary_generate = True
autosummary_imported_members = True

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True
napoleon_attr_annotations = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "numpy": ("https://numpy.org/doc/stable/", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "dollarmath",
    "fieldlist",
    "html_admonition",
    "html_image",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]

todo_include_todos = True
add_module_names = False
python_use_unqualified_type_names = True
