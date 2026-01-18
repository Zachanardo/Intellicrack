"""Resource path resolution for Intellicrack assets.

Provides centralized path resolution supporting both development environments
and PyInstaller frozen applications.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final


_ASSETS_DIR_NAME: Final[str] = "assets"
_PACKAGE_NAME: Final[str] = "intellicrack"


def _get_package_root() -> Path:
    """Get the root directory of the intellicrack package.

    Returns:
        Path to the package root directory.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass: str = getattr(sys, "_MEIPASS")  # noqa: B009
        base_path = Path(meipass)
        package_path = base_path / _PACKAGE_NAME
        if package_path.exists():
            return package_path
        return base_path

    current_file = Path(__file__).resolve()
    ui_resources_dir = current_file.parent
    ui_dir = ui_resources_dir.parent
    return ui_dir.parent


def get_assets_path() -> Path:
    """Get the path to the assets directory.

    Returns:
        Path to the assets directory.

    Raises:
        FileNotFoundError: If the assets directory cannot be found.
    """
    package_root = _get_package_root()
    assets_path = package_root / _ASSETS_DIR_NAME

    if assets_path.exists():
        return assets_path

    search_paths = [
        package_root / _ASSETS_DIR_NAME,
        package_root.parent / _ASSETS_DIR_NAME,
        package_root.parent / _PACKAGE_NAME / _ASSETS_DIR_NAME,
    ]

    for path in search_paths:
        if path.exists():
            return path

    raise FileNotFoundError(  # noqa: TRY003
        f"Assets directory not found. Searched: {[str(p) for p in search_paths]}"
    )


def get_resource_path(resource_path: str) -> Path:
    """Resolve a resource path relative to the assets directory.

    Args:
        resource_path: Relative path to the resource within assets directory.
            Forward slashes are automatically converted to OS-specific separators.

    Returns:
        Absolute path to the resource.

    Example:
        >>> path = get_resource_path("icons/status_success.svg")
        >>> print(path)
        /path/to/intellicrack/assets/icons/status_success.svg
    """
    normalized_path = resource_path.replace("/", os.sep).replace("\\", os.sep)
    assets_dir = get_assets_path()
    return assets_dir / normalized_path


def get_icon_path(icon_name: str) -> Path:
    """Get the path to an icon file.

    Args:
        icon_name: Name of the icon file (with or without extension).

    Returns:
        Path to the icon file.
    """
    icons_dir = get_assets_path() / "icons"

    if "." in icon_name:
        return icons_dir / icon_name

    for ext in (".svg", ".png", ".ico"):
        path = icons_dir / f"{icon_name}{ext}"
        if path.exists():
            return path

    return icons_dir / f"{icon_name}.svg"


def get_font_path(font_name: str) -> Path:
    """Get the path to a font file.

    Args:
        font_name: Name of the font file.

    Returns:
        Path to the font file.
    """
    return get_assets_path() / "fonts" / font_name


def get_style_path(style_name: str) -> Path:
    """Get the path to a stylesheet file.

    Args:
        style_name: Name of the stylesheet file.

    Returns:
        Path to the stylesheet file.
    """
    return get_assets_path() / "styles" / style_name


def resource_exists(resource_path: str) -> bool:
    """Check if a resource exists.

    Args:
        resource_path: Relative path to the resource within assets directory.

    Returns:
        True if the resource exists, False otherwise.
    """
    try:
        path = get_resource_path(resource_path)
        return path.exists()
    except FileNotFoundError:
        return False
