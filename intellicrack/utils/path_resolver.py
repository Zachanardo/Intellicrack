"""Path Resolution Utilities for Intellicrack

Provides consistent path resolution across the application,
ensuring paths are relative to the project root or user directories.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
from pathlib import Path


def get_project_root() -> Path:
    """Get the project root directory."""
    # Go up from this file to the project root
    # This file is at: intellicrack/utils/path_resolver.py
    return Path(__file__).parent.parent.parent.resolve()


def get_data_dir() -> Path:
    """Get the data directory within the project."""
    return get_project_root() / "data"


# ML models directory removed - using LLM-only approach


def get_qemu_images_dir() -> Path:
    """Get the QEMU images directory."""
    data_dir = get_data_dir()
    qemu_dir = data_dir / "qemu_images"
    qemu_dir.mkdir(parents=True, exist_ok=True)
    return qemu_dir


# ML model path resolution removed - using LLM-only approach


def resolve_qemu_image_path(image_name: str) -> Path:
    """Resolve a QEMU image file path."""
    # Remove any hardcoded path prefixes
    if isinstance(image_name, str):
        # Strip common hardcoded prefixes
        for prefix in [
            "C:\\Intellicrack\\qemu\\images\\",
            "C:/Intellicrack/qemu/images/",
            "/Intellicrack/qemu/images/",
            "qemu/images/",
            "qemu\\images\\",
            "intellicrack/",
        ]:
            image_name = image_name.removeprefix(prefix)

        # Handle backslashes
        image_name = image_name.replace("\\", "/")

        # Get just the filename
        image_name = os.path.basename(image_name)

    return get_qemu_images_dir() / image_name


def ensure_data_directories():
    """Ensure all data directories exist."""
    directories = [
        get_data_dir(),
        get_qemu_images_dir(),
        get_data_dir() / "cache",
        get_data_dir() / "logs",
        get_data_dir() / "output",
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


# Initialize directories on import
ensure_data_directories()
