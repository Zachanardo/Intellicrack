"""File Reading Helper for AI Components

This module provides a unified interface for file reading operations in AI components,
integrating the AIFileTools.read_file() method with fallback to direct file reading.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging

logger = logging.getLogger(__name__)


def read_file_with_ai_tools(
    file_path: str,
    purpose: str = "File analysis",
    app_instance=None,
    mode: str = "text",
    encoding: str = "utf-8",
    max_bytes: int | None = None,
) -> tuple[str | bytes | None, bool]:
    """Read a file using AIFileTools with fallback to direct file reading.

    Args:
        file_path: Path to the file to read
        purpose: Purpose of reading the file (for AIFileTools approval dialog)
        app_instance: Application instance for AIFileTools
        mode: 'text' or 'binary' reading mode
        encoding: Encoding for text mode (default: utf-8)
        max_bytes: Maximum bytes to read (for binary mode)

    Returns:
        Tuple of (content, used_ai_tools) where:
        - content: File content as string (text mode) or bytes (binary mode), or None if failed
        - used_ai_tools: True if AIFileTools was used, False if direct read was used

    """
    content = None
    used_ai_tools = False

    # Try to use AIFileTools first
    try:
        from .ai_file_tools import get_ai_file_tools
        ai_file_tools = get_ai_file_tools(app_instance)
        file_data = ai_file_tools.read_file(file_path, purpose=purpose)

        if file_data.get("status") == "success" and file_data.get("content") is not None:
            raw_content = file_data["content"]

            if mode == "binary":
                # Convert to bytes if needed
                if isinstance(raw_content, str):
                    content = raw_content.encode("latin-1", errors="ignore")
                else:
                    content = raw_content

                # Apply max_bytes limit if specified
                if max_bytes and len(content) > max_bytes:
                    content = content[:max_bytes]
            # Text mode - ensure string
            elif isinstance(raw_content, bytes):
                content = raw_content.decode(encoding, errors="ignore")
            else:
                content = raw_content

            used_ai_tools = True
            logger.debug(f"Successfully read file using AIFileTools: {file_path}")

    except (ImportError, AttributeError, KeyError) as e:
        logger.debug(f"AIFileTools not available: {e}")
    except Exception as e:
        logger.warning(f"Error using AIFileTools for {file_path}: {e}")

    # Fallback to direct file reading if AIFileTools didn't work
    if content is None:
        try:
            if mode == "binary":
                with open(file_path, "rb") as f:
                    if max_bytes:
                        content = f.read(max_bytes)
                    else:
                        content = f.read()
            else:
                with open(file_path, encoding=encoding) as f:
                    content = f.read()

            logger.debug(f"Read file using direct file access: {file_path}")

        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return None, False

    return content, used_ai_tools


def read_binary_header(
    file_path: str,
    header_size: int = 512,
    purpose: str = "Binary header analysis",
    app_instance=None,
) -> bytes | None:
    """Read the header of a binary file.

    Args:
        file_path: Path to the binary file
        header_size: Number of bytes to read from the beginning
        purpose: Purpose for AIFileTools
        app_instance: Application instance

    Returns:
        Binary header as bytes, or None if failed

    """
    content, _ = read_file_with_ai_tools(
        file_path=file_path,
        purpose=purpose,
        app_instance=app_instance,
        mode="binary",
        max_bytes=header_size,
    )
    return content


def read_text_file(
    file_path: str,
    purpose: str = "Text file analysis",
    app_instance=None,
    encoding: str = "utf-8",
) -> str | None:
    """Read a text file with encoding support.

    Args:
        file_path: Path to the text file
        purpose: Purpose for AIFileTools
        app_instance: Application instance
        encoding: Text encoding

    Returns:
        File content as string, or None if failed

    """
    content, _ = read_file_with_ai_tools(
        file_path=file_path,
        purpose=purpose,
        app_instance=app_instance,
        mode="text",
        encoding=encoding,
    )
    return content


class FileReadingMixin:
    """Mixin class to add AIFileTools integration to AI components.

    Classes using this mixin should have an 'app_instance' attribute.
    """

    def read_file_safe(
        self,
        file_path: str,
        purpose: str = "File analysis",
        mode: str = "text",
        encoding: str = "utf-8",
        max_bytes: int | None = None,
    ) -> str | bytes | None:
        """Read a file using AIFileTools with fallback.

        Args:
            file_path: Path to the file
            purpose: Purpose of reading
            mode: 'text' or 'binary'
            encoding: Text encoding
            max_bytes: Max bytes for binary mode

        Returns:
            File content or None

        """
        app_instance = getattr(self, "app_instance", None)
        content, _ = read_file_with_ai_tools(
            file_path=file_path,
            purpose=purpose,
            app_instance=app_instance,
            mode=mode,
            encoding=encoding,
            max_bytes=max_bytes,
        )
        return content
