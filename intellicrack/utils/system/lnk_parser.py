"""
Pure Python Windows .lnk (shortcut) file parser.

This module provides a cross-platform implementation for parsing Windows .lnk files
without dependencies on Windows APIs or external tools.

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
import os
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class LnkParseError(Exception):
    """Exception raised when parsing .lnk files fails."""
    pass


class LinkFlags:
    """Link flags constants from the .lnk file format specification."""
    HasLinkTargetIDList = 0x01
    HasLinkInfo = 0x02
    HasName = 0x04
    HasRelativePath = 0x08
    HasWorkingDir = 0x10
    HasArguments = 0x20
    HasIconLocation = 0x40
    IsUnicode = 0x80
    ForceNoLinkInfo = 0x100
    HasExpString = 0x200
    RunInSeparateProcess = 0x400
    Unused1 = 0x800
    HasDarwinID = 0x1000
    RunAsUser = 0x2000
    HasExpIcon = 0x4000
    NoPidlAlias = 0x8000
    Unused2 = 0x10000
    RunWithShimLayer = 0x20000
    ForceNoLinkTrack = 0x40000
    EnableTargetMetadata = 0x80000
    DisableLinkPathTracking = 0x100000
    DisableKnownFolderTracking = 0x200000
    DisableKnownFolderAlias = 0x400000
    AllowLinkToLink = 0x800000
    UnaliasOnSave = 0x1000000
    PreferEnvironmentPath = 0x2000000
    KeepLocalIDListForUNCTarget = 0x4000000


class FileAttributes:
    """File attributes constants."""
    FILE_ATTRIBUTE_READONLY = 0x1
    FILE_ATTRIBUTE_HIDDEN = 0x2
    FILE_ATTRIBUTE_SYSTEM = 0x4
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    FILE_ATTRIBUTE_ARCHIVE = 0x20
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_ATTRIBUTE_TEMPORARY = 0x100
    FILE_ATTRIBUTE_SPARSE_FILE = 0x200
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_COMPRESSED = 0x800
    FILE_ATTRIBUTE_OFFLINE = 0x1000
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
    FILE_ATTRIBUTE_ENCRYPTED = 0x4000


class ShowWindow:
    """ShowWindow constants."""
    SW_HIDE = 0
    SW_SHOWNORMAL = 1
    SW_SHOWMINIMIZED = 2
    SW_SHOWMAXIMIZED = 3
    SW_SHOWNOACTIVATE = 4
    SW_SHOW = 5
    SW_MINIMIZE = 6
    SW_SHOWMINNOACTIVE = 7
    SW_SHOWNA = 8
    SW_RESTORE = 9
    SW_SHOWDEFAULT = 10


class LnkInfo:
    """Container for parsed .lnk file information."""

    def __init__(self):
        """Initialize empty LnkInfo structure."""
        # Header information
        self.header_size = 0
        self.link_clsid = None
        self.link_flags = 0
        self.file_attributes = 0
        self.creation_time = None
        self.access_time = None
        self.write_time = None
        self.file_size = 0
        self.icon_index = 0
        self.show_command = 0
        self.hotkey = 0

        # Link target information
        self.target_path = None
        self.relative_path = None
        self.working_directory = None
        self.command_line_arguments = None
        self.icon_location = None

        # Descriptive information
        self.name = None
        self.description = None

        # Link information
        self.link_info = {}
        self.target_idlist = []

        # Extra data
        self.extra_data = {}

        # Parsing metadata
        self.is_unicode = False
        self.parse_errors = []

    def to_dict(self) -> Dict[str, any]:
        """Convert LnkInfo to dictionary format."""
        return {
            "target_path": self.target_path,
            "relative_path": self.relative_path,
            "working_directory": self.working_directory,
            "command_line_arguments": self.command_line_arguments,
            "icon_location": self.icon_location,
            "name": self.name,
            "description": self.description,
            "file_size": self.file_size,
            "creation_time": self.creation_time.isoformat() if self.creation_time else None,
            "access_time": self.access_time.isoformat() if self.access_time else None,
            "write_time": self.write_time.isoformat() if self.write_time else None,
            "icon_index": self.icon_index,
            "show_command": self.show_command,
            "hotkey": self.hotkey,
            "link_flags": self.link_flags,
            "file_attributes": self.file_attributes,
            "is_unicode": self.is_unicode,
            "link_info": self.link_info,
            "extra_data": self.extra_data,
            "parse_errors": self.parse_errors
        }


class LnkParser:
    """Pure Python parser for Windows .lnk (shortcut) files."""

    # Expected .lnk file header signature
    LNK_SIGNATURE = b'\x4c\x00\x00\x00'  # "L\x00\x00\x00"
    
    # Expected CLSID for Shell Link
    SHELL_LINK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'

    def __init__(self):
        """Initialize the .lnk parser."""
        self.logger = logger

    def parse_lnk_file(self, lnk_path: Union[str, Path]) -> LnkInfo:
        """
        Parse a Windows .lnk shortcut file.

        Args:
            lnk_path: Path to the .lnk file

        Returns:
            LnkInfo object containing parsed information

        Raises:
            LnkParseError: If the file cannot be parsed
        """
        lnk_path = Path(lnk_path)
        
        if not lnk_path.exists():
            raise LnkParseError(f"File not found: {lnk_path}")

        if not lnk_path.suffix.lower() == '.lnk':
            raise LnkParseError(f"Not a .lnk file: {lnk_path}")

        try:
            with open(lnk_path, 'rb') as f:
                return self._parse_lnk_data(f.read())
        except Exception as e:
            raise LnkParseError(f"Failed to parse {lnk_path}: {str(e)}") from e

    def _parse_lnk_data(self, data: bytes) -> LnkInfo:
        """Parse .lnk file data from bytes."""
        if len(data) < 76:  # Minimum size for a valid .lnk file
            raise LnkParseError("File too small to be a valid .lnk file")

        lnk_info = LnkInfo()
        offset = 0

        # Parse header
        offset = self._parse_header(data, offset, lnk_info)

        # Parse LinkTargetIDList if present
        if lnk_info.link_flags & LinkFlags.HasLinkTargetIDList:
            offset = self._parse_link_target_idlist(data, offset, lnk_info)

        # Parse LinkInfo if present
        if lnk_info.link_flags & LinkFlags.HasLinkInfo:
            offset = self._parse_link_info(data, offset, lnk_info)

        # Parse string data
        offset = self._parse_string_data(data, offset, lnk_info)

        # Parse extra data
        self._parse_extra_data(data, offset, lnk_info)

        return lnk_info

    def _parse_header(self, data: bytes, offset: int, lnk_info: LnkInfo) -> int:
        """Parse the .lnk file header."""
        if len(data) < offset + 76:
            raise LnkParseError("Insufficient data for header")

        # Verify signature
        signature = data[offset:offset + 4]
        if signature != self.LNK_SIGNATURE:
            raise LnkParseError(f"Invalid .lnk signature: {signature.hex()}")

        lnk_info.header_size = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        # Parse CLSID
        lnk_info.link_clsid = data[offset:offset + 16]
        if lnk_info.link_clsid != self.SHELL_LINK_CLSID:
            self.logger.warning(f"Unexpected CLSID: {lnk_info.link_clsid.hex()}")
        offset += 16

        # Parse flags and attributes
        lnk_info.link_flags = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        lnk_info.file_attributes = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        # Parse timestamps (Windows FILETIME format)
        creation_time = struct.unpack('<Q', data[offset:offset + 8])[0]
        lnk_info.creation_time = self._filetime_to_datetime(creation_time)
        offset += 8

        access_time = struct.unpack('<Q', data[offset:offset + 8])[0]
        lnk_info.access_time = self._filetime_to_datetime(access_time)
        offset += 8

        write_time = struct.unpack('<Q', data[offset:offset + 8])[0]
        lnk_info.write_time = self._filetime_to_datetime(write_time)
        offset += 8

        # Parse file size, icon index, show command, hotkey
        lnk_info.file_size = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        lnk_info.icon_index = struct.unpack('<i', data[offset:offset + 4])[0]
        offset += 4

        lnk_info.show_command = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        lnk_info.hotkey = struct.unpack('<H', data[offset:offset + 2])[0]
        offset += 2

        # Skip reserved fields
        offset += 10

        # Check if Unicode flag is set
        lnk_info.is_unicode = bool(lnk_info.link_flags & LinkFlags.IsUnicode)

        return offset

    def _parse_link_target_idlist(self, data: bytes, offset: int, lnk_info: LnkInfo) -> int:
        """Parse the LinkTargetIDList structure."""
        if len(data) < offset + 2:
            raise LnkParseError("Insufficient data for LinkTargetIDList size")

        idlist_size = struct.unpack('<H', data[offset:offset + 2])[0]
        offset += 2

        if len(data) < offset + idlist_size:
            raise LnkParseError("Insufficient data for LinkTargetIDList")

        # Parse IDList items
        idlist_end = offset + idlist_size
        while offset < idlist_end:
            if offset + 2 > idlist_end:
                break

            item_size = struct.unpack('<H', data[offset:offset + 2])[0]
            if item_size == 0:  # End of list
                offset += 2
                break

            if offset + item_size > idlist_end:
                break

            # Extract item data (simplified - full parsing would decode PIDL structure)
            item_data = data[offset + 2:offset + item_size]
            lnk_info.target_idlist.append({
                'size': item_size,
                'data': item_data
            })

            offset += item_size

        return offset

    def _parse_link_info(self, data: bytes, offset: int, lnk_info: LnkInfo) -> int:
        """Parse the LinkInfo structure."""
        if len(data) < offset + 4:
            raise LnkParseError("Insufficient data for LinkInfo size")

        link_info_size = struct.unpack('<I', data[offset:offset + 4])[0]
        link_info_start = offset

        if len(data) < offset + link_info_size:
            raise LnkParseError("Insufficient data for LinkInfo")

        offset += 4

        # Parse LinkInfo header
        if len(data) < offset + 24:
            raise LnkParseError("Insufficient data for LinkInfo header")

        link_info_header_size = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        link_info_flags = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        volume_id_offset = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        local_base_path_offset = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        common_network_relative_link_offset = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        common_path_suffix_offset = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        # Parse optional Unicode offsets (if header size > 28)
        local_base_path_unicode_offset = 0
        common_path_suffix_unicode_offset = 0

        if link_info_header_size >= 36:
            if len(data) >= offset + 8:
                local_base_path_unicode_offset = struct.unpack('<I', data[offset:offset + 4])[0]
                offset += 4
                common_path_suffix_unicode_offset = struct.unpack('<I', data[offset:offset + 4])[0]
                offset += 4

        lnk_info.link_info = {
            'flags': link_info_flags,
            'volume_id_offset': volume_id_offset,
            'local_base_path_offset': local_base_path_offset,
            'common_network_relative_link_offset': common_network_relative_link_offset,
            'common_path_suffix_offset': common_path_suffix_offset
        }

        # Extract path information
        base_offset = link_info_start

        # Local base path
        if local_base_path_offset > 0:
            path_start = base_offset + local_base_path_offset
            if local_base_path_unicode_offset > 0:
                unicode_start = base_offset + local_base_path_unicode_offset
                if unicode_start < len(data):
                    path = self._read_null_terminated_unicode_string(data, unicode_start)
                else:
                    path = self._read_null_terminated_string(data, path_start)
            else:
                path = self._read_null_terminated_string(data, path_start)

            if path:
                lnk_info.target_path = path

        # Common path suffix
        if common_path_suffix_offset > 0:
            suffix_start = base_offset + common_path_suffix_offset
            if common_path_suffix_unicode_offset > 0:
                unicode_start = base_offset + common_path_suffix_unicode_offset
                if unicode_start < len(data):
                    suffix = self._read_null_terminated_unicode_string(data, unicode_start)
                else:
                    suffix = self._read_null_terminated_string(data, suffix_start)
            else:
                suffix = self._read_null_terminated_string(data, suffix_start)

            if suffix and lnk_info.target_path:
                lnk_info.target_path = os.path.join(lnk_info.target_path, suffix)
            elif suffix:
                lnk_info.target_path = suffix

        return link_info_start + link_info_size

    def _parse_string_data(self, data: bytes, offset: int, lnk_info: LnkInfo) -> int:
        """Parse string data sections."""
        # NAME_STRING
        if lnk_info.link_flags & LinkFlags.HasName:
            string_value, offset = self._read_string_data(data, offset, lnk_info.is_unicode)
            lnk_info.name = string_value

        # RELATIVE_PATH
        if lnk_info.link_flags & LinkFlags.HasRelativePath:
            string_value, offset = self._read_string_data(data, offset, lnk_info.is_unicode)
            lnk_info.relative_path = string_value

        # WORKING_DIR
        if lnk_info.link_flags & LinkFlags.HasWorkingDir:
            string_value, offset = self._read_string_data(data, offset, lnk_info.is_unicode)
            lnk_info.working_directory = string_value

        # COMMAND_LINE_ARGUMENTS
        if lnk_info.link_flags & LinkFlags.HasArguments:
            string_value, offset = self._read_string_data(data, offset, lnk_info.is_unicode)
            lnk_info.command_line_arguments = string_value

        # ICON_LOCATION
        if lnk_info.link_flags & LinkFlags.HasIconLocation:
            string_value, offset = self._read_string_data(data, offset, lnk_info.is_unicode)
            lnk_info.icon_location = string_value

        return offset

    def _parse_extra_data(self, data: bytes, offset: int, lnk_info: LnkInfo):
        """Parse extra data blocks."""
        while offset < len(data):
            if len(data) < offset + 4:
                break

            block_size = struct.unpack('<I', data[offset:offset + 4])[0]
            
            if block_size < 4:  # Terminal block or invalid
                break

            if len(data) < offset + block_size:
                break

            if block_size >= 8:
                block_signature = struct.unpack('<I', data[offset + 4:offset + 8])[0]
                block_data = data[offset + 8:offset + block_size]

                # Store extra data block (simplified parsing)
                lnk_info.extra_data[f"block_{block_signature:08x}"] = {
                    'size': block_size,
                    'signature': block_signature,
                    'data': block_data
                }

            offset += block_size

    def _read_string_data(self, data: bytes, offset: int, is_unicode: bool) -> Tuple[str, int]:
        """Read string data with length prefix."""
        if len(data) < offset + 2:
            return "", offset

        string_length = struct.unpack('<H', data[offset:offset + 2])[0]
        offset += 2

        if string_length == 0:
            return "", offset

        if is_unicode:
            string_bytes = string_length * 2
            if len(data) < offset + string_bytes:
                return "", offset + string_bytes

            try:
                string_value = data[offset:offset + string_bytes].decode('utf-16le')
                return string_value, offset + string_bytes
            except UnicodeDecodeError:
                return "", offset + string_bytes
        else:
            if len(data) < offset + string_length:
                return "", offset + string_length

            try:
                string_value = data[offset:offset + string_length].decode('cp1252', errors='replace')
                return string_value, offset + string_length
            except UnicodeDecodeError:
                return "", offset + string_length

    def _read_null_terminated_string(self, data: bytes, offset: int) -> str:
        """Read null-terminated ANSI string."""
        if offset >= len(data):
            return ""

        end_offset = offset
        while end_offset < len(data) and data[end_offset] != 0:
            end_offset += 1

        if end_offset == offset:
            return ""

        try:
            return data[offset:end_offset].decode('cp1252', errors='replace')
        except UnicodeDecodeError:
            return ""

    def _read_null_terminated_unicode_string(self, data: bytes, offset: int) -> str:
        """Read null-terminated Unicode string."""
        if offset >= len(data):
            return ""

        end_offset = offset
        while end_offset + 1 < len(data) and (data[end_offset] != 0 or data[end_offset + 1] != 0):
            end_offset += 2

        if end_offset == offset:
            return ""

        try:
            return data[offset:end_offset].decode('utf-16le')
        except UnicodeDecodeError:
            return ""

    def _filetime_to_datetime(self, filetime: int) -> Optional[datetime]:
        """Convert Windows FILETIME to datetime object."""
        if filetime == 0:
            return None

        try:
            # FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
            # Convert to seconds since epoch (January 1, 1970 UTC)
            EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as FILETIME
            timestamp = (filetime - EPOCH_AS_FILETIME) / 10000000.0
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, OSError):
            return None

    def get_file_attributes_description(self, attributes: int) -> List[str]:
        """Get human-readable file attributes."""
        attrs = []
        if attributes & FileAttributes.FILE_ATTRIBUTE_READONLY:
            attrs.append("readonly")
        if attributes & FileAttributes.FILE_ATTRIBUTE_HIDDEN:
            attrs.append("hidden")
        if attributes & FileAttributes.FILE_ATTRIBUTE_SYSTEM:
            attrs.append("system")
        if attributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY:
            attrs.append("directory")
        if attributes & FileAttributes.FILE_ATTRIBUTE_ARCHIVE:
            attrs.append("archive")
        if attributes & FileAttributes.FILE_ATTRIBUTE_NORMAL:
            attrs.append("normal")
        if attributes & FileAttributes.FILE_ATTRIBUTE_TEMPORARY:
            attrs.append("temporary")
        if attributes & FileAttributes.FILE_ATTRIBUTE_COMPRESSED:
            attrs.append("compressed")
        if attributes & FileAttributes.FILE_ATTRIBUTE_ENCRYPTED:
            attrs.append("encrypted")
        return attrs

    def get_show_command_description(self, show_command: int) -> str:
        """Get human-readable show command."""
        commands = {
            ShowWindow.SW_HIDE: "hidden",
            ShowWindow.SW_SHOWNORMAL: "normal",
            ShowWindow.SW_SHOWMINIMIZED: "minimized",
            ShowWindow.SW_SHOWMAXIMIZED: "maximized",
            ShowWindow.SW_SHOWNOACTIVATE: "no_activate",
            ShowWindow.SW_SHOW: "show",
            ShowWindow.SW_MINIMIZE: "minimize",
            ShowWindow.SW_SHOWMINNOACTIVE: "minimized_no_activate",
            ShowWindow.SW_SHOWNA: "show_no_activate",
            ShowWindow.SW_RESTORE: "restore",
            ShowWindow.SW_SHOWDEFAULT: "default"
        }
        return commands.get(show_command, f"unknown_{show_command}")


def parse_lnk_file(lnk_path: Union[str, Path]) -> Dict[str, any]:
    """
    Convenience function to parse a .lnk file and return a dictionary.

    Args:
        lnk_path: Path to the .lnk file

    Returns:
        Dictionary containing parsed .lnk information

    Raises:
        LnkParseError: If the file cannot be parsed
    """
    parser = LnkParser()
    lnk_info = parser.parse_lnk_file(lnk_path)
    return lnk_info.to_dict()