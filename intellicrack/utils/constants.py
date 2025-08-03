"""This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Shared constants for Intellicrack.

This module contains constants that are used across multiple modules
to avoid code duplication.
"""

import os

# Adobe process names used by multiple injection modules
ADOBE_PROCESSES = [
    "Photoshop.exe",
    "Illustrator.exe",
    "PremierePro.exe",
    "AfterFX.exe",
    "MediaEncoder.exe",
    "InDesign.exe",
    "Animate.exe",
    "Audition.exe",
    "CharacterAnimator.exe",
    "Dreamweaver.exe",
    "Lightroom.exe",
    "LightroomClassic.exe",
    "Substance 3D Designer.exe",
    "Substance 3D Painter.exe",
    "Substance 3D Sampler.exe",
    "Substance 3D Stager.exe",
    "Substance 3D Modeler.exe",
]

# Common file size formatting breakpoints
SIZE_UNITS = [
    (1024 ** 3, "GB"),
    (1024 ** 2, "MB"),
    (1024, "KB"),
    (1, "B"),
]

# C2 Server default configuration
C2_DEFAULTS = {
    "http": {
        "host": os.environ.get("C2_HTTP_HOST", "127.0.0.1"),
        "port": int(os.environ.get("C2_HTTP_PORT", "8080")),
    },
    "https": {
        "host": os.environ.get("C2_HTTPS_HOST", "127.0.0.1"),
        "port": int(os.environ.get("C2_HTTPS_PORT", "8443")),
    },
    "dns": {
        "host": os.environ.get("C2_DNS_HOST", "127.0.0.1"),
        "port": int(os.environ.get("C2_DNS_PORT", "5353")),
        "domain": os.environ.get("C2_DNS_DOMAIN", "localhost.localdomain"),
    },
    "tcp": {
        "host": os.environ.get("C2_TCP_HOST", "127.0.0.1"),
        "port": int(os.environ.get("C2_TCP_PORT", "4444")),
    },
}
