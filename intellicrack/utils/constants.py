"""
Shared constants for Intellicrack.

This module contains constants that are used across multiple modules
to avoid code duplication.
"""

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
    "Substance 3D Modeler.exe"
]

# Common file size formatting breakpoints
SIZE_UNITS = [
    (1024 ** 3, "GB"),
    (1024 ** 2, "MB"),
    (1024, "KB"),
    (1, "B")
]