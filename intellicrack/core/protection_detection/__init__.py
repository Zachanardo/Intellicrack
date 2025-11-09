"""Protection detection modules for Intellicrack.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""
Protection detection modules for Intellicrack.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from intellicrack.utils.logger import get_logger
logger = get_logger(__name__)
logger.debug("Protection detection package initialized")

from intellicrack.core.protection_detection.arxan_detector import (
    ArxanDetectionResult,
    ArxanDetector,
    ArxanProtectionFeatures,
    ArxanVersion,
)
from intellicrack.core.protection_detection.securom_detector import (
    SecuROMActivation,
    SecuROMDetection,
    SecuROMDetector,
    SecuROMVersion,
)
from intellicrack.core.protection_detection.starforce_detector import (
    StarForceDetection,
    StarForceDetector,
    StarForceVersion,
)

__all__ = [
    "ArxanDetector",
    "ArxanVersion",
    "ArxanProtectionFeatures",
    "ArxanDetectionResult",
    "StarForceDetector",
    "StarForceDetection",
    "StarForceVersion",
    "SecuROMDetector",
    "SecuROMDetection",
    "SecuROMVersion",
    "SecuROMActivation",
]
