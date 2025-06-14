"""
Helper function to format log messages.

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

# Missing methods for IntellicrackApp - to be integrated into main_app.py

import time


def log_message(message: str) -> str:
    """Helper function to format log messages."""
    return f"[{time.strftime('%H:%M:%S')}] {message}"

def generate_exploit_strategy(self):
    """Generate an exploit strategy based on found vulnerabilities."""
    from ..utils.ui_helpers import check_binary_path_and_warn, emit_log_message

    if not check_binary_path_and_warn(self):
        return

    emit_log_message(self, "[Exploit Strategy] Generating exploitation strategy...")

    from ..utils.exploit_common import handle_exploit_strategy_generation
    handle_exploit_strategy_generation(self.update_output, self.binary_path)

def generate_exploit_payload(self, payload_type):
    """Generate an exploit payload of the specified type."""
    from ..utils.ui_helpers import check_binary_path_and_warn, emit_log_message, generate_exploit_payload_common
    from ..utils.logger import log_message

    if not check_binary_path_and_warn(self):
        return

    emit_log_message(self, f"[Payload Generator] Generating {payload_type} payload...")

    from ..utils.exploit_common import handle_exploit_payload_generation
    handle_exploit_payload_generation(self.update_output, payload_type)
