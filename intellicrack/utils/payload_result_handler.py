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
along with this program.  If not, see https://www.gnu.org/licenses/.

Payload Result Handler

Handles the results of payload execution and exploitation attempts.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PayloadResultHandler:
    """Handles results from payload execution and exploitation attempts."""

    def __init__(self, storage_path: str | None = None):
        """Initialize the payload result handler.

        Args:
            storage_path: Optional path to store results

        """
        self.storage_path = storage_path or "exploitation_results"
        self.results_cache = []

    def handle_result(self, payload_info: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        """Handle the result of a payload execution.

        Args:
            payload_info: Information about the payload
            result: Execution result

        Returns:
            Processed result dictionary

        """
        processed_result = {
            "timestamp": time.time(),
            "payload_id": payload_info.get("id", "unknown"),
            "payload_type": payload_info.get("type", "unknown"),
            "success": result.get("success", False),
            "output": result.get("output", ""),
            "error": result.get("error", ""),
            "execution_time": result.get("execution_time", 0),
            "target_info": result.get("target_info", {}),
            "metadata": result.get("metadata", {}),
        }

        self.results_cache.append(processed_result)

        # Log result
        if processed_result["success"]:
            logger.info(f"Payload {processed_result['payload_id']} executed successfully")
        else:
            logger.warning(
                f"Payload {processed_result['payload_id']} failed: {processed_result['error']}"
            )

        return processed_result

    def get_results(self, payload_id: str | None = None) -> list[dict[str, Any]]:
        """Get stored results, optionally filtered by payload ID.

        Args:
            payload_id: Optional payload ID to filter by

        Returns:
            List of result dictionaries

        """
        if payload_id:
            return [r for r in self.results_cache if r["payload_id"] == payload_id]
        return self.results_cache.copy()

    def clear_results(self):
        """Clear all cached results."""
        self.results_cache.clear()
        logger.info("Payload results cache cleared")

    def save_results(self, filename: str | None = None) -> str:
        """Save results to file.

        Args:
            filename: Optional filename to save to

        Returns:
            Path to saved file

        """
        if not filename:
            timestamp = int(time.time())
            filename = f"payload_results_{timestamp}.json"

        filepath = Path(self.storage_path) / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(self.results_cache, f, indent=2)

        logger.info(f"Payload results saved to {filepath}")
        return str(filepath)
