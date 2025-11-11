"""MonkeyType configuration for Intellicrack type inference and annotation generation.

This module configures MonkeyType to trace and analyze runtime type information
for Intellicrack components, enabling automated type hint generation and validation.
"""

from pathlib import Path

from monkeytype.config import DefaultConfig
from monkeytype.db.sqlite import SQLiteStore


class IntellicrackMonkeyTypeConfig(DefaultConfig):
    """Custom MonkeyType configuration for Intellicrack type tracing.

    Configures MonkeyType to use a SQLite database for storing runtime type traces
    and provides customization for code filtering and trace management specific to
    the Intellicrack binary analysis platform.
    """

    def __init__(self) -> None:
        """Initialize the MonkeyType configuration with Intellicrack-specific settings."""
        super().__init__()
        self.db_path = Path(__file__).parent / "monkeytype.sqlite3"

    def trace_store(self) -> SQLiteStore:
        """Provide the SQLite trace store for runtime type information.

        Returns:
            SQLiteStore: Configured SQLite store instance for persisting type traces

        """
        return SQLiteStore.make_store(str(self.db_path))

    def code_filter(self) -> None:
        """Define code filtering rules for type tracing.

        Returns:
            None: No custom filtering applied, traces all Intellicrack code

        """
        return


CONFIG = IntellicrackMonkeyTypeConfig()
