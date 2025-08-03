"""Initialize protection database with built-in signatures.

This script initializes the protection database with built-in signatures
for common protection schemes and packers.

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
from pathlib import Path

from .database_updater import DatabaseUpdater
from .signature_database import ProtectionSignatureDatabase
import logging

logger = logging.getLogger(__name__)


def initialize_protection_database(database_path: Path = None) -> bool:
    """Initialize the protection database with built-in signatures.
    
    Args:
        database_path: Optional path to database directory
        
    Returns:
        True if initialization successful
    """
    try:
        # Initialize database
        if database_path is None:
            database_path = Path(__file__).parent / "databases"
        
        database = ProtectionSignatureDatabase(database_path)
        updater = DatabaseUpdater(database)
        
        logger.info("Initializing protection database...")
        
        # Install built-in signatures
        success = updater.install_builtin_signatures()
        
        if success:
            # Load the database to verify
            database.load_database()
            stats = database.get_statistics()
            
            logger.info(f"Database initialized successfully!")
            logger.info(f"Total signatures: {stats['total_signatures']}")
            logger.info(f"By type: {stats['by_type']}")
            
            return True
        else:
            logger.error("Failed to install built-in signatures")
            return False
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    success = initialize_protection_database()
    exit(0 if success else 1)