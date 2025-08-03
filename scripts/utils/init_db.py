import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)

sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.core.protection_database.signature_database import ProtectionSignatureDatabase
from intellicrack.core.protection_database.database_updater import DatabaseUpdater

db_path = Path("intellicrack/core/protection_database/databases")
database = ProtectionSignatureDatabase(db_path)
updater = DatabaseUpdater(database)

print("Installing signatures...")
try:
    success = updater.install_builtin_signatures()
    print(f"Result: {success}")
    if success:
        database.load_database()
        stats = database.get_statistics()
        print(f"Installed {stats['total_signatures']} signatures")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()