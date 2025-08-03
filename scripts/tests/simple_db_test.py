import sys
sys.path.insert(0, '.')

from intellicrack.core.protection_database.signature_database import ProtectionSignatureDatabase
from intellicrack.core.protection_database.database_updater import DatabaseUpdater
from pathlib import Path

# Test basic import
print("Testing protection database...")

db_path = Path("intellicrack/core/protection_database/databases")
database = ProtectionSignatureDatabase(db_path)
updater = DatabaseUpdater(database)

print("Installing signatures...")
success = updater.install_builtin_signatures()
print(f"Installation result: {success}")

if success:
    database.load_database()
    stats = database.get_statistics()
    print(f"Total signatures: {stats['total_signatures']}")
    print("SUCCESS")
else:
    print("FAILED")