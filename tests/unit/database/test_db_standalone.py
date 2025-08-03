#!/usr/bin/env python3
"""Standalone test for protection database."""

import json
import logging
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_database():
    """Test the protection database system."""
    try:
        print("Testing protection database system...")
        
        # Import modules
        from intellicrack.core.protection_database.signature_database import (
            ProtectionSignatureDatabase, ProtectionType
        )
        from intellicrack.core.protection_database.database_updater import DatabaseUpdater
        print("✓ Imports successful")
        
        # Set up database path
        db_path = project_root / "intellicrack" / "core" / "protection_database" / "databases"
        
        # Initialize database
        print(f"Initializing database at: {db_path}")
        database = ProtectionSignatureDatabase(db_path)
        print("✓ Database initialized")
        
        # Create updater
        updater = DatabaseUpdater(database)
        print("✓ Updater created")
        
        # Check built-in signatures
        print(f"Built-in signatures available: {len(updater.builtin_signatures)}")
        for sig_id, signature in updater.builtin_signatures.items():
            print(f"  - {signature.name} ({signature.protection_type.value})")
        
        # Install signatures
        print("\nInstalling built-in signatures...")
        success = updater.install_builtin_signatures()
        
        if success:
            print("✓ Installation successful")
            
            # Load and verify
            database.load_database()
            stats = database.get_statistics()
            
            print(f"\nDatabase Statistics:")
            print(f"  Total signatures: {stats['total_signatures']}")
            print(f"  Average confidence: {stats['average_confidence']:.2f}")
            
            print(f"  By protection type:")
            for prot_type, count in stats['by_type'].items():
                if count > 0:
                    print(f"    {prot_type}: {count}")
            
            # Test signature retrieval
            print(f"\nTesting signature retrieval...")
            upx_sigs = database.get_signatures_by_type(ProtectionType.PACKER)
            print(f"  Packer signatures: {len(upx_sigs)}")
            
            protection_sigs = database.get_signatures_by_type(ProtectionType.CODE_PROTECTION)
            print(f"  Protection signatures: {len(protection_sigs)}")
            
            # Test search
            search_results = database.search_signatures("UPX")
            print(f"  Search results for 'UPX': {len(search_results)}")
            
            print("\n🎉 Protection database test completed successfully!")
            return True
            
        else:
            print("❌ Installation failed")
            return False
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_database()
    sys.exit(0 if success else 1)