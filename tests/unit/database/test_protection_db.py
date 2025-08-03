#!/usr/bin/env python3
"""Test script for protection database initialization."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellicrack.core.protection_database import (
        ProtectionSignatureDatabase, 
        ProtectionDatabaseManager,
        DatabaseUpdater,
        ProtectionPatternEngine
    )
    
    print("✓ Successfully imported protection database modules")
    
    # Initialize database
    db_path = Path(__file__).parent / "intellicrack" / "core" / "protection_database" / "databases"
    
    print(f"Initializing database at: {db_path}")
    
    # Create database instance
    database = ProtectionSignatureDatabase(db_path)
    print("✓ Created ProtectionSignatureDatabase instance")
    
    # Create updater and install signatures
    updater = DatabaseUpdater(database)
    print("✓ Created DatabaseUpdater instance")
    
    # Install built-in signatures
    print("Installing built-in signatures...")
    success = updater.install_builtin_signatures()
    
    if success:
        print("✓ Built-in signatures installed successfully")
        
        # Load database and get stats
        database.load_database()
        stats = database.get_statistics()
        
        print(f"\nDatabase Statistics:")
        print(f"  Total signatures: {stats['total_signatures']}")
        print(f"  Average confidence: {stats['average_confidence']:.2f}")
        print(f"  By type:")
        for prot_type, count in stats['by_type'].items():
            if count > 0:
                print(f"    {prot_type}: {count}")
        
        # Test pattern engine
        print("\nTesting pattern engine...")
        engine = ProtectionPatternEngine(db_path)
        engine_stats = engine.get_protection_database_info()
        print(f"✓ Pattern engine initialized with {engine_stats['database']['total_signatures']} signatures")
        
        print("\n🎉 Protection database system initialized successfully!")
        
    else:
        print("❌ Failed to install built-in signatures")
        sys.exit(1)
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)