#!/usr/bin/env python3
"""Final test of protection database system."""

import logging
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_database():
    """Test the protection database."""
    try:
        print("🔍 Testing Protection Database System")
        print("=" * 50)
        
        # Import the modules
        from intellicrack.core.protection_database import (
            ProtectionSignatureDatabase,
            ProtectionDatabaseManager, 
            ProtectionPatternEngine
        )
        
        print("✓ Successfully imported protection database modules")
        
        # Test database loading
        db_path = Path("intellicrack/core/protection_database/databases")
        database = ProtectionSignatureDatabase(db_path)
        
        print(f"✓ Database initialized at: {db_path}")
        
        # Load signatures
        success = database.load_database()
        if not success:
            print("❌ Failed to load database")
            return False
            
        print(f"✓ Database loaded successfully")
        
        # Get statistics
        stats = database.get_statistics()
        print(f"✓ Total signatures loaded: {stats['total_signatures']}")
        
        if stats['total_signatures'] == 0:
            print("❌ No signatures found in database")
            return False
        
        print(f"  - Average confidence: {stats['average_confidence']:.2f}")
        print(f"  - Protection types:")
        for prot_type, count in stats['by_type'].items():
            if count > 0:
                print(f"    • {prot_type}: {count} signatures")
        
        # Test signature search
        upx_results = database.search_signatures("UPX")
        print(f"✓ Found {len(upx_results)} UPX-related signatures")
        
        themida_results = database.search_signatures("Themida")
        print(f"✓ Found {len(themida_results)} Themida-related signatures")
        
        # Test database manager
        manager = ProtectionDatabaseManager(db_path)
        manager_stats = manager.get_database_statistics()
        print(f"✓ Database manager initialized with {manager_stats['database']['total_signatures']} signatures")
        
        # Test pattern engine
        engine = ProtectionPatternEngine(db_path)
        supported = engine.get_supported_protections()
        print(f"✓ Pattern engine supports {sum(len(sigs) for sigs in supported.values())} protection schemes")
        
        print("\n🎉 Protection Database System Test PASSED!")
        print("\nSupported Protection Schemes:")
        for prot_type, schemes in supported.items():
            if schemes:
                print(f"  {prot_type.upper()}:")
                for scheme in schemes:
                    print(f"    - {scheme}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_database()
    sys.exit(0 if success else 1)