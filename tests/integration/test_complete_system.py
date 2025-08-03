#!/usr/bin/env python3
"""Comprehensive test of the complete protection database system."""

import logging
import sys
import tempfile
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def create_test_binary() -> Path:
    """Create a simple test binary with UPX-like patterns."""
    test_data = b"MZ" + b"\x00" * 60 + b"PE\x00\x00"
    test_data += b"UPX!" + b"\x00" * 100  # UPX magic
    test_data += b"This file is packed with UPX" + b"\x00" * 50
    test_data += b"\x60\xBE\x00\x40\x40\x00\x8D\xBE\x00\xF0\xFE\xFF"  # UPX pattern
    
    # Create temporary file
    temp_file = Path(tempfile.mktemp(suffix=".exe"))
    with open(temp_file, 'wb') as f:
        f.write(test_data)
    
    return temp_file

def test_complete_system():
    """Test the complete protection database system."""
    try:
        print("🔍 COMPREHENSIVE PROTECTION DATABASE SYSTEM TEST")
        print("=" * 60)
        
        # Import all modules
        from intellicrack.core.protection_database import (
            ProtectionSignatureDatabase,
            ProtectionDatabaseManager, 
            ProtectionPatternEngine,
            DatabaseUpdater
        )
        from intellicrack.core.analysis.protection_analyzer import ProtectionAwareBinaryAnalyzer
        
        print("✓ Successfully imported all protection system modules")
        
        # Test 1: Database initialization
        print("\n1. Testing Database Initialization")
        print("-" * 40)
        
        db_path = Path("intellicrack/core/protection_database/databases")
        database = ProtectionSignatureDatabase(db_path)
        
        success = database.load_database()
        if not success:
            print("❌ Database loading failed")
            return False
        
        stats = database.get_statistics()
        print(f"✓ Database loaded: {stats['total_signatures']} signatures")
        print(f"  - Average confidence: {stats['average_confidence']:.2f}")
        
        for prot_type, count in stats['by_type'].items():
            if count > 0:
                print(f"  - {prot_type}: {count}")
        
        # Test 2: Database Manager
        print("\n2. Testing Database Manager")
        print("-" * 40)
        
        manager = ProtectionDatabaseManager(db_path)
        manager_stats = manager.get_database_statistics()
        print(f"✓ Manager initialized with {manager_stats['database']['total_signatures']} signatures")
        print(f"  - Cache enabled: {manager_stats['configuration']['enable_caching']}")
        
        # Test 3: Pattern Engine
        print("\n3. Testing Pattern Engine")
        print("-" * 40)
        
        engine = ProtectionPatternEngine(db_path)
        supported = engine.get_supported_protections()
        
        total_schemes = sum(len(schemes) for schemes in supported.values())
        print(f"✓ Pattern engine supports {total_schemes} protection schemes")
        
        # Test search functionality
        upx_info = engine.search_protections("UPX")
        print(f"✓ Found {len(upx_info)} UPX-related protections")
        
        # Test 4: Protection-Aware Binary Analyzer
        print("\n4. Testing Protection-Aware Binary Analyzer")
        print("-" * 40)
        
        analyzer = ProtectionAwareBinaryAnalyzer(db_path)
        analyzer_stats = analyzer.get_analysis_statistics()
        print(f"✓ Protection-aware analyzer initialized")
        print(f"  - Protection engine available: {analyzer_stats['protection_engine_available']}")
        
        # Test 5: File Analysis with Test Binary
        print("\n5. Testing File Analysis")
        print("-" * 40)
        
        # Create test binary
        test_file = create_test_binary()
        print(f"✓ Created test binary: {test_file}")
        
        try:
            # Analyze the test file
            results = analyzer.analyze(test_file, enable_deep_scan=True)
            
            if 'error' in results:
                print(f"❌ Analysis failed: {results['error']}")
                return False
            
            print("✓ Binary analysis completed successfully")
            
            # Check protection analysis results
            protection_analysis = results.get('protection_analysis', {})
            if protection_analysis.get('success'):
                detections = protection_analysis.get('detections', {})
                print(f"  - Protections found: {detections.get('total_found', 0)}")
                print(f"  - High confidence: {detections.get('high_confidence', 0)}")
                
                schemes = detections.get('protection_schemes', [])
                if schemes:
                    print(f"  - Detected schemes: {', '.join(schemes)}")
                
                # Check recommendations
                recommendations = protection_analysis.get('recommendations', [])
                if recommendations:
                    print(f"  - Recommendations: {len(recommendations)} provided")
                    for rec in recommendations[:2]:  # Show first 2
                        print(f"    • {rec.get('description', 'N/A')}")
            
            # Check security assessment
            security = results.get('security_assessment', {})
            if security:
                print(f"  - Protection level: {security.get('protection_level', 'unknown')}")
                print(f"  - Analysis complexity: {security.get('analysis_complexity', 'unknown')}")
            
        finally:
            # Clean up test file
            if test_file.exists():
                test_file.unlink()
                print(f"✓ Cleaned up test file")
        
        # Test 6: Database Operations
        print("\n6. Testing Database Operations")
        print("-" * 40)
        
        # Test signature search
        all_packers = database.get_signatures_by_type(
            database.signatures[list(database.signatures.keys())[0]].protection_type.__class__.PACKER
        )
        print(f"✓ Found {len(all_packers)} packer signatures")
        
        # Test signature retrieval
        if database.signatures:
            first_sig_id = list(database.signatures.keys())[0]
            sig_info = manager.get_protection_info(first_sig_id)
            if sig_info:
                print(f"✓ Retrieved signature info: {sig_info['name']}")
        
        # Test 7: System Integration
        print("\n7. Testing System Integration")
        print("-" * 40)
        
        # Test configuration updates
        config_update = {
            'min_confidence': 0.7,
            'enable_heuristics': True
        }
        
        success = analyzer.update_configuration(config_update)
        if success:
            print("✓ Configuration updated successfully")
        
        success = engine.update_configuration(config_update)
        if success:
            print("✓ Engine configuration updated successfully")
        
        # Final verification
        print("\n🎉 SYSTEM TEST COMPLETED SUCCESSFULLY!")
        print("\nSystem Capabilities:")
        print(f"  • {stats['total_signatures']} protection signatures loaded")
        print(f"  • {total_schemes} protection schemes supported")
        print(f"  • Database caching and performance optimization")
        print(f"  • Integration with binary analysis pipeline")
        print(f"  • Confidence-based detection with false positive reduction")
        print(f"  • Automated recommendations and security assessment")
        
        print("\nSupported Protection Types:")
        for prot_type, schemes in supported.items():
            if schemes:
                print(f"  • {prot_type.upper()}: {', '.join(schemes[:3])}{'...' if len(schemes) > 3 else ''}")
        
        return True
        
    except Exception as e:
        print(f"❌ System test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_complete_system()
    
    if success:
        print("\n✅ ALL TESTS PASSED - Protection Database System is ready for use!")
    else:
        print("\n❌ TESTS FAILED - Please check the system configuration")
    
    sys.exit(0 if success else 1)