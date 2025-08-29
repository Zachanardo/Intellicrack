"""
Day 8.2: Simple End-to-End Workflow Test
Tests core binary analysis pipeline with actual API methods
Validates real functionality without mocks or stubs
"""

import os
import sys
import time
import tempfile
import tracemalloc
from pathlib import Path
from unittest.mock import patch

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from intellicrack.core.analysis.analysis_orchestrator import AnalysisOrchestrator, AnalysisPhase
from intellicrack.core.analysis.commercial_license_analyzer import CommercialLicenseAnalyzer
from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator
from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine
from intellicrack.core.exploitation.shellcode_generator import ShellcodeGenerator
from intellicrack.core.exploitation.cet_bypass import CETBypass
from intellicrack.utils.logger import setup_logger


def create_test_binary(protection_type: str, output_dir: str) -> str:
    """Create a test binary with protection markers"""
    test_file = os.path.join(output_dir, f"test_{protection_type.lower()}.exe")
    
    # PE header
    pe_header = b'MZ' + b'\x90' * 58 + b'\x40\x00\x00\x00'
    pe_signature = b'PE\x00\x00'
    
    # Protection markers
    protection_markers = {
        "FlexLM": b'FLEXlm' + b'lmgrd' + b'lmutil',
        "HASP": b'HASP' + b'hasp_login' + b'hasp_encrypt',
        "CodeMeter": b'CodeMeter' + b'CmDongle' + b'WupiQueryEx',
    }
    
    with open(test_file, 'wb') as f:
        f.write(pe_header)
        f.write(pe_signature)
        f.write(b'\x00' * 200)
        
        if protection_type in protection_markers:
            f.write(protection_markers[protection_type])
            
        # Add code section
        f.write(b'\x55\x8B\xEC')  # push ebp; mov ebp, esp
        f.write(b'\x68\x00\x00\x00\x00')  # push 0
        f.write(b'\xE8\x00\x00\x00\x00')  # call
        f.write(b'\x5D\xC3')  # pop ebp; ret
        
        # Pad to minimum size
        f.write(b'\x00' * (4096 - f.tell()))
        
    return test_file


def test_complete_workflow():
    """Test complete analysis workflow using actual API"""
    logger = setup_logger("E2E_Test")
    logger.info("=== Starting End-to-End Workflow Test ===")
    
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_e2e_")
    results = {
        "total_tests": 0,
        "passed": 0,
        "failed": 0,
        "errors": []
    }
    
    try:
        # Test 1: Basic Analysis Orchestration
        logger.info("\n[TEST 1] Testing Analysis Orchestration")
        results["total_tests"] += 1
        
        binary_path = create_test_binary("FlexLM", temp_dir)
        orchestrator = AnalysisOrchestrator()
        
        # Use the actual analyze_binary method
        result = orchestrator.analyze_binary(
            binary_path,
            phases=[
                AnalysisPhase.PREPARATION,
                AnalysisPhase.BASIC_INFO,
                AnalysisPhase.STATIC_ANALYSIS
            ]
        )
        
        if result and result.success:
            logger.info("✓ Analysis orchestration successful")
            results["passed"] += 1
        else:
            error = f"Analysis orchestration failed: {result.errors if result else 'No result'}"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
        # Test 2: Commercial License Analysis
        logger.info("\n[TEST 2] Testing Commercial License Analysis")
        results["total_tests"] += 1
        
        try:
            analyzer = CommercialLicenseAnalyzer(binary_path)
            license_info = analyzer.analyze()
            
            if license_info:
                logger.info("✓ Commercial license analysis completed")
                results["passed"] += 1
            else:
                logger.error("✗ No license info returned")
                results["failed"] += 1
        except Exception as e:
            error = f"Commercial license analysis error: {e}"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
        # Test 3: Bypass Generation
        logger.info("\n[TEST 3] Testing Bypass Generation")
        results["total_tests"] += 1
        
        try:
            bypass_gen = R2BypassGenerator(binary_path)
            
            # Test with minimal license info
            test_license_info = {
                "protection_detected": True,
                "protection_type": "FlexLM",
                "version": "11.16.2",
                "confidence": 0.85
            }
            
            bypass = bypass_gen.generate_bypass(test_license_info)
            
            if bypass and "method" in bypass:
                logger.info("✓ Bypass generation successful")
                results["passed"] += 1
            else:
                logger.error("✗ Invalid bypass structure")
                results["failed"] += 1
        except Exception as e:
            error = f"Bypass generation error: {e}"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
        # Test 4: Vulnerability Detection
        logger.info("\n[TEST 4] Testing Vulnerability Detection")
        results["total_tests"] += 1
        
        try:
            vuln_engine = R2VulnerabilityEngine(binary_path)
            vulnerabilities = vuln_engine.find_vulnerabilities()
            
            if vulnerabilities is not None:
                logger.info(f"✓ Vulnerability scan completed, found {len(vulnerabilities)} items")
                results["passed"] += 1
            else:
                logger.error("✗ Vulnerability scan returned None")
                results["failed"] += 1
        except Exception as e:
            error = f"Vulnerability detection error: {e}"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
        # Test 5: Shellcode Generation
        logger.info("\n[TEST 5] Testing Shellcode Generation")
        results["total_tests"] += 1
        
        try:
            shellcode_gen = ShellcodeGenerator()
            
            # Use actual method signature
            shellcode = shellcode_gen.generate_shellcode(
                arch="x86",
                payload_type="reverse_shell",
                options={"host": "127.0.0.1", "port": 4444}
            )
            
            if shellcode and isinstance(shellcode, bytes) and len(shellcode) > 0:
                logger.info(f"✓ Shellcode generated: {len(shellcode)} bytes")
                results["passed"] += 1
            else:
                logger.error("✗ Invalid shellcode generated")
                results["failed"] += 1
        except Exception as e:
            error = f"Shellcode generation error: {e}"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
        # Test 6: CET Bypass
        logger.info("\n[TEST 6] Testing CET Bypass")
        results["total_tests"] += 1
        
        try:
            cet_bypass = CETBypass()
            cet_exploit = cet_bypass.generate_bypass()
            
            if cet_exploit and "technique" in cet_exploit:
                logger.info("✓ CET bypass generated")
                results["passed"] += 1
            else:
                logger.error("✗ Invalid CET bypass structure")
                results["failed"] += 1
        except Exception as e:
            error = f"CET bypass error: {e}"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
        # Test 7: Performance Check
        logger.info("\n[TEST 7] Testing Performance Requirements")
        results["total_tests"] += 1
        
        start_time = time.time()
        binary_path2 = create_test_binary("HASP", temp_dir)
        
        orchestrator2 = AnalysisOrchestrator()
        result2 = orchestrator2.analyze_binary(
            binary_path2,
            phases=[AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
        )
        
        elapsed = time.time() - start_time
        
        if elapsed < 30:  # Should complete basic analysis in 30 seconds
            logger.info(f"✓ Performance test passed: {elapsed:.2f}s")
            results["passed"] += 1
        else:
            error = f"Performance test failed: {elapsed:.2f}s exceeds 30s limit"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
        # Test 8: Memory Usage
        logger.info("\n[TEST 8] Testing Memory Usage")
        results["total_tests"] += 1
        
        tracemalloc.start()
        
        # Process multiple binaries
        for i in range(3):
            test_binary = create_test_binary("CodeMeter", temp_dir)
            orch = AnalysisOrchestrator()
            orch.analyze_binary(test_binary, phases=[AnalysisPhase.PREPARATION])
            
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        peak_mb = peak / 1024 / 1024
        
        if peak_mb < 500:  # Should use less than 500MB
            logger.info(f"✓ Memory test passed: {peak_mb:.2f}MB")
            results["passed"] += 1
        else:
            error = f"Memory test failed: {peak_mb:.2f}MB exceeds 500MB limit"
            logger.error(f"✗ {error}")
            results["errors"].append(error)
            results["failed"] += 1
            
    except Exception as e:
        logger.error(f"Unexpected error in test suite: {e}")
        results["errors"].append(str(e))
        
    # Generate final report
    logger.info("\n" + "=" * 60)
    logger.info("END-TO-END WORKFLOW TEST RESULTS")
    logger.info("=" * 60)
    logger.info(f"Total Tests: {results['total_tests']}")
    logger.info(f"Passed: {results['passed']}")
    logger.info(f"Failed: {results['failed']}")
    logger.info(f"Success Rate: {(results['passed'] / results['total_tests'] * 100):.1f}%")
    
    if results['errors']:
        logger.info("\nErrors encountered:")
        for error in results['errors']:
            logger.info(f"  - {error}")
            
    # Save report
    report_path = project_root / "tests" / "results" / "DAY_8_2_SIMPLE_REPORT.txt"
    report_path.parent.mkdir(exist_ok=True)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("DAY 8.2: END-TO-END WORKFLOW TEST REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Total Tests: {results['total_tests']}\n")
        f.write(f"Passed: {results['passed']}\n")
        f.write(f"Failed: {results['failed']}\n")
        f.write(f"Success Rate: {(results['passed'] / results['total_tests'] * 100):.1f}%\n\n")
        
        if results['passed'] == results['total_tests']:
            f.write("STATUS: ALL TESTS PASSED\n")
            f.write("The end-to-end workflow is functioning correctly.\n")
        else:
            f.write("STATUS: SOME TESTS FAILED\n")
            f.write("\nErrors:\n")
            for error in results['errors']:
                f.write(f"  - {error}\n")
                
    # Return exit code
    return 0 if results['passed'] == results['total_tests'] else 1


if __name__ == "__main__":
    exit(test_complete_workflow())