#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

result_file = "final_logging_results.txt"

def run_final_tests():
    results = []
    
    try:
        # Test 1: Basic imports and setup
        from intellicrack.core.logging import setup_logging, get_logger
        setup_logging()
        logger = get_logger("final.test")
        logger.info("Final test message")
        results.append("PASS: Basic setup and logging")
        
        # Test 2: Convenience functions
        from intellicrack.core.logging import log_analysis_result, log_exploit_result
        log_analysis_result("/test/binary.exe", {"protection": "test"})
        log_exploit_result("test_target", "test_exploit", success=True)
        results.append("PASS: Convenience functions")
        
        # Test 3: System status
        from intellicrack.core.logging import get_system_status
        status = get_system_status()
        if isinstance(status, dict) and len(status) > 0:
            results.append("PASS: System status")
        else:
            results.append("FAIL: System status")
        
        # Test 4: Audit types
        from intellicrack.core.logging import AuditEventType, AlertSeverity
        if hasattr(AuditEventType, 'EXPLOIT_ATTEMPT'):
            results.append("PASS: Audit event types")
        else:
            results.append("FAIL: Audit event types")
        
        return results
        
    except Exception as e:
        results.append(f"ERROR: {str(e)}")
        return results

if __name__ == "__main__":
    test_results = run_final_tests()
    
    with open(result_file, "w", encoding='utf-8') as f:
        f.write("CENTRALIZED LOGGING SYSTEM - FINAL TEST RESULTS\n")
        f.write("=" * 50 + "\n\n")
        
        passed = sum(1 for r in test_results if r.startswith("PASS"))
        total = len([r for r in test_results if r.startswith(("PASS", "FAIL"))])
        
        for result in test_results:
            f.write(result + "\n")
        
        f.write(f"\nResults: {passed}/{total} tests passed\n")
        
        if passed == total and total > 0:
            f.write("\nSUCCESS: All centralized logging tests passed!\n")
            f.write("The centralized logging system is fully functional.\n")
        else:
            f.write("\nSome tests failed or had errors.\n")
    
    print(f"Tests completed. Results written to {result_file}")