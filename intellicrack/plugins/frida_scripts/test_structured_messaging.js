/**
 * Test script for structured messaging system
 * Tests all message types: info, warning, error, status, bypass, success, detection, notification
 */

// Test script initialization
send({
    type: "status",
    target: "test_structured_messaging",
    action: "initializing_test_script"
});

// Test info messages
send({
    type: "info",
    target: "test_structured_messaging",
    action: "testing_info_messages",
    details: "This is a test info message"
});

// Test warning messages
send({
    type: "warning",
    target: "test_structured_messaging",
    action: "testing_warning_messages",
    warning_type: "test_warning"
});

// Test error messages
send({
    type: "error",
    target: "test_structured_messaging",
    action: "testing_error_messages",
    error: "This is a test error message"
});

// Test status messages
send({
    type: "status",
    target: "test_structured_messaging",
    action: "testing_status_messages",
    status: "active"
});

// Test bypass messages
send({
    type: "bypass",
    target: "test_structured_messaging",
    action: "testing_bypass_messages",
    function_name: "test_function",
    original_value: "original",
    bypassed_value: "bypassed"
});

// Test success messages
send({
    type: "success",
    target: "test_structured_messaging",
    action: "testing_success_messages",
    operation: "test_operation_complete"
});

// Test detection messages
send({
    type: "detection",
    target: "test_structured_messaging",
    action: "testing_detection_messages",
    detected_item: "test_protection_mechanism"
});

// Test notification messages
send({
    type: "notification",
    target: "test_structured_messaging",
    action: "testing_notification_messages",
    notification_type: "system_event"
});

// Test complex message with multiple data fields
send({
    type: "info",
    target: "test_structured_messaging",
    action: "complex_message_test",
    module_name: "test_module",
    function_name: "test_function",
    address: "0x12345678",
    parameters: ["param1", "param2", "param3"],
    timestamp: new Date().toISOString()
});

// Test final completion message
send({
    type: "success",
    target: "test_structured_messaging",
    action: "test_script_completed",
    tests_run: 9,
    status: "all_tests_passed"
});
