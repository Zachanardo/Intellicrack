/*
 * Test Program 1: License Validation Application
 * 
 * This program simulates a commercial software with license key validation.
 * It includes realistic license checking mechanisms that Intellicrack should detect and patch.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#define MAX_LICENSE_LENGTH 32
#define VALID_LICENSE_COUNT 3

// Simulated valid license keys (in real software, these would be encrypted/obfuscated)
const char* valid_licenses[] = {
    "ABCD-1234-EFGH-5678",
    "WXYZ-9876-QRST-5432", 
    "MNOP-1357-UVWX-2468"
};

// Simple XOR encryption/decryption (common in real software)
void xor_encrypt_decrypt(char* data, const char* key, int data_len) {
    int key_len = strlen(key);
    for (int i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// Check if license is valid (main target for patching)
int validate_license(const char* license) {
    printf("Validating license: %s\n", license);
    
    // Basic format check (XXXX-XXXX-XXXX-XXXX)
    if (strlen(license) != 19) {
        printf("Invalid license format: incorrect length\n");
        return 0; // FALSE - target for patching (change to return 1)
    }
    
    // Check for correct dash positions
    if (license[4] != '-' || license[9] != '-' || license[14] != '-') {
        printf("Invalid license format: incorrect dash positions\n");
        return 0; // FALSE - target for patching
    }
    
    // Compare against valid licenses
    for (int i = 0; i < VALID_LICENSE_COUNT; i++) {
        if (strcmp(license, valid_licenses[i]) == 0) {
            printf("License validation successful!\n");
            return 1; // TRUE
        }
    }
    
    // Additional validation - checksum calculation
    int checksum = 0;
    for (int i = 0; i < strlen(license); i++) {
        if (license[i] != '-') {
            checksum += license[i];
        }
    }
    
    // Magic checksum check (another target for patching)
    if (checksum == 1337) { // Arbitrary magic number
        printf("License checksum validation successful!\n");
        return 1; // TRUE
    }
    
    printf("License validation failed!\n");
    return 0; // FALSE - main target for patching
}

// Check license expiration (trial mechanism)
int check_license_expiry() {
    time_t current_time = time(NULL);
    time_t expiry_time = 1735689600; // Jan 1, 2025 (hardcoded expiry)
    
    printf("Checking license expiry...\n");
    printf("Current time: %ld\n", current_time);
    printf("Expiry time: %ld\n", expiry_time);
    
    if (current_time > expiry_time) {
        printf("License has expired!\n");
        return 0; // FALSE - target for patching
    }
    
    printf("License is still valid (not expired)\n");
    return 1; // TRUE
}

// Hardware fingerprinting (HWID check)
int check_hardware_id() {
    char volume_serial[32];
    DWORD serial_number;
    
    // Get system volume serial number
    if (GetVolumeInformation("C:\\", NULL, 0, &serial_number, NULL, NULL, NULL, 0)) {
        sprintf(volume_serial, "%08X", serial_number);
        printf("Hardware ID: %s\n", volume_serial);
        
        // Check against authorized hardware ID (hardcoded for demo)
        if (strcmp(volume_serial, "12345678") == 0) {
            printf("Hardware validation successful!\n");
            return 1; // TRUE
        }
    }
    
    printf("Hardware validation failed!\n");
    return 0; // FALSE - target for patching
}

// Registry-based activation check
int check_activation_status() {
    HKEY hkey;
    DWORD value_type, data_size = sizeof(DWORD);
    DWORD activation_status = 0;
    
    // Check registry for activation status
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\TestApp\\License", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hkey, "Activated", NULL, &value_type, (LPBYTE)&activation_status, &data_size) == ERROR_SUCCESS) {
            RegCloseKey(hkey);
            
            if (activation_status == 1) {
                printf("Software is activated!\n");
                return 1; // TRUE
            }
        }
        RegCloseKey(hkey);
    }
    
    printf("Software is not activated!\n");
    return 0; // FALSE - target for patching
}

// Main application logic
void run_protected_feature() {
    printf("\n=== PROTECTED FEATURE ACCESSED ===\n");
    printf("This is the main functionality of the software.\n");
    printf("You successfully bypassed all protection mechanisms!\n");
    printf("===================================\n\n");
}

// Anti-debugging check (simple)
int detect_debugger() {
    if (IsDebuggerPresent()) {
        printf("Debugger detected! Exiting...\n");
        return 1; // TRUE - debugger detected
    }
    return 0; // FALSE - no debugger
}

int main(int argc, char* argv[]) {
    printf("=== Test License Validation Application ===\n");
    printf("This application simulates realistic license checking.\n\n");
    
    // Anti-debugging check
    if (detect_debugger()) {
        printf("Please run without a debugger.\n");
        return 1;
    }
    
    char license_key[MAX_LICENSE_LENGTH];
    
    // Get license key from user
    if (argc > 1) {
        strncpy(license_key, argv[1], MAX_LICENSE_LENGTH - 1);
        license_key[MAX_LICENSE_LENGTH - 1] = '\0';
    } else {
        printf("Enter license key: ");
        fgets(license_key, MAX_LICENSE_LENGTH, stdin);
        
        // Remove newline if present
        char* newline = strchr(license_key, '\n');
        if (newline) *newline = '\0';
    }
    
    printf("\n=== License Validation Process ===\n");
    
    // Step 1: Validate license format and key
    if (!validate_license(license_key)) {
        printf("Access denied: Invalid license key!\n");
        return 1;
    }
    
    // Step 2: Check license expiry
    if (!check_license_expiry()) {
        printf("Access denied: License expired!\n");
        return 1;
    }
    
    // Step 3: Check hardware ID
    if (!check_hardware_id()) {
        printf("Access denied: Hardware not authorized!\n");
        return 1;
    }
    
    // Step 4: Check activation status
    if (!check_activation_status()) {
        printf("Access denied: Software not activated!\n");
        return 1;
    }
    
    // All checks passed - run protected feature
    run_protected_feature();
    
    return 0;
}

/*
 * INTELLICRACK TESTING NOTES:
 * 
 * This program should trigger detection of:
 * 1. License key validation routines (validate_license function)
 * 2. Time-based expiry checks (check_license_expiry function)
 * 3. Hardware fingerprinting (check_hardware_id function)
 * 4. Registry-based activation (check_activation_status function)
 * 5. Anti-debugging techniques (detect_debugger function)
 * 
 * Target addresses for patching (when compiled):
 * - validate_license: Patch return 0 to return 1
 * - check_license_expiry: Patch time comparison to always pass
 * - check_hardware_id: Patch hardware check to always return 1
 * - check_activation_status: Patch registry check to always return 1
 * - detect_debugger: Patch to always return 0 (no debugger)
 * 
 * Compilation:
 * gcc -o license_validation_app.exe license_validation_app.c -ladvapi32
 */