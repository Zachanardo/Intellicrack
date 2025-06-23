#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>

#define MAX_LICENSE_LENGTH 32
#define VALID_LICENSE_COUNT 3

// Simulated valid license keys
const char* valid_licenses[] = {
    "ABCD-1234-EFGH-5678",
    "WXYZ-9876-QRST-5432", 
    "MNOP-1357-UVWX-2468"
};

// Check if license is valid (main target for patching)
int validate_license(const char* license) {
    printf("Validating license: %s\n", license);
    
    // Basic format check (XXXX-XXXX-XXXX-XXXX)
    if (strlen(license) \!= 19) {
        printf("Invalid license format: incorrect length\n");
        return 0; // FALSE - target for patching (change to return 1)
    }
    
    // Check for correct dash positions
    if (license[4] \!= '-' || license[9] \!= '-' || license[14] \!= '-') {
        printf("Invalid license format: incorrect dash positions\n");
        return 0; // FALSE - target for patching
    }
    
    // Compare against valid licenses
    for (int i = 0; i < VALID_LICENSE_COUNT; i++) {
        if (strcmp(license, valid_licenses[i]) == 0) {
            printf("License validation successful\!\n");
            return 1; // TRUE
        }
    }
    
    // Additional validation - checksum calculation
    int checksum = 0;
    for (int i = 0; i < strlen(license); i++) {
        if (license[i] \!= '-') {
            checksum += license[i];
        }
    }
    
    // Magic checksum check (another target for patching)
    if (checksum == 1337) { // Arbitrary magic number
        printf("License checksum validation successful\!\n");
        return 1; // TRUE
    }
    
    printf("License validation failed\!\n");
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
        printf("License has expired\!\n");
        return 0; // FALSE - target for patching
    }
    
    printf("License is still valid (not expired)\n");
    return 1; // TRUE
}

// Hardware fingerprinting (simplified for Linux)
int check_hardware_id() {
    printf("Checking hardware ID...\n");
    
    // Simulate hardware check - in real software this would check MAC address, CPU ID, etc.
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "processor")) {
                printf("Hardware ID check: CPU detected\n");
                fclose(fp);
                
                // Hardcoded check - always fails unless patched
                printf("Hardware validation failed\!\n");
                return 0; // FALSE - target for patching
            }
        }
        fclose(fp);
    }
    
    printf("Hardware validation failed\!\n");
    return 0; // FALSE - target for patching
}

// Anti-debugging check
int detect_debugger() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        printf("Debugger detected\! Exiting...\n");
        return 1; // TRUE - debugger detected
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return 0; // FALSE - no debugger
}

// Main application logic
void run_protected_feature() {
    printf("\n=== PROTECTED FEATURE ACCESSED ===\n");
    printf("This is the main functionality of the software.\n");
    printf("You successfully bypassed all protection mechanisms\!\n");
    printf("===================================\n\n");
}

int main(int argc, char* argv[]) {
    printf("=== Linux License Validation Application ===\n");
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
    if (\!validate_license(license_key)) {
        printf("Access denied: Invalid license key\!\n");
        return 1;
    }
    
    // Step 2: Check license expiry
    if (\!check_license_expiry()) {
        printf("Access denied: License expired\!\n");
        return 1;
    }
    
    // Step 3: Check hardware ID
    if (\!check_hardware_id()) {
        printf("Access denied: Hardware not authorized\!\n");
        return 1;
    }
    
    // All checks passed - run protected feature
    run_protected_feature();
    
    return 0;
}
EOF < /dev/null
