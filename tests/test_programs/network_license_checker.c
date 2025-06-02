#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#else
#include <curl/curl.h>
#include <unistd.h>
#endif

#define LICENSE_SERVER "https://license.example.com/validate"
#define MAX_RESPONSE_SIZE 1024
#define MAX_LICENSE_SIZE 256

typedef struct {
    char* data;
    size_t size;
} HTTPResponse;

// Anti-debugging check
int is_debugger_present() {
#ifdef _WIN32
    return IsDebuggerPresent();
#else
    // Check for ptrace on Linux
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1; // Debugger detected
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return 0;
#endif
}

// Obfuscated license validation function
int validate_network_license(const char* license_key, const char* machine_id) {
    // Anti-debugging protection
    if (is_debugger_present()) {
        printf("Debug environment detected. Exiting.\n");
        exit(1);
    }
    
    printf("Validating license with server...\n");
    
    // Simulate network delay
    #ifdef _WIN32
    Sleep(2000);
    #else
    sleep(2);
    #endif
    
    // Basic license format check
    if (!license_key || strlen(license_key) < 16) {
        printf("Invalid license format\n");
        return 0;
    }
    
    // Simulate network request
    char request_url[512];
    snprintf(request_url, sizeof(request_url), 
             "%s?key=%s&machine=%s&version=1.0", 
             LICENSE_SERVER, license_key, machine_id);
    
    printf("Contacting: %s\n", request_url);
    
    // Hardcoded validation logic (target for patching)
    // Check for specific "valid" license patterns
    if (strstr(license_key, "VALID-") == license_key) {
        printf("Server validation: SUCCESS\n");
        return 1;
    } else if (strstr(license_key, "TRIAL-") == license_key) {
        printf("Server validation: TRIAL VERSION\n");
        return 2; // Trial mode
    } else {
        printf("Server validation: FAILED\n");
        return 0;
    }
}

// Get machine identifier
void get_machine_id(char* machine_id, size_t size) {
#ifdef _WIN32
    DWORD volume_serial;
    if (GetVolumeInformationA("C:\\", NULL, 0, &volume_serial, NULL, NULL, NULL, 0)) {
        snprintf(machine_id, size, "WIN-%08X", volume_serial);
    } else {
        strcpy(machine_id, "WIN-UNKNOWN");
    }
#else
    // Use hostname on Linux
    if (gethostname(machine_id, size) != 0) {
        strcpy(machine_id, "LINUX-UNKNOWN");
    }
#endif
}

// Encrypted license storage check
int check_cached_license() {
    FILE* license_file;
    char cached_license[MAX_LICENSE_SIZE];
    
#ifdef _WIN32
    license_file = fopen("C:\\ProgramData\\AppLicense\\cached.lic", "r");
#else
    license_file = fopen("/tmp/.app_license_cache", "r");
#endif
    
    if (!license_file) {
        printf("No cached license found\n");
        return 0;
    }
    
    if (fgets(cached_license, sizeof(cached_license), license_file) != NULL) {
        // Simple XOR "encryption" with key 0x42
        for (int i = 0; cached_license[i]; i++) {
            cached_license[i] ^= 0x42;
        }
        
        printf("Found cached license: %s\n", cached_license);
        fclose(license_file);
        
        // Validate cached license
        if (strstr(cached_license, "CACHED-VALID")) {
            return 1;
        }
    }
    
    fclose(license_file);
    return 0;
}

// Main license check routine
int main(int argc, char* argv[]) {
    printf("=== Network License Checker v2.1 ===\n");
    printf("Checking application license...\n\n");
    
    char machine_id[128];
    char license_key[MAX_LICENSE_SIZE];
    
    // Get machine identifier
    get_machine_id(machine_id, sizeof(machine_id));
    printf("Machine ID: %s\n", machine_id);
    
    // Check for cached license first
    if (check_cached_license()) {
        printf("Using cached license validation\n");
        printf("Application startup: SUCCESS\n");
        return 0;
    }
    
    // Get license from user or command line
    if (argc > 1) {
        strncpy(license_key, argv[1], sizeof(license_key) - 1);
        license_key[sizeof(license_key) - 1] = '\0';
    } else {
        printf("Enter license key: ");
        if (fgets(license_key, sizeof(license_key), stdin) != NULL) {
            // Remove newline
            license_key[strcspn(license_key, "\n")] = '\0';
        }
    }
    
    // Validate license with network server
    int validation_result = validate_network_license(license_key, machine_id);
    
    switch (validation_result) {
        case 1:
            printf("\n✓ License validation successful!\n");
            printf("Application startup: SUCCESS\n");
            break;
        case 2:
            printf("\n⚠ Trial license detected\n");
            printf("Application startup: TRIAL MODE\n");
            break;
        default:
            printf("\n✗ License validation failed!\n");
            printf("Application startup: BLOCKED\n");
            printf("Please contact support or purchase a valid license.\n");
            return 1;
    }
    
    return 0;
}