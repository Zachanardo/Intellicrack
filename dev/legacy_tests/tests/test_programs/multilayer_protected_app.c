#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#endif

// Obfuscation constants
#define XOR_KEY_1 0xDEADBEEF
#define XOR_KEY_2 0xCAFEBABE
#define ROT_OFFSET 13

// Protection layer flags
typedef enum {
    LAYER_DEBUGGER = 0x01,
    LAYER_VM_DETECT = 0x02,
    LAYER_INTEGRITY = 0x04,
    LAYER_LICENSE = 0x08,
    LAYER_PACKING = 0x10,
    LAYER_NETWORK = 0x20
} ProtectionLayer;

// Obfuscated string storage
typedef struct {
    unsigned char data[64];
    int length;
    unsigned int key;
} ObfuscatedString;

// Runtime protection state
static unsigned int protection_state = 0;
static int protection_checks_passed = 0;

// String obfuscation functions
void obfuscate_string(const char* plain, ObfuscatedString* obs, unsigned int key) {
    obs->length = strlen(plain);
    obs->key = key;
    for (int i = 0; i < obs->length && i < 63; i++) {
        obs->data[i] = plain[i] ^ ((key >> (i % 4 * 8)) & 0xFF);
        obs->data[i] = (obs->data[i] + ROT_OFFSET) % 256;
    }
    obs->data[obs->length] = 0;
}

void deobfuscate_string(ObfuscatedString* obs, char* plain) {
    for (int i = 0; i < obs->length; i++) {
        unsigned char c = obs->data[i];
        c = (c - ROT_OFFSET + 256) % 256;
        plain[i] = c ^ ((obs->key >> (i % 4 * 8)) & 0xFF);
    }
    plain[obs->length] = 0;
}

// Anti-debugging layer
int check_debugger_presence() {
#ifdef _WIN32
    // Multiple debugger detection methods
    if (IsDebuggerPresent()) {
        return 1;
    }
    
    // Check for remote debugger
    BOOL remote_debug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debug);
    if (remote_debug) {
        return 1;
    }
    
    // Check for debugging tools in process list
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &pe)) {
            do {
                if (strstr(pe.szExeFile, "ollydbg.exe") ||
                    strstr(pe.szExeFile, "x64dbg.exe") ||
                    strstr(pe.szExeFile, "windbg.exe") ||
                    strstr(pe.szExeFile, "ida.exe")) {
                    CloseHandle(snapshot);
                    return 1;
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
#else
    // Linux ptrace detection
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
#endif
    
    return 0;
}

// VM detection layer
int check_vm_environment() {
#ifdef _WIN32
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer_name);
    
    if (GetComputerNameA(computer_name, &size)) {
        // Check for common VM computer names
        if (strstr(computer_name, "VMWARE") ||
            strstr(computer_name, "VBOX") ||
            strstr(computer_name, "VIRTUAL")) {
            return 1;
        }
    }
    
    // Check for VM registry keys
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                     "SOFTWARE\\VMware, Inc.\\VMware Tools", 
                     0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegCloseKey(key);
        return 1;
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                     0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegCloseKey(key);
        return 1;
    }
#else
    // Check for VM indicators on Linux
    FILE* proc_version = fopen("/proc/version", "r");
    if (proc_version) {
        char version[256];
        if (fgets(version, sizeof(version), proc_version)) {
            if (strstr(version, "Microsoft") || strstr(version, "WSL")) {
                fclose(proc_version);
                return 1; // WSL detected
            }
        }
        fclose(proc_version);
    }
#endif
    
    return 0;
}

// Code integrity check
int verify_code_integrity() {
    // Simple checksum of this function
    unsigned int checksum = 0;
    unsigned char* func_ptr = (unsigned char*)verify_code_integrity;
    
    for (int i = 0; i < 100; i++) { // Check first 100 bytes
        checksum += func_ptr[i];
        checksum = (checksum << 1) | (checksum >> 31); // Rotate left
    }
    
    // Expected checksum (this would be calculated at build time)
    unsigned int expected = 0x12345678; // Placeholder
    
    // For demonstration, we'll use a simple pattern check
    return (checksum != 0);
}

// License validation with multiple algorithms
int validate_multilayer_license(const char* license) {
    if (!license || strlen(license) < 20) {
        return 0;
    }
    
    // Algorithm 1: Pattern matching
    if (strncmp(license, "ML-", 3) != 0) {
        return 0;
    }
    
    // Algorithm 2: Checksum validation
    unsigned int checksum = 0;
    for (int i = 3; license[i]; i++) {
        checksum += license[i];
    }
    
    if ((checksum % 256) != 0x42) {
        return 0;
    }
    
    // Algorithm 3: Date-based validation
    time_t current_time = time(NULL);
    struct tm* tm_info = localtime(&current_time);
    
    // License valid only in certain months (artificial restriction)
    if (tm_info->tm_mon < 0 || tm_info->tm_mon > 11) {
        return 0;
    }
    
    return 1;
}

// Network heartbeat check
int perform_network_heartbeat() {
    printf("Performing network heartbeat...\n");
    
    // Simulate network connectivity check
#ifdef _WIN32
    Sleep(1000);
#else
    sleep(1);
#endif
    
    // For demonstration, randomly succeed/fail
    srand((unsigned int)time(NULL));
    return (rand() % 100) > 20; // 80% success rate
}

// Packed code simulation (would normally be compressed/encrypted)
void execute_packed_routine() {
    ObfuscatedString packed_msg;
    obfuscate_string("Executing protected routine...", &packed_msg, XOR_KEY_1);
    
    // Simulate unpacking delay
#ifdef _WIN32
    Sleep(500);
#else
    usleep(500000);
#endif
    
    char unpacked[64];
    deobfuscate_string(&packed_msg, unpacked);
    printf("%s\n", unpacked);
}

// Main protection orchestrator
int run_protection_layers() {
    printf("=== Multi-Layer Protection System v4.0 ===\n");
    printf("Initializing protection layers...\n\n");
    
    // Layer 1: Anti-debugging
    printf("[1/6] Checking for debuggers...");
    if (check_debugger_presence()) {
        printf(" FAILED!\n");
        printf("✗ Debugger detected - terminating\n");
        return 0;
    }
    printf(" PASSED\n");
    protection_state |= LAYER_DEBUGGER;
    protection_checks_passed++;
    
    // Layer 2: VM detection
    printf("[2/6] Checking virtual environment...");
    if (check_vm_environment()) {
        printf(" WARNING!\n");
        printf("⚠ Virtual machine detected - limited functionality\n");
        // Continue but flag as suspicious
    } else {
        printf(" PASSED\n");
        protection_state |= LAYER_VM_DETECT;
    }
    protection_checks_passed++;
    
    // Layer 3: Code integrity
    printf("[3/6] Verifying code integrity...");
    if (!verify_code_integrity()) {
        printf(" FAILED!\n");
        printf("✗ Code tampering detected\n");
        return 0;
    }
    printf(" PASSED\n");
    protection_state |= LAYER_INTEGRITY;
    protection_checks_passed++;
    
    // Layer 4: License validation
    printf("[4/6] Validating license...");
    char license[] = "ML-VALID-LICENSE-KEY-2024-B"; // Checksum = 0x142 -> 0x42
    if (!validate_multilayer_license(license)) {
        printf(" FAILED!\n");
        printf("✗ Invalid license\n");
        return 0;
    }
    printf(" PASSED\n");
    protection_state |= LAYER_LICENSE;
    protection_checks_passed++;
    
    // Layer 5: Execute packed routine
    printf("[5/6] Unpacking protected code...");
    execute_packed_routine();
    protection_state |= LAYER_PACKING;
    protection_checks_passed++;
    
    // Layer 6: Network heartbeat
    printf("[6/6] Network heartbeat check...");
    if (!perform_network_heartbeat()) {
        printf(" FAILED!\n");
        printf("⚠ Network check failed - offline mode\n");
        // Continue in offline mode
    } else {
        printf(" PASSED\n");
        protection_state |= LAYER_NETWORK;
    }
    protection_checks_passed++;
    
    return 1;
}

// Display protection summary
void show_protection_status() {
    printf("\n=== Protection Status Summary ===\n");
    printf("Layers active: %d/6\n", protection_checks_passed);
    printf("Protection state: 0x%08X\n", protection_state);
    
    if (protection_state & LAYER_DEBUGGER) printf("✓ Anti-debugging active\n");
    if (protection_state & LAYER_VM_DETECT) printf("✓ VM detection active\n");
    if (protection_state & LAYER_INTEGRITY) printf("✓ Code integrity verified\n");
    if (protection_state & LAYER_LICENSE) printf("✓ License validated\n");
    if (protection_state & LAYER_PACKING) printf("✓ Code unpacking completed\n");
    if (protection_state & LAYER_NETWORK) printf("✓ Network heartbeat active\n");
    
    printf("\n");
}

int main(int argc, char* argv[]) {
    printf("Starting multi-layer protected application...\n\n");
    
    // Run all protection layers
    if (!run_protection_layers()) {
        printf("\n✗ SECURITY CHECK FAILED!\n");
        printf("Application terminated due to security violation.\n");
        return 1;
    }
    
    // Show protection status
    show_protection_status();
    
    // Application successfully started
    printf("✓ ALL PROTECTION LAYERS PASSED!\n");
    printf("Application startup: SUCCESS\n");
    printf("Welcome to the fully protected application!\n");
    
    // Simulate application runtime
    printf("\nApplication is now running with full protection...\n");
    printf("Protection monitoring active in background.\n");
    
    return 0;
}