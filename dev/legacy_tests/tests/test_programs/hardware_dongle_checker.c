#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#pragma comment(lib, "setupapi.lib")
#else
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#endif

#define DONGLE_VENDOR_ID 0x1234
#define DONGLE_PRODUCT_ID 0x5678
#define EXPECTED_DONGLE_SIZE 64
#define CHALLENGE_SIZE 16

typedef struct {
    unsigned short vendor_id;
    unsigned short product_id;
    char serial_number[32];
    unsigned char challenge_response[32];
} DongleInfo;

// Simulated hardware dongle identifiers
const char* known_dongles[] = {
    "HASP_HL",
    "SafeNet_USB",
    "Sentinel_HASP",
    "CodeMeter_USB",
    "WibuKey_USB",
    "Dinkey_Pro",
    NULL
};

// Generate challenge for dongle authentication
void generate_challenge(unsigned char* challenge) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < CHALLENGE_SIZE; i++) {
        challenge[i] = rand() % 256;
    }
}

// Simulate dongle challenge-response
int authenticate_dongle(const char* dongle_name, unsigned char* challenge, unsigned char* response) {
    printf("Authenticating dongle: %s\n", dongle_name);
    
    // Simulate hardware-specific response generation
    for (int i = 0; i < CHALLENGE_SIZE; i++) {
        response[i] = challenge[i] ^ 0xAA; // Simple XOR for simulation
        response[i] += (i % 4); // Add some variation
    }
    
    // Add dongle-specific signature
    if (strstr(dongle_name, "HASP")) {
        response[0] ^= 0x48; // 'H'
        response[1] ^= 0x41; // 'A'
    } else if (strstr(dongle_name, "SafeNet")) {
        response[0] ^= 0x53; // 'S'
        response[1] ^= 0x4E; // 'N'
    }
    
    return 1; // Success
}

// Check for USB dongles on Windows
#ifdef _WIN32
int scan_usb_devices() {
    HDEVINFO dev_info;
    SP_DEVINFO_DATA dev_info_data;
    DWORD i;
    
    dev_info = SetupDiGetClassDevs(&GUID_DEVCLASS_USB, NULL, NULL, DIGCF_PRESENT);
    if (dev_info == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot enumerate USB devices\n");
        return 0;
    }
    
    printf("Scanning USB devices for dongles...\n");
    
    dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
    for (i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data); i++) {
        char device_desc[256];
        char hardware_id[256];
        
        // Get device description
        if (SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_DEVICEDESC,
                                            NULL, (PBYTE)device_desc, sizeof(device_desc), NULL)) {
            
            // Get hardware ID
            if (SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_HARDWAREID,
                                                NULL, (PBYTE)hardware_id, sizeof(hardware_id), NULL)) {
                
                // Check against known dongle patterns
                for (int j = 0; known_dongles[j]; j++) {
                    if (strstr(device_desc, known_dongles[j]) || strstr(hardware_id, known_dongles[j])) {
                        printf("Found potential dongle: %s\n", device_desc);
                        printf("Hardware ID: %s\n", hardware_id);
                        
                        SetupDiDestroyDeviceInfoList(dev_info);
                        return 1; // Dongle found
                    }
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(dev_info);
    return 0; // No dongle found
}
#else
// Check for USB dongles on Linux
int scan_usb_devices() {
    FILE* lsusb;
    char line[512];
    
    printf("Scanning USB devices for dongles...\n");
    
    lsusb = popen("lsusb", "r");
    if (!lsusb) {
        printf("Error: Cannot execute lsusb command\n");
        return 0;
    }
    
    while (fgets(line, sizeof(line), lsusb)) {
        // Check against known dongle patterns
        for (int i = 0; known_dongles[i]; i++) {
            if (strstr(line, known_dongles[i])) {
                printf("Found potential dongle: %s", line);
                pclose(lsusb);
                return 1; // Dongle found
            }
        }
        
        // Check for specific vendor/product IDs
        if (strstr(line, "1234:5678")) { // Our simulated dongle
            printf("Found target dongle: %s", line);
            pclose(lsusb);
            return 1;
        }
    }
    
    pclose(lsusb);
    return 0; // No dongle found
}
#endif

// Check for dongle emulation files (common bypass technique)
int detect_dongle_emulation() {
    const char* emulation_files[] = {
#ifdef _WIN32
        "C:\\Windows\\System32\\aksdf.dll",
        "C:\\Windows\\System32\\hardlock.sys",
        "C:\\Windows\\System32\\sentinel.sys",
        "haspnt.sys",
        "aksdf.dll",
#else
        "/tmp/dongle_emu",
        "/dev/hardlock",
        "/tmp/.hasp_emulator",
        "libhasp_linux.so",
#endif
        NULL
    };
    
    printf("Checking for dongle emulation...\n");
    
    for (int i = 0; emulation_files[i]; i++) {
        FILE* test_file = fopen(emulation_files[i], "r");
        if (test_file) {
            printf("Warning: Emulation file detected: %s\n", emulation_files[i]);
            fclose(test_file);
            return 1; // Emulation detected
        }
    }
    
    return 0; // No emulation detected
}

// Verify dongle functionality with challenge-response
int verify_dongle_functionality(const char* dongle_name) {
    unsigned char challenge[CHALLENGE_SIZE];
    unsigned char response[CHALLENGE_SIZE];
    unsigned char expected[CHALLENGE_SIZE];
    
    printf("\nPerforming dongle challenge-response test...\n");
    
    // Generate random challenge
    generate_challenge(challenge);
    
    printf("Challenge: ");
    for (int i = 0; i < CHALLENGE_SIZE; i++) {
        printf("%02X ", challenge[i]);
    }
    printf("\n");
    
    // Get response from dongle
    if (!authenticate_dongle(dongle_name, challenge, response)) {
        printf("Error: Dongle authentication failed\n");
        return 0;
    }
    
    printf("Response:  ");
    for (int i = 0; i < CHALLENGE_SIZE; i++) {
        printf("%02X ", response[i]);
    }
    printf("\n");
    
    // Verify response (in real implementation, this would check against expected algorithm)
    // For simulation, we regenerate the expected response
    authenticate_dongle(dongle_name, challenge, expected);
    
    if (memcmp(response, expected, CHALLENGE_SIZE) == 0) {
        printf("✓ Challenge-response verification: PASSED\n");
        return 1;
    } else {
        printf("✗ Challenge-response verification: FAILED\n");
        return 0;
    }
}

// Main dongle checking routine
int main(int argc, char* argv[]) {
    printf("=== Hardware Dongle Security Checker v3.2 ===\n");
    printf("Checking for required security dongle...\n\n");
    
    // Check for dongle emulation first
    if (detect_dongle_emulation()) {
        printf("\n✗ SECURITY VIOLATION: Dongle emulation detected!\n");
        printf("Application startup: BLOCKED\n");
        printf("Please remove emulation software and use genuine hardware dongle.\n");
        return 1;
    }
    
    // Scan for physical dongles
    int dongle_found = scan_usb_devices();
    
    if (!dongle_found) {
        printf("\n✗ No security dongle detected!\n");
        printf("Application startup: BLOCKED\n");
        printf("Please insert the required hardware dongle and try again.\n");
        return 1;
    }
    
    // Verify dongle functionality
    if (!verify_dongle_functionality("HASP_HL")) {
        printf("\n✗ Dongle verification failed!\n");
        printf("Application startup: BLOCKED\n");
        printf("The dongle may be damaged or counterfeit.\n");
        return 1;
    }
    
    printf("\n✓ Hardware dongle verification successful!\n");
    printf("Application startup: SUCCESS\n");
    printf("Welcome! Hardware protection active.\n");
    
    return 0;
}