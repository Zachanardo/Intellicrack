#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#define TRIAL_DAYS 30
#define ENCRYPTION_KEY 0xDEADBEEF
#define MAGIC_HEADER 0x54524941 // "TRIA"

typedef struct {
    unsigned int magic;
    unsigned int install_date;
    unsigned int last_check;
    unsigned int trial_days;
    unsigned int checksum;
} TrialData;

// Simple encryption/decryption
void encrypt_decrypt_data(void* data, size_t size, unsigned int key) {
    unsigned char* bytes = (unsigned char*)data;
    for (size_t i = 0; i < size; i++) {
        bytes[i] ^= ((key >> (i % 4 * 8)) & 0xFF);
    }
}

// Calculate checksum
unsigned int calculate_checksum(TrialData* data) {
    unsigned int sum = 0;
    sum += data->magic;
    sum += data->install_date;
    sum += data->last_check;
    sum += data->trial_days;
    return sum ^ 0x12345678;
}

// Get trial data file path
void get_trial_file_path(char* path, size_t size) {
#ifdef _WIN32
    char app_data[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, app_data) == S_OK) {
        snprintf(path, size, "%s\\Microsoft\\Windows\\trial.dat", app_data);
    } else {
        strcpy(path, "C:\\Windows\\Temp\\trial.dat");
    }
#else
    strcpy(path, "/tmp/.trial_data");
#endif
}

// Create initial trial data
int create_trial_data() {
    char file_path[512];
    get_trial_file_path(file_path, sizeof(file_path));

    TrialData data;
    data.magic = MAGIC_HEADER;
    data.install_date = (unsigned int)time(NULL);
    data.last_check = data.install_date;
    data.trial_days = TRIAL_DAYS;
    data.checksum = calculate_checksum(&data);

    // Encrypt the data
    encrypt_decrypt_data(&data, sizeof(data), ENCRYPTION_KEY);

    FILE* file = fopen(file_path, "wb");
    if (!file) {
        printf("Error: Cannot create trial data file\n");
        return 0;
    }

    fwrite(&data, sizeof(data), 1, file);
    fclose(file);

    printf("Trial period initialized: %d days\n", TRIAL_DAYS);
    return 1;
}

// Load and validate trial data
int load_trial_data(TrialData* data) {
    char file_path[512];
    get_trial_file_path(file_path, sizeof(file_path));

    FILE* file = fopen(file_path, "rb");
    if (!file) {
        return 0; // File doesn't exist
    }

    if (fread(data, sizeof(TrialData), 1, file) != 1) {
        fclose(file);
        return 0;
    }
    fclose(file);

    // Decrypt the data
    encrypt_decrypt_data(data, sizeof(TrialData), ENCRYPTION_KEY);

    // Validate magic header
    if (data->magic != MAGIC_HEADER) {
        printf("Warning: Trial data corrupted (invalid magic)\n");
        return 0;
    }

    // Validate checksum
    unsigned int expected_checksum = calculate_checksum(data);
    if (data->checksum != expected_checksum) {
        printf("Warning: Trial data corrupted (invalid checksum)\n");
        return 0;
    }

    return 1;
}

// Update trial data with current timestamp
int update_trial_data(TrialData* data) {
    char file_path[512];
    get_trial_file_path(file_path, sizeof(file_path));

    data->last_check = (unsigned int)time(NULL);
    data->checksum = calculate_checksum(data);

    // Encrypt the data
    TrialData encrypted_data = *data;
    encrypt_decrypt_data(&encrypted_data, sizeof(encrypted_data), ENCRYPTION_KEY);

    FILE* file = fopen(file_path, "wb");
    if (!file) {
        return 0;
    }

    fwrite(&encrypted_data, sizeof(encrypted_data), 1, file);
    fclose(file);

    return 1;
}

// Check if trial period is valid
int check_trial_validity() {
    TrialData data;

    // Try to load existing trial data
    if (!load_trial_data(&data)) {
        // No trial data found, create new
        printf("First time run - initializing trial period\n");
        return create_trial_data();
    }

    time_t current_time = time(NULL);
    time_t install_time = (time_t)data.install_date;
    time_t last_check = (time_t)data.last_check;

    // Check for time manipulation (system clock moved backward)
    if (current_time < last_check) {
        printf("Error: System clock manipulation detected!\n");
        printf("Trial period invalidated.\n");
        return 0;
    }

    // Calculate days since installation
    double days_elapsed = difftime(current_time, install_time) / (24 * 60 * 60);
    int remaining_days = data.trial_days - (int)days_elapsed;

    printf("Trial status:\n");
    printf("- Installed: %s", ctime(&install_time));
    printf("- Days elapsed: %.1f\n", days_elapsed);
    printf("- Days remaining: %d\n", remaining_days);

    // Update last check time
    update_trial_data(&data);

    if (remaining_days <= 0) {
        printf("\n✗ Trial period has expired!\n");
        printf("Please purchase a license to continue using this software.\n");
        return 0;
    } else if (remaining_days <= 7) {
        printf("\n⚠ Warning: Trial expires in %d days\n", remaining_days);
    } else {
        printf("\n✓ Trial period is active\n");
    }

    return 1;
}

// Anti-tampering check
int verify_trial_integrity() {
    char file_path[512];
    get_trial_file_path(file_path, sizeof(file_path));

    // Check if multiple trial files exist (indicates tampering)
    char alt_paths[][256] = {
        "trial.dat",
        "trial.bak",
        "/tmp/trial.dat",
        "C:\\trial.dat"
    };

    int files_found = 0;
    for (int i = 0; i < 4; i++) {
        FILE* test_file = fopen(alt_paths[i], "rb");
        if (test_file) {
            files_found++;
            fclose(test_file);
        }
    }

    if (files_found > 1) {
        printf("Warning: Multiple trial files detected - possible tampering\n");
        return 0;
    }

    return 1;
}

int main(int argc, char* argv[]) {
    printf("=== Trial Period Manager v1.5 ===\n");
    printf("Checking trial license status...\n\n");

    // Verify trial data integrity
    if (!verify_trial_integrity()) {
        printf("Trial integrity check failed!\n");
        return 1;
    }

    // Check trial validity
    if (check_trial_validity()) {
        printf("\nApplication startup: SUCCESS (Trial Mode)\n");
        printf("Welcome to the trial version!\n");
        return 0;
    } else {
        printf("\nApplication startup: BLOCKED\n");
        printf("Trial period has ended or is invalid.\n");
        return 1;
    }
}
