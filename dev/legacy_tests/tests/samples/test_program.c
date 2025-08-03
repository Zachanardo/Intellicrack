#include <stdio.h>
#include <string.h>

int main() {
    char license_key[100];
    printf("Enter license key: ");
    fgets(license_key, sizeof(license_key), stdin);

    // Simple license check
    if (strncmp(license_key, "VALID-KEY-", 10) == 0) {
        printf("License valid\! Access granted.\n");
        return 0;
    } else {
        printf("Invalid license. Access denied.\n");
        return 1;
    }
}
EOF < /dev/null
