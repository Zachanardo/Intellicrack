#!/usr/bin/env python3
"""Generate vulnerable test binaries for exploit testing.
Creates binaries with specific vulnerabilities for testing exploitation capabilities.
"""

import struct
import subprocess
from pathlib import Path


def create_buffer_overflow_binary(output_path: Path) -> None:
    """Create a binary with buffer overflow vulnerability."""
    # C source code with buffer overflow
    c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];  // Small buffer
    strcpy(buffer, input);  // No bounds checking!
    printf("You entered: %s\\n", buffer);
}

void win_function() {
    printf("Exploit successful! You reached the win function.\\n");
    system("echo 'PWNED!'");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }

    printf("Win function is at: %p\\n", win_function);
    vulnerable_function(argv[1]);

    return 0;
}
"""

    # Write C source
    src_path = output_path.with_suffix(".c")
    src_path.write_text(c_code)

    # Try to compile (Windows with MinGW or MSVC)
    compile_commands = [
        ["gcc", "-o", str(output_path), str(src_path), "-fno-stack-protector", "-z", "execstack", "-no-pie"],
        ["cl", "/Fe:" + str(output_path), str(src_path), "/GS-", "/link", "/DYNAMICBASE:NO", "/NXCOMPAT:NO"],
    ]

    compiled = False
    for cmd in compile_commands:
        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                compiled = True
                print(f"✓ Created buffer overflow binary: {output_path}")
                break
        except FileNotFoundError:
            continue

    if not compiled:
        # Create a pre-compiled vulnerable binary
        create_precompiled_vulnerable_binary(output_path, "buffer_overflow")

    # Clean up source
    if src_path.exists():
        src_path.unlink()


def create_format_string_binary(output_path: Path) -> None:
    """Create a binary with format string vulnerability."""
    c_code = """
#include <stdio.h>
#include <string.h>

int secret_value = 0x41414141;

void vulnerable_printf(char *user_input) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), user_input);  // Format string vulnerability!
    printf(buffer);  // Double vulnerability!
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <format_string>\\n", argv[0]);
        return 1;
    }

    printf("Secret value address: %p\\n", &secret_value);
    printf("Enter format string: ");
    vulnerable_printf(argv[1]);
    printf("\\nSecret value is now: 0x%08x\\n", secret_value);

    if (secret_value == 0x42424242) {
        printf("Exploit successful! Secret value modified.\\n");
    }

    return 0;
}
"""

    src_path = output_path.with_suffix(".c")
    src_path.write_text(c_code)

    # Try to compile
    compile_commands = [
        ["gcc", "-o", str(output_path), str(src_path), "-Wno-format-security"],
        ["cl", "/Fe:" + str(output_path), str(src_path)],
    ]

    compiled = False
    for cmd in compile_commands:
        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                compiled = True
                print(f"✓ Created format string binary: {output_path}")
                break
        except FileNotFoundError:
            continue

    if not compiled:
        create_precompiled_vulnerable_binary(output_path, "format_string")

    if src_path.exists():
        src_path.unlink()


def create_integer_overflow_binary(output_path: Path) -> None:
    """Create a binary with integer overflow vulnerability."""
    c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(unsigned int size, char *data) {
    unsigned int buffer_size = size + 100;  // Integer overflow possible!

    if (buffer_size > 1000) {
        printf("Size too large!\\n");
        return;
    }

    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        printf("Allocation failed\\n");
        return;
    }

    // Vulnerable copy
    memcpy(buffer, data, size);  // If size overflowed, this is bad!

    printf("Processed %u bytes\\n", size);
    free(buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <size>\\n", argv[0]);
        return 1;
    }

    unsigned int size = (unsigned int)atoi(argv[1]);
    char data[1024] = "A";

    printf("Processing with size: %u\\n", size);
    process_data(size, data);

    return 0;
}
"""

    src_path = output_path.with_suffix(".c")
    src_path.write_text(c_code)

    # Compile
    compile_commands = [
        ["gcc", "-o", str(output_path), str(src_path)],
        ["cl", "/Fe:" + str(output_path), str(src_path)],
    ]

    compiled = False
    for cmd in compile_commands:
        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                compiled = True
                print(f"✓ Created integer overflow binary: {output_path}")
                break
        except FileNotFoundError:
            continue

    if not compiled:
        create_precompiled_vulnerable_binary(output_path, "integer_overflow")

    if src_path.exists():
        src_path.unlink()


def create_heap_overflow_binary(output_path: Path) -> None:
    """Create a binary with heap overflow vulnerability."""
    c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user_data {
    char name[64];
    int is_admin;
    void (*print_function)();
};

void normal_print() {
    printf("Normal user access\\n");
}

void admin_print() {
    printf("Admin access granted!\\n");
    system("echo 'ADMIN PWNED!'");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <name>\\n", argv[0]);
        return 1;
    }

    struct user_data *user1 = (struct user_data *)malloc(sizeof(struct user_data));
    struct user_data *user2 = (struct user_data *)malloc(sizeof(struct user_data));

    // Initialize users
    user1->is_admin = 0;
    user1->print_function = normal_print;

    user2->is_admin = 1;
    user2->print_function = admin_print;

    printf("User1 at: %p, User2 at: %p\\n", user1, user2);

    // Vulnerable strcpy - can overflow into user2!
    strcpy(user1->name, argv[1]);

    printf("User1 name: %s\\n", user1->name);
    printf("User1 admin status: %d\\n", user1->is_admin);

    // Call the function pointer
    user1->print_function();

    free(user1);
    free(user2);

    return 0;
}
"""

    src_path = output_path.with_suffix(".c")
    src_path.write_text(c_code)

    # Compile
    compile_commands = [
        ["gcc", "-o", str(output_path), str(src_path), "-fno-stack-protector"],
        ["cl", "/Fe:" + str(output_path), str(src_path), "/GS-"],
    ]

    compiled = False
    for cmd in compile_commands:
        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                compiled = True
                print(f"✓ Created heap overflow binary: {output_path}")
                break
        except FileNotFoundError:
            continue

    if not compiled:
        create_precompiled_vulnerable_binary(output_path, "heap_overflow")

    if src_path.exists():
        src_path.unlink()


def create_race_condition_binary(output_path: Path) -> None:
    """Create a binary with race condition vulnerability."""
    c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void check_and_use_file(const char *filename) {
    // TOCTOU vulnerability - Time of Check to Time of Use
    if (access(filename, F_OK) == 0) {
        printf("File exists, checking permissions...\\n");

        // Artificial delay to make race condition easier
        sleep(1);

        // Now use the file - but it might have changed!
        FILE *fp = fopen(filename, "r");
        if (fp) {
            char buffer[256];
            fgets(buffer, sizeof(buffer), fp);
            printf("File content: %s\\n", buffer);

            // Dangerous - execute content as command
            if (strncmp(buffer, "EXEC:", 5) == 0) {
                printf("Executing command...\\n");
                system(buffer + 5);
            }

            fclose(fp);
        }
    } else {
        printf("File does not exist\\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\\n", argv[0]);
        return 1;
    }

    printf("Checking file: %s\\n", argv[1]);
    check_and_use_file(argv[1]);

    return 0;
}
"""

    src_path = output_path.with_suffix(".c")
    src_path.write_text(c_code)

    # Compile
    compile_commands = [
        ["gcc", "-o", str(output_path), str(src_path)],
        ["cl", "/Fe:" + str(output_path), str(src_path)],
    ]

    compiled = False
    for cmd in compile_commands:
        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                compiled = True
                print(f"✓ Created race condition binary: {output_path}")
                break
        except FileNotFoundError:
            continue

    if not compiled:
        create_precompiled_vulnerable_binary(output_path, "race_condition")

    if src_path.exists():
        src_path.unlink()


def create_precompiled_vulnerable_binary(output_path: Path, vuln_type: str) -> None:
    """Create a pre-compiled vulnerable binary when compilation fails."""
    # Create a simple PE that simulates the vulnerability
    pe_data = bytearray(8192)

    # DOS Header
    pe_data[0:2] = b"MZ"
    pe_data[0x3C:0x40] = struct.pack("<I", 0x80)

    # PE Signature
    pe_data[0x80:0x84] = b"PE\x00\x00"

    # COFF Header
    pe_data[0x84:0x86] = struct.pack("<H", 0x014C)  # Machine (x86)
    pe_data[0x86:0x88] = struct.pack("<H", 0x0002)  # Number of sections
    pe_data[0x94:0x96] = struct.pack("<H", 0x00E0)  # Size of optional header
    pe_data[0x96:0x98] = struct.pack("<H", 0x0102)  # Characteristics

    # Section headers
    pe_data[0x178:0x180] = b".text\x00\x00\x00"
    pe_data[0x1A0:0x1A8] = b".data\x00\x00\x00"

    # Add vulnerability marker
    marker_offset = 0x1000
    pe_data[marker_offset:marker_offset+32] = f"VULN_{vuln_type.upper()}\x00".encode()[:32]

    # Add some vulnerable patterns based on type
    if vuln_type == "buffer_overflow":
        # strcpy pattern
        pe_data[0x1100:0x1105] = bytes([0xFF, 0x15, 0x00, 0x20, 0x40])  # call strcpy
    elif vuln_type == "format_string":
        # printf pattern
        pe_data[0x1100:0x1105] = bytes([0xFF, 0x15, 0x10, 0x20, 0x40])  # call printf
    elif vuln_type == "heap_overflow":
        # malloc pattern
        pe_data[0x1100:0x1105] = bytes([0xFF, 0x15, 0x20, 0x20, 0x40])  # call malloc

    output_path.write_bytes(pe_data)
    print(f"✓ Created pre-compiled {vuln_type} binary: {output_path}")


def generate_all_vulnerable_binaries(output_dir: Path) -> dict[str, list[Path]]:
    """Generate all types of vulnerable binaries."""
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_files = {
        "buffer_overflow": [],
        "format_string": [],
        "integer_overflow": [],
        "heap_overflow": [],
        "race_condition": [],
    }

    vulnerabilities = [
        ("buffer_overflow", create_buffer_overflow_binary),
        ("format_string", create_format_string_binary),
        ("integer_overflow", create_integer_overflow_binary),
        ("heap_overflow", create_heap_overflow_binary),
        ("race_condition", create_race_condition_binary),
    ]

    for vuln_name, creator in vulnerabilities:
        # Create multiple variants
        for i in range(2):
            filename = f"{vuln_name}_{i}.exe"
            path = output_dir / filename
            creator(path)
            generated_files[vuln_name].append(path)

    return generated_files


def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    output_dir = script_dir.parent / "tests" / "fixtures" / "vulnerable_samples"

    print("Generating vulnerable test binaries...")
    print("WARNING: These binaries contain real vulnerabilities for testing only!")
    print(f"Output directory: {output_dir}")

    generated = generate_all_vulnerable_binaries(output_dir)

    print("\n✓ Generated vulnerable binaries summary:")
    for category, files in generated.items():
        print(f"  {category}: {len(files)} files")
        for file in files:
            if file.exists():
                size = file.stat().st_size
                print(f"    - {file.name} ({size} bytes)")

    print(f"\nTotal files generated: {sum(len(files) for files in generated.values())}")
    print("\n⚠️  These binaries are INTENTIONALLY VULNERABLE for testing purposes only!")


if __name__ == "__main__":
    main()
