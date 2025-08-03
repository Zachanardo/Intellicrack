#!/usr/bin/env python3
"""
Generate protected binary samples for testing.
Creates real PE/ELF binaries with various packers and protectors.
"""

import struct
import subprocess
import random
from pathlib import Path
from typing import List, Dict

# Test binary templates
SIMPLE_PE_TEMPLATE = bytearray([
    # DOS Header
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
])

def create_base_pe(output_path: Path, size: int = 4096) -> None:
    """Create a basic PE executable."""
    pe_data = bytearray(size)
    
    # DOS Header
    pe_data[0:2] = b"MZ"
    pe_data[0x3C:0x40] = struct.pack("<I", 0x80)  # PE header offset
    
    # PE Signature
    pe_data[0x80:0x84] = b"PE\x00\x00"
    
    # COFF Header
    pe_data[0x84:0x86] = struct.pack("<H", 0x014C)  # Machine (x86)
    pe_data[0x86:0x88] = struct.pack("<H", 0x0003)  # Number of sections
    pe_data[0x94:0x96] = struct.pack("<H", 0x00E0)  # Size of optional header
    pe_data[0x96:0x98] = struct.pack("<H", 0x0102)  # Characteristics
    
    # Optional Header
    pe_data[0x98:0x9A] = struct.pack("<H", 0x010B)  # Magic (PE32)
    pe_data[0xA8:0xAC] = struct.pack("<I", 0x1000)  # Entry point
    pe_data[0xB0:0xB4] = struct.pack("<I", 0x400000)  # Image base
    pe_data[0xB4:0xB8] = struct.pack("<I", 0x1000)  # Section alignment
    pe_data[0xB8:0xBC] = struct.pack("<I", 0x200)   # File alignment
    
    # Section Headers
    # .text section
    text_offset = 0x178
    pe_data[text_offset:text_offset+8] = b".text\x00\x00\x00"
    pe_data[text_offset+8:text_offset+12] = struct.pack("<I", 0x1000)  # Virtual size
    pe_data[text_offset+12:text_offset+16] = struct.pack("<I", 0x1000)  # Virtual address
    pe_data[text_offset+16:text_offset+20] = struct.pack("<I", 0x400)   # Raw size
    pe_data[text_offset+20:text_offset+24] = struct.pack("<I", 0x400)   # Raw offset
    pe_data[text_offset+36:text_offset+40] = struct.pack("<I", 0x60000020)  # Characteristics
    
    # .data section
    data_offset = text_offset + 40
    pe_data[data_offset:data_offset+8] = b".data\x00\x00\x00"
    pe_data[data_offset+8:data_offset+12] = struct.pack("<I", 0x1000)
    pe_data[data_offset+12:data_offset+16] = struct.pack("<I", 0x2000)
    pe_data[data_offset+16:data_offset+20] = struct.pack("<I", 0x200)
    pe_data[data_offset+20:data_offset+24] = struct.pack("<I", 0x800)
    pe_data[data_offset+36:data_offset+40] = struct.pack("<I", 0xC0000040)
    
    # .rsrc section
    rsrc_offset = data_offset + 40
    pe_data[rsrc_offset:rsrc_offset+8] = b".rsrc\x00\x00\x00"
    pe_data[rsrc_offset+8:rsrc_offset+12] = struct.pack("<I", 0x1000)
    pe_data[rsrc_offset+12:rsrc_offset+16] = struct.pack("<I", 0x3000)
    pe_data[rsrc_offset+16:rsrc_offset+20] = struct.pack("<I", 0x200)
    pe_data[rsrc_offset+20:rsrc_offset+24] = struct.pack("<I", 0xA00)
    pe_data[rsrc_offset+36:rsrc_offset+40] = struct.pack("<I", 0x40000040)
    
    # Add some code in .text section
    code_offset = 0x400
    # Simple MessageBox code
    pe_data[code_offset:code_offset+16] = bytes([
        0x6A, 0x00,              # push 0
        0x68, 0x00, 0x20, 0x40, 0x00,  # push offset szText
        0x68, 0x10, 0x20, 0x40, 0x00,  # push offset szCaption
        0x6A, 0x00,              # push 0
        0xFF, 0x15,              # call dword ptr
    ])
    
    # Add strings in .data section
    pe_data[0x800:0x810] = b"Hello World!\x00\x00\x00\x00"
    pe_data[0x810:0x820] = b"Test Program\x00\x00\x00\x00"
    
    output_path.write_bytes(pe_data)


def create_upx_packed_binary(output_path: Path) -> None:
    """Create a UPX-packed binary."""
    # First create a base binary
    temp_path = output_path.with_suffix(".tmp")
    create_base_pe(temp_path)
    
    # Try to pack with UPX if available
    try:
        result = subprocess.run(["upx", "--best", "-o", str(output_path), str(temp_path)], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Created UPX packed binary: {output_path}")
        else:
            # If UPX not available, create a simulated UPX-like binary
            create_simulated_upx_binary(output_path)
    except FileNotFoundError:
        # UPX not installed, create simulated version
        create_simulated_upx_binary(output_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def create_simulated_upx_binary(output_path: Path) -> None:
    """Create a binary that looks like it's UPX packed."""
    pe_data = bytearray(8192)
    
    # DOS Header
    pe_data[0:2] = b"MZ"
    pe_data[0x3C:0x40] = struct.pack("<I", 0x80)
    
    # PE Signature
    pe_data[0x80:0x84] = b"PE\x00\x00"
    
    # Modified section names typical of UPX
    pe_data[0x178:0x180] = b"UPX0\x00\x00\x00\x00"
    pe_data[0x1A0:0x1A8] = b"UPX1\x00\x00\x00\x00"
    pe_data[0x1C8:0x1D0] = b".rsrc\x00\x00\x00"
    
    # Add UPX signature
    pe_data[0x200:0x203] = b"UPX!"
    
    # Add high entropy data (compressed appearance)
    import random
    for i in range(0x400, 0x1000):
        pe_data[i] = random.randint(0, 255)
    
    output_path.write_bytes(pe_data)
    print(f"✓ Created simulated UPX packed binary: {output_path}")


def create_net_assembly(output_path: Path) -> None:
    """Create a .NET assembly."""
    # .NET PE has specific characteristics
    pe_data = bytearray(16384)
    
    # Standard PE headers
    pe_data[0:2] = b"MZ"
    pe_data[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_data[0x80:0x84] = b"PE\x00\x00"
    
    # CLR Runtime Header in Data Directory
    pe_data[0x108:0x10C] = struct.pack("<I", 0x2000)  # RVA
    pe_data[0x10C:0x110] = struct.pack("<I", 0x48)    # Size
    
    # .text section with CLR header
    pe_data[0x2000:0x2004] = struct.pack("<I", 0x48)  # Cb
    pe_data[0x2004:0x2006] = struct.pack("<H", 2)     # MajorRuntimeVersion
    pe_data[0x2006:0x2008] = struct.pack("<H", 5)     # MinorRuntimeVersion
    
    # Metadata header
    pe_data[0x2200:0x2204] = b"BSJB"  # Metadata signature
    
    # Add typical .NET section
    pe_data[0x178:0x180] = b".text\x00\x00\x00"
    pe_data[0x1A0:0x1A8] = b".rsrc\x00\x00\x00"
    pe_data[0x1C8:0x1D0] = b".reloc\x00\x00"
    
    output_path.write_bytes(pe_data)
    print(f"✓ Created .NET assembly: {output_path}")


def create_themida_style_binary(output_path: Path) -> None:
    """Create a binary with Themida-like characteristics."""
    pe_data = bytearray(32768)
    
    # Standard PE headers
    pe_data[0:2] = b"MZ"
    pe_data[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_data[0x80:0x84] = b"PE\x00\x00"
    
    # Themida-like section names
    pe_data[0x178:0x180] = b".themida"
    pe_data[0x1A0:0x1A8] = b".mackt\x00\x00"
    pe_data[0x1C8:0x1D0] = b".rsrc\x00\x00"
    
    # Add anti-debug checks pattern
    anti_debug_pattern = bytes([
        0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,  # mov eax, fs:[30h]
        0x80, 0x78, 0x02, 0x01,              # cmp byte ptr [eax+2], 1
        0x75, 0x05,                          # jnz short
    ])
    pe_data[0x1000:0x1000+len(anti_debug_pattern)] = anti_debug_pattern
    
    # Add obfuscated code patterns
    import random
    for i in range(0x2000, 0x4000):
        if i % 16 == 0:
            # Add junk code patterns
            pe_data[i:i+2] = bytes([0xEB, random.randint(1, 10)])  # Short jumps
        else:
            pe_data[i] = random.randint(0x80, 0xFF)
    
    # Add Themida signature pattern
    pe_data[0x5000:0x5008] = b"Themida\x00"
    
    output_path.write_bytes(pe_data)
    print(f"✓ Created Themida-style protected binary: {output_path}")


def create_vmprotect_style_binary(output_path: Path) -> None:
    """Create a binary with VMProtect-like characteristics."""
    pe_data = bytearray(65536)
    
    # Standard PE headers
    pe_data[0:2] = b"MZ"
    pe_data[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_data[0x80:0x84] = b"PE\x00\x00"
    
    # VMProtect-like section names
    pe_data[0x178:0x180] = b".vmp0\x00\x00\x00"
    pe_data[0x1A0:0x1A8] = b".vmp1\x00\x00\x00"
    pe_data[0x1C8:0x1D0] = b".vmp2\x00\x00\x00"
    
    # Add virtualized code patterns (high complexity)
    vm_handlers = [
        bytes([0x50, 0x53, 0x51, 0x52]),  # push registers
        bytes([0x8B, 0x45, 0x00]),         # mov eax, [ebp]
        bytes([0x81, 0xC4, 0x04, 0x00, 0x00, 0x00]),  # add esp, 4
        bytes([0x5A, 0x59, 0x5B, 0x58]),  # pop registers
    ]
    
    offset = 0x3000
    for _ in range(100):
        handler = random.choice(vm_handlers)
        pe_data[offset:offset+len(handler)] = handler
        offset += len(handler) + random.randint(1, 10)
    
    # Add VMProtect markers
    pe_data[0x8000:0x8010] = b"VMProtectBegin\x00\x00"
    pe_data[0x8100:0x8110] = b"VMProtectEnd\x00\x00\x00\x00"
    
    output_path.write_bytes(pe_data)
    print(f"✓ Created VMProtect-style protected binary: {output_path}")


def create_custom_packed_binary(output_path: Path, packer_name: str) -> None:
    """Create a custom packed binary with specific characteristics."""
    pe_data = bytearray(16384)
    
    # Standard PE headers
    pe_data[0:2] = b"MZ"
    pe_data[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_data[0x80:0x84] = b"PE\x00\x00"
    
    # Custom section name
    section_name = f".{packer_name[:5]}\x00\x00\x00"
    pe_data[0x178:0x180] = section_name.encode()[:8]
    
    # Add packer signature
    pe_data[0x1000:0x1000+len(packer_name)] = packer_name.encode()
    
    # Add high entropy data
    import random
    for i in range(0x2000, 0x3000):
        pe_data[i] = random.randint(0, 255)
    
    output_path.write_bytes(pe_data)
    print(f"✓ Created {packer_name} packed binary: {output_path}")


def create_elf_binary(output_path: Path, arch: str = "x64") -> None:
    """Create a basic ELF binary."""
    # ELF header
    elf_data = bytearray(4096)
    
    # ELF magic
    elf_data[0:4] = b"\x7fELF"
    
    # Class (32/64 bit)
    elf_data[4] = 2 if arch == "x64" else 1
    
    # Data encoding (little endian)
    elf_data[5] = 1
    
    # Version
    elf_data[6] = 1
    
    # OS/ABI
    elf_data[7] = 0  # System V
    
    # Type (executable)
    elf_data[16:18] = struct.pack("<H", 2)
    
    # Machine
    if arch == "x64":
        elf_data[18:20] = struct.pack("<H", 0x3E)  # x86-64
    else:
        elf_data[18:20] = struct.pack("<H", 0x03)  # x86
    
    # Version
    elf_data[20:24] = struct.pack("<I", 1)
    
    # Entry point
    elf_data[24:32] = struct.pack("<Q", 0x400000) if arch == "x64" else struct.pack("<I", 0x8048000)
    
    # Program header offset
    elf_data[32:40] = struct.pack("<Q", 0x40) if arch == "x64" else struct.pack("<I", 0x34)
    
    # Add some code
    code_offset = 0x1000
    # Simple exit syscall
    if arch == "x64":
        elf_data[code_offset:code_offset+7] = bytes([
            0xB8, 0x3C, 0x00, 0x00, 0x00,  # mov eax, 60 (exit)
            0x0F, 0x05                      # syscall
        ])
    else:
        elf_data[code_offset:code_offset+7] = bytes([
            0xB8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1 (exit)
            0xCD, 0x80                      # int 0x80
        ])
    
    output_path.write_bytes(elf_data)
    print(f"✓ Created ELF {arch} binary: {output_path}")


def generate_all_protected_binaries(output_dir: Path) -> Dict[str, List[Path]]:
    """Generate all types of protected binaries."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    generated_files = {
        "pe_simple": [],
        "pe_packed": [],
        "pe_protected": [],
        "pe_dotnet": [],
        "elf": []
    }
    
    # Simple PE files
    for i in range(3):
        path = output_dir / f"simple_pe_{i}.exe"
        create_base_pe(path, size=4096 + i * 1024)
        generated_files["pe_simple"].append(path)
    
    # UPX packed
    for i in range(2):
        path = output_dir / f"upx_packed_{i}.exe"
        create_upx_packed_binary(path)
        generated_files["pe_packed"].append(path)
    
    # .NET assemblies
    for i in range(2):
        path = output_dir / f"dotnet_assembly_{i}.exe"
        create_net_assembly(path)
        generated_files["pe_dotnet"].append(path)
    
    # Protected binaries
    protectors = [
        ("themida", create_themida_style_binary),
        ("vmprotect", create_vmprotect_style_binary),
    ]
    
    for name, creator in protectors:
        path = output_dir / f"{name}_protected.exe"
        creator(path)
        generated_files["pe_protected"].append(path)
    
    # Custom packers
    custom_packers = ["ASPack", "PECompact", "Enigma", "Obsidium"]
    for packer in custom_packers:
        path = output_dir / f"{packer.lower()}_packed.exe"
        create_custom_packed_binary(path, packer)
        generated_files["pe_packed"].append(path)
    
    # ELF binaries
    for arch in ["x86", "x64"]:
        for i in range(2):
            path = output_dir / f"elf_{arch}_{i}"
            create_elf_binary(path, arch)
            generated_files["elf"].append(path)
    
    return generated_files


def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    output_dir = script_dir.parent / "tests" / "fixtures" / "binaries" / "protected"
    
    print("Generating protected binary samples...")
    print(f"Output directory: {output_dir}")
    
    generated = generate_all_protected_binaries(output_dir)
    
    print("\n✓ Generated binaries summary:")
    for category, files in generated.items():
        print(f"  {category}: {len(files)} files")
        for file in files:
            size = file.stat().st_size
            print(f"    - {file.name} ({size} bytes)")
    
    print(f"\nTotal files generated: {sum(len(files) for files in generated.values())}")


if __name__ == "__main__":
    main()