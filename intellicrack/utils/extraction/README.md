# Package Extraction Modules

## Overview

The extraction modules provide functionality to extract and analyze various package formats within the Intellicrack framework. Currently supported formats include Windows Installer (MSI) packages and Debian (DEB) packages. These modules support multiple extraction methods and integrate seamlessly with the analysis system.

## Supported Formats

### MSI (Windows Installer)
- File extensions: .msi, .msp, .msm
- Platform: Primarily Windows, cross-platform support available
- Use case: Windows software installers

### DEB (Debian Package)
- File extensions: .deb, .udeb
- Platform: Linux/Unix, cross-platform support available
- Use case: Debian/Ubuntu software packages

### DMG (Apple Disk Image)
- File extensions: .dmg, .smi, .img, .sparseimage
- Platform: Primarily macOS, cross-platform support available
- Use case: macOS software distribution and disk images

## Common Features

- **Multiple Extraction Methods**: Each format supports multiple extraction tools with automatic fallback
- **File Categorization**: Automatically categorizes extracted files (executables, configs, scripts, etc.)
- **Main Executable Detection**: Intelligently identifies the main application executable
- **Metadata Extraction**: Extracts package metadata and properties
- **Cleanup Management**: Handles temporary directory cleanup
- **Cross-Platform Support**: Works on Windows, Linux, and macOS where possible

---

# MSI Extraction Module

## Features

- **Multiple Extraction Methods**: Supports msiexec, lessmsi, 7-Zip, msitools, and Python's msilib
- **Automatic Fallback**: Tries multiple extraction methods if one fails
- **MSI Properties**: Extracts ProductName, Version, Manufacturer, etc.
- **Caching**: Caches extractions to avoid redundant work

## Usage

```python
from intellicrack.utils.extraction import MSIExtractor

# Create extractor instance
extractor = MSIExtractor()

# Validate MSI file
is_valid, error = extractor.validate_msi("path/to/installer.msi")

# Extract MSI contents
if is_valid:
    result = extractor.extract("path/to/installer.msi")
    
    if result['success']:
        print(f"Extracted {result['file_count']} files")
        print(f"Output directory: {result['output_dir']}")
        
        # Find main executable
        main_exe = extractor.find_main_executable(result['extracted_files'])
        if main_exe:
            print(f"Main executable: {main_exe['filename']}")

# Clean up when done
extractor.cleanup()
```

## Extraction Methods

1. **msiexec** (Windows only) - Administrative install
2. **lessmsi** - Lightweight MSI extractor tool
3. **7-Zip** - Universal archive extractor
4. **msitools** (Linux/Unix) - Open source MSI tools
5. **Python msilib** (Windows only) - Built-in Python library

---

# DEB Extraction Module

## Features

- **Multiple Extraction Methods**: Supports dpkg-deb, ar, 7-Zip, and pure Python
- **Control File Parsing**: Extracts package metadata from control files
- **Maintainer Script Detection**: Identifies pre/post install scripts
- **Dependency Analysis**: Extracts package dependencies
- **Security Analysis**: Identifies SUID/SGID binaries and sensitive file locations

## Usage

```python
from intellicrack.utils.extraction import DEBExtractor

# Create extractor instance
extractor = DEBExtractor()

# Validate DEB file
is_valid, error = extractor.validate_deb("path/to/package.deb")

# Extract DEB contents
if is_valid:
    result = extractor.extract("path/to/package.deb")
    
    if result['success']:
        print(f"Extracted {result['file_count']} files")
        print(f"Package: {result['metadata']['control'].get('Package')}")
        print(f"Version: {result['metadata']['control'].get('Version')}")
        
        # Find main executable
        main_exe = extractor.find_main_executable(
            result['extracted_files'], 
            result['metadata']
        )
        if main_exe:
            print(f"Main executable: {main_exe['filename']}")

# Clean up when done
extractor.cleanup()
```

## Extraction Methods

1. **dpkg-deb** (Debian/Ubuntu) - Native DEB extraction tool
2. **ar** (Unix/Linux) - Archive extraction command
3. **Python ar parser** - Pure Python implementation
4. **7-Zip** - Universal archive extractor

## DEB Structure

DEB files are ar archives containing:
- **control.tar.***: Package metadata and maintainer scripts
- **data.tar.***: Actual package files
- **debian-binary**: Format version file

## Metadata Extraction

The DEB extractor parses:
- **Control file**: Package name, version, architecture, dependencies
- **Maintainer scripts**: preinst, postinst, prerm, postrm
- **MD5 checksums**: File integrity verification
- **Configuration files**: List of config files

---

# DMG Extraction Module

## Features

- **Multiple Extraction Methods**: Supports hdiutil, 7-Zip, dmg2img, and pure Python parser
- **App Bundle Analysis**: Parses .app bundles and extracts Info.plist metadata
- **Mach-O Detection**: Identifies macOS binaries by magic bytes
- **Cross-Platform Support**: Works on Windows/Linux for analyzing macOS software
- **Format Detection**: Handles UDIF, encrypted, compressed, and sparse bundle formats

## Usage

```python
from intellicrack.utils.extraction import DMGExtractor

# Create extractor instance
extractor = DMGExtractor()

# Validate DMG file
is_valid, error = extractor.validate_dmg("path/to/application.dmg")

# Extract DMG contents
if is_valid:
    result = extractor.extract("path/to/application.dmg")
    
    if result['success']:
        print(f"Extracted {result['file_count']} files")
        print(f"DMG format: {result['metadata']['format']}")
        
        # Analyze app bundles
        for app in result['app_bundles']:
            print(f"App: {app['name']}")
            print(f"Bundle ID: {app['bundle_id']}")
            print(f"Version: {app['version']}")
        
        # Find main executable
        main_exe = extractor.find_main_executable(
            result['extracted_files'],
            result['app_bundles']
        )
        if main_exe:
            print(f"Main executable: {main_exe['filename']}")

# Clean up when done
extractor.cleanup()
```

## Extraction Methods

1. **hdiutil** (macOS only) - Native DMG mounting tool
2. **7-Zip** - Universal archive extractor with DMG support
3. **dmg2img** (Linux/Unix) - Converts DMG to mountable format
4. **Python parser** - Pure Python fallback for simple DMGs

## DMG Structure

DMG files can contain:
- **HFS+ filesystem**: Traditional macOS filesystem
- **APFS filesystem**: Modern macOS filesystem
- **Hybrid formats**: ISO/HFS+ hybrid images
- **UDIF format**: Universal Disk Image Format with koly trailer

## App Bundle Analysis

The DMG extractor analyzes .app bundles:
- **Info.plist**: Bundle ID, version, executable name
- **Frameworks**: Embedded frameworks and libraries
- **Plugins**: Bundle plugins and extensions
- **Resources**: Resource file counts
- **Executable**: Main Mach-O binary location

---

## File Categories

Both extractors categorize files as:

### MSI Categories
- **executable**: .exe, .dll, .sys, .ocx, .scr, .cpl
- **configuration**: .xml, .ini, .config, .json, .yaml, .yml
- **script**: .ps1, .bat, .cmd, .vbs, .js, .py
- **other**: All other file types

### DEB Categories
- **executable**: Files in bin/, sbin/, or with execute permissions
- **library**: .so, .ko, .a files
- **configuration**: Files in etc/ or with config extensions
- **script**: .sh, .py, .pl, .rb, .lua files
- **documentation**: Files in doc/, man/, info/ directories
- **other**: All other file types

### DMG Categories
- **application_bundle**: .app directories (macOS applications)
- **macho_executable**: Mach-O binaries identified by magic bytes
- **executable**: .dylib, .framework, .bundle, .plugin files
- **configuration**: .plist, .xml, .json configuration files
- **interface**: .nib, .xib, .storyboard interface files
- **localization**: .strings, .lproj localization files
- **resource**: All other resource files

## Integration Example

```python
from intellicrack.utils.extraction import MSIExtractor, DEBExtractor, DMGExtractor
from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer

def analyze_package(package_path):
    """Extract and analyze a software package."""
    path = Path(package_path)
    
    # Choose appropriate extractor
    if path.suffix.lower() in ['.msi', '.msp', '.msm']:
        extractor = MSIExtractor()
        result = extractor.extract(package_path)
    elif path.suffix.lower() in ['.deb', '.udeb']:
        extractor = DEBExtractor()
        result = extractor.extract(package_path)
    elif path.suffix.lower() in ['.dmg', '.smi', '.img', '.sparseimage']:
        extractor = DMGExtractor()
        result = extractor.extract(package_path)
    else:
        print(f"Unsupported package format: {path.suffix}")
        return
    
    if result['success']:
        # Find and analyze main executable
        main_exe = extractor.find_main_executable(
            result['extracted_files'],
            result.get('app_bundles', []) if hasattr(extractor, 'find_main_executable') else result.get('metadata', {})
        )
        
        if main_exe:
            analyzer = MultiFormatBinaryAnalyzer()
            analysis = analyzer.analyze_binary(main_exe['full_path'])
            print(f"Binary analysis: {analysis}")
    
    # Cleanup
    extractor.cleanup()
```

## Requirements

### Windows
- MSI: No additional requirements (uses built-in tools)
- DEB: 7-Zip recommended for extraction support

### Linux/Unix
- MSI: Install msitools (`apt-get install msitools`)
- DEB: dpkg-deb usually pre-installed, ar available in binutils

### macOS/Cross-platform
- DMG: hdiutil (macOS), 7-Zip, dmg2img (Linux), Python parser

### Cross-platform Tools
- 7-Zip: Available on all platforms, supports MSI, DEB, and DMG
- Python: Pure Python fallbacks for all formats

## Error Handling

Both modules handle:
- Invalid package signatures
- Corrupted package files
- Missing extraction tools
- Insufficient permissions
- Disk space issues

## Performance Considerations

- Extraction results can be cached
- Large packages may require significant disk space
- Always call cleanup() to free disk space
- Consider using output_dir parameter for persistent extraction

## Security Notes

- Package files can contain scripts and executables
- Extract only trusted packages
- Review maintainer scripts before installation
- Check for SUID/SGID binaries in extracted files
- Validate file paths to prevent directory traversal