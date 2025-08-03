# Protection Database System

A comprehensive protection detection and analysis system for the Intellicrack security research framework.

## Overview

The Protection Database System provides advanced detection capabilities for various software protection schemes, including packers, DRM systems, code protection, anti-debugging, and obfuscation techniques. It integrates seamlessly with the existing binary analysis pipeline to enhance security research capabilities.

## Features

### Core Components

- **ProtectionSignatureDatabase**: Manages protection signatures with JSON-based storage
- **AdvancedPatternMatcher**: High-performance pattern matching with confidence scoring
- **ProtectionDatabaseManager**: Centralized management with caching and performance optimization
- **ProtectionPatternEngine**: Main engine integrating multiple detection methods
- **DatabaseUpdater**: Version control and automated signature updates
- **ProtectionAwareBinaryAnalyzer**: Enhanced binary analyzer with protection detection

### Detection Capabilities

- **Packer Detection**: UPX, generic packers, compression analysis
- **Code Protection**: Themida, VMProtect, Enigma, code virtualization
- **DRM Systems**: Denuvo Anti-Tamper, SafeDisc, SecuROM, licensing schemes
- **Anti-Analysis**: Anti-debugging, anti-VM, timing attacks, obfuscation
- **Heuristic Analysis**: High-entropy detection, suspicious imports, behavioral patterns

### Advanced Features

- **Multi-Method Detection**: Database signatures + YARA rules + heuristics
- **Confidence Scoring**: Sophisticated scoring with false positive reduction
- **Performance Optimization**: Caching, parallel processing, optimized lookups
- **Integration Ready**: Seamless integration with existing analysis components
- **Extensible**: Easy addition of custom signatures and detection rules

## Architecture

```
Protection Database System
├── Signature Database (JSON-based storage)
├── Pattern Matcher (High-performance matching)
├── Database Manager (Caching & optimization)
├── Pattern Engine (Multi-method detection)
├── Database Updater (Version control)
└── Protection Analyzer (Integration layer)
```

## Supported Protection Schemes

### Packers
- **UPX**: Ultimate Packer for eXecutables
- **Generic Packers**: Heuristic-based detection
- **Compression**: High-entropy content analysis

### Code Protection
- **Themida**: Advanced software protection by Oreans Technologies
- **VMProtect**: Code virtualization and licensing protection
- **Custom Protection**: User-defined protection schemes

### DRM Systems
- **Denuvo Anti-Tamper**: Advanced game copy protection
- **SafeDisc**: Legacy CD-based copy protection
- **SecuROM**: Digital rights management system

### Anti-Analysis
- **Anti-Debug**: Debugger detection and evasion
- **Anti-VM**: Virtual machine detection
- **Obfuscation**: Code obfuscation techniques

## Usage Examples

### Basic Protection Detection

```python
from intellicrack.core.protection_database import ProtectionPatternEngine

# Initialize the pattern engine
engine = ProtectionPatternEngine()

# Analyze a binary file
result = engine.analyze_file("sample.exe")

if result.has_protections:
    print(f"Detected protections: {result.combined_detections}")
    print(f"Confidence scores: {result.confidence_scores}")
```

### Enhanced Binary Analysis

```python
from intellicrack.core.analysis.protection_analyzer import ProtectionAwareBinaryAnalyzer

# Initialize the analyzer
analyzer = ProtectionAwareBinaryAnalyzer()

# Perform comprehensive analysis
results = analyzer.analyze("sample.exe", enable_deep_scan=True)

# Check protection analysis
protection_info = results['protection_analysis']
if protection_info['success']:
    detections = protection_info['detections']
    print(f"Found {detections['total_found']} protection schemes")
    
    # Get recommendations
    recommendations = protection_info['recommendations']
    for rec in recommendations:
        print(f"- {rec['description']}")
```

### Database Management

```python
from intellicrack.core.protection_database import ProtectionDatabaseManager

# Initialize database manager
manager = ProtectionDatabaseManager()

# Search for protections
upx_protections = manager.search_protections("UPX")
print(f"Found {len(upx_protections)} UPX-related signatures")

# Get database statistics
stats = manager.get_database_statistics()
print(f"Total signatures: {stats['database']['total_signatures']}")
```

## Configuration

### Engine Configuration

```python
config = {
    'use_database': True,
    'use_yara': True,
    'min_confidence': 0.5,
    'enable_heuristics': True,
    'enable_caching': True,
    'max_file_size': 100 * 1024 * 1024  # 100MB
}

engine.update_configuration(config)
```

### Database Configuration

```python
db_config = {
    'enable_caching': True,
    'cache_size': 1000,
    'enable_parallel_scanning': True,
    'scan_timeout': 30
}

manager.update_configuration(db_config)
```

## Database Structure

### Signature Format

```json
{
  "id": "protection_id",
  "name": "Protection Name",
  "protection_type": "packer|drm|code_protection|anti_debug",
  "architecture": "x86|x64|any",
  "confidence": 0.9,
  "description": "Description of the protection",
  "binary_signatures": [
    {
      "name": "Signature Name",
      "pattern": "hex_pattern",
      "mask": "optional_mask",
      "description": "Pattern description"
    }
  ],
  "string_signatures": [
    {
      "name": "String Name", 
      "pattern": "search_pattern",
      "match_type": "exact|regex|wildcards",
      "case_sensitive": false
    }
  ],
  "import_signatures": [
    {
      "name": "Import Name",
      "dll_name": "target_dll",
      "function_names": ["api1", "api2"],
      "min_functions": 2
    }
  ],
  "section_signatures": [
    {
      "name": "Section Name",
      "section_name": ".section",
      "min_entropy": 7.0,
      "characteristics": 0x60000020
    }
  ]
}
```

### Directory Structure

```
databases/
├── packers/           # Packer signatures
├── drm/              # DRM system signatures  
├── code_protection/  # Code protection signatures
├── anti_debug/       # Anti-debugging signatures
├── anti_vm/          # Anti-VM signatures
├── obfuscation/      # Obfuscation signatures
├── licensing/        # Licensing system signatures
├── integrity_check/  # Integrity check signatures
├── custom/           # Custom signatures
└── version.json      # Database version info
```

## Performance

### Optimization Features

- **Signature Indexing**: Fast lookup by protection type
- **Caching System**: Results and pattern caching
- **Parallel Processing**: Multi-threaded file scanning
- **Memory Optimization**: Efficient pattern storage
- **False Positive Reduction**: Advanced confidence scoring

### Benchmarks

- **Signature Loading**: ~100ms for complete database
- **Single File Scan**: ~10-50ms depending on file size
- **Pattern Matching**: ~1-5ms per signature
- **Cache Hit Rate**: >90% for repeated scans

## Integration

### With Existing Components

The protection database integrates with:

- **Binary Analyzer**: Enhanced analysis with protection detection
- **YARA Engine**: Combined pattern matching capabilities  
- **Radare2**: Signature-based analysis enhancement
- **Dynamic Analyzer**: Protection-aware dynamic analysis
- **Report Generator**: Protection information in reports

### API Compatibility

All components provide consistent APIs for:
- Signature management
- Pattern matching
- Result formatting
- Configuration management
- Performance monitoring

## Maintenance

### Adding New Signatures

1. Create signature JSON file in appropriate directory
2. Use DatabaseUpdater to install and validate
3. Test with known samples
4. Update database version

### Database Updates

```python
from intellicrack.core.protection_database import DatabaseUpdater

updater = DatabaseUpdater(database)

# Add new signature
updater.update_signature(new_signature)

# Create backup
backup_path = updater._create_backup()

# Verify integrity
integrity = updater.verify_database_integrity()
```

### Version Control

- Automatic version increments
- Backup creation before changes
- Integrity verification
- Rollback capabilities

## Security Considerations

- **Signature Validation**: All signatures are validated before use
- **Safe Pattern Matching**: Protected against malicious patterns
- **Resource Limits**: File size and timeout protections
- **Error Handling**: Graceful degradation on failures

## Future Enhancements

- **Machine Learning**: AI-powered protection detection
- **Cloud Updates**: Automatic signature updates from cloud
- **Behavioral Analysis**: Runtime behavior correlation
- **Custom Rules**: User-defined detection rules
- **Plugin System**: Extensible detection modules

## License

This protection database system is part of Intellicrack and is licensed under the GNU General Public License v3.0.