# Intellicrack Ghidra Scripts

This is the centralized location for ALL Ghidra scripts used by Intellicrack.

## Directory Structure

```
scripts/ghidra/
├── README.md                    # This file
├── community/                   # Community-contributed scripts directory
│   └── README.md               # Community scripts documentation
├── default/                     # Reserved for default scripts
├── examples/                    # Example scripts for learning
├── user/                        # User-added custom scripts
└── [script files]               # All Ghidra scripts (.java, .py)
    ├── AdvancedAnalysis.java
    ├── AntiAnalysisDetector.py
    ├── FindCryptoSignatures.java
    ├── LicensePatternScanner.java
    ├── NetworkAnalysis.java
    ├── QuickStringDump.java
    ├── SimpleStringExtractor.java
    └── FunctionLister.java
```

## Script Categories

- **Analysis**: Binary analysis and information extraction
- **Cryptography**: Cryptographic signature detection
- **License**: License and protection detection
- **Network**: Network communication analysis
- **Protection**: Anti-analysis and protection detection
- **Strings**: String extraction and analysis
- **Vulnerability**: Vulnerability detection
- **Examples**: Learning examples for script development

## Using Scripts

1. Click "Run Ghidra Headless Analysis" in Intellicrack
2. The script selector dialog will show all available scripts
3. Select a script and click "Select" (or use default)
4. Ghidra will run the selected script on your binary

## Adding Custom Scripts

### Method 1: Through UI

1. In the script selector, click "Add Script..."
2. Browse to your script file
3. It will be copied to the `user/` directory

### Method 2: Manual

1. Place your script in `ghidra_scripts/user/`
2. Ensure it has proper metadata (see below)
3. Click "Refresh" in the script selector

## Script Metadata

Include these tags in your script comments:

### Java Script Comments

```java
/**
 * Your Script Title
 *
 * @description Brief description of what the script does
 * @author Your Name
 * @category Category Name (e.g., Analysis, Protection)
 * @version 1.0
 * @tags comma,separated,tags
 */
```

### Python Script Comments

```python
"""
Your Script Title

Brief description of what the script does

@author Your Name
@category Category Name
@version 1.0
@tags comma,separated,tags
"""
```

## Script Requirements

### Java Script Requirements

- Must extend `GhidraScript`
- Must implement `public void run() throws Exception`
- Use Ghidra API for program analysis

### Python Script Requirements

- Must be compatible with Ghidra's Jython interpreter
- Import Ghidra modules as needed
- Follow Ghidra's Python scripting conventions

## Important Notes

1. **Centralized Location**: This is the ONLY location Intellicrack looks for Ghidra scripts
2. **Automatic Discovery**: Scripts are automatically found when you use the script selector
3. **Validation**: Only valid Ghidra scripts can be selected and run
4. **Temporary Execution**: Scripts are copied to a temp directory during execution

## Troubleshooting

- **Script Not Appearing**: Ensure it has valid metadata and structure
- **Script Fails Validation**: Check that it extends GhidraScript (Java) or follows Python conventions
- **Script Not Running**: Check Ghidra path in Settings and ensure script has no syntax errors

## Contributing Scripts

To share your scripts with the Intellicrack community:

1. Ensure your script is well-documented
2. Test it thoroughly on various binaries
3. Consider submitting it to the Intellicrack project
