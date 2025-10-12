# Getting Started with Intellicrack

## Prerequisites

Before getting started with Intellicrack, ensure you have the following:

- **Python 3.8 or higher** installed on your system
- **Git** for cloning the repository (optional)
- **Qt6** for the graphical interface (will be installed via pip)

## Installation

1. **Clone or download the repository:**
   ```bash
   git clone https://github.com/your-repo/intellicrack.git
   cd intellicrack
   ```

2. **Install core dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

   If you don't have a `requirements.txt` file, install the core dependencies manually:
   ```bash
   pip install psutil requests pefile capstone keystone unicorn lief yara cryptography
   ```

3. **Optional: Install GUI dependencies:**
   ```bash
   pip install PyQt6
   ```

4. **Optional: Install additional analysis tools:**
   ```bash
   pip install numpy scikit-learn matplotlib networkx frida angr
   ```

## First Launch

1. **Navigate to the project directory:**
   ```bash
   cd /path/to/intellicrack
   ```

2. **Run Intellicrack:**
   ```bash
   python main.py
   ```

3. **Initial Setup:**
   - On first launch, Intellicrack will perform startup checks
   - The GUI will open if PyQt6 is available
   - If GUI is not available, it will run in CLI mode

## Basic Usage

### Loading a Binary

1. Open Intellicrack
2. Use the "Open File" menu or drag-and-drop a binary file
3. The file will be loaded into the analysis workspace

### Performing Analysis

1. Navigate to the Analysis tab
2. Select the type of analysis you want to perform:
   - Static analysis
   - Dynamic analysis (requires Frida)
   - Protection detection
   - AI-assisted analysis

### Viewing Results

- Analysis results are displayed in the main workspace
- Use the tabs to switch between different views:
  - Dashboard: Overview of analysis results
  - Analysis: Detailed analysis output
  - Hex View: Raw binary data
  - Tools: Additional utilities

## Next Steps

- Explore the [Installation Guide](../installation/setup.md) for detailed setup instructions
- Read the [Architecture Overview](../developer-guide/architecture.md) to understand how Intellicrack works
- Check the [FAQ](../faq.md) for common questions and troubleshooting

## Troubleshooting

### Common Issues

1. **Import Errors:**
   - Ensure all dependencies are installed
   - Try reinstalling with `pip install --force-reinstall <package>`

2. **GUI Won't Start:**
   - Check that PyQt6 is installed
   - On Linux, ensure you have a display server running
   - On Windows, try running with administrator privileges

3. **Analysis Fails:**
   - Verify the binary file is valid and not corrupted
   - Check file permissions
   - Ensure you have necessary system libraries installed

### Getting Help

- Check the [FAQ](../faq.md) for common solutions
- Review the logs in `logs/` for detailed error information
- Ensure your system meets the minimum requirements

## Configuration

Intellicrack can be configured through the Settings tab or by modifying configuration files in the `utils/config.py` directory. Common settings include:

- Logging levels
- Analysis timeout settings
- UI preferences
- Plugin configurations

For advanced configuration options, refer to the developer documentation.
