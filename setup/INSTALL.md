# Intellicrack Installation Guide

## Overview

Intellicrack is an advanced binary analysis and security research platform
optimized for Windows systems. All dependencies are managed through `pixi`,
providing a unified installation experience with 336+ pre-configured packages
for comprehensive offensive security research.

## System Requirements

### Required

- **Windows 10/11** (primary platform, full compatibility)
- **Git** for repository cloning
- **Pixi**: For environment and dependency management
- **8GB+ RAM** recommended for analysis operations
- **20GB+ free disk space** for tools and cache

### Optional but Recommended

- **Intel GPU** for hardware acceleration (XPU support)
- **Visual Studio Build Tools 2022** for compiling native extensions
- **Windows Terminal** or **PowerShell 7+** for better CLI experience

## Installation

Intellicrack uses **Pixi** to manage its environment and dependencies. This
ensures a consistent and reproducible setup.

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Zachanardo/Intellicrack.git
    cd Intellicrack
    ```

2. **Install dependencies with Pixi:**

    ```bash
    pixi install
    ```

3. **Activate the environment:**

    ```bash
    pixi shell
    ```

4. **Launch Intellicrack:**
    ```bash
    pixi run start
    ```
    Alternatively, you can run the `RUN_INTELLICRACK.bat` script.

## Verifying Installation

```powershell
# Verify Intellicrack import
pixi run python -c "import intellicrack; print(intellicrack.__version__)"

# Check for dependency conflicts
pixi run pip check
```

## Updating Intellicrack

To update your existing Intellicrack installation:

1. **Pull the latest changes:**

    ```bash
    git pull
    ```

2. **Update the environment:**
    ```bash
    pixi install
    ```

## Troubleshooting

- If you encounter any issues, please ensure you have the latest version of
  `pixi` installed.
- For further assistance, please open an issue on our
  [GitHub repository](https://github.com/Zachanardo/Intellicrack/issues).
