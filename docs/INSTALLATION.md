# Intellicrack Installation Guide

## Prerequisites

### System Requirements
- **Operating System**: Windows 11
- **RAM**: 8GB minimum (16GB recommended for large binary analysis)
- **Disk Space**: 2GB for base installation, additional space for models and analysis data
- **GPU** (Optional): NVIDIA, AMD, or Intel GPU for acceleration features

### Required Software
- **Git**: For cloning the repository
- **Pixi**: For environment and dependency management

## Installation

Intellicrack uses **Pixi** to manage its environment and dependencies. This ensures a consistent and reproducible setup.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Zachanardo/Intellicrack.git
    cd Intellicrack
    ```

2.  **Install dependencies with Pixi:**
    ```bash
    pixi install
    ```

3.  **Activate the environment:**
    ```bash
    pixi shell
    ```

4.  **Launch Intellicrack:**
    ```bash
    pixi run start
    ```
    Alternatively, you can run the `RUN_INTELLICRACK.bat` script.

## Updating Intellicrack

To update your existing Intellicrack installation:

1.  **Pull the latest changes:**
    ```bash
    git pull
    ```

2.  **Update the environment:**
    ```bash
    pixi install
    ```

## Troubleshooting

- If you encounter any issues, please ensure you have the latest version of `pixi` installed.
- For further assistance, please open an issue on our [GitHub repository](https://github.com/Zachanardo/Intellicrack/issues).
