#Requires -Version 5.1
<#
.SYNOPSIS
    Intellicrack Installation Script
.DESCRIPTION
    Automated installation script for Intellicrack binary analysis platform.
    Installs all 336+ dependencies from pyproject.toml using pixi.
.PARAMETER SkipXPU
    Skip Intel XPU support installation
.PARAMETER Dev
    Install development dependencies
.EXAMPLE
    .\install.ps1
    .\install.ps1 -Dev
#>

param(
    [switch]$SkipXPU,
    [switch]$Dev
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Color output functions
function Write-ColorOutput {
    param([string]$Message, [string]$Color = 'White')
    Write-Host $Message -ForegroundColor $Color
}

function Write-Step {
    param([string]$Message)
    Write-ColorOutput "`n▶ $Message" 'Cyan'
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "✓ $Message" 'Green'
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "⚠ $Message" 'Yellow'
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "✗ $Message" 'Red'
}

# Banner
Write-ColorOutput @"

╔══════════════════════════════════════════════════════════════╗
║           INTELLICRACK INSTALLATION SCRIPT                   ║
║         Advanced Binary Analysis Platform                    ║
║              Version: 2025.1.0                              ║
╚══════════════════════════════════════════════════════════════╝
"@ 'Magenta'

# Step 1: Verify Pixi installation
Write-Step "[1/4] Verifying Pixi installation..."

$pixiCmd = Get-Command pixi -ErrorAction SilentlyContinue
if (-not $pixiCmd) {
    Write-Error "Pixi not found!"
    Write-ColorOutput @"

Please install Pixi from: https://pixi.sh/latest/

Then run this script again.
"@ 'Yellow'
    exit 1
}

Write-Success "Found Pixi: $($pixiCmd.Source)"

# Step 2: Install Intellicrack and all dependencies
Write-Step "[2/4] Installing Intellicrack (336+ packages)..."
Write-ColorOutput "This may take 10-20 minutes depending on your connection..." 'Gray'

$startTime = Get-Date

try {
    pixi install
    if ($Dev) {
        pixi install --dev
    }

    $duration = (Get-Date) - $startTime
    Write-Success "All packages installed successfully in $([math]::Round($duration.TotalMinutes, 1)) minutes"
}
catch {
    Write-Error "Installation failed: $_"
    Write-ColorOutput @"

Troubleshooting tips:
1. Ensure you have stable internet connection
2. Try clearing pixi cache: pixi cache clean
3. Check available disk space (20GB+ recommended)
"@ 'Yellow'
    exit 1
}

# Step 3: Optional Intel XPU support
if (-not $SkipXPU) {
    Write-Step "[3/4] Installing Intel XPU support (optional)..."

    $installXPU = Read-Host "Install Intel GPU acceleration support? (y/N)"
    if ($installXPU -eq 'y') {
        try {
            pixi run pip install torch==2.5.0 torchvision==0.20.0 torchaudio==2.5.0 --index-url https://download.pytorch.org/whl/xpu
            pixi run pip install intel-extension-for-pytorch==2.5.0+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
            Write-Success "Intel XPU support installed"
        }
        catch {
            Write-Warning "XPU installation failed - continuing without GPU acceleration"
        }
    }
} else {
    Write-ColorOutput "[3/4] Skipping Intel XPU support" 'Gray'
}

# Step 4: Verification
Write-Step "[4/4] Verifying installation..."

pixi run python -c "import intellicrack; print(f'Intellicrack version: {intellicrack.__version__}')"
pixi run python -m pip check

# Final instructions
Write-ColorOutput @"

╔══════════════════════════════════════════════════════════════╗
║              INSTALLATION COMPLETE!                          ║
╚══════════════════════════════════════════════════════════════╝
"@ 'Green'

Write-ColorOutput @"

To start using Intellicrack:
1. Activate environment: pixi shell
2. Launch GUI: pixi run start
3. Or use CLI: pixi run intellicrack --help

"@ 'Cyan'

if ($Dev) {
    Write-ColorOutput @"
Development tools installed:
- Pre-commit hooks: pixi run pre-commit install
- Run tests: pixi run pytest
- Format code: pixi run ruff format intellicrack/
- Lint: pixi run ruff check intellicrack/
"@ 'Gray'
}

Write-ColorOutput "Documentation: https://github.com/Zachanardo/Intellicrack/wiki" 'Gray'
Write-ColorOutput "Report issues: https://github.com/Zachanardo/Intellicrack/issues" 'Gray'
