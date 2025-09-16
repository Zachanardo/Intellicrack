#Requires -Version 5.1
<#
.SYNOPSIS
    Intellicrack Installation Script
.DESCRIPTION
    Automated installation script for Intellicrack binary analysis platform.
    Installs all 336+ dependencies from pyproject.toml with optimizations for Windows.
.PARAMETER Environment
    Type of environment to create: 'venv' (default), 'mamba', or 'uv'
.PARAMETER PythonPath
    Path to Python 3.12 executable (auto-detected if not specified)
.PARAMETER SkipXPU
    Skip Intel XPU support installation
.PARAMETER Dev
    Install development dependencies
.EXAMPLE
    .\install.ps1
    .\install.ps1 -Environment mamba -Dev
#>

param(
    [ValidateSet('venv', 'mamba', 'uv')]
    [string]$Environment = 'venv',

    [string]$PythonPath = '',

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

# Step 1: Verify Python version
Write-Step "[1/6] Verifying Python installation..."

if (-not $PythonPath) {
    # Try to find Python 3.12
    $pythonCandidates = @(
        (Get-Command python -ErrorAction SilentlyContinue).Path,
        (Get-Command python3 -ErrorAction SilentlyContinue).Path,
        (Get-Command python3.12 -ErrorAction SilentlyContinue).Path,
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "C:\Python312\python.exe",
        "C:\Program Files\Python312\python.exe"
    )

    foreach ($candidate in $pythonCandidates) {
        if ($candidate -and (Test-Path $candidate)) {
            $version = & $candidate --version 2>&1
            if ($version -match "3\.12\.\d+") {
                $PythonPath = $candidate
                break
            }
        }
    }
}

if (-not $PythonPath -or -not (Test-Path $PythonPath)) {
    Write-Error "Python 3.12 not found!"
    Write-ColorOutput @"

Please install Python 3.12 from one of these sources:
1. Microsoft Store: winget install Python.Python.3.12
2. Python.org: https://www.python.org/downloads/release/python-3120/
3. Chocolatey: choco install python312

Then run this script again.
"@ 'Yellow'
    exit 1
}

$pythonVersion = & $PythonPath --version 2>&1
if ($pythonVersion -notmatch "3\.12\.\d+") {
    Write-Error "Python 3.12 required, but found: $pythonVersion"
    exit 1
}

Write-Success "Found Python: $pythonVersion at $PythonPath"

# Step 2: Check for Visual Studio Build Tools
Write-Step "[2/6] Checking for Visual Studio Build Tools..."

$vswhereCmd = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$hasBuildTools = $false

if (Test-Path $vswhereCmd) {
    $vsInstalls = & $vswhereCmd -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsInstalls) {
        $hasBuildTools = $true
        Write-Success "Visual Studio Build Tools found"
    }
}

if (-not $hasBuildTools) {
    Write-Warning "Visual Studio Build Tools not found - some packages may fail to compile"
    Write-ColorOutput "Install with: winget install Microsoft.VisualStudio.2022.BuildTools" 'Gray'
}

# Step 3: Create environment based on selected type
Write-Step "[3/6] Creating $Environment environment..."

$envPath = ""
$activateScript = ""

switch ($Environment) {
    'venv' {
        $envPath = ".\intellicrack_env"
        if (Test-Path $envPath) {
            Write-Warning "Environment already exists at $envPath"
            $response = Read-Host "Remove and recreate? (y/N)"
            if ($response -eq 'y') {
                Remove-Item -Recurse -Force $envPath
            }
        }

        & $PythonPath -m venv $envPath
        $activateScript = "$envPath\Scripts\Activate.ps1"
        Write-Success "Created virtual environment at $envPath"
    }

    'mamba' {
        # Check if mamba is installed
        $mambaCmd = Get-Command mamba -ErrorAction SilentlyContinue
        if (-not $mambaCmd) {
            Write-Error "Mamba not found! Install from: https://mamba.readthedocs.io"
            exit 1
        }

        Write-ColorOutput "Creating minimal mamba environment..." 'Gray'
        & mamba create -n intellicrack python=3.12 pip -y

        # Get mamba environment path
        $condaInfo = & mamba info --json | ConvertFrom-Json
        $envPath = $condaInfo.envs | Where-Object { $_ -match "intellicrack" } | Select-Object -First 1

        if (-not $envPath) {
            $envPath = "$($condaInfo.envs_dirs[0])\intellicrack"
        }

        Write-Success "Created mamba environment: intellicrack"
        Write-ColorOutput "Activate with: mamba activate intellicrack" 'Gray'
    }

    'uv' {
        # Check if uv is installed
        $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
        if (-not $uvCmd) {
            Write-ColorOutput "Installing uv package manager..." 'Gray'
            & $PythonPath -m pip install --quiet uv
        }

        $envPath = ".\venv"
        if (Test-Path $envPath) {
            Remove-Item -Recurse -Force $envPath
        }

        & uv venv --python 3.12
        $activateScript = "$envPath\Scripts\Activate.ps1"
        Write-Success "Created uv environment at $envPath"
    }
}

# Step 4: Upgrade pip and install build tools
Write-Step "[4/6] Upgrading pip and installing build tools..."

if ($Environment -eq 'mamba') {
    # For mamba, we need to use the environment's python
    $envPython = "$envPath\python.exe"
    if (-not (Test-Path $envPython)) {
        $envPython = "$envPath\Scripts\python.exe"
    }
    & $envPython -m pip install --upgrade --quiet pip setuptools wheel
} elseif ($Environment -eq 'uv') {
    & uv pip install --upgrade pip setuptools wheel
} else {
    # Activate venv and upgrade
    & $activateScript
    & python -m pip install --upgrade --quiet pip setuptools wheel
}

Write-Success "Build tools updated"

# Step 5: Install Intellicrack and all dependencies
Write-Step "[5/6] Installing Intellicrack (336+ packages)..."
Write-ColorOutput "This may take 10-20 minutes depending on your connection..." 'Gray'

$startTime = Get-Date

try {
    if ($Environment -eq 'mamba') {
        & $envPython -m pip install -e .
        if ($Dev) {
            & $envPython -m pip install -e .[dev]
        }
    } elseif ($Environment -eq 'uv') {
        & uv pip install -e .
        if ($Dev) {
            & uv pip install -e .[dev]
        }
    } else {
        & pip install -e .
        if ($Dev) {
            & pip install -e .[dev]
        }
    }

    $duration = (Get-Date) - $startTime
    Write-Success "All packages installed successfully in $([math]::Round($duration.TotalMinutes, 1)) minutes"
}
catch {
    Write-Error "Installation failed: $_"
    Write-ColorOutput @"

Troubleshooting tips:
1. Ensure you have stable internet connection
2. Try clearing pip cache: pip cache purge
3. Install Visual Studio Build Tools if compilation errors occur
4. Check available disk space (20GB+ recommended)
5. Try installing with --no-cache-dir flag
"@ 'Yellow'
    exit 1
}

# Step 6: Optional Intel XPU support
if (-not $SkipXPU) {
    Write-Step "[6/6] Installing Intel XPU support (optional)..."

    $installXPU = Read-Host "Install Intel GPU acceleration support? (y/N)"
    if ($installXPU -eq 'y') {
        try {
            if ($Environment -eq 'mamba') {
                & $envPython -m pip install torch==2.5.0 torchvision==0.20.0 torchaudio==2.5.0 --index-url https://download.pytorch.org/whl/xpu
                & $envPython -m pip install intel-extension-for-pytorch==2.5.0+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
            } elseif ($Environment -eq 'uv') {
                & uv pip install torch==2.5.0 torchvision==0.20.0 torchaudio==2.5.0 --index-url https://download.pytorch.org/whl/xpu
                & uv pip install intel-extension-for-pytorch==2.5.0+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
            } else {
                & pip install torch==2.5.0 torchvision==0.20.0 torchaudio==2.5.0 --index-url https://download.pytorch.org/whl/xpu
                & pip install intel-extension-for-pytorch==2.5.0+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
            }
            Write-Success "Intel XPU support installed"
        }
        catch {
            Write-Warning "XPU installation failed - continuing without GPU acceleration"
        }
    }
} else {
    Write-ColorOutput "[6/6] Skipping Intel XPU support" 'Gray'
}

# Verification
Write-Step "Verifying installation..."

$verifyScript = @"
import sys
print(f'Python: {sys.version}')

try:
    import intellicrack
    print(f'✓ Intellicrack {intellicrack.__version__} loaded')
except ImportError as e:
    print(f'✗ Intellicrack import failed: {e}')
    sys.exit(1)

# Check core dependencies
deps_status = []
critical_deps = [
    'frida', 'angr', 'capstone', 'keystone', 'unicorn',
    'pwntools', 'torch', 'tensorflow', 'transformers'
]

for dep in critical_deps:
    try:
        __import__(dep)
        deps_status.append(f'✓ {dep}')
    except ImportError:
        deps_status.append(f'✗ {dep} (missing)')

print('\nCore dependencies:')
for status in deps_status:
    print(f'  {status}')

# Check for conflicts
import subprocess
result = subprocess.run([sys.executable, '-m', 'pip', 'check'],
                       capture_output=True, text=True)
if result.returncode == 0:
    print('\n✓ No dependency conflicts detected')
else:
    print(f'\n⚠ Dependency conflicts:\n{result.stdout}')
"@

$tempVerifyFile = [System.IO.Path]::GetTempFileName() + ".py"
Set-Content -Path $tempVerifyFile -Value $verifyScript

try {
    if ($Environment -eq 'mamba') {
        & $envPython $tempVerifyFile
    } elseif ($Environment -eq 'uv') {
        & .\venv\Scripts\python.exe $tempVerifyFile
    } else {
        & python $tempVerifyFile
    }
}
finally {
    Remove-Item $tempVerifyFile -ErrorAction SilentlyContinue
}

# Final instructions
Write-ColorOutput @"

╔══════════════════════════════════════════════════════════════╗
║              INSTALLATION COMPLETE!                          ║
╚══════════════════════════════════════════════════════════════╝
"@ 'Green'

if ($Environment -eq 'mamba') {
    Write-ColorOutput @"

To start using Intellicrack:
1. Activate environment: mamba activate intellicrack
2. Launch GUI: python -m intellicrack.ui
3. Or use CLI: intellicrack --help

"@ 'Cyan'
} else {
    $activateCmd = if ($Environment -eq 'uv') { ".\venv\Scripts\Activate.ps1" } else { ".\intellicrack_env\Scripts\Activate.ps1" }
    Write-ColorOutput @"

To start using Intellicrack:
1. Activate environment: $activateCmd
2. Launch GUI: python -m intellicrack.ui
3. Or use CLI: intellicrack --help

"@ 'Cyan'
}

if ($Dev) {
    Write-ColorOutput @"
Development tools installed:
- Pre-commit hooks: pre-commit install
- Run tests: pytest
- Format code: black intellicrack/
- Lint: ruff check intellicrack/
"@ 'Gray'
}

Write-ColorOutput "Documentation: https://github.com/Zachanardo/Intellicrack/wiki" 'Gray'
Write-ColorOutput "Report issues: https://github.com/Zachanardo/Intellicrack/issues" 'Gray'
