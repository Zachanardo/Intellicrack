<#
.SYNOPSIS
    Intellicrack Complete Installer - Installs and configures everything automatically

.DESCRIPTION
    This script installs ALL dependencies for Intellicrack including:
    - Python 3.11 (if not present)
    - 100+ Python packages with GPU optimization
    - System tools (Ghidra, Radare2, etc.)
    - Visual C++ Build Tools
    - GPU-specific configurations (NVIDIA/AMD/Intel)
    - Complete environment setup

.PARAMETER SkipGPU
    Skip GPU detection and GPU-specific package installation

.PARAMETER SkipSystemTools
    Skip system tools installation (Ghidra, Radare2, etc.)

.EXAMPLE
    .\Install.ps1
    Run complete installation with all features

.EXAMPLE
    .\Install.ps1 -SkipSystemTools
    Install only Python and packages, skip system tools

.NOTES
    Run this script directly - it will auto-elevate to Administrator
    No need for batch file wrappers or manual elevation
#>

param(
    [switch]$SkipGPU = $false,
    [switch]$SkipSystemTools = $false,
    [switch]$Force = $false
)

# Self-elevate to Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Elevating to Administrator privileges..." -ForegroundColor Yellow
    # Pass along any parameters
    $params = @()
    if ($SkipGPU) { $params += '-SkipGPU' }
    if ($SkipSystemTools) { $params += '-SkipSystemTools' }
    if ($Force) { $params += '-Force' }
    
    $allArgs = @("-File", "`"$($MyInvocation.MyCommand.Path)`"") + $params
    Start-Process powershell -Verb runAs -ArgumentList $allArgs
    exit
}

# Set up console
$Host.UI.RawUI.WindowTitle = "Intellicrack Complete Installer (Administrator)"
$ErrorActionPreference = "Continue"
$ProgressPreference = 'SilentlyContinue'  # Speed up downloads

# Get Intellicrack paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$intellicrackRoot = $scriptDir
$logsDir = "C:\Intellicrack\logs"
$configDir = "C:\Intellicrack\config"
$toolsDir = "C:\Intellicrack\tools"

# Create log directory if needed
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}

# Set up logging
$logFile = Join-Path $logsDir "install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$transcript = Start-Transcript -Path $logFile -Append

# Global error counter
$script:TotalErrors = 0
$script:TotalWarnings = 0

# Color functions
function Write-Header {
    param([string]$Text)
    Write-Host "`n$("="*80)" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Yellow
    Write-Host "$("="*80)`n" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n[$Text]" -ForegroundColor Green
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-Error {
    param([string]$Text)
    Write-Host "[ERROR] $Text" -ForegroundColor Red
    $script:TotalErrors++
}

function Write-Warning {
    param([string]$Text)
    Write-Host "[WARNING] $Text" -ForegroundColor Yellow
    $script:TotalWarnings++
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $Text" -ForegroundColor Cyan
}

# Progress bar function
function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

# Download with progress and retry
function Download-WithProgress {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$DisplayName,
        [int]$MaxRetries = 3
    )
    
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            Write-Info "Downloading $DisplayName (Attempt $attempt/$MaxRetries)..."
            
            $ProgressPreference = 'Continue'
            Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
            $ProgressPreference = 'SilentlyContinue'
            
            if (Test-Path $OutputPath) {
                $fileSize = (Get-Item $OutputPath).Length / 1MB
                Write-Success "$DisplayName downloaded successfully (${fileSize}MB)"
                return $true
            }
        }
        catch {
            Write-Warning "Download attempt $attempt failed: $_"
            if ($attempt -lt $MaxRetries) {
                Write-Info "Retrying in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }
    }
    
    Write-Error "Failed to download $DisplayName after $MaxRetries attempts"
    return $false
}

# GPU Detection Function
function Get-GPUInfo {
    Write-Step "Detecting GPU hardware"
    
    $gpuInfo = @{
        HasNVIDIA = $false
        HasAMD = $false
        HasIntel = $false
        NVIDIADevice = $null
        AMDDevice = $null
        IntelDevice = $null
        CUDACapable = $false
        CUDAVersion = $null
    }
    
    # Check for NVIDIA GPU
    $nvidiaGPU = Get-WmiObject Win32_VideoController | Where-Object {$_.Name -match "NVIDIA"}
    if ($nvidiaGPU) {
        $gpuInfo.HasNVIDIA = $true
        $gpuInfo.NVIDIADevice = $nvidiaGPU.Name
        Write-Success "Found NVIDIA GPU: $($nvidiaGPU.Name)"
        
        # Check CUDA capability
        if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
            $cudaVersion = & nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>$null
            if ($cudaVersion) {
                $gpuInfo.CUDACapable = $true
                $gpuInfo.CUDAVersion = $cudaVersion
                Write-Info "NVIDIA driver version: $cudaVersion"
            }
        }
    }
    
    # Check for AMD GPU
    $amdGPU = Get-WmiObject Win32_VideoController | Where-Object {$_.Name -match "AMD|Radeon"}
    if ($amdGPU) {
        $gpuInfo.HasAMD = $true
        $gpuInfo.AMDDevice = $amdGPU.Name
        Write-Success "Found AMD GPU: $($amdGPU.Name)"
    }
    
    # Check for Intel GPU
    $intelGPU = Get-WmiObject Win32_VideoController | Where-Object {$_.Name -match "Intel"}
    if ($intelGPU) {
        $gpuInfo.HasIntel = $true
        $gpuInfo.IntelDevice = $intelGPU.Name
        Write-Success "Found Intel GPU: $($intelGPU.Name)"
    }
    
    if (-not $gpuInfo.HasNVIDIA -and -not $gpuInfo.HasAMD -and -not $gpuInfo.HasIntel) {
        Write-Warning "No dedicated GPU detected. Will use CPU-only configurations."
    }
    
    return $gpuInfo
}

# Create required directories
function Initialize-Directories {
    Write-Step "Creating Intellicrack directories"
    
    $directories = @(
        "C:\Intellicrack",
        "C:\Intellicrack\logs",
        "C:\Intellicrack\config",
        "C:\Intellicrack\tools",
        "C:\Intellicrack\data",
        "C:\Intellicrack\data\signatures",
        "C:\Intellicrack\data\templates",
        "C:\Intellicrack\reports",
        "C:\Intellicrack\plugins",
        "C:\Intellicrack\models",
        "C:\Intellicrack\cache"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Success "Created $dir"
        }
    }
}

# Install NVIDIA CUDA and cuDNN
function Install-NVIDIATools {
    param($gpuInfo)
    
    if (-not $gpuInfo.HasNVIDIA) { return }
    
    Write-Step "Installing NVIDIA CUDA toolkit and cuDNN"
    
    # Check if CUDA is already installed
    $cudaInstalled = Test-Path "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA"
    
    if (-not $cudaInstalled) {
        Write-Info "Downloading CUDA 11.8 (compatible with PyTorch)"
        $cudaUrl = "https://developer.download.nvidia.com/compute/cuda/11.8.0/local_installers/cuda_11.8.0_522.06_windows.exe"
        $cudaInstaller = "$env:TEMP\cuda_installer.exe"
        
        try {
            Invoke-WebRequest -Uri $cudaUrl -OutFile $cudaInstaller -UseBasicParsing
            Write-Info "Installing CUDA (this may take 10-15 minutes)..."
            Start-Process -FilePath $cudaInstaller -ArgumentList "-s" -Wait
            Write-Success "CUDA installed"
        }
        catch {
            Write-Warning "Failed to install CUDA: $_"
        }
        finally {
            if (Test-Path $cudaInstaller) { Remove-Item $cudaInstaller -Force }
        }
    }
    else {
        Write-Success "CUDA already installed"
    }
    
    # Set CUDA environment variables
    [Environment]::SetEnvironmentVariable("CUDA_PATH", "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8", "Machine")
    $cudaBin = "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8\bin"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$cudaBin*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$cudaBin", "Machine")
    }
    
    # Install cuDNN
    Write-Info "Note: cuDNN requires manual download from NVIDIA (login required)"
    Write-Info "Download from: https://developer.nvidia.com/cudnn"
}

# Install AMD ROCm
function Install-AMDTools {
    param($gpuInfo)
    
    if (-not $gpuInfo.HasAMD) { return }
    
    Write-Step "Configuring AMD GPU support"
    Write-Warning "ROCm is primarily supported on Linux. Installing OpenCL for Windows instead."
    
    # AMD GPUs can use OpenCL on Windows
    Write-Info "AMD GPUs will use OpenCL acceleration via pyopencl"
}

# Install Intel GPU tools
function Install-IntelTools {
    param($gpuInfo)
    
    if (-not $gpuInfo.HasIntel) { return }
    
    Write-Step "Installing Intel GPU tools"
    
    # Install Intel Graphics Driver if needed
    Write-Info "Checking Intel GPU drivers..."
    
    # Intel Extension for PyTorch will be installed via pip
    Write-Success "Intel GPU support will be configured via Python packages"
}

# Check network connectivity
function Test-NetworkConnection {
    Write-Step "Checking network connectivity"
    
    $testUrls = @(
        "https://www.google.com",
        "https://pypi.org",
        "https://github.com"
    )
    
    $hasInternet = $false
    foreach ($url in $testUrls) {
        try {
            $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                $hasInternet = $true
                break
            }
        }
        catch { }
    }
    
    if (-not $hasInternet) {
        Write-Error "No internet connection detected!"
        Write-Host "This installer requires internet access to download dependencies."
        exit 1
    }
    
    Write-Success "Network connection verified"
}

# Check for previous installation state
function Get-InstallationState {
    $stateFile = Join-Path $configDir "installation_state.json"
    if (Test-Path $stateFile) {
        try {
            $state = Get-Content $stateFile | ConvertFrom-Json
            return $state
        }
        catch {
            return $null
        }
    }
    return $null
}

# Save installation state
function Save-InstallationState {
    param($State)
    
    $stateFile = Join-Path $configDir "installation_state.json"
    $State | ConvertTo-Json -Depth 5 | Set-Content $stateFile
}

# Check system requirements
function Test-SystemRequirements {
    Write-Step "Checking system requirements"
    
    $issues = @()
    
    # Check Windows version
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [System.Version]$os.Version
    if ($osVersion.Major -lt 10) {
        $issues += "Windows 10 or higher required (found Windows $($osVersion.Major))"
    }
    
    # Check available disk space
    $drive = Get-PSDrive -Name C
    $freeSpaceGB = [Math]::Round($drive.Free / 1GB, 2)
    if ($freeSpaceGB -lt 5) {
        $issues += "At least 5GB free disk space required (found ${freeSpaceGB}GB)"
    }
    
    # Check RAM
    $totalRAM = [Math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    if ($totalRAM -lt 8) {
        Write-Warning "8GB RAM recommended (found ${totalRAM}GB). Installation may be slow."
    }
    
    # Check CPU cores
    $cpuCores = (Get-WmiObject -Class Win32_Processor).NumberOfLogicalProcessors
    Write-Info "Found $cpuCores CPU cores"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "PowerShell 5.0 or higher required"
    }
    
    if ($issues.Count -gt 0) {
        Write-Error "System requirements not met:"
        foreach ($issue in $issues) {
            Write-Error "  - $issue"
        }
        exit 1
    }
    
    Write-Success "System requirements verified"
    Write-Info "Free disk space: ${freeSpaceGB}GB"
    Write-Info "Total RAM: ${totalRAM}GB"
    Write-Info "PowerShell version: $($PSVersionTable.PSVersion)"
}

# Start installation
Clear-Host
Write-Header "INTELLICRACK COMPLETE INSTALLER WITH GPU SUPPORT"
Write-Host "This script will install ALL dependencies and configure GPU acceleration"
Write-Host "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# Check system requirements
Test-SystemRequirements

# Initialize directories
Initialize-Directories

# Check network
Test-NetworkConnection

# Check for previous installation
$previousState = Get-InstallationState
if ($previousState) {
    Write-Warning "Previous installation detected"
    Write-Host "Last run: $($previousState.LastRun)"
    Write-Host "Status: $($previousState.Status)"
    
    if ($previousState.Status -eq "Incomplete") {
        Write-Host "`nDo you want to resume the previous installation? (Y/N)" -ForegroundColor Yellow
        $resume = Read-Host
        if ($resume -eq 'Y' -or $resume -eq 'y') {
            Write-Info "Resuming from step: $($previousState.LastStep)"
        }
        else {
            Write-Info "Starting fresh installation"
            $previousState = $null
        }
    }
}

# Initialize installation state
$installState = @{
    StartTime = Get-Date
    LastRun = Get-Date
    Status = "InProgress"
    LastStep = ""
    CompletedSteps = @()
    PythonPath = ""
    Errors = @()
}

# Detect GPU
$gpuInfo = Get-GPUInfo

# Step 1: Install Python 3.11
Write-Step "STEP 1/10: Installing Python 3.11"

$python = $null
$pythonPaths = @(
    "C:\Python311\python.exe",
    "C:\Program Files\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
)

foreach ($path in $pythonPaths) {
    if (Test-Path $path) {
        $version = & $path --version 2>&1
        if ($version -match "3\.11") {
            $python = $path
            Write-Success "Found Python 3.11 at: $path"
            break
        }
    }
}

if (-not $python) {
    Write-Warning "No compatible Python found. Installing Python 3.11.9..."
    $pythonInstaller = "$env:TEMP\python-3.11.9-amd64.exe"
    $pythonUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    
    # Download Python with retry logic
    if (Download-WithProgress -Url $pythonUrl -OutputPath $pythonInstaller -DisplayName "Python 3.11.9") {
        try {
            Write-Info "Installing Python 3.11.9 (this may take a few minutes)..."
            $installArgs = @(
                "/quiet",
                "InstallAllUsers=1",
                "PrependPath=1", 
                "Include_test=0",
                "Include_pip=1",
                "Include_launcher=1",
                "InstallLauncherAllUsers=1",
                "TargetDir=C:\Python311"
            )
            
            $process = Start-Process -FilePath $pythonInstaller -ArgumentList $installArgs -Wait -PassThru
            
            if ($process.ExitCode -eq 0) {
                $python = "C:\Python311\python.exe"
                
                # Add to PATH
                $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
                if ($currentPath -notlike "*C:\Python311*") {
                    [Environment]::SetEnvironmentVariable("Path", "$currentPath;C:\Python311;C:\Python311\Scripts", "Machine")
                    $env:Path = "$currentPath;C:\Python311;C:\Python311\Scripts"
                }
                
                Write-Success "Python 3.11.9 installed successfully"
                $installState.PythonPath = $python
            }
            else {
                throw "Python installer returned exit code: $($process.ExitCode)"
            }
        }
        catch {
            Write-Error "Failed to install Python: $_"
            exit 1
        }
        finally {
            if (Test-Path $pythonInstaller) { Remove-Item $pythonInstaller -Force }
        }
    }
    else {
        Write-Error "Cannot proceed without Python. Please install Python 3.11 manually."
        exit 1
    }
}

# Step 2: Configure Python environment
Write-Step "STEP 2/10: Configuring Python environment"

[Environment]::SetEnvironmentVariable("PYTHONIOENCODING", "utf-8", "Machine")
[Environment]::SetEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1", "Machine")

& $python -m pip install --upgrade pip setuptools wheel build cython numpy
Write-Success "Python environment configured"

# Step 3: Install Visual C++ Build Tools
Write-Step "STEP 3/10: Installing Visual C++ Build Tools"

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsInstalls = & $vsWhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsInstalls) {
        Write-Success "Visual C++ Build Tools already installed"
    }
}
else {
    Write-Info "Installing Visual Studio Build Tools..."
    $vsUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
    $vsInstaller = "$env:TEMP\vs_buildtools.exe"
    
    try {
        Invoke-WebRequest -Uri $vsUrl -OutFile $vsInstaller -UseBasicParsing
        $vsArgs = "--quiet", "--wait", "--add", "Microsoft.VisualStudio.Workload.VCTools", "--includeRecommended"
        Start-Process -FilePath $vsInstaller -ArgumentList $vsArgs -Wait
        Write-Success "Visual C++ Build Tools installed"
    }
    catch {
        Write-Warning "Failed to install build tools: $_"
    }
    finally {
        if (Test-Path $vsInstaller) { Remove-Item $vsInstaller -Force }
    }
}

# Step 4: Install GPU-specific tools
if (-not $SkipGPU) {
    Write-Step "STEP 4/10: Installing GPU-specific tools"
    
    Install-NVIDIATools -gpuInfo $gpuInfo
    Install-AMDTools -gpuInfo $gpuInfo
    Install-IntelTools -gpuInfo $gpuInfo
}
else {
    Write-Step "STEP 4/10: Skipping GPU tools (--SkipGPU specified)"
}

# Step 5: Install base Python packages
Write-Step "STEP 5/10: Installing Python packages"

$requirementsFile = Join-Path $scriptDir "requirements.txt"
if (-not (Test-Path $requirementsFile)) {
    Write-Error "requirements.txt not found at: $requirementsFile"
    exit 1
}

# Function to check if package is installed
function Test-PythonPackage {
    param([string]$PackageName)
    $result = & $python -m pip show $PackageName 2>&1
    return $LASTEXITCODE -eq 0
}

# Read requirements and install only missing packages
Write-Info "Checking installed packages..."
$requirements = Get-Content $requirementsFile | Where-Object { $_ -and $_ -notmatch '^#' }
$totalPackages = $requirements.Count
$installedCount = 0
$toInstall = @()

foreach ($req in $requirements) {
    # Extract package name from requirement line
    $packageName = $req -split '[<>=!]' | Select-Object -First 1
    $packageName = $packageName.Trim()
    
    if ($packageName) {
        if (Test-PythonPackage -PackageName $packageName) {
            $installedCount++
            Write-Host "  [OK] $packageName already installed" -ForegroundColor DarkGray
        }
        else {
            $toInstall += $req
        }
    }
}

Write-Info "Found $installedCount/$totalPackages packages already installed"

if ($toInstall.Count -gt 0) {
    Write-Info "Installing $($toInstall.Count) missing packages..."
    
    # Create temporary requirements file with only missing packages
    $tempReq = "$env:TEMP\intellicrack_missing_reqs.txt"
    $toInstall | Set-Content $tempReq
    
    & $python -m pip install -r $tempReq --no-warn-script-location
    
    Remove-Item $tempReq -Force
}
else {
    Write-Success "All required packages already installed"
}

# Step 6: Install GPU-specific Python packages
Write-Step "STEP 6/10: Installing GPU-specific Python packages"

# Function to install package if not present
function Install-IfMissing {
    param(
        [string]$Package,
        [string]$IndexUrl = "",
        [string]$DisplayName = ""
    )
    
    if (-not $DisplayName) { $DisplayName = $Package }
    
    if (Test-PythonPackage -PackageName ($Package -split '==' | Select-Object -First 1)) {
        Write-Host "  [OK] $DisplayName already installed" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Installing $DisplayName..." -NoNewline
        if ($IndexUrl) {
            $result = & $python -m pip install $Package --index-url $IndexUrl --no-warn-script-location 2>&1
        }
        else {
            $result = & $python -m pip install $Package --no-warn-script-location 2>&1
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " [OK]" -ForegroundColor Green
        }
        else {
            Write-Host " [FAIL]" -ForegroundColor Red
        }
    }
}

if ($gpuInfo.HasNVIDIA) {
    Write-Info "Configuring NVIDIA GPU packages..."
    Install-IfMissing -Package "torch" -IndexUrl "https://download.pytorch.org/whl/cu118" -DisplayName "PyTorch (CUDA)"
    Install-IfMissing -Package "torchvision" -IndexUrl "https://download.pytorch.org/whl/cu118" -DisplayName "TorchVision (CUDA)"
    Install-IfMissing -Package "torchaudio" -IndexUrl "https://download.pytorch.org/whl/cu118" -DisplayName "TorchAudio (CUDA)"
    Install-IfMissing -Package "tensorflow==2.13.0" -DisplayName "TensorFlow (GPU)"
    Install-IfMissing -Package "pycuda" -DisplayName "PyCUDA"
    Install-IfMissing -Package "cupy-cuda11x" -DisplayName "CuPy"
}
elseif ($gpuInfo.HasIntel) {
    Write-Info "Configuring Intel GPU packages..."
    Install-IfMissing -Package "torch" -DisplayName "PyTorch"
    Install-IfMissing -Package "torchvision" -DisplayName "TorchVision"
    Install-IfMissing -Package "torchaudio" -DisplayName "TorchAudio"
    
    # Intel Extension for PyTorch often fails - try multiple approaches
    Write-Host "  Installing Intel Extension for PyTorch..." -NoNewline
    
    # Try stable version first
    $intelResult = & $python -m pip install intel-extension-for-pytorch==2.1.10+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/ --no-warn-script-location 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host " [OK]" -ForegroundColor Green
    }
    else {
        # Try without XPU suffix
        Write-Host " [RETRY]" -ForegroundColor Yellow
        $intelResult = & $python -m pip install intel-extension-for-pytorch --no-warn-script-location 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host " [OK]" -ForegroundColor Green
        }
        else {
            # Try CPU-only version
            Write-Host " [RETRY-CPU]" -ForegroundColor Yellow
            $intelResult = & $python -m pip install intel-extension-for-pytorch-cpu --no-warn-script-location 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host " [OK-CPU]" -ForegroundColor Green
            }
            else {
                Write-Host " [FAIL]" -ForegroundColor Red
                Write-Warning "Intel Extension failed - this is normal for:"
                Write-Warning "  - Non-Intel systems"
                Write-Warning "  - Older Intel GPUs"
                Write-Warning "  - Systems without Intel GPU drivers"
                Write-Info "Continuing with standard PyTorch (fully functional)"
            }
        }
    }
    
    Install-IfMissing -Package "openvino" -DisplayName "OpenVINO"
    Install-IfMissing -Package "openvino-dev" -DisplayName "OpenVINO Dev Tools"
    Install-IfMissing -Package "tensorflow-cpu" -DisplayName "TensorFlow (CPU)"
}
elseif ($gpuInfo.HasAMD) {
    Write-Info "Configuring AMD GPU packages..."
    Install-IfMissing -Package "torch" -IndexUrl "https://download.pytorch.org/whl/cpu" -DisplayName "PyTorch (CPU)"
    Install-IfMissing -Package "torchvision" -IndexUrl "https://download.pytorch.org/whl/cpu" -DisplayName "TorchVision (CPU)"
    Install-IfMissing -Package "torchaudio" -IndexUrl "https://download.pytorch.org/whl/cpu" -DisplayName "TorchAudio (CPU)"
    Install-IfMissing -Package "tensorflow-cpu" -DisplayName "TensorFlow (CPU)"
}
else {
    Write-Info "Configuring CPU-only packages..."
    Install-IfMissing -Package "torch" -IndexUrl "https://download.pytorch.org/whl/cpu" -DisplayName "PyTorch (CPU)"
    Install-IfMissing -Package "torchvision" -IndexUrl "https://download.pytorch.org/whl/cpu" -DisplayName "TorchVision (CPU)"
    Install-IfMissing -Package "torchaudio" -IndexUrl "https://download.pytorch.org/whl/cpu" -DisplayName "TorchAudio (CPU)"
    Install-IfMissing -Package "tensorflow-cpu" -DisplayName "TensorFlow (CPU)"
}

# Always check/install OpenCL for universal GPU support
Install-IfMissing -Package "pyopencl" -DisplayName "PyOpenCL"

# Step 7: Install additional analysis packages
Write-Step "STEP 7/10: Installing additional analysis packages"

$additionalPackages = @(
    "angr", "claripy", "z3-solver",
    "manticore",
    "qiling",
    "volatility3",
    "binwalk",
    "pypcap"  # Modern replacement for pcapy
)

foreach ($pkg in $additionalPackages) {
    Write-Host "Installing $pkg..." -NoNewline
    $result = & $python -m pip install $pkg 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host " [OK]" -ForegroundColor Green
    }
    else {
        Write-Host " [FAIL]" -ForegroundColor Red
    }
}

# Direct tool installation functions
function Install-GhidraDirect {
    Write-Info "Installing Ghidra directly..."
    
    # Check if already installed in tools folder
    $ghidraDir = "C:\Intellicrack\tools\ghidra"
    if (Test-Path $ghidraDir) {
        $existing = Get-ChildItem $ghidraDir -Directory | Where-Object { $_.Name -match "ghidra_" }
        if ($existing) {
            Write-Success "Ghidra already installed in tools folder"
            return
        }
    }
    
    # Download latest Ghidra
    $ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20241203.zip"
    $ghidraZip = "$env:TEMP\ghidra.zip"
    
    try {
        if (Download-WithProgress -Url $ghidraUrl -OutputPath $ghidraZip -DisplayName "Ghidra 11.3.2") {
            Write-Info "Extracting Ghidra to tools folder..."
            
            # Create tools directory if needed
            if (-not (Test-Path $ghidraDir)) {
                New-Item -ItemType Directory -Path $ghidraDir -Force | Out-Null
            }
            
            # Extract ZIP
            Expand-Archive -Path $ghidraZip -DestinationPath $ghidraDir -Force
            
            # Set environment variable
            $ghidraExtracted = Get-ChildItem $ghidraDir -Directory | Where-Object { $_.Name -match "ghidra_" } | Select-Object -First 1
            if ($ghidraExtracted) {
                [Environment]::SetEnvironmentVariable("GHIDRA_HOME", $ghidraExtracted.FullName, "Machine")
                Write-Success "Ghidra installed to: $($ghidraExtracted.FullName)"
            }
        }
    }
    catch {
        Write-Error "Failed to install Ghidra: $_"
    }
    finally {
        if (Test-Path $ghidraZip) { Remove-Item $ghidraZip -Force }
    }
}

function Install-Radare2Direct {
    Write-Info "Installing Radare2 directly..."
    
    # Check if already installed in tools folder
    $r2Dir = "C:\Intellicrack\tools\radare2"
    if (Test-Path "$r2Dir\bin\radare2.exe") {
        Write-Success "Radare2 already installed in tools folder"
        return
    }
    
    # Download latest Radare2 Windows build
    $r2Url = "https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-5.9.8-w64.zip"
    $r2Zip = "$env:TEMP\radare2.zip"
    
    try {
        if (Download-WithProgress -Url $r2Url -OutputPath $r2Zip -DisplayName "Radare2 5.9.8") {
            Write-Info "Extracting Radare2 to tools folder..."
            
            # Create tools directory if needed
            if (-not (Test-Path $r2Dir)) {
                New-Item -ItemType Directory -Path $r2Dir -Force | Out-Null
            }
            
            # Extract ZIP
            Expand-Archive -Path $r2Zip -DestinationPath "C:\Intellicrack\tools" -Force
            
            # Rename extracted folder to standardize path
            $extractedFolder = Get-ChildItem "C:\Intellicrack\tools" -Directory | Where-Object { $_.Name -match "radare2.*w64" } | Select-Object -First 1
            if ($extractedFolder -and $extractedFolder.Name -ne "radare2") {
                if (Test-Path $r2Dir) { Remove-Item $r2Dir -Recurse -Force }
                Rename-Item $extractedFolder.FullName $r2Dir
            }
            
            # Add to PATH
            $r2BinPath = "$r2Dir\bin"
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            if ($currentPath -notlike "*$r2BinPath*") {
                [Environment]::SetEnvironmentVariable("Path", "$currentPath;$r2BinPath", "Machine")
                [Environment]::SetEnvironmentVariable("R2_HOME", $r2Dir, "Machine")
            }
            
            Write-Success "Radare2 installed to: $r2Dir"
        }
    }
    catch {
        Write-Error "Failed to install Radare2: $_"
    }
    finally {
        if (Test-Path $r2Zip) { Remove-Item $r2Zip -Force }
    }
}

# Step 8: Install system tools
if (-not $SkipSystemTools) {
    Write-Step "STEP 8/10: Installing system tools"
    
    # Install Chocolatey if needed (only for remaining tools)
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Chocolatey package manager..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        Write-Success "Chocolatey installed"
    }
    else {
        Write-Success "Chocolatey already installed"
    }
    
    # Function to check if tool is installed
    function Test-SystemTool {
        param(
            [string]$ToolName,
            [string]$TestCommand = $null,
            [string]$TestPath = $null
        )
        
        # First check via Chocolatey
        $chocoList = choco list --local-only $ToolName 2>$null
        if ($chocoList -match $ToolName) {
            return $true
        }
        
        # Then check via command
        if ($TestCommand) {
            if (Get-Command $TestCommand -ErrorAction SilentlyContinue) {
                return $true
            }
        }
        
        # Finally check via path
        if ($TestPath -and (Test-Path $TestPath)) {
            return $true
        }
        
        return $false
    }
    
    # Install Ghidra directly (no Chocolatey needed)
    Install-GhidraDirect
    
    # Install Radare2 directly (no Chocolatey needed)
    Install-Radare2Direct
    
    # Define tools that still use Chocolatey (standard installers)
    $systemTools = @(
        @{name="wireshark"; description="Network analyzer (REQUIRED for pyshark)"; testPath="C:\Program Files\Wireshark"},
        @{name="docker-desktop"; description="Container platform (REQUIRED)"; testCommand="docker"},
        @{name="git"; description="Version control"; testCommand="git"},
        @{name="qemu"; description="QEMU emulator (REQUIRED)"; testCommand="qemu-system-x86_64"}
    )
    
    $installedCount = 0
    $toInstallCount = 0
    
    Write-Info "Checking installed system tools..."
    
    foreach ($tool in $systemTools) {
        $isInstalled = Test-SystemTool -ToolName $tool.name -TestCommand $tool.testCommand -TestPath $tool.testPath
        
        if ($isInstalled) {
            Write-Host "  [OK] $($tool.description) already installed" -ForegroundColor DarkGray
            $installedCount++
        }
        else {
            Write-Host "  Installing $($tool.description)..." -NoNewline
            $result = choco install $tool.name -y --no-progress --force 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host " [OK]" -ForegroundColor Green
                $toInstallCount++
            }
            else {
                Write-Host " [FAIL]" -ForegroundColor Red
            }
        }
    }
    
    Write-Info "System tools: $installedCount already installed, $toInstallCount newly installed"
    
    # Note: Removed unnecessary tool installations (Volatility3, MSYS2, etc.)
    # Intellicrack uses Python libraries for these functionalities
}
else {
    Write-Step "STEP 8/10: Skipping system tools (--SkipSystemTools specified)"
}

# Step 9: Configure Intellicrack
Write-Step "STEP 9/10: Configuring Intellicrack"

# Create comprehensive configuration
$configFile = Join-Path $configDir "intellicrack.json"
$config = @{
    version = "2.0"
    python_path = $python
    install_date = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    gpu_info = @{
        nvidia = $gpuInfo.HasNVIDIA
        nvidia_device = $gpuInfo.NVIDIADevice
        amd = $gpuInfo.HasAMD
        amd_device = $gpuInfo.AMDDevice
        intel = $gpuInfo.HasIntel
        intel_device = $gpuInfo.IntelDevice
        cuda_capable = $gpuInfo.CUDACapable
        cuda_version = $gpuInfo.CUDAVersion
    }
    directories = @{
        root = $intellicrackRoot
        logs = $logsDir
        config = $configDir
        tools = $toolsDir
        reports = "C:\Intellicrack\reports"
        plugins = "C:\Intellicrack\plugins"
        models = "C:\Intellicrack\models"
        cache = "C:\Intellicrack\cache"
    }
    tools = @{
        ghidra = if (Test-Path "C:\ProgramData\chocolatey\lib\ghidra") { 
            (Get-ChildItem "C:\ProgramData\chocolatey\lib\ghidra\tools" -Directory | Select-Object -First 1).FullName 
        } else { "" }
        radare2 = "C:\ProgramData\chocolatey\lib\radare2\tools\radare2\bin"
        python = $python
        docker = if (Get-Command docker -ErrorAction SilentlyContinue) { (Get-Command docker).Path } else { "" }
        qemu = if (Get-Command qemu-system-x86_64 -ErrorAction SilentlyContinue) { (Get-Command qemu-system-x86_64).Path } else { "" }
        wireshark = "C:\Program Files\Wireshark"
    }
    settings = @{
        gpu_acceleration = ($gpuInfo.HasNVIDIA -or $gpuInfo.HasAMD -or $gpuInfo.HasIntel)
        gpu_backend = $(if ($gpuInfo.HasNVIDIA) { "cuda" } elseif ($gpuInfo.HasIntel) { "intel" } elseif ($gpuInfo.HasAMD) { "opencl" } else { "cpu" })
        distributed_processing = $true
        max_workers = [Environment]::ProcessorCount
        log_level = "INFO"
        enable_ml = $true
        enable_gpu_ml = ($gpuInfo.HasNVIDIA -or $gpuInfo.HasIntel)
    }
}

$config | ConvertTo-Json -Depth 5 | Set-Content $configFile
Write-Success "Created comprehensive configuration"

# Set environment variables for tools
[Environment]::SetEnvironmentVariable("INTELLICRACK_ROOT", $intellicrackRoot, "Machine")
[Environment]::SetEnvironmentVariable("INTELLICRACK_CONFIG", $configFile, "Machine")

if (Test-Path $config.tools.ghidra) {
    [Environment]::SetEnvironmentVariable("GHIDRA_HOME", $config.tools.ghidra, "Machine")
}
if (Test-Path $config.tools.radare2) {
    [Environment]::SetEnvironmentVariable("R2_HOME", (Split-Path $config.tools.radare2), "Machine")
}

# Copy data files
Write-Host "Copying data files..."
$dataPatterns = @(
    "protocol_signatures.json",
    "data\signatures\*",
    "data\templates\*",
    "assets\*",
    "plugins\*"
)

foreach ($pattern in $dataPatterns) {
    $source = Join-Path $scriptDir $pattern
    if (Test-Path $source) {
        $destBase = if ($pattern -match "^(data|assets|plugins)\\") { "C:\Intellicrack" } else { "C:\Intellicrack\data" }
        $dest = Join-Path $destBase (Split-Path $pattern)
        Copy-Item $source $dest -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Skip shortcut creation as per user preference
Write-Info "Skipping shortcut creation"

# Step 10: Comprehensive verification
Write-Step "STEP 10/10: Verifying installation"

$verifyItems = @(
    @{name="Python 3.11"; test={& $python --version 2>&1 | Select-String "3\.11"}},
    @{name="PyQt5 GUI"; test={& $python -c "import PyQt5" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="NumPy"; test={& $python -c "import numpy" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="Capstone"; test={& $python -c "import capstone" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="PE File Support"; test={& $python -c "import pefile" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="ELF Support"; test={& $python -c "import elftools" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="LIEF"; test={& $python -c "import lief" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="Angr"; test={& $python -c "import angr" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="Frida"; test={& $python -c "import frida" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="Ray"; test={& $python -c "import ray" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="PyTorch"; test={& $python -c "import torch" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="TensorFlow"; test={& $python -c "import tensorflow" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="Scapy"; test={& $python -c "import scapy" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="Cryptography"; test={& $python -c "import cryptography" 2>&1; $LASTEXITCODE -eq 0}},
    @{name="Ghidra"; test={Test-Path $config.tools.ghidra}},
    @{name="Radare2"; test={Get-Command r2 -ErrorAction SilentlyContinue}},
    @{name="Docker"; test={Get-Command docker -ErrorAction SilentlyContinue}},
    @{name="QEMU"; test={Get-Command qemu-system-x86_64 -ErrorAction SilentlyContinue}},
    @{name="Wireshark/tshark"; test={Test-Path "C:\Program Files\Wireshark\tshark.exe"}},
    @{name="Git"; test={Get-Command git -ErrorAction SilentlyContinue}},
    @{name="Configuration"; test={Test-Path $configFile}}
)

# GPU-specific checks
if ($gpuInfo.HasNVIDIA) {
    $verifyItems += @{name="CUDA Support"; test={& $python -c "import torch; print(torch.cuda.is_available())" 2>&1 | Select-String "True"}}
    $verifyItems += @{name="PyCUDA"; test={& $python -c "import pycuda" 2>&1; $LASTEXITCODE -eq 0}}
}
if ($gpuInfo.HasIntel) {
    # Intel Extension is optional - don't fail if it doesn't work
    Write-Info "Note: Intel Extension for PyTorch is optional and may fail on non-Intel GPU systems"
    $verifyItems += @{name="OpenVINO"; test={& $python -c "import openvino" 2>&1; $LASTEXITCODE -eq 0}}
}
$verifyItems += @{name="OpenCL"; test={& $python -c "import pyopencl" 2>&1; $LASTEXITCODE -eq 0}}

$passed = 0
$failed = 0

foreach ($item in $verifyItems) {
    Write-Host "Checking $($item.name)..." -NoNewline
    if (& $item.test) {
        Write-Host " [OK]" -ForegroundColor Green
        $passed++
    }
    else {
        Write-Host " [FAIL]" -ForegroundColor Red
        $failed++
    }
}

# Test GPU functionality if available
if ($gpuInfo.HasNVIDIA -or $gpuInfo.HasIntel -or $gpuInfo.HasAMD) {
    Write-Step "Testing GPU acceleration"
    
    # Create Python test script - encode to avoid PowerShell parsing issues
    $testFile = "$env:TEMP\gpu_test.py"
    
    # Base64 encoded Python script to test GPU
    $pythonScript = "aW1wb3J0IHRvcmNoCmltcG9ydCB0aW1lCgpwcmludCgnVGVzdGluZyBHUFUuLi4nKQp0cnk6CiAgICBpZiB0b3JjaC5jdWRhLmlzX2F2YWlsYWJsZSgpOgogICAgICAgIHByaW50KCdDVURBIEdQVSBkZXRlY3RlZCcpCiAgICAgICAgZGV2aWNlID0gJ2N1ZGEnCiAgICBlbHNlOgogICAgICAgIHByaW50KCdObyBDVURBIEdQVScpCiAgICAgICAgZGV2aWNlID0gJ2NwdScKICAgIHByaW50KCdHUFUgdGVzdCBjb21wbGV0ZWQgb246JywgZGV2aWNlKQpleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICBwcmludCgnR1BVIHRlc3QgZmFpbGVkOicsIHN0cihlKSk="
    
    # Decode and write to file
    $bytes = [System.Convert]::FromBase64String($pythonScript)
    [System.IO.File]::WriteAllBytes($testFile, $bytes)
    
    Write-Info "Running GPU benchmark..."
    & $python $testFile
    Remove-Item $testFile -Force
}

# Final summary
Write-Header "INSTALLATION COMPLETE"
Write-Host "Verification: $passed passed, $failed failed"

if ($gpuInfo.HasNVIDIA) {
    Write-Info "NVIDIA GPU configured for CUDA acceleration"
}
elseif ($gpuInfo.HasIntel) {
    Write-Info "Intel GPU configured with Intel Extension for PyTorch"
}
elseif ($gpuInfo.HasAMD) {
    Write-Info "AMD GPU configured with OpenCL support"
}
else {
    Write-Info "CPU-only mode configured"
}

# Save final state
$installState.Status = if ($failed -eq 0) { "Complete" } else { "CompleteWithErrors" }
$installState.CompletedTime = Get-Date
$installState.TotalErrors = $script:TotalErrors
$installState.TotalWarnings = $script:TotalWarnings
Save-InstallationState -State $installState

if ($failed -eq 0) {
    Write-Success "`nIntellicrack is fully installed with ALL features!"
    Write-Host "`nTo run Intellicrack:"
    Write-Host "  cd $(Split-Path $scriptDir)"
    Write-Host "  python launch_intellicrack.py"
}
else {
    Write-Warning "`nSome components failed. Check above for details."
}

# Stop logging
Stop-Transcript | Out-Null

Write-Host "`nInstallation log saved to: $logFile"

# Create summary report
$summaryFile = Join-Path $configDir "installation_summary.txt"

# Build summary using string concatenation instead of here-string
$summary = "Intellicrack Installation Summary`n"
$summary += "Generated: $(Get-Date)`n`n"
$summary += "Installation Type: "
if ($gpuInfo.HasNVIDIA) { $summary += "NVIDIA GPU" }
elseif ($gpuInfo.HasIntel) { $summary += "Intel GPU" }
elseif ($gpuInfo.HasAMD) { $summary += "AMD GPU" }
else { $summary += "CPU Only" }
$summary += "`n"
$summary += "Python Version: $(& $python --version 2>&1)`n"
$summary += "Total Errors: $($script:TotalErrors)`n"
$summary += "Total Warnings: $($script:TotalWarnings)`n`n"
$summary += "Components Status:`n"
$summary += "- Python: $(if ($python) { 'Installed' } else { 'Failed' })`n"
$summary += "- GPU Support: $(if ($gpuInfo.HasNVIDIA -or $gpuInfo.HasIntel -or $gpuInfo.HasAMD) { 'Configured' } else { 'N/A' })`n"
$summary += "- System Tools: $(if ($SkipSystemTools) { 'Skipped' } else { 'Installed' })`n"
$summary += "- Configuration: Created`n`n"
$summary += "Verification Results: $passed passed, $failed failed`n`n"
$summary += "For detailed logs, see: $logFile"

$summary | Set-Content $summaryFile

if ($failed -eq 0 -and $script:TotalErrors -eq 0) {
    Write-Host "`n" -NoNewline
    Write-Host "===============================================================" -ForegroundColor Green
    Write-Host "         INSTALLATION COMPLETED SUCCESSFULLY!              " -ForegroundColor Green
    Write-Host "===============================================================" -ForegroundColor Green
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
