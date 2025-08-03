# PowerShell script to download Intel Extension for PyTorch wheels for Windows

$pythonVersion = "311"  # For Python 3.11
$ipexVersion = "2.5.10+xpu"
$torchVersion = "2.5.1"

# Create directory for wheels
New-Item -ItemType Directory -Force -Path ".\intel_gpu_wheels"

# URLs for Intel Extension wheels
$urls = @{
    "torch" = "https://download.pytorch.org/whl/cpu/torch-$torchVersion-cp$pythonVersion-cp$pythonVersion-win_amd64.whl"
    "torchvision" = "https://download.pytorch.org/whl/cpu/torchvision-0.20.1-cp$pythonVersion-cp$pythonVersion-win_amd64.whl"
    "ipex" = "https://pytorch-extension.intel.com/release-whl/stable/xpu/us/intel_extension_for_pytorch-$ipexVersion-cp$pythonVersion-cp$pythonVersion-win_amd64.whl"
}

Write-Host "Downloading Intel GPU wheels..." -ForegroundColor Green

foreach ($package in $urls.Keys) {
    $url = $urls[$package]
    $filename = Split-Path $url -Leaf
    $output = ".\intel_gpu_wheels\$filename"

    Write-Host "Downloading $package..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
        Write-Host "✓ Downloaded $filename" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to download $package from $url" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

Write-Host "`nTo install:" -ForegroundColor Cyan
Write-Host "cd intel_gpu_wheels"
Write-Host "pip install *.whl"
