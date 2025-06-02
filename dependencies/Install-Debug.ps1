# Debug version of installer to identify crash issue

Write-Host "Starting installer debug..." -ForegroundColor Yellow

# Check PowerShell version
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan

# Check execution policy
Write-Host "Execution Policy: $(Get-ExecutionPolicy)" -ForegroundColor Cyan

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as Administrator: $isAdmin" -ForegroundColor Cyan

# Check current directory
Write-Host "Current Directory: $(Get-Location)" -ForegroundColor Cyan
Write-Host "Script Directory: $PSScriptRoot" -ForegroundColor Cyan

# Check if requirements.txt exists
$reqFile = Join-Path $PSScriptRoot "requirements.txt"
Write-Host "Requirements.txt exists: $(Test-Path $reqFile)" -ForegroundColor Cyan

Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")