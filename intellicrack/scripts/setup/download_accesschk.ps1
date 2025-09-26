# Download AccessChk from Microsoft Sysinternals
$url = "https://download.sysinternals.com/files/AccessChk.zip"
$output = "C:\Intellicrack\AccessChk.zip"
$destination = "C:\SysinternalsSuite"

Write-Host "Downloading AccessChk from Microsoft Sysinternals..."

# Create destination directory if it doesn't exist
if (-not (Test-Path $destination)) {
    New-Item -ItemType Directory -Path $destination -Force
}

# Download the zip file
try {
    Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
    Write-Host "✅ Downloaded AccessChk.zip"

    # Extract the zip file
    Expand-Archive -Path $output -DestinationPath $destination -Force
    Write-Host "✅ Extracted AccessChk to $destination"

    # List extracted files
    $files = Get-ChildItem -Path $destination -Name "accesschk*"
    Write-Host "Extracted files:"
    $files | ForEach-Object { Write-Host "  $_" }

    # Clean up zip file
    Remove-Item $output
    Write-Host "✅ Cleaned up download file"

    # Test if AccessChk works
    $accesschkPath = "$destination\accesschk.exe"
    if (Test-Path $accesschkPath) {
        Write-Host "Testing AccessChk installation..."
        & $accesschkPath -accepteula "-?"
        Write-Host "✅ AccessChk installed successfully"
    } else {
        Write-Host "❌ AccessChk executable not found"
    }

} catch {
    Write-Host "❌ Error downloading or extracting AccessChk: $($_.Exception.Message)"
}
