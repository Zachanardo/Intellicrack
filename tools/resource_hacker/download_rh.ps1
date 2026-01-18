# Download Resource Hacker
$url = "http://www.angusj.com/resourcehacker/reshacker_setup.exe"
$output = "$PSScriptRoot\reshacker_setup.exe"

Write-Host "Downloading Resource Hacker..."
Invoke-WebRequest -Uri $url -OutFile $output

Write-Host "Download complete. Please run the installer."
Write-Host "After installation, copy ResourceHacker.exe to this directory."
