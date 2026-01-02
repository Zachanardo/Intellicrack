# Intellicrack Testing Commands
# Configure shell for Windows

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

# ==================== INSTALLATION ====================

# Complete installation with all post-install tasks
install:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; $totalSteps = 10; $currentStep = 0; function Write-Step { param($msg) $script:currentStep++; Write-Host "$e[36m[$script:currentStep/$totalSteps]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" -ForegroundColor Red }; Write-Host "`n$e[1;36m=== Intellicrack Installation ===$e[0m`n"; $startTime = Get-Date; Write-Step "Preparing environment..."; if (Test-Path "pixi.lock") { Remove-Item -Force "pixi.lock" -ErrorAction Stop; Write-Success "Removed existing pixi.lock" } else { Write-Success "Environment clean" }; Write-Step "Installing dependencies with pixi..."; try { pixi install; if ($LASTEXITCODE -ne 0) { throw "pixi install failed with exit code $LASTEXITCODE" }; Write-Success "Pixi dependencies installed" } catch { Write-Fail "Pixi installation failed: $_"; exit 1 }; Write-Step "Generating requirements.txt for Dependabot..."; try { pixi run generate-requirements; if ($LASTEXITCODE -ne 0) { throw "generate-requirements failed with exit code $LASTEXITCODE" }; Write-Success "requirements.txt generated" } catch { Write-Fail "Requirements generation failed: $_"; exit 1 }; Write-Step "Installing Rustup (if needed)..."; try { & just install-rustup; if ($LASTEXITCODE -ne 0) { throw "install-rustup failed with exit code $LASTEXITCODE" }; Write-Success "Rustup ready" } catch { Write-Fail "Rustup installation failed: $_"; exit 1 }; Write-Step "Updating Rust toolchain..."; try { rustup update stable; if ($LASTEXITCODE -ne 0) { throw "rustup update failed with exit code $LASTEXITCODE" }; Write-Success "Rust toolchain updated" } catch { Write-Fail "Rust update failed: $_"; exit 1 }; Write-Step "Installing JDK 21..."; try { & just install-jdk; if ($LASTEXITCODE -ne 0) { throw "install-jdk failed with exit code $LASTEXITCODE" }; Write-Success "JDK 21 ready" } catch { Write-Fail "JDK installation failed: $_"; exit 1 }; Write-Step "Installing Ghidra..."; try { & just install-ghidra; if ($LASTEXITCODE -ne 0) { throw "install-ghidra failed with exit code $LASTEXITCODE" }; Write-Success "Ghidra ready" } catch { Write-Fail "Ghidra installation failed: $_"; exit 1 }; Write-Step "Installing radare2..."; try { & just install-radare2; if ($LASTEXITCODE -ne 0) { throw "install-radare2 failed with exit code $LASTEXITCODE" }; Write-Success "radare2 ready" } catch { Write-Fail "radare2 installation failed: $_"; exit 1 }; Write-Step "Installing QEMU..."; try { & just install-qemu; if ($LASTEXITCODE -ne 0) { throw "install-qemu failed with exit code $LASTEXITCODE" }; Write-Success "QEMU ready" } catch { Write-Fail "QEMU installation failed: $_"; exit 1 }; Write-Step "Installing Yarn 4 and Node.js dependencies..."; try { pixi run install-yarn-deps; if ($LASTEXITCODE -ne 0) { throw "yarn deps failed with exit code $LASTEXITCODE" }; Write-Success "Node.js dependencies installed" } catch { Write-Fail "Yarn dependencies installation failed: $_"; exit 1 }; Write-Step "Building Rust launcher..."; try { pixi run create-shortcut; if ($LASTEXITCODE -ne 0) { throw "create-shortcut failed with exit code $LASTEXITCODE" }; Write-Success "Rust launcher built" } catch { Write-Fail "Launcher build failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Installation Complete ===$e[0m"; Write-Host "$e[90mTotal time: $("{0:N1}" -f $elapsed) seconds$e[0m`n"

# Remove pixi environment and node_modules
uninstall:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[UNINSTALL]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Warn { param($msg) Write-Host "  $e[33m[SKIP]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Host "`n$e[1;36m=== Intellicrack Uninstall ===$e[0m`n"; $startTime = Get-Date; Write-Step "Cleaning pixi environment..."; try { pixi clean; if ($LASTEXITCODE -ne 0) { throw "pixi clean failed with exit code $LASTEXITCODE" }; Write-Success "Pixi environment cleaned" } catch { Write-Fail "Pixi clean failed: $_"; exit 1 }; Write-Step "Removing pixi.lock..."; if (Test-Path "pixi.lock") { try { Remove-Item -Force "pixi.lock" -ErrorAction Stop; Write-Success "pixi.lock removed" } catch { Write-Fail "Failed to remove pixi.lock: $_"; exit 1 } } else { Write-Warn "pixi.lock not found" }; Write-Step "Removing node_modules..."; if (Test-Path "node_modules") { try { Remove-Item -Recurse -Force "node_modules" -ErrorAction Stop; Write-Success "node_modules removed" } catch { Write-Fail "Failed to remove node_modules: $_"; exit 1 } } else { Write-Warn "node_modules not found" }; Write-Step "Removing yarn.lock..."; if (Test-Path "yarn.lock") { try { Remove-Item -Force "yarn.lock" -ErrorAction Stop; Write-Success "yarn.lock removed" } catch { Write-Fail "Failed to remove yarn.lock: $_"; exit 1 } } else { Write-Warn "yarn.lock not found" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Uninstall Complete ===$e[0m"; Write-Host "$e[90mTotal time: $("{0:N1}" -f $elapsed) seconds$e[0m`n"

# Install Rustup if not already installed
install-rustup:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[RUSTUP]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Checking Rustup installation..."; $rustupInstalled = $false; try { $version = rustup --version 2>&1; if ($LASTEXITCODE -eq 0) { $rustupInstalled = $true; Write-Success "Rustup already installed: $($version -split "`n" | Select-Object -First 1)" } } catch { }; if (-not $rustupInstalled) { Write-Step "Installing Rustup..."; $wingetAvailable = $false; try { $null = Get-Command winget -ErrorAction Stop; $wingetAvailable = $true } catch { }; if ($wingetAvailable) { Write-Step "Using winget to install Rustup..."; try { $result = winget install --id Rustlang.Rustup -e --silent --accept-source-agreements --accept-package-agreements 2>&1; if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) { throw "winget install failed with exit code $LASTEXITCODE" }; Write-Success "Rustup installed via winget" } catch { Write-Fail "Winget installation failed: $_"; exit 1 } } else { Write-Step "Winget not available, using rustup-init.exe..."; try { $installerUrl = "https://win.rustup.rs/x86_64"; $installerPath = Join-Path $env:TEMP "rustup-init.exe"; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -TimeoutSec 120; if (-not (Test-Path $installerPath)) { throw "Download failed" }; Write-Step "Running rustup-init.exe..."; Start-Process -FilePath $installerPath -ArgumentList "-y", "--default-toolchain", "stable" -Wait -NoNewWindow; Remove-Item $installerPath -Force -ErrorAction SilentlyContinue; Write-Success "Rustup installed via rustup-init.exe" } catch { Write-Fail "Rustup-init installation failed: $_"; exit 1 } } }; Write-Step "Verifying Rustup installation..."; try { $version = rustup --version 2>&1; if ($LASTEXITCODE -ne 0) { throw "Rustup verification failed" }; Write-Success "Rustup verified: $($version -split "`n" | Select-Object -First 1)" } catch { Write-Fail "Rustup verification failed: $_"; exit 1 }; exit 0

# Install JDK 21 to system if not already installed
install-jdk:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[JDK]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Checking Java installation..."; $jdk21Installed = $false; try { $javaOutput = java -version 2>&1 | Out-String; if ($javaOutput -match '21\.\d+\.\d+') { $jdk21Installed = $true; $versionLine = ($javaOutput -split "`n" | Select-Object -First 1).Trim(); Write-Success "JDK 21 already installed: $versionLine" } elseif ($javaOutput -match 'version') { $versionLine = ($javaOutput -split "`n" | Select-Object -First 1).Trim(); Write-Step "Found different Java version: $versionLine" } } catch { Write-Step "Java not found in PATH" }; if (-not $jdk21Installed) { Write-Step "Installing JDK 21..."; $wingetAvailable = $false; try { $null = Get-Command winget -ErrorAction Stop; $wingetAvailable = $true } catch { }; if ($wingetAvailable) { Write-Step "Using winget to install JDK 21..."; try { $result = winget install --id Oracle.JDK.21 -e --silent --accept-source-agreements --accept-package-agreements 2>&1; if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) { throw "winget install failed with exit code $LASTEXITCODE" }; Write-Success "JDK 21 installed via winget" } catch { Write-Fail "Winget installation failed: $_"; exit 1 } } else { Write-Fail "Winget not available - please install JDK 21 manually from https://www.oracle.com/java/technologies/downloads/"; exit 1 } }; Write-Step "Verifying Java installation..."; try { $javaOutput = java -version 2>&1 | Out-String; if ($javaOutput -match '21\.\d+\.\d+') { $versionLine = ($javaOutput -split "`n" | Select-Object -First 1).Trim(); Write-Success "JDK 21 verified: $versionLine" } else { Write-Step "Note: JDK 21 may require PATH refresh or system restart" } } catch { Write-Step "Note: JDK 21 may require PATH refresh or system restart" }; exit 0

# Downloads and installs the latest Ghidra reverse engineering tool.

# Uses SSL validation and verifies downloaded file integrity.
install-ghidra:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[GHIDRA]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing Ghidra installation..."; $existingGhidra = Get-ChildItem -Path "tools" -Recurse -Filter "ghidraRun.bat" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($existingGhidra) { Write-Success "Ghidra already installed at $($existingGhidra.DirectoryName)"; exit 0 }; Write-Step "Fetching latest Ghidra release from GitHub..."; $maxRetries = 3; $release = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $release = Invoke-RestMethod -Uri "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest" -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $asset = $release.assets | Where-Object { $_.name -match '\.zip$' -and $_.name -notmatch 'DEV' } | Select-Object -First 1; if (!$asset) { Write-Fail "Could not find Ghidra release asset in GitHub response"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $fileSize = [math]::Round($asset.size / 1MB, 1); $zipPath = Join-Path "tools" $fileName; Write-Success "Found: $fileName ($fileSize MB)"; Write-Step "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 600; if (-not (Test-Path $zipPath)) { throw "Download file not found" }; $actualSize = (Get-Item $zipPath).Length; if ($actualSize -lt 1000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Extracting Ghidra..."; $tempExtract = Join-Path "tools" "ghidra_temp"; try { if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract -ErrorAction Stop; Write-Success "Extraction complete" } catch { Write-Fail "Extraction failed: $_"; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; exit 1 }; Write-Step "Installing Ghidra..."; try { $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1; if (!$extractedDir) { throw "No directory found in archive" }; $destPath = Join-Path "tools" "ghidra"; if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }; Move-Item -Path $extractedDir.FullName -Destination $destPath -ErrorAction Stop; if (-not (Test-Path (Join-Path $destPath "ghidraRun.bat"))) { throw "ghidraRun.bat not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mGhidra installed to tools\ghidra$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Downloads and installs the latest radare2 reverse engineering framework.

# Uses SSL validation and verifies downloaded file integrity.
install-radare2:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[RADARE2]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing radare2 installation..."; $existingRadare2 = Get-ChildItem -Path "tools" -Recurse -Filter "radare2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingRadare2) { $existingRadare2 = Get-ChildItem -Path "tools" -Recurse -Filter "r2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingRadare2) { Write-Success "radare2 already installed at $($existingRadare2.DirectoryName)"; exit 0 }; Write-Step "Fetching latest radare2 release from GitHub..."; $maxRetries = 3; $release = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $release = Invoke-RestMethod -Uri "https://api.github.com/repos/radareorg/radare2/releases/latest" -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $asset = $release.assets | Where-Object { $_.name -match 'w64\.zip$' -or $_.name -match 'windows.*\.zip$' } | Select-Object -First 1; if (!$asset) { Write-Fail "Could not find radare2 Windows release asset in GitHub response"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $fileSize = [math]::Round($asset.size / 1MB, 1); $zipPath = Join-Path "tools" $fileName; Write-Success "Found: $fileName ($fileSize MB)"; Write-Step "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 300; if (-not (Test-Path $zipPath)) { throw "Download file not found" }; $actualSize = (Get-Item $zipPath).Length; if ($actualSize -lt 1000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Extracting radare2..."; $tempExtract = Join-Path "tools" "radare2_temp"; try { if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract -ErrorAction Stop; Write-Success "Extraction complete" } catch { Write-Fail "Extraction failed: $_"; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; exit 1 }; Write-Step "Installing radare2..."; try { $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1; $destPath = Join-Path "tools" "radare2"; if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }; if ($extractedDir) { Move-Item -Path $extractedDir.FullName -Destination $destPath -ErrorAction Stop } else { Move-Item -Path $tempExtract -Destination $destPath -ErrorAction Stop }; $r2exe = Get-ChildItem -Path $destPath -Recurse -Filter "radare2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$r2exe) { $r2exe = Get-ChildItem -Path $destPath -Recurse -Filter "r2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if (!$r2exe) { throw "radare2.exe or r2.exe not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mradare2 installed to tools\radare2$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Downloads and installs the latest QEMU emulator.

# Uses SSL validation and verifies downloaded installer integrity.
install-qemu:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[QEMU]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing QEMU installation..."; $existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingQemu) { $existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-img.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingQemu) { Write-Success "QEMU already installed at $($existingQemu.DirectoryName)"; exit 0 }; Write-Step "Fetching QEMU release page..."; $maxRetries = 3; $html = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $html = Invoke-WebRequest -Uri "https://qemu.weilnetz.de/w64/" -UseBasicParsing -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "Failed to fetch QEMU release page after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $links = $html.Links | Where-Object { $_.href -match 'qemu-w64-setup-.*\.exe$' } | Sort-Object { $_.href } -Descending | Select-Object -First 1; if (!$links) { Write-Fail "Could not find QEMU installer on release page"; exit 1 }; $installerName = $links.href; $installerUrl = "https://qemu.weilnetz.de/w64/$installerName"; Write-Success "Found: $installerName"; $installerPath = Join-Path "tools" $installerName; Write-Step "Downloading $installerName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -TimeoutSec 600; if (-not (Test-Path $installerPath)) { throw "Download file not found" }; $actualSize = (Get-Item $installerPath).Length; if ($actualSize -lt 10000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $installerPath) { Remove-Item $installerPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Installing QEMU (this may take a minute)..."; try { $installDir = Join-Path (Get-Location) "tools\qemu"; if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }; $process = Start-Process -FilePath $installerPath -ArgumentList "/S", "/D=$installDir" -Wait -NoNewWindow -PassThru; if ($process.ExitCode -ne 0) { throw "Installer exited with code $($process.ExitCode)" }; Start-Sleep -Seconds 2; $qemuExe = Get-ChildItem -Path $installDir -Recurse -Filter "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$qemuExe) { $qemuExe = Get-ChildItem -Path $installDir -Recurse -Filter "qemu-img.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if (!$qemuExe) { throw "QEMU executables not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $installerPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mQEMU installed to tools\qemu$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# ==================== BUILD ====================

# Build Rust launcher in release mode with maximum optimization
build-rust:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[BUILD]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building Rust Launcher (Release) ===$e[0m`n"; Write-Step "Checking cargo installation..."; try { $cargoVersion = cargo --version 2>&1; if ($LASTEXITCODE -ne 0) { throw "Cargo not found" }; Write-Success "Cargo: $cargoVersion" } catch { Write-Fail "Cargo not installed: $_"; exit 1 }; Write-Step "Building with maximum optimization..."; try { $env:RUSTFLAGS = "-C target-cpu=native"; cargo build --release --manifest-path intellicrack-launcher/Cargo.toml 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Cargo build failed with exit code $LASTEXITCODE" }; Write-Success "Build complete" } catch { Write-Fail "Build failed: $_"; exit 1 }; Write-Step "Validating build artifact..."; $exePath = "intellicrack-launcher\target\release\Intellicrack.exe"; if (-not (Test-Path $exePath)) { Write-Fail "Build artifact not found: $exePath"; exit 1 }; $exeSize = [math]::Round((Get-Item $exePath).Length / 1KB, 1); Write-Success "Artifact validated: Intellicrack.exe ($exeSize KB)"; Write-Step "Creating shortcut..."; try { $WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("$PWD\Intellicrack.lnk"); $Shortcut.TargetPath = "$PWD\$exePath"; $Shortcut.IconLocation = "$PWD\intellicrack\assets\icon.ico"; $Shortcut.WorkingDirectory = "$PWD"; $Shortcut.Save(); if (-not (Test-Path "Intellicrack.lnk")) { throw "Shortcut creation failed" }; Write-Success "Shortcut created: Intellicrack.lnk" } catch { Write-Fail "Shortcut creation failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Build Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Build Rust launcher in debug mode
build-rust-debug:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[BUILD]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building Rust Launcher (Debug) ===$e[0m`n"; Write-Step "Building debug build..."; try { cargo build --manifest-path intellicrack-launcher/Cargo.toml 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Cargo build failed with exit code $LASTEXITCODE" }; Write-Success "Build complete" } catch { Write-Fail "Build failed: $_"; exit 1 }; Write-Step "Validating build artifact..."; $exePath = "intellicrack-launcher\target\debug\Intellicrack.exe"; if (-not (Test-Path $exePath)) { Write-Fail "Build artifact not found: $exePath"; exit 1 }; $exeSize = [math]::Round((Get-Item $exePath).Length / 1KB, 1); Write-Success "Artifact validated: Intellicrack.exe ($exeSize KB)"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Debug Build Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Clean Rust build artifacts
build-rust-clean:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[CLEAN]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Cleaning Rust build artifacts..."; try { cargo clean --manifest-path intellicrack-launcher/Cargo.toml 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Cargo clean failed with exit code $LASTEXITCODE" }; Write-Success "Build artifacts cleaned" } catch { Write-Fail "Clean failed: $_"; exit 1 }; Write-Step "Verifying cleanup..."; $targetDir = "intellicrack-launcher\target"; if (Test-Path $targetDir) { $remainingSize = [math]::Round((Get-ChildItem -Path $targetDir -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 1); if ($remainingSize -gt 0) { Write-Step "Remaining cache: $remainingSize MB" } } else { Write-Success "Target directory removed" }

# Clean all build artifacts (Rust, Python, test caches)
clean:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; $removed = 0; function Write-Step { param($msg) Write-Host "$e[36m[CLEAN]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Skip { param($msg) Write-Host "  $e[33m[SKIP]$e[0m $msg" }; Write-Host "`n$e[1;36m=== Cleaning Project Artifacts ===$e[0m`n"; Write-Step "Cleaning Rust build artifacts (intellicrack-launcher)..."; try { cargo clean --manifest-path intellicrack-launcher/Cargo.toml 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { Write-Success "Rust artifacts cleaned"; $removed++ } else { Write-Fail "cargo clean failed" } } catch { Write-Skip "Rust cleanup skipped: $_" }; Write-Step "Cleaning Python bytecode (intellicrack, tests)..."; try { pixi run pyclean intellicrack tests 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { Write-Success "Python bytecode cleaned"; $removed++ } else { Write-Fail "pyclean failed" } } catch { Write-Skip "Python cleanup skipped: $_" }; Write-Step "Checking for MagicMock artifact directory..."; $magicMockPath = Join-Path (Get-Location) "MagicMock"; if ((Test-Path $magicMockPath) -and (Get-Item $magicMockPath).PSIsContainer -and (Test-Path (Join-Path $magicMockPath "mock"))) { Remove-Item -Recurse -Force $magicMockPath -ErrorAction Stop; Write-Success "MagicMock directory removed"; $removed++ } else { Write-Skip "MagicMock not found or not matching expected structure" }; Write-Step "Cleaning test artifacts..."; if (Test-Path ".pytest_cache") { Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path "coverage_html_report") { Remove-Item -Recurse -Force coverage_html_report -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path ".coverage") { Remove-Item -Force .coverage -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path ".mypy_cache") { Remove-Item -Recurse -Force .mypy_cache -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path ".ruff_cache") { Remove-Item -Recurse -Force .ruff_cache -ErrorAction SilentlyContinue; $removed++ }; Write-Success "Test artifacts cleaned"; Write-Host "`n$e[1;32m=== Cleanup Complete ($removed items) ===$e[0m`n"

# Build and run Rust tests
build-rust-test:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[TEST]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Running Rust Tests ===$e[0m`n"; Write-Step "Building and testing..."; try { cargo test --manifest-path intellicrack-launcher/Cargo.toml 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Cargo test failed with exit code $LASTEXITCODE" }; Write-Success "All tests passed" } catch { Write-Fail "Tests failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Tests Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Build Rust launcher with optimizations and copy to project root
build-rust-optimized:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[BUILD]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building Optimized Launcher ===$e[0m`n"; Write-Step "Building release build..."; try { cargo build --release --manifest-path intellicrack-launcher/Cargo.toml 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Cargo build failed with exit code $LASTEXITCODE" }; Write-Success "Build complete" } catch { Write-Fail "Build failed: $_"; exit 1 }; Write-Step "Copying to project root..."; $srcPath = "intellicrack-launcher\target\release\intellicrack-launcher.exe"; $destPath = "intellicrack-launcher.exe"; try { if (-not (Test-Path $srcPath)) { throw "Source file not found: $srcPath" }; Copy-Item -Path $srcPath -Destination $destPath -Force -ErrorAction Stop; if (-not (Test-Path $destPath)) { throw "Copy failed" }; $exeSize = [math]::Round((Get-Item $destPath).Length / 1KB, 1); Write-Success "Copied: $destPath ($exeSize KB)" } catch { Write-Fail "Copy failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Optimized Build Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# ==================== SANDBOX ====================

# Launch interactive Windows Sandbox for Intellicrack testing (READ-ONLY)
sandbox:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType interactive }

# Launch interactive Windows Sandbox with READ-WRITE access (changes persist to host)
sandbox-rw:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType interactive-rw }

# Launch sandbox and run unit tests
sandbox-test:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType unit }

# Launch sandbox and run all tests
sandbox-test-all:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType all }

# Launch sandbox and run tests with coverage
sandbox-test-coverage:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType coverage }

# Launch sandbox and run hardware spoofer registry tests
sandbox-test-registry:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType registry }

# ==================== TESTING ====================

# Quick unit tests - runs in Windows Sandbox for isolation
test:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType unit }

# Full test suite - runs in Windows Sandbox for isolation
test-all:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType all }

# Coverage report - runs in Windows Sandbox with 95%+ coverage requirement
test-coverage:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType coverage }

# Runs tests for a specific module in Windows Sandbox
test-module module:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType module -Module "{{ module }}" }

# Benchmarks - runs in Windows Sandbox
test-bench:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType bench }

# Integration tests - runs in Windows Sandbox
test-integration:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType integration }

# End-to-end tests - runs in Windows Sandbox
test-e2e:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType e2e }

# Quick smoke test - runs in Windows Sandbox
test-smoke:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType smoke }

# Module tests with coverage - runs in Windows Sandbox
test-module-cov module:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType module-cov -Module "{{ module }}" }

# HTML coverage report - runs in Windows Sandbox (uses coverage type)
test-cov-html:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType coverage }

# Parallel tests - runs in Windows Sandbox
test-parallel:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType parallel }

# Retest failed tests - runs in Windows Sandbox
test-failed:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType failed }

# Verbose tests - runs in Windows Sandbox
test-verbose:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType verbose }

# Install test dependencies
test-install:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[INSTALL]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Installing test dependencies..."; try { pip install pytest pytest-cov pytest-benchmark pytest-asyncio pytest-qt pytest-xdist pytest-mock 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "pip install failed with exit code $LASTEXITCODE" }; Write-Success "Test dependencies installed" } catch { Write-Fail "Installation failed: $_"; exit 1 }

# Verify no mocks or fake data
test-verify-real:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[VERIFY]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Verifying no mocks or fake data..."; try { pixi run python tests/utils/verify_no_mocks.py 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Verification failed with exit code $LASTEXITCODE" }; Write-Success "All tests use REAL data" } catch { Write-Fail "Verification failed: $_"; exit 1 }

# Lint code with ruff
lint:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[LINT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Running Ruff Linter ===$e[0m`n"; Write-Step "Checking code style..."; try { pixi run ruff check intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; $checkCode = $LASTEXITCODE } catch { $checkCode = 1 }; Write-Step "Checking formatting..."; try { pixi run ruff format --check intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; $formatCode = $LASTEXITCODE } catch { $formatCode = 1 }; if ($checkCode -ne 0 -or $formatCode -ne 0) { Write-Fail "Linting issues found"; exit 1 }; Write-Success "All lint checks passed"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Lint Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Fix linting issues automatically
lint-fix:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[LINT-FIX]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Fixing Lint Issues ===$e[0m`n"; Write-Step "Fixing code style issues..."; try { pixi run ruff check --fix intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "ruff check --fix failed" } } catch { Write-Fail "Style fix failed: $_"; exit 1 }; Write-Step "Formatting code..."; try { pixi run ruff format intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "ruff format failed" } } catch { Write-Fail "Format failed: $_"; exit 1 }; Write-Success "Lint issues fixed"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Lint Fix Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Detect dead code with vulture and output sorted findings
vulture:
    @echo "[Vulture] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run vulture intellicrack/ tests/ --min-confidence 60 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py vulture --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Upgrade Python syntax to newer versions
pyupgrade:
    @Get-ChildItem -Path .\intellicrack\ -Recurse -Include "*.py" | ForEach-Object { pixi run pyupgrade --py312-plus $_.FullName }
    @Get-ChildItem -Path .\tests\ -Recurse -Include "*.py" | ForEach-Object { pixi run pyupgrade --py312-plus $_.FullName }

# Apply AI-powered code suggestions (auto-fix enabled)
sourcery:
    @pixi run sourcery review --fix --verbose intellicrack
    @pixi run sourcery review --fix --verbose tests

# Check docstring validity with darglint and output sorted findings
darglint:
    @echo "[Darglint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run darglint intellicrack 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py darglint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Check code line statistics with pygount
pygount:
    @pixi run pygount intellicrack --format=summary
    @pixi run pygount tests --format=summary

# Check Python packaging best practices with pyroma
pyroma:
    @pixi run pyroma .

# Detect dead code and output sorted findings
dead:
    @echo "[Dead Code] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run dead 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py dead --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run type checking with ty and output sorted findings
ty:
    @echo "[Ty Type] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run ty check intellicrack tests --output-format concise 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py ty $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run type checking with pyright and output sorted findings
pyright:
    @echo "[Pyright] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NODE_OPTIONS = '--max-old-space-size=8192'; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run pyright --outputjson 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py pyright $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run type checking with mypy and output sorted findings
mypy:
    @echo "[Mypy] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run mypy intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py mypy --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Security linting with bandit and output sorted findings
bandit:
    @echo "[Bandit Security] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run bandit -r intellicrack/ tests/ -c pyproject.toml 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py bandit --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run flake8 style linting and output sorted findings
flake8:
    @echo "[Flake8] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run flake8 intellicrack tests --statistics 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py flake8 --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run wemake-python-styleguide (strictest linter) and output sorted findings
wemake:
    @echo "[Wemake Styleguide] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run flake8 intellicrack tests --select=WPS,C9 --max-complexity 10 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py wemake --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run mccabe complexity checker and output sorted findings
mccabe:
    @echo "[McCabe Complexity] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run flake8 intellicrack tests --select=C901 --max-complexity 10 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py mccabe --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run pydocstyle docstring checker and output sorted findings
pydocstyle:
    @echo "[Pydocstyle] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run pydocstyle intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py pydocstyle --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run radon cyclomatic complexity analysis and output sorted findings
radon:
    @echo "[Radon Complexity] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run radon cc intellicrack tests -s -a 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py radon --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run xenon complexity threshold checker and output sorted findings
xenon:
    @echo "[Xenon Complexity] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run xenon intellicrack tests -b B -m C -a C 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py xenon --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run ruff linter and output sorted findings (uses native JSON output for speed)
ruff:
    @echo "[Ruff Linter] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run ruff check intellicrack/ tests/ --output-format=json -o $tmpFile 2>&1 | Out-Null; pixi run python scripts/process_lint_json.py ruff $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run ruff format to format Python code
ruff-fmt:
    @echo "[Ruff Format] Running..."
    @pixi run ruff format intellicrack/ tests/ 2>&1 | Out-Null; Write-Host "[RUFF FMT] Done"

# Run clippy and output sorted findings
clippy:
    @echo "[Rust Clippy] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { cargo clippy --manifest-path intellicrack-launcher/Cargo.toml --all-targets --all-features -- -W clippy::all -W clippy::pedantic -W clippy::nursery 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py clippy --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run markdownlint and output sorted findings
mdlint:
    @echo "[Markdown Lint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run markdownlint "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py markdownlint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run yamllint and output sorted findings
yamllint:
    @echo "[YAML Lint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run yamllint . 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py yamllint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Detect uncalled functions with uncalled and output sorted findings
uncalled:
    @echo "[Uncalled] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run uncalled --how both intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py uncalled --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Detect dead code with deadcode and output sorted findings
deadcode:
    @echo "[Deadcode] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run deadcode intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py deadcode --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Detect unused JS/TS exports with knip and output sorted findings
knip:
    @echo "[Knip JS/TS] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NO_COLOR = '1'; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $output = pixi run yarn run knip --no-progress --reporter json 2>&1 | Out-String; $jsonMatch = [regex]::Match($output, '\{"files":\[.*\],"issues":\[.*\]\}'); if ($jsonMatch.Success) { $jsonMatch.Value | Out-File -FilePath $tmpFile -Encoding utf8 } else { '{"files":[],"issues":[]}' | Out-File -FilePath $tmpFile -Encoding utf8 }; pixi run python scripts/process_lint_json.py knip $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run PMD Java analysis and output sorted findings
pmd:
    @echo "[PMD Java] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { java -cp "tools/pmd/lib/*" net.sourceforge.pmd.cli.PmdCli check -d intellicrack/scripts/ghidra -R tools/pmd/intellicrack-ruleset.xml -f text 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py pmd --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run checkstyle Java analysis and output sorted findings
checkstyle:
    @echo "[Checkstyle Java] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $javaFiles = @(Get-ChildItem -Path intellicrack/scripts/ghidra -Filter "*.java" -Recurse -ErrorAction SilentlyContinue); if ($javaFiles.Count -eq 0) { Write-Host "[Checkstyle Java] 0 findings"; 'No findings.' | Out-File -FilePath 'reports/txt/checkstyle_findings.txt' -Encoding utf8; @{ tool = 'checkstyle'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/checkstyle_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="checkstyle"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/checkstyle_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $javaFiles | ForEach-Object { java -jar .pixi/envs/default/libexec/checkstyle/checkstyle.jar -c checkstyle.xml $_.FullName 2>&1 } | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py checkstyle --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run ESLint on JavaScript files and output sorted findings (JS only - uses native JSON output for speed)
eslint:
    @echo "[ESLint JS] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NO_COLOR = '1'; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $result = pixi run yarn eslint "intellicrack/**/*.js" --format=json 2>&1 | Out-String; $jsonLine = ($result -split "`n" | Where-Object { $_.Trim().StartsWith('[') }) -join "`n"; if ($jsonLine) { $jsonLine | Out-File -FilePath $tmpFile -Encoding utf8 } else { '[]' | Out-File -FilePath $tmpFile -Encoding utf8 }; pixi run python scripts/process_lint_json.py eslint $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run Biome on JavaScript files and output sorted findings (uses text parsing since JSON is unreliable)
biome:
    @echo "[Biome JS] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NO_COLOR = '1'; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run yarn biome lint intellicrack/scripts/frida --max-diagnostics=5000 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py biome --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run cargo-audit for Rust security vulnerabilities and output sorted findings
cargo-audit:
    @echo "[Cargo Audit] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $crateDir = Get-ChildItem -Path . -Filter "Cargo.toml" -Recurse | Where-Object { $_.DirectoryName -notmatch '\.pixi|node_modules|target' } | Select-Object -First 1; if (-not $crateDir) { Write-Host "[Cargo Audit] 0 findings (no Cargo.toml found)"; 'No findings.' | Out-File -FilePath 'reports/txt/cargo_audit_findings.txt' -Encoding utf8; @{ tool = 'cargo-audit'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/cargo_audit_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="cargo-audit"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/cargo_audit_findings.xml' -Encoding utf8; exit 0 }; Push-Location $crateDir.DirectoryName; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run cargo-audit audit 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; Pop-Location; pixi run python scripts/process_lint_json.py cargo_audit --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run cargo-deny for Rust dependency policy enforcement and output sorted findings
cargo-deny:
    @echo "[Cargo Deny] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $crateDir = Get-ChildItem -Path . -Filter "Cargo.toml" -Recurse | Where-Object { $_.DirectoryName -notmatch '\.pixi|node_modules|target' } | Select-Object -First 1; if (-not $crateDir) { Write-Host "[Cargo Deny] 0 findings (no Cargo.toml found)"; 'No findings.' | Out-File -FilePath 'reports/txt/cargo_deny_findings.txt' -Encoding utf8; @{ tool = 'cargo-deny'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/cargo_deny_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="cargo-deny"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/cargo_deny_findings.xml' -Encoding utf8; exit 0 }; Push-Location $crateDir.DirectoryName; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run cargo-deny check 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; Pop-Location; pixi run python scripts/process_lint_json.py cargo_deny --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run shellcheck on shell scripts and output sorted findings
shellcheck:
    @echo "[ShellCheck] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $shFiles = @(Get-ChildItem -Path . -Include "*.sh","*.bash" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.pixi|node_modules|\.git|target' }); if ($shFiles.Count -eq 0) { Write-Host "[ShellCheck] 0 findings (no shell scripts found)"; 'No findings.' | Out-File -FilePath 'reports/txt/shellcheck_findings.txt' -Encoding utf8; @{ tool = 'shellcheck'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/shellcheck_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="shellcheck"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/shellcheck_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $shFiles | ForEach-Object { pixi run shellcheck --format=gcc $_.FullName 2>&1 } | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py shellcheck --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Validates JSON files in the project using PowerShell JSON parsing.

# Reports any syntax errors found in the JSON files.
jsonlint:
    @echo "[JSONLint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $jsonFiles = fd -e json --type f --exclude 'package-lock.json' --exclude 'pixi.lock' --exclude 'reports' 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }; if ($null -eq $jsonFiles -or @($jsonFiles).Count -eq 0) { Write-Host "[JSONLint] 0 findings (no JSON files found)"; 'No findings.' | Out-File -FilePath 'reports/txt/jsonlint_findings.txt' -Encoding utf8; @{ tool = 'jsonlint'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/jsonlint_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="jsonlint"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/jsonlint_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $errors = @(); foreach ($file in $jsonFiles) { try { Get-Content $file -Raw | ConvertFrom-Json | Out-Null } catch { $errors += "$file`: $($_.Exception.Message)" } }; if ($errors.Count -gt 0) { $errors | Out-File -FilePath $tmpFile -Encoding utf8 } else { "No JSON syntax errors found" | Out-File -FilePath $tmpFile -Encoding utf8 }; pixi run python scripts/process_lint_json.py jsonlint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run PSScriptAnalyzer on PowerShell files and output sorted findings
psscriptanalyzer:
    @echo "[PSScriptAnalyzer] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $psFiles = Get-ChildItem -Path . -Include "*.ps1","*.psm1","*.psd1" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.pixi|node_modules|\.git|target' } | ForEach-Object { $_.FullName }; if ($null -eq $psFiles -or @($psFiles).Count -eq 0) { Write-Host "[PSScriptAnalyzer] 0 findings (no PowerShell scripts found)"; 'No findings.' | Out-File -FilePath 'reports/txt/psscriptanalyzer_findings.txt' -Encoding utf8; @{ tool = 'psscriptanalyzer'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/psscriptanalyzer_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="psscriptanalyzer"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/psscriptanalyzer_findings.xml' -Encoding utf8; exit 0 }; if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) { Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $psFiles | ForEach-Object { Invoke-ScriptAnalyzer -Path $_ -Severity @('Error','Warning','Information') } | ForEach-Object { "$($_.ScriptPath):$($_.Line):$($_.Column): [$($_.Severity)] $($_.Message) ($($_.RuleName))" } | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py psscriptanalyzer --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Lint JavaScript files with ESLint
lint-js:
    @pixi run yarn eslint . --ext .js

# Fix JavaScript linting issues automatically
lint-js-fix:
    @pixi run yarn eslint . --ext .js --fix

# Lint Java files with PMD
lint-java:
    @java -cp "tools/pmd/conf;tools/pmd/lib/*" net.sourceforge.pmd.cli.PmdCli check -d intellicrack/scripts/ghidra -R tools/pmd/intellicrack-ruleset.xml -f text

# Format Java files with google-java-format
lint-java-fmt:
    @Get-ChildItem -Recurse -Path intellicrack -Filter *.java | ForEach-Object { Write-Host "Formatting: $($_.FullName)"; java -jar tools/google-java-format/google-java-format.jar --replace $_.FullName; if ($LASTEXITCODE -eq 0) { Write-Host "  ✓ Formatted" -ForegroundColor Green } else { Write-Host "  ✗ Error" -ForegroundColor Red } }

# Lint Markdown files with markdownlint
lint-md:
    @pixi run markdownlint "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Fix Markdown linting issues automatically
lint-md-fix:
    @pixi run markdownlint "**/*.md" --fix --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Lint all TOML files in the project (excluding third-party via eslint config)
lint-toml:
    @pixi run yarn eslint "**/*.toml"

# Fix TOML linting issues automatically for all TOML files
lint-toml-fix:
    @pixi run yarn eslint "**/*.toml" --fix

# Lint all YAML files in the project with yamllint
lint-yaml:
    @pixi run yamllint .

# Fix YAML linting issues (yamllint does not auto-fix, uses Prettier instead)
lint-yaml-fix:
    @echo "[YAML Format] Running Prettier for YAML formatting..."
    @pixi run yarn prettier --write "**/*.yaml" "**/*.yml" --ignore-unknown --log-level warn 2>&1 | Out-Null; Write-Host "[YAMLFMT] Done"

# Lint all file types (Python, Rust, Java, JavaScript, Markdown, TOML, YAML, JSON, Formatting)
lint-all:
    -@just lint
    -@just lint-rust
    -@just lint-java
    -@just lint-js
    -@just lint-md
    -@just lint-toml
    -@just lint-yaml
    -@just jsonlint
    @echo "All linting complete ✓"

# Lint Rust code with clippy (comprehensive - all lints)
lint-rust:
    @cargo clippy --manifest-path intellicrack-launcher/Cargo.toml --all-targets --all-features -- -W clippy::all -W clippy::pedantic -W clippy::nursery

# Format Rust code with rustfmt
# NOTE: Requires modern Rust toolchain via rustup (https://rustup.rs/)

# If you see "deprecated rustfmt" error, install rustup and run: rustup component add rustfmt
lint-rust-fmt:
    @echo "Formatting Rust code..."
    @rustup run stable cargo fmt --manifest-path intellicrack-launcher/Cargo.toml

# Check Rust formatting without applying changes
lint-rust-fmt-check:
    @echo "Checking Rust formatting..."
    @rustup run stable cargo fmt --manifest-path intellicrack-launcher/Cargo.toml -- --check

# Format Rust code
rustfmt:
    @echo "[Rust Format] Running..."
    @rustup run stable cargo fmt --manifest-path intellicrack-launcher/Cargo.toml 2>&1 | Out-Null; Write-Host "[RUSTFMT] Done"

# Format JS/TS files with Prettier
prettier:
    @echo "[Prettier] Running..."
    @pixi run yarn prettier --write "intellicrack/scripts/frida/**/*.js" "intellicrack/scripts/frida/**/*.ts" 2>&1 | Out-Null; Write-Host "[PRETTIER] Done"

# Format Java files with google-java-format
javafmt:
    @echo "[Java Format] Running..."
    @Get-ChildItem -Recurse -Path intellicrack/scripts/ghidra -Filter *.java -ErrorAction SilentlyContinue | ForEach-Object { java -jar tools/google-java-format/google-java-format.jar --replace $_.FullName 2>&1 | Out-Null }; Write-Host "[JAVAFMT] Done"

# Format JSON files with Prettier (respects .prettierignore)
jsonfmt:
    @echo "[JSON Format] Running..."
    @try { pixi run yarn prettier --write "**/*.json" --ignore-unknown --log-level warn 2>&1 | Out-Null; Write-Host "[JSONFMT] Done" } catch { Write-Host "[JSONFMT] Error: $_" -ForegroundColor Red }

# Format YAML files with Prettier (respects .prettierignore)
yamlfmt:
    @echo "[YAML Format] Running..."
    @try { pixi run yarn prettier --write "**/*.yaml" "**/*.yml" --ignore-unknown --log-level warn 2>&1 | Out-Null; Write-Host "[YAMLFMT] Done" } catch { Write-Host "[YAMLFMT] Error: $_" -ForegroundColor Red }

# Format TOML files with Prettier (uses prettier-plugin-toml)
tomlfmt:
    @echo "[TOML Format] Running..."
    @try { pixi run yarn prettier --write "**/*.toml" --ignore-unknown --log-level warn 2>&1 | Out-Null; Get-ChildItem -Recurse -Filter *.toml -File | Where-Object { $_.FullName -notmatch '[\\/](node_modules|\.pixi|\.venv|tools|build|dist)[\\/]' } | ForEach-Object { $c = [System.IO.File]::ReadAllText($_.FullName); $c = $c -replace "`r(?!`n)", "`n" -replace "`r`n", "`n"; [System.IO.File]::WriteAllText($_.FullName, $c) }; Write-Host "[TOMLFMT] Done" } catch { Write-Host "[TOMLFMT] Error: $_" -ForegroundColor Red }

# Format Markdown files with Prettier (respects .prettierignore)
mdfmt:
    @echo "[Markdown Format] Running..."
    @try { pixi run yarn prettier --write "**/*.md" --ignore-unknown --log-level warn 2>&1 | Out-Null; Write-Host "[MDFMT] Done" } catch { Write-Host "[MDFMT] Error: $_" -ForegroundColor Red }

# Fix Rust linting issues automatically
lint-rust-fix:
    @cargo clippy --manifest-path intellicrack-launcher/Cargo.toml --fix --allow-dirty --allow-staged -- -D warnings

# Fix all auto-fixable linting issues (Python, Rust, Java, JavaScript, Markdown, TOML, YAML, JSON, Formatting)

# Note: PMD does not support auto-fix (linting only), yamllint does not auto-fix (use Prettier instead)
lint-all-fix:
    -@just lint-fix
    -@just lint-rust-fix
    -@just lint-rust-fmt
    -@just lint-java-fmt
    -@just lint-js-fix
    -@just lint-md-fix
    -@just lint-toml-fix
    -@just jsonfmt
    @echo "All auto-fixable linting issues resolved ✓"

# ==================== GIT ====================

# Watch GitHub Actions CI runs in real-time
watch:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[GIT]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Checking gh CLI..."; try { $ghVersion = gh --version 2>&1 | Select-Object -First 1; if ($LASTEXITCODE -ne 0) { throw "gh CLI not found" } } catch { Write-Fail "gh CLI not installed: $_"; exit 1 }; Write-Step "Watching GitHub Actions..."; gh run watch

# Cleans Windows NUL file artifacts from the repository.
nul-cleanup:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[35m[NUL]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;35m=== NUL File Cleanup ===$e[0m`n"; Write-Step "Scanning for NUL file artifacts..."; try { $output = pixi run python scripts/clean_nul.py 2>&1; $outputStr = $output -join "`n"; if ($outputStr -match '(\d+)\s+file\(s\)\s+deleted') { $deleted = $matches[1] } else { $deleted = 0 }; if ($LASTEXITCODE -ne 0) { throw "Clean script failed" }; Write-Success "Cleanup complete ($deleted files removed)" } catch { Write-Fail "Cleanup failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;35m=== NUL Cleanup Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Generates project structure files (HTA and TXT).
generate-structure:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[34m[STRUCT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;34m=== Generating Structure Files ===$e[0m`n"; Write-Step "Running structure generator..."; try { $output = pixi run python scripts/generate_tree.py 2>&1; if ($LASTEXITCODE -ne 0) { throw "Generator script failed" }; Write-Success "Generator completed" } catch { Write-Fail "Generation failed: $_"; exit 1 }; Write-Step "Validating outputs..."; $htaPath = "IntellicrackStructure.hta"; $txtPath = "IntellicrackStructure.txt"; if (-not (Test-Path $htaPath)) { Write-Fail "HTA file not found: $htaPath"; exit 1 }; Write-Success "HTA: $htaPath"; if (-not (Test-Path $txtPath)) { Write-Fail "TXT file not found: $txtPath"; exit 1 }; Write-Success "TXT: $txtPath"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;34m=== Structure Generation Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Creates a quick WIP commit with automatic timestamp and pushes to origin.
# Runs NUL cleanup, structure generation, and knowledge map generation before committing.

# Skips git hooks for faster commits during development work.
git-commit:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[32m[GIT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;32m=== WIP Commit with Generated Files ===$e[0m`n"; Write-Step "Step 1/4: Running NUL cleanup..."; try { just nul-cleanup 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "NUL cleanup failed" }; Write-Success "NUL cleanup complete" } catch { Write-Fail "NUL cleanup failed: $_"; exit 1 }; Write-Step "Step 2/4: Generating structure files..."; try { just generate-structure 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "Structure generation failed" }; Write-Success "Structure files generated" } catch { Write-Fail "Structure generation failed: $_"; exit 1 }; Write-Step "Step 3/4: Generating knowledge map..."; try { just generate-map 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "Map generation failed" }; Write-Success "Knowledge map generated" } catch { Write-Fail "Map generation failed: $_"; exit 1 }; Write-Step "Step 4/4: Committing and pushing..."; $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; try { git add -A 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git add failed" }; Write-Success "Changes staged" } catch { Write-Fail "Staging failed: $_"; exit 1 }; try { git commit --no-verify -m "WIP: $timestamp" 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git commit failed" }; Write-Success "Committed: WIP: $timestamp" } catch { Write-Fail "Commit failed: $_"; exit 1 }; try { git push origin HEAD 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git push failed" }; Write-Success "Pushed to origin" } catch { Write-Fail "Push failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Commit Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Full commit with hooks - prompts for message, runs pre-commit hooks, pushes to origin
git-commit-hooks message:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[GIT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Step "Full commit with hooks..."; $commitMsg = '{{ message }}' -replace "'", "''"; Write-Step "Staging all changes..."; try { git add -A 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "git add failed" }; Write-Success "Changes staged" } catch { Write-Fail "Staging failed: $_"; exit 1 }; Write-Step "Committing with hooks..."; try { git commit -m $commitMsg 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "git commit failed (hooks may have failed)" }; Write-Success "Committed" } catch { Write-Fail "Commit failed: $_"; exit 1 }; Write-Step "Pushing to origin..."; try { git push origin HEAD 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "git push failed" }; Write-Success "Pushed to origin" } catch { Write-Fail "Push failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Commit Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# ==================== DOCUMENTATION ====================

# Generate Sphinx documentation
docs-build:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building Documentation ===$e[0m`n"; Write-Step "Running Sphinx build..."; try { pixi run sphinx-build -b html docs/source docs/build/html 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "sphinx-build failed with exit code $LASTEXITCODE" }; Write-Success "Documentation built" } catch { Write-Fail "Build failed: $_"; exit 1 }; Write-Step "Validating output..."; if (-not (Test-Path "docs/build/html/index.html")) { Write-Fail "index.html not found"; exit 1 }; Write-Success "Output validated: docs/build/html/index.html"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Documentation Built ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Clean documentation build
docs-clean:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; Write-Step "Cleaning documentation build..."; if (Test-Path "docs\build") { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue docs\build\*; Write-Success "Documentation build cleaned" } else { Write-Success "Nothing to clean" }

# Regenerate API documentation from code
docs-apidoc:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Generating API documentation..."; try { pixi run sphinx-apidoc -f -o docs/source intellicrack 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "sphinx-apidoc failed" }; Write-Success "API documentation generated" } catch { Write-Fail "Generation failed: $_"; exit 1 }

# Full documentation rebuild
docs-rebuild: docs-clean docs-apidoc docs-build
    @$e = [char]27; Write-Host "`n$e[1;32m=== Documentation Rebuild Complete ===$e[0m"; Write-Host "View at: docs/build/html/index.html`n"

# Open documentation in browser (Windows)
docs-open:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $docPath = "docs\build\html\index.html"; if (-not (Test-Path $docPath)) { Write-Fail "Documentation not found. Run 'just docs-build' first."; exit 1 }; Write-Step "Opening documentation in browser..."; Start-Process $docPath; Write-Success "Opened in browser"

# Build PDF documentation
docs-pdf:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building PDF Documentation ===$e[0m`n"; Write-Step "Generating LaTeX files..."; try { pixi run sphinx-build -b latex docs/source docs/build/latex 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "sphinx-build latex failed" }; Write-Success "LaTeX files generated in docs/build/latex/" } catch { Write-Fail "Generation failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== PDF Build Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Scanner recipes
# Builds the binary scanner tool for code analysis.

# Creates a scanner executable in the scripts/scanner/target directory.
build-scanner:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[SCANNER]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building Scanner ===$e[0m`n"; Write-Step "Building with maximum optimization..."; $origDir = Get-Location; try { Set-Location scripts/scanner; $env:RUSTFLAGS = "-C target-cpu=native -C opt-level=3 -C codegen-units=1 -C strip=symbols"; cargo build --release 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }; Write-Success "Build complete" } catch { Write-Fail "Build failed: $_"; Set-Location $origDir; exit 1 } finally { Set-Location $origDir }; Write-Step "Validating build artifact..."; $exePath = "scripts\scanner\target\release\scanner.exe"; if (-not (Test-Path $exePath)) { Write-Fail "scanner.exe not found"; exit 1 }; $exeSize = [math]::Round((Get-Item $exePath).Length / 1KB, 1); Write-Success "Artifact validated: scanner.exe ($exeSize KB)"; Write-Step "Creating shortcut..."; try { $WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("$PWD\Scanner.lnk"); $Shortcut.TargetPath = "$PWD\$exePath"; $Shortcut.WorkingDirectory = "$PWD"; $Shortcut.IconLocation = "C:\Windows\System32\shell32.dll,22"; $Shortcut.Save(); Write-Success "Shortcut created: Scanner.lnk" } catch { Write-Fail "Shortcut creation failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Scanner Build Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Runs the binary scanner on the Intellicrack source code to analyze potential issues.

# Scans the codebase and reports findings about code quality and security.
scan:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[SCAN]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $exePath = "scripts\scanner\target\release\scanner.exe"; if (-not (Test-Path $exePath)) { Write-Fail "Scanner not built. Run 'just build-scanner' first."; exit 1 }; Write-Step "Running code scanner..."; try { & $exePath -d intellicrack --format console 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Scanner failed with exit code $LASTEXITCODE" }; Write-Success "Scan complete" } catch { Write-Fail "Scan failed: $_"; exit 1 }

# Check documentation links
docs-linkcheck:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Step "Checking documentation links..."; try { pixi run sphinx-build -b linkcheck docs/source docs/build/linkcheck 2>&1 | ForEach-Object { Write-Host "  $_" }; Write-Success "Link check complete. Results in docs/build/linkcheck/output.txt" } catch { Write-Fail "Link check failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mLink check complete$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Generate interactive knowledge graph visualization of codebase architecture.

# Creates an interactive HTML visualization (IntellicrackKnowledgeGraph.html) at project root.
generate-map:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[MAP]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Generating Knowledge Map ===$e[0m`n"; Write-Step "Running map generator..."; $scriptPath = "scripts\knowledge-graph\visualize_architecture.py"; try { $output = pixi run python $scriptPath --layout hierarchical 2>&1; if ($LASTEXITCODE -ne 0) { throw "Map generation failed" }; Write-Success "Map generated" } catch { Write-Fail "Generation failed: $_"; exit 1 }; Write-Step "Validating outputs..."; $htmlPath = "IntellicrackKnowledgeGraph.html"; $kgDir = "scripts\knowledge-graph"; $graphmlPath = "$kgDir\IntellicrackKnowledgeGraph.graphml"; $dotPath = "$kgDir\IntellicrackKnowledgeGraph.dot"; if (-not (Test-Path $htmlPath)) { Write-Fail "HTML not found: $htmlPath"; exit 1 }; Write-Success "HTML: $htmlPath"; if (Test-Path $graphmlPath) { Write-Success "GraphML: $graphmlPath" }; if (Test-Path $dotPath) { Write-Success "DOT: $dotPath" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;36m=== Knowledge Map Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Open knowledge map in browser (Windows)
open-map:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[MAP]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $htmlPath = "IntellicrackKnowledgeGraph.html"; if (-not (Test-Path $htmlPath)) { Write-Fail "Knowledge map not found. Run 'just generate-map' first."; exit 1 }; Write-Step "Opening knowledge map in browser..."; Start-Process $htmlPath; Write-Success "Opened in browser"

# ==================== COMPREHENSIVE REPORTS ====================
# Runs all development tools in batches of 8 for controlled resource usage.

# Executes tools in sequential batches (8 at a time) with progress tracking and results summary.
run-all-tools:
    @$ErrorActionPreference = 'SilentlyContinue'; Write-Host "`n$([char]27)[1;36m=== Running All Dev Tools (37 tools) in batches of 8 ===$([char]27)[0m`n"; $tools = @(@{N='Ruff Fmt';R='ruff-fmt';F=$true}, @{N='Rustfmt';R='rustfmt';F=$true}, @{N='Prettier';R='prettier';F=$true}, @{N='Javafmt';R='javafmt';F=$true}, @{N='JSONfmt';R='jsonfmt';F=$true}, @{N='YAMLfmt';R='yamlfmt';F=$true}, @{N='TOMLfmt';R='tomlfmt';F=$true}, @{N='MDfmt';R='mdfmt';F=$true}, @{N='Ruff';R='ruff';F=$false}, @{N='Biome';R='biome';F=$false}, @{N='JSONLint';R='jsonlint';F=$false}, @{N='ShellCheck';R='shellcheck';F=$false}, @{N='Clippy';R='clippy';F=$false}, @{N='Cargo Audit';R='cargo-audit';F=$false}, @{N='Cargo Deny';R='cargo-deny';F=$false}, @{N='ESLint';R='eslint';F=$false}, @{N='Vulture';R='vulture';F=$false}, @{N='Dead';R='dead';F=$false}, @{N='Ty';R='ty';F=$false}, @{N='Bandit';R='bandit';F=$false}, @{N='Flake8';R='flake8';F=$false}, @{N='McCabe';R='mccabe';F=$false}, @{N='Radon';R='radon';F=$false}, @{N='Xenon';R='xenon';F=$false}, @{N='Markdown';R='mdlint';F=$false}, @{N='YAML';R='yamllint';F=$false}, @{N='Uncalled';R='uncalled';F=$false}, @{N='Deadcode';R='deadcode';F=$false}, @{N='Knip';R='knip';F=$false}, @{N='PMD';R='pmd';F=$false}, @{N='Checkstyle';R='checkstyle';F=$false}, @{N='PSScript';R='psscriptanalyzer';F=$false}, @{N='Pydocstyle';R='pydocstyle';F=$false}, @{N='Wemake';R='wemake';F=$false}, @{N='Pyright';R='pyright';F=$false}, @{N='Darglint';R='darglint';F=$false}, @{N='Mypy';R='mypy';F=$false}); $batchSize = 8; $results = @{}; $globalStart = Get-Date; for ($i = 0; $i -lt $tools.Count; $i += $batchSize) { $startIdx = $i; $endIdx = [Math]::Min($i + $batchSize - 1, $tools.Count - 1); $batch = $tools[$startIdx..$endIdx]; $batchNum = [Math]::Floor($i / $batchSize) + 1; $totalBatches = [Math]::Ceiling($tools.Count / $batchSize); Write-Host "$([char]27)[36m[Batch $batchNum/$totalBatches]$([char]27)[0m Running $($batch.Count) tools..."; $batchNames = $batch | ForEach-Object { $_.N }; Write-Host "  Tools: $($batchNames -join ', ')"; foreach ($tool in $batch) { try { $toolStart = Get-Date; $output = & { just $tool.R 2>&1 }; $duration = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 1); $findings = 0; $outputStr = $output -join "`n"; if (-not $tool.F -and $outputStr -match '(\d+)\s+findings') { $findings = [int]$matches[1] }; $results[$tool.R] = @{ Name = $tool.N; Findings = $findings; Duration = $duration; Success = $true; IsFormatter = $tool.F }; if ($tool.F) { Write-Host "  $([char]0x2714) $($tool.N): Done in ${duration}s" -ForegroundColor Green } else { Write-Host "  $([char]0x2714) $($tool.N): Completed in ${duration}s with $($findings) findings" -ForegroundColor Green } } catch { $duration = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 1); $results[$tool.R] = @{ Name = $tool.N; Findings = 0; Duration = $duration; Success = $false; IsFormatter = $tool.F }; Write-Host "  $([char]0x2718) $($tool.N): Failed after ${duration}s - $_" -ForegroundColor Red } }; $overallComplete = [Math]::Min($i + $batchSize, $tools.Count); $overallPercent = [Math]::Round(($overallComplete / $tools.Count) * 100); $overallBar = [System.Text.StringBuilder]::new(); $overallBarLen = [Math]::Floor($overallPercent / 2); for ($j = 0; $j -lt $overallBarLen; $j++) { $overallBar.Append("$([char]0x2588)") | Out-Null }; for ($j = $overallBarLen; $j -lt 50; $j++) { $overallBar.Append("$([char]0x2591)") | Out-Null }; Write-Host "$([char]27)[90mProgress:$([char]27)[0m [$($overallBar.ToString())] $overallPercent% ($overallComplete/$($tools.Count))"; Write-Host ""; }; Write-Host "`n$([char]27)[90m$('-' * 60)$([char]27)[0m"; $totalTime = [Math]::Round(((Get-Date) - $globalStart).TotalSeconds, 1); $totalFindings = ($results.Values | ForEach-Object { $_.Findings } | Measure-Object -Sum).Sum; $passedCount = ($results.Values | Where-Object { $_.Success -and $_.Findings -eq 0 }).Count; Write-Host "Time: $([char]27)[36m${totalTime}s$([char]27)[0m | Findings: $([char]27)[33m$totalFindings$([char]27)[0m | Passed: $([char]27)[32m$passedCount/$($tools.Count)$([char]27)[0m"; $failedCount = ($results.Values | Where-Object { -not $_.Success }).Count; if ($failedCount -gt 0) { Write-Host "Failed: $([char]27)[31m$failedCount$([char]27)[0m`n"; $results.Values | Where-Object { -not $_.Success } | ForEach-Object { Write-Host "  $([char]0x2718) $($_.Name): Failed" -ForegroundColor Red } }; exit 0
