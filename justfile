# Intellicrack Testing Commands

# Configure shell for Windows
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# ==================== INSTALLATION ====================

# Complete installation with all post-install tasks
install:
    @echo "Installing Intellicrack dependencies..."
    if (Test-Path "pixi.lock") { Remove-Item -Force "pixi.lock"; Write-Output "Removed existing pixi.lock" }
    @echo "Installing dependencies with pixi..."
    pixi install
    @echo "Generating requirements.txt for Dependabot..."
    pixi run generate-requirements
    @echo "requirements.txt generated"
    @echo ""
    @echo "Installing Rustup (if needed)..."
    @just install-rustup
    @echo ""
    @echo "Updating Rust toolchain..."
    rustup update stable
    @echo ""
    @echo "Installing JDK 21..."
    @just install-jdk
    @echo ""
    @echo "Installing Ghidra..."
    @just install-ghidra
    @echo ""
    @echo "Installing radare2..."
    @just install-radare2
    @echo ""
    @echo "Installing QEMU..."
    @just install-qemu
    @echo ""
    @echo "Installing Yarn 4 and Node.js dependencies (eslint, prettier, knip)..."
    pixi run install-yarn-deps
    @echo ""
    @echo "Building Rust launcher..."
    pixi run create-shortcut
    @echo ""
    @echo "Installation complete!"

# Remove pixi environment and node_modules
uninstall:
    @echo "Removing pixi environment..."
    pixi clean
    if (Test-Path "pixi.lock") { Remove-Item -Force "pixi.lock" }
    @echo "Removing node_modules..."
    if (Test-Path "node_modules") { Remove-Item -Recurse -Force "node_modules" }
    if (Test-Path "yarn.lock") { Remove-Item -Force "yarn.lock" }
    @echo "Uninstall complete!"

# Install Rustup if not already installed
install-rustup:
    $rustupInstalled = & { try { rustup --version 2>&1 | Out-Null; $true } catch { $false } }; if ($rustupInstalled) { Write-Output "Rustup already installed" } else { Write-Output "Installing Rustup via winget..."; winget install --id Rustlang.Rustup -e --silent --accept-source-agreements --accept-package-agreements | Out-Null }; Write-Output "Rustup check complete"; exit 0

# Install JDK 21 to system if not already installed
install-jdk:
    $javaVersion = & { try { java -version 2>&1 | Select-String -Pattern 'version' | ForEach-Object { $_.Line } } catch { $null } }; if ($javaVersion -match '21\.\d+\.\d+') { Write-Output "JDK 21 already installed: $javaVersion" } else { Write-Output "Installing JDK 21 via winget..."; winget install --id Oracle.JDK.21 -e --silent --accept-source-agreements --accept-package-agreements | Out-Null }; Write-Output "JDK 21 check complete"; exit 0

# Install latest Ghidra to tools/ghidra directory
install-ghidra:
    if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" | Out-Null }; $existingGhidra = Get-ChildItem -Path "tools" -Recurse -Filter "ghidraRun.bat" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($existingGhidra) { Write-Output "Ghidra already installed at $($existingGhidra.DirectoryName)"; exit 0 }; Write-Output "Fetching latest Ghidra release..."; $release = Invoke-RestMethod -Uri "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"; $asset = $release.assets | Where-Object { $_.name -match '\.zip$' -and $_.name -notmatch 'DEV' } | Select-Object -First 1; if (!$asset) { Write-Error "Could not find Ghidra release asset"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $zipPath = Join-Path "tools" $fileName; Write-Output "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath; Write-Output "Extracting Ghidra..."; $tempExtract = Join-Path "tools" "ghidra_temp"; if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract; $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1; if ($extractedDir) { Move-Item -Path $extractedDir.FullName -Destination (Join-Path "tools" "ghidra") }; Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force; Write-Output "Ghidra installed to tools\ghidra ✓"

# Install latest radare2 to tools/radare2 directory
install-radare2:
    if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" | Out-Null }; $existingRadare2 = Get-ChildItem -Path "tools" -Recurse -Filter "radare2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingRadare2) { $existingRadare2 = Get-ChildItem -Path "tools" -Recurse -Filter "r2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingRadare2) { Write-Output "radare2 already installed at $($existingRadare2.DirectoryName)"; exit 0 }; Write-Output "Fetching latest radare2 release..."; $release = Invoke-RestMethod -Uri "https://api.github.com/repos/radareorg/radare2/releases/latest"; $asset = $release.assets | Where-Object { $_.name -match 'w64\.zip$' -or $_.name -match 'windows.*\.zip$' } | Select-Object -First 1; if (!$asset) { Write-Error "Could not find radare2 Windows release asset"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $zipPath = Join-Path "tools" $fileName; Write-Output "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath; Write-Output "Extracting radare2..."; $tempExtract = Join-Path "tools" "radare2_temp"; if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract; $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1; if ($extractedDir) { Move-Item -Path $extractedDir.FullName -Destination (Join-Path "tools" "radare2") } else { Move-Item -Path $tempExtract -Destination (Join-Path "tools" "radare2") }; Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force; Write-Output "radare2 installed to tools\radare2 ✓"

# Install latest QEMU to tools/qemu directory
install-qemu:
    if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" | Out-Null }; $existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingQemu) { $existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-img.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingQemu) { Write-Output "QEMU already installed at $($existingQemu.DirectoryName)"; exit 0 }; Write-Output "Fetching latest QEMU release..."; $html = Invoke-WebRequest -Uri "https://qemu.weilnetz.de/w64/" -UseBasicParsing; $links = $html.Links | Where-Object { $_.href -match 'qemu-w64-setup-.*\.exe$' } | Sort-Object { $_.href } -Descending | Select-Object -First 1; if (!$links) { Write-Error "Could not find QEMU installer"; exit 1 }; $installerUrl = "https://qemu.weilnetz.de/w64/$($links.href)"; $installerName = $links.href; $installerPath = Join-Path "tools" $installerName; Write-Output "Downloading $installerName..."; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath; Write-Output "Installing QEMU to tools\qemu..."; $installDir = Join-Path (Get-Location) "tools\qemu"; Start-Process -FilePath $installerPath -ArgumentList "/S", "/D=$installDir" -Wait -NoNewWindow; Remove-Item $installerPath -Force; Write-Output "QEMU installed to tools\qemu ✓"

# ==================== BUILD ====================

# Build Rust launcher in release mode with maximum optimization
build-rust:
    @echo "Building Rust launcher with maximum optimization..."
    $env:RUSTFLAGS="-C target-cpu=native"; cargo build --release --manifest-path intellicrack-launcher/Cargo.toml
    @echo "Creating shortcut with icon..."
    $WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("$PWD\Intellicrack.lnk"); $Shortcut.TargetPath = "$PWD\intellicrack-launcher\target\release\Intellicrack.exe"; $Shortcut.IconLocation = "$PWD\intellicrack\assets\icon.ico"; $Shortcut.WorkingDirectory = "$PWD"; $Shortcut.Save()
    @echo "Rust launcher built with maximum optimization ✓"
    @echo "Shortcut created: Intellicrack.lnk"

# Build Rust launcher in debug mode
build-rust-debug:
    @echo "Building Rust launcher (debug)..."
    cargo build --manifest-path intellicrack-launcher/Cargo.toml
    @echo "Rust launcher debug build complete ✓"

# Clean Rust build artifacts
build-rust-clean:
    @echo "Cleaning Rust build artifacts..."
    cargo clean --manifest-path intellicrack-launcher/Cargo.toml
    @echo "Rust build artifacts cleaned ✓"

# Build and run Rust tests
build-rust-test:
    @echo "Building and testing Rust launcher..."
    cargo test --manifest-path intellicrack-launcher/Cargo.toml
    @echo "Rust tests complete ✓"

# Build Rust launcher with optimizations and copy to project root
build-rust-optimized:
    @echo "Building optimized Rust launcher..."
    cargo build --release --manifest-path intellicrack-launcher/Cargo.toml
    Copy-Item -Path "intellicrack-launcher\target\release\intellicrack-launcher.exe" -Destination "intellicrack-launcher.exe" -Force
    @echo "Optimized launcher copied to project root ✓"

# ==================== TESTING ====================

# Quick unit tests - validates REAL functionality
test:
    pixi run pytest tests/unit -v --tb=short

# Full test suite - comprehensive REAL data validation
test-all:
    pixi run pytest tests/ -v

# Coverage report - ensures 95%+ REAL code coverage
test-coverage:
    pixi run pytest --cov=intellicrack --cov-report=html --cov-report=term --cov-fail-under=95 tests/

# Test specific module with REAL data
test-module module:
    pixi run pytest tests/unit/{{module}} -v

# Performance benchmarks on REAL operations
test-bench:
    pixi run pytest tests/performance --benchmark-only

# Security tests with REAL attack vectors
test-security:
    pixi run pytest tests/security -v

# Integration tests with REAL workflows
test-integration:
    pixi run pytest tests/integration -v -m integration

# Functional tests with REAL binaries
test-functional:
    pixi run pytest tests/functional -v -m functional

# Quick smoke test
test-smoke:
    pixi run pytest tests/unit -k "not slow" --tb=short -v

# Test with coverage for specific module
test-module-cov module:
    pixi run pytest --cov=intellicrack.{{module}} --cov-report=term-missing tests/unit/{{module}}

# Generate HTML coverage report
test-cov-html:
    pixi run pytest --cov=intellicrack --cov-report=html tests/
    @echo "Coverage report generated in coverage_html_report/"

# Run tests in parallel
test-parallel:
    pixi run pytest -n auto tests/

# Test only failed tests from last run
test-failed:
    pixi run pytest --lf tests/

# Test with verbose output
test-verbose:
    pixi run pytest -vvv tests/

# Clean test artifacts
test-clean:
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .pytest_cache
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue coverage_html_report
    Remove-Item -Force -ErrorAction SilentlyContinue .coverage
    Remove-Item -Force -ErrorAction SilentlyContinue *.pyc
    Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force

# Install test dependencies
test-install:
    pip install pytest pytest-cov pytest-benchmark pytest-asyncio pytest-qt pytest-xdist pytest-mock

# Verify no mocks or fake data
test-verify-real:
    pixi run python tests/utils/verify_no_mocks.py
    @echo "All tests use REAL data ✓"

# Lint code with ruff
lint:
    pixi run ruff check intellicrack/
    pixi run ruff format --check intellicrack/

# Fix linting issues automatically
lint-fix:
    pixi run ruff check --fix intellicrack/
    pixi run ruff format intellicrack/

# Format code with ruff
format-ruff:
    pixi run ruff format intellicrack/

# Detect dead code with vulture and output sorted findings (--min-confidence 60 to catch unused code that might be dead)
vulture:
    @echo "[Vulture] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run vulture intellicrack/ tests/ --min-confidence 60 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py vulture --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Upgrade Python syntax to newer versions
pyupgrade:
    Get-ChildItem -Path .\intellicrack\ -Recurse -Include "*.py" | ForEach-Object { pixi run pyupgrade --py312-plus $_.FullName }
    Get-ChildItem -Path .\tests\ -Recurse -Include "*.py" | ForEach-Object { pixi run pyupgrade --py312-plus $_.FullName }

# Apply AI-powered code suggestions
sourcery:
    pixi run sourcery review intellicrack
    pixi run sourcery review tests

# Check docstring validity with darglint and output sorted findings
darglint:
    @echo "[Darglint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run darglint intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py darglint --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Check code line statistics with pygount
pygount:
    pixi run pygount intellicrack --format=summary
    pixi run pygount tests --format=summary

# Check Python packaging best practices with pyroma
pyroma:
    pixi run pyroma .

# Detect dead code and output sorted findings
dead:
    @echo "[Dead Code] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run dead 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py dead --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run type checking with ty and output sorted findings
ty:
    @echo "[Ty Type] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run ty check intellicrack tests --output-format concise 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py ty $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run type checking with pyright and output sorted findings
pyright:
    @echo "[Pyright] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run pyright --outputjson 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py pyright $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run type checking with mypy and output sorted findings
mypy:
    @echo "[Mypy] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run mypy intellicrack 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py mypy --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Security linting with bandit and output sorted findings
bandit:
    @echo "[Bandit Security] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run bandit -r intellicrack/ tests/ -c pyproject.toml 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py bandit --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run ruff linter and output sorted findings (uses native JSON output for speed)
ruff:
    @echo "[Ruff Linter] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run ruff check intellicrack/ tests/ --output-format=json -o $tmpFile 2>&1 | Out-Null; pixi run python scripts/process_lint_json.py ruff $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run ruff format check (no output file)
ruff-fmt:
    @echo "[Ruff Format] Running..."
    $output = pixi run ruff format --check intellicrack/ tests/ 2>&1 | Out-String; $lines = $output -split "`n" | Where-Object { $_ -match 'Would reformat:' -or ($_ -match '^\S+\.py$' -and $_ -notmatch '^(All checked|[0-9]+ files)') }; $cnt = @($lines).Count; Write-Host "[Ruff Format] $cnt findings"

# Run clippy and output sorted findings
clippy:
    @echo "[Rust Clippy] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); cargo clippy --manifest-path intellicrack-launcher/Cargo.toml --all-targets --all-features -- -W clippy::all -W clippy::pedantic -W clippy::nursery 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py clippy --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run markdownlint and output sorted findings
mdlint:
    @echo "[Markdown Lint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run markdownlint "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py markdownlint --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run yamllint and output sorted findings
yamllint:
    @echo "[YAML Lint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run yamllint . 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py yamllint --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Detect uncalled functions with uncalled and output sorted findings
uncalled:
    @echo "[Uncalled] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run uncalled --how both intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py uncalled --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Detect dead code with deadcode and output sorted findings
deadcode:
    @echo "[Deadcode] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run deadcode intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py deadcode --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Detect unused JS/TS exports with knip and output sorted findings
knip:
    @echo "[Knip JS/TS] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NO_COLOR = '1'; $tmpFile = [System.IO.Path]::GetTempFileName(); $output = yarn run knip --no-progress --reporter json 2>&1 | Out-String; $jsonMatch = [regex]::Match($output, '\{"files":\[.*\],"issues":\[.*\]\}'); if ($jsonMatch.Success) { $jsonMatch.Value | Out-File -FilePath $tmpFile -Encoding utf8 } else { '{"files":[],"issues":[]}' | Out-File -FilePath $tmpFile -Encoding utf8 }; pixi run python scripts/process_lint_json.py knip $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run PMD Java analysis and output sorted findings
pmd:
    @echo "[PMD Java] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); java -cp "tools/pmd/lib/*" net.sourceforge.pmd.cli.PmdCli check -d intellicrack/scripts/ghidra -R tools/pmd/intellicrack-ruleset.xml -f text 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py pmd --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run checkstyle Java analysis and output sorted findings
checkstyle:
    @echo "[Checkstyle Java] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $javaFiles = Get-ChildItem -Path intellicrack/scripts/ghidra -Filter "*.java" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }; if ($null -eq $javaFiles -or @($javaFiles).Count -eq 0) { Write-Host "[Checkstyle Java] 0 findings"; 'No findings.' | Out-File -FilePath 'reports/txt/checkstyle_findings.txt' -Encoding utf8; @{ tool = 'checkstyle'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/checkstyle_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="checkstyle"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/checkstyle_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); java -jar .pixi/envs/default/libexec/checkstyle/checkstyle.jar -c checkstyle.xml $javaFiles 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py checkstyle --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run ESLint on JavaScript files and output sorted findings (JS only - uses native JSON output for speed)
eslint:
    @echo "[ESLint JS] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NO_COLOR = '1'; $tmpFile = [System.IO.Path]::GetTempFileName(); $result = yarn eslint "intellicrack/**/*.js" --format=json 2>&1 | Out-String; $jsonLine = ($result -split "`n" | Where-Object { $_.Trim().StartsWith('[') }) -join "`n"; if ($jsonLine) { $jsonLine | Out-File -FilePath $tmpFile -Encoding utf8 } else { '[]' | Out-File -FilePath $tmpFile -Encoding utf8 }; pixi run python scripts/process_lint_json.py eslint $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run Biome on JavaScript files and output sorted findings (uses text parsing since JSON is unreliable)
biome:
    @echo "[Biome JS] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NO_COLOR = '1'; $tmpFile = [System.IO.Path]::GetTempFileName(); yarn biome lint intellicrack/scripts/frida --max-diagnostics=5000 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py biome --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run cargo-audit for Rust security vulnerabilities and output sorted findings
cargo-audit:
    @echo "[Cargo Audit] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $crateDir = Get-ChildItem -Path . -Filter "Cargo.toml" -Recurse | Where-Object { $_.DirectoryName -notmatch '\.pixi|node_modules|target' } | Select-Object -First 1; if (-not $crateDir) { Write-Host "[Cargo Audit] 0 findings (no Cargo.toml found)"; 'No findings.' | Out-File -FilePath 'reports/txt/cargo_audit_findings.txt' -Encoding utf8; @{ tool = 'cargo-audit'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/cargo_audit_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="cargo-audit"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/cargo_audit_findings.xml' -Encoding utf8; exit 0 }; Push-Location $crateDir.DirectoryName; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run cargo-audit audit 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; Pop-Location; pixi run python scripts/process_lint_json.py cargo_audit --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run cargo-deny for Rust dependency policy enforcement and output sorted findings
cargo-deny:
    @echo "[Cargo Deny] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $crateDir = Get-ChildItem -Path . -Filter "Cargo.toml" -Recurse | Where-Object { $_.DirectoryName -notmatch '\.pixi|node_modules|target' } | Select-Object -First 1; if (-not $crateDir) { Write-Host "[Cargo Deny] 0 findings (no Cargo.toml found)"; 'No findings.' | Out-File -FilePath 'reports/txt/cargo_deny_findings.txt' -Encoding utf8; @{ tool = 'cargo-deny'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/cargo_deny_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="cargo-deny"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/cargo_deny_findings.xml' -Encoding utf8; exit 0 }; Push-Location $crateDir.DirectoryName; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run cargo-deny check 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; Pop-Location; pixi run python scripts/process_lint_json.py cargo_deny --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run shellcheck on shell scripts and output sorted findings
shellcheck:
    @echo "[ShellCheck] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $shFiles = Get-ChildItem -Path . -Include "*.sh","*.bash" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.pixi|node_modules|\.git|target' } | ForEach-Object { $_.FullName }; if ($null -eq $shFiles -or @($shFiles).Count -eq 0) { Write-Host "[ShellCheck] 0 findings (no shell scripts found)"; 'No findings.' | Out-File -FilePath 'reports/txt/shellcheck_findings.txt' -Encoding utf8; @{ tool = 'shellcheck'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/shellcheck_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="shellcheck"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/shellcheck_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); pixi run shellcheck --format=gcc $shFiles 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py shellcheck --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run JSON validation on JSON files (uses fd to respect .gitignore)
jsonlint:
    @echo "[JSONLint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $jsonFiles = fd -e json --type f --exclude 'package-lock.json' --exclude 'pixi.lock' --exclude 'reports' 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }; if ($null -eq $jsonFiles -or @($jsonFiles).Count -eq 0) { Write-Host "[JSONLint] 0 findings (no JSON files found)"; 'No findings.' | Out-File -FilePath 'reports/txt/jsonlint_findings.txt' -Encoding utf8; @{ tool = 'jsonlint'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/jsonlint_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="jsonlint"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/jsonlint_findings.xml' -Encoding utf8; exit 0 }; $filesList = @($jsonFiles) -join "`n"; $tmpFile = [System.IO.Path]::GetTempFileName(); $pyLines = @("import json, sys", "errors = []", "files = sys.stdin.read().strip().split('\\n')", "for path in files:", "    if not path:", "        continue", "    try:", "        with open(path, 'r', encoding='utf-8') as fp:", "            json.load(fp)", "    except json.JSONDecodeError as e:", "        errors.append(f'{path}:{e.lineno}:{e.colno}: {e.msg}')", "    except Exception as e:", "        errors.append(f'{path}:1:1: {type(e).__name__}: {e}')", "for err in errors:", "    print(err)"); $pyScript = $pyLines -join "`n"; $pyScript | Out-File -FilePath '_jsonlint_tmp.py' -Encoding utf8 -NoNewline; $filesList | pixi run python _jsonlint_tmp.py 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; Remove-Item '_jsonlint_tmp.py' -Force; pixi run python scripts/process_lint_json.py jsonlint --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Run PSScriptAnalyzer on PowerShell files and output sorted findings
psscriptanalyzer:
    @echo "[PSScriptAnalyzer] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $psFiles = Get-ChildItem -Path . -Include "*.ps1","*.psm1","*.psd1" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.pixi|node_modules|\.git|target' } | ForEach-Object { $_.FullName }; if ($null -eq $psFiles -or @($psFiles).Count -eq 0) { Write-Host "[PSScriptAnalyzer] 0 findings (no PowerShell scripts found)"; 'No findings.' | Out-File -FilePath 'reports/txt/psscriptanalyzer_findings.txt' -Encoding utf8; @{ tool = 'psscriptanalyzer'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/psscriptanalyzer_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="psscriptanalyzer"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/psscriptanalyzer_findings.xml' -Encoding utf8; exit 0 }; if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) { Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck }; $tmpFile = [System.IO.Path]::GetTempFileName(); $psFiles | ForEach-Object { Invoke-ScriptAnalyzer -Path $_ -Severity @('Error','Warning','Information') } | ForEach-Object { "$($_.ScriptPath):$($_.Line):$($_.Column): [$($_.Severity)] $($_.Message) ($($_.RuleName))" } | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py psscriptanalyzer --text $tmpFile; Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

# Lint JavaScript files with ESLint
lint-js:
    pixi run yarn eslint . --ext .js

# Fix JavaScript linting issues automatically
lint-js-fix:
    pixi run yarn eslint . --ext .js --fix

# Lint Java files with PMD
lint-java:
    java -cp "tools/pmd/conf;tools/pmd/lib/*" net.sourceforge.pmd.cli.PmdCli check -d intellicrack/scripts/ghidra -R tools/pmd/intellicrack-ruleset.xml -f text

# Format Java files with google-java-format
lint-java-fix:
    Get-ChildItem -Recurse -Path intellicrack -Filter *.java | ForEach-Object { Write-Host "Formatting: $($_.FullName)"; java -jar tools/google-java-format/google-java-format.jar --replace $_.FullName; if ($LASTEXITCODE -eq 0) { Write-Host "  ✓ Formatted" -ForegroundColor Green } else { Write-Host "  ✗ Error" -ForegroundColor Red } }

# Lint Markdown files with markdownlint
lint-md:
    pixi run markdownlint "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Fix Markdown linting issues automatically
lint-md-fix:
    pixi run markdownlint "**/*.md" --fix --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Lint all TOML files in the project (excluding third-party via eslint config)
lint-toml:
    yarn eslint "**/*.toml"

# Fix TOML linting issues automatically for all TOML files
lint-toml-fix:
    yarn eslint "**/*.toml" --fix

# Lint all YAML files in the project with yamllint
lint-yaml:
    pixi run yamllint .

# Fix YAML linting issues (yamllint does not auto-fix, this runs lint only)
lint-yaml-fix:
    @echo "yamllint does not support auto-fix. Use Prettier for YAML formatting."
    @just format-fix

# Lint all JSON files in the project with Prettier
lint-json:
    yarn prettier --check "**/*.json"

# Fix JSON linting issues automatically with Prettier
lint-json-fix:
    yarn prettier --write "**/*.json"

# Check formatting with Prettier for all supported files
format:
    yarn prettier --check "**/*.{js,md,toml,yaml,yml,json}"

# Fix formatting with Prettier for all supported files
format-fix:
    yarn prettier --write "**/*.{js,md,toml,yaml,yml,json}"

# Lint all file types (Python, Rust, Java, JavaScript, Markdown, TOML, YAML, JSON, Formatting)
lint-all:
    -@just lint
    -@just lint-rust-all
    -@just lint-java
    -@just lint-js
    -@just lint-md
    -@just lint-toml
    -@just lint-yaml
    -@just lint-json
    -@just format
    @echo "All linting complete ✓"

# Lint Rust code with clippy (comprehensive - all lints)
lint-rust:
    cargo clippy --manifest-path intellicrack-launcher/Cargo.toml --all-targets --all-features -- -W clippy::all -W clippy::pedantic -W clippy::nursery

# Lint Rust code with clippy (basic - default warnings only)
lint-rust-basic:
    cargo clippy --manifest-path intellicrack-launcher/Cargo.toml -- -D warnings

# Format Rust code with rustfmt
# NOTE: Requires modern Rust toolchain via rustup (https://rustup.rs/)
# If you see "deprecated rustfmt" error, install rustup and run: rustup component add rustfmt
lint-rust-fmt:
    @echo "Formatting Rust code..."
    rustup run stable cargo fmt --manifest-path intellicrack-launcher/Cargo.toml

# Check Rust formatting without applying changes
lint-rust-fmt-check:
    @echo "Checking Rust formatting..."
    rustup run stable cargo fmt --manifest-path intellicrack-launcher/Cargo.toml -- --check

# Fix Rust linting issues automatically
lint-rust-fix:
    cargo clippy --manifest-path intellicrack-launcher/Cargo.toml --fix --allow-dirty --allow-staged -- -D warnings

# All Rust linting and formatting
lint-rust-all: lint-rust lint-rust-fmt-check
    @echo "Rust linting and formatting complete ✓"

# Fix all auto-fixable linting issues (Python, Rust, Java, JavaScript, Markdown, TOML, YAML, JSON, Formatting)
# Note: PMD does not support auto-fix (linting only), yamllint does not auto-fix (use Prettier instead)
lint-all-fix:
    -@just lint-fix
    -@just lint-rust-fix
    -@just lint-rust-fmt
    -@just lint-java-fix
    -@just lint-js-fix
    -@just lint-md-fix
    -@just lint-toml-fix
    -@just lint-json-fix
    -@just format-fix
    @echo "All auto-fixable linting issues resolved ✓"

# ==================== GIT ====================

# Watch GitHub Actions CI runs in real-time
watch:
    gh run watch

# Quick WIP commit - skips hooks, auto timestamp message, pushes to origin
git-commit:
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; git add -A; git commit --no-verify -m "WIP: $timestamp"; git push origin HEAD

# Full commit with hooks - prompts for message, runs pre-commit hooks, pushes to origin
git-commit-hooks message:
    git add -A; git commit -m "{{message}}"; git push origin HEAD

# ==================== DOCUMENTATION ====================

# Generate Sphinx documentation
docs-build:
    pixi run sphinx-build -b html docs/source docs/build/html

# Clean documentation build
docs-clean:
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue docs\build\*

# Regenerate API documentation from code
docs-apidoc:
    pixi run sphinx-apidoc -f -o docs/source intellicrack

# Full documentation rebuild
docs-rebuild: docs-clean docs-apidoc docs-build
    Write-Output "Documentation rebuilt in docs/build/html/index.html"

# Open documentation in browser (Windows)
docs-open:
    Start-Process docs\build\html\index.html

# Build PDF documentation
docs-pdf:
    pixi run sphinx-build -b latex docs/source docs/build/latex
    Write-Output "LaTeX files generated in docs/build/latex/"

# Scanner recipes

build-scanner:
    @echo "Building scanner with maximum optimization..."
    Set-Location scripts/scanner; $env:RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C codegen-units=1 -C strip=symbols"; cargo build --release; Set-Location ../..
    @echo "Creating Scanner shortcut..."
    $WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("$PWD\Scanner.lnk"); $Shortcut.TargetPath = "$PWD\scripts\scanner\target\release\scanner.exe"; $Shortcut.WorkingDirectory = "$PWD"; $Shortcut.IconLocation = "C:\Windows\System32\shell32.dll,22"; $Shortcut.Save()
    @echo "Scanner shortcut created ✓"

scan:
    ./scripts/scanner/target/release/scanner.exe -d intellicrack --format console

# Check documentation links
docs-linkcheck:
    pixi run sphinx-build -b linkcheck docs/source docs/build/linkcheck
    Write-Output "Link check results in docs/build/linkcheck/output.txt"


# ==================== COMPREHENSIVE REPORTS ====================

# Run all linting tools in PARALLEL with simple progress, results at end
run-all-tools:
    @$e = [char]27; $blk = [char]0x2588; $lgt = [char]0x2591; $chk = [char]0x2714; $tools = @( @{N='Ruff';R='ruff'}, @{N='Ruff Fmt';R='ruff-fmt'}, @{N='Vulture';R='vulture'}, @{N='Darglint';R='darglint'}, @{N='Dead';R='dead'}, @{N='Ty';R='ty'}, @{N='Pyright';R='pyright'}, @{N='Mypy';R='mypy'}, @{N='Bandit';R='bandit'}, @{N='Clippy';R='clippy'}, @{N='Markdown';R='mdlint'}, @{N='YAML';R='yamllint'}, @{N='Uncalled';R='uncalled'}, @{N='Deadcode';R='deadcode'}, @{N='Knip';R='knip'}, @{N='PMD';R='pmd'}, @{N='Checkstyle';R='checkstyle'}, @{N='ESLint';R='eslint'}, @{N='Biome';R='biome'}, @{N='Cargo Audit';R='cargo-audit'}, @{N='Cargo Deny';R='cargo-deny'}, @{N='ShellCheck';R='shellcheck'}, @{N='JSONLint';R='jsonlint'}, @{N='PSScript';R='psscriptanalyzer'} ); $total = $tools.Count; Write-Host "$e[36mRUNNING DEV TOOLS$e[0m`n"; $pool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount * 2); $pool.Open(); $runspaces = @{}; $results = @{}; $globalStart = Get-Date; $wd = $PWD.Path; foreach ($t in $tools) { $r = $t.R; $ps = [powershell]::Create().AddScript({ param($recipe, $workdir); Set-Location $workdir; $out = & just $recipe 2>&1 | Out-String; $m = [regex]::Match($out, '(\d+)\s+findings'); @{ Findings = if ($m.Success) { [int]$m.Groups[1].Value } else { 0 } } }).AddArgument($r).AddArgument($wd); $ps.RunspacePool = $pool; $runspaces[$r] = @{ PS = $ps; Handle = $ps.BeginInvoke(); Start = Get-Date } }; $spin = @('|','/','-','\'); $frame = 0; while ($results.Count -lt $total) { foreach ($t in $tools) { $r = $t.R; if ($runspaces[$r].Handle.IsCompleted -and -not $results.ContainsKey($r)) { $res = $runspaces[$r].PS.EndInvoke($runspaces[$r].Handle); $dur = ((Get-Date) - $runspaces[$r].Start).TotalSeconds; $f = if ($res -and $res.Findings) { $res.Findings } else { 0 }; $results[$r] = @{ F = $f; D = $dur; N = $t.N }; $runspaces[$r].PS.Dispose() } }; $done = $results.Count; $pctDone = [math]::Round(($done / $total) * 100); $barLen = 30; $fillLen = [math]::Round(($done / $total) * $barLen); $progFill = ''; for($i=0;$i -lt $fillLen;$i++){$progFill+=$blk}; $progEmpty = ''; for($i=0;$i -lt ($barLen-$fillLen);$i++){$progEmpty+=$lgt}; $sp = $spin[$frame % 4]; $elapsed = ((Get-Date) - $globalStart).TotalSeconds; Write-Host "`r$e[K$sp [$progFill$progEmpty] $pctDone% ($done/$total) - $("{0:N0}s" -f $elapsed)" -NoNewline; $frame++; Start-Sleep -Milliseconds 100 }; $pool.Close(); $pool.Dispose(); Write-Host "`r$e[K"; Write-Host ""; $maxN = ($tools | ForEach-Object { $_.N.Length } | Measure-Object -Maximum).Maximum; $fullB = "$blk$blk$blk$blk$blk$blk$blk$blk$blk$blk"; foreach ($t in $tools) { $r = $t.R; $n = $t.N.PadRight($maxN); $f = $results[$r].F; $d = $results[$r].D; if ($f -eq 0) { Write-Host "$e[32m$chk$e[0m $n $e[32m[$fullB]$e[0m $e[90m$("{0,6:N1}s" -f $d)$e[0m" } else { Write-Host "$e[33m!$e[0m $n $e[33m[$fullB]$e[0m $e[90m$("{0,6:N1}s" -f $d) $e[33m($f findings)$e[0m" } }; $totalTime = ((Get-Date) - $globalStart).TotalSeconds; $totalFindings = ($results.Values | ForEach-Object { $_.F } | Measure-Object -Sum).Sum; $passed = ($results.Values | Where-Object { $_.F -eq 0 }).Count; Write-Host "`n$e[90m$('-' * 55)$e[0m"; $fc = if ($totalFindings -gt 0) { '33' } else { '32' }; Write-Host "Time: $e[36m$("{0:N1}s" -f $totalTime)$e[0m | Findings: $e[$($fc)m$totalFindings$e[0m | Passed: $e[32m$passed/$total$e[0m"
