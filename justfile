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
    pixi list --environment ci --json | python -c "import json, sys; data = json.load(sys.stdin); pypi_packages = [p for p in data if p.get('kind') == 'pypi']; [print(f\"{pkg['name']}=={pkg.get('version', '')}\") if pkg.get('version') else print(pkg['name']) for pkg in sorted(pypi_packages, key=lambda x: x['name'])]" > requirements.txt
    @echo "requirements.txt generated ✓"
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
    @echo "Installing Intel XPU PyTorch..."
    pixi run install-intel-xpu
    @echo ""
    @echo "Installing linters..."
    pixi run install-linters
    @echo ""
    @echo "Building Rust launcher..."
    pixi run build-rust-launcher
    @echo ""
    @echo "Installation complete! ✓"

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

# Detect dead code with vulture
vulture:
    pixi run vulture intellicrack/

# Security linting with bandit
bandit:
    pixi run bandit -r intellicrack/ -c pyproject.toml -f xml

# Lint JavaScript files with ESLint
lint-js:
    pixi run npx eslint . --ext .js

# Fix JavaScript linting issues automatically
lint-js-fix:
    pixi run npx eslint . --ext .js --fix

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
    npx eslint "**/*.toml"

# Fix TOML linting issues automatically for all TOML files
lint-toml-fix:
    npx eslint "**/*.toml" --fix

# Lint all YAML files in the project with yamllint
lint-yaml:
    pixi run yamllint .

# Fix YAML linting issues (yamllint does not auto-fix, this runs lint only)
lint-yaml-fix:
    @echo "yamllint does not support auto-fix. Use Prettier for YAML formatting."
    @just format-fix

# Lint all JSON files in the project with Prettier
lint-json:
    npx prettier --check "**/*.json"

# Fix JSON linting issues automatically with Prettier
lint-json-fix:
    npx prettier --write "**/*.json"

# Check formatting with Prettier for all supported files
format:
    npx prettier --check "**/*.{js,md,toml,yaml,yml,json}"

# Fix formatting with Prettier for all supported files
format-fix:
    npx prettier --write "**/*.{js,md,toml,yaml,yml,json}"

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
