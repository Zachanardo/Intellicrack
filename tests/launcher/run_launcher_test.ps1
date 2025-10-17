# PowerShell script to test the Rust launcher
Write-Host "=== Testing Rust Launcher Environment Configuration ===" -ForegroundColor Cyan
Write-Host ""

# Set test mode
$env:RUST_LAUNCHER_TEST_MODE = "1"
$env:RUST_LOG = "intellicrack_launcher=debug"

# Run the launcher
Write-Host "Running launcher in test mode..." -ForegroundColor Yellow
& "intellicrack-launcher\target\release\intellicrack-launcher.exe"
$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "Exit code: $exitCode" -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })

# Check if test results file exists
if (Test-Path "rust_launcher_env_test_results.json") {
    Write-Host ""
    Write-Host "=== Environment Variables Test Results ===" -ForegroundColor Cyan
    $results = Get-Content "rust_launcher_env_test_results.json" | ConvertFrom-Json

    $successCount = 0
    $failCount = 0

    foreach ($var in $results.environment_variables.PSObject.Properties) {
        if ($var.Value.set) {
            $successCount++
            Write-Host "✅ $($var.Name): $($var.Value.value)" -ForegroundColor Green
        } else {
            $failCount++
            Write-Host "❌ $($var.Name): NOT SET" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total variables: $($successCount + $failCount)"
    Write-Host "Successfully set: $successCount" -ForegroundColor Green
    Write-Host "Failed to set: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })
}
