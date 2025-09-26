@echo off
echo Testing Rust Launcher Environment Setup...
echo ========================================

set RUST_LAUNCHER_TEST_MODE=1
set RUST_LOG=intellicrack_launcher=debug

echo Running launcher in test mode...
intellicrack-launcher\target\release\intellicrack-launcher.exe

echo.
echo Exit code: %ERRORLEVEL%

if exist rust_launcher_env_test_results.json (
    echo.
    echo Test results saved. Checking environment variables...
    type rust_launcher_env_test_results.json
)
