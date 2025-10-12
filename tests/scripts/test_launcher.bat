@echo off
echo Testing Intellicrack launcher with PATH fix
cd /d "%INTELLICRACK_ROOT%\intellicrack-launcher"
cargo build --release
if %errorlevel% neq 0 (
    echo Build failed
    exit /b 1
)
echo Build successful
cd /d "%INTELLICRACK_ROOT%"
"intellicrack-launcher\target\release\Intellicrack.exe"
echo Launcher exit code: %errorlevel%
