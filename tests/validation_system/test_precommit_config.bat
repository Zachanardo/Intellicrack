@echo off
echo Testing Pre-Commit Hook Configuration
echo =====================================

echo.
echo 1. Testing Pixi Environment (Already Active)
cd /d %INTELLICRACK_ROOT%
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo   ✅ Pixi environment access: SUCCESS
) else (
    echo   ❌ Pixi environment access: FAILED
    exit /b 1
)

echo.
echo 2. Testing Python Availability
python --version
if %errorlevel% equ 0 (
    echo   ✅ Python availability: SUCCESS
) else (
    echo   ❌ Python availability: FAILED
    exit /b 1
)

echo.
echo 3. Testing pytest Coverage (80% threshold)
python -m pytest --help | findstr "cov-fail-under"
if %errorlevel% equ 0 (
    echo   ✅ Coverage plugin availability: SUCCESS
) else (
    echo   ❌ Coverage plugin availability: FAILED
    exit /b 1
)

echo.
echo 4. Testing Production Readiness Audit Tool
python tests/utils/Production_Readiness_Audit.py --help
if %errorlevel% equ 0 (
    echo   ✅ Production Readiness Audit: SUCCESS
) else (
    echo   ❌ Production Readiness Audit: FAILED
    exit /b 1
)

echo.
echo 5. Testing Directory Exclusions
if exist ".pixi\" (
    echo   ✅ .pixi directory found (will be excluded from testing)
) else (
    echo   ⚠️  .pixi directory not found
)

if exist "dev\" (
    echo   ✅ dev directory found (will be excluded from testing)
) else (
    echo   ⚠️  dev directory not found
)

if exist "tools\" (
    echo   ✅ tools directory found (will be excluded from testing)
) else (
    echo   ⚠️  tools directory not found
)

echo.
echo =====================================
echo Pre-Commit Configuration Test Complete
echo All critical components verified ✅
