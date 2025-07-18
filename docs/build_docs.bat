@echo off
REM Build Sphinx documentation for Intellicrack

echo ========================================
echo Building Intellicrack Documentation
echo ========================================
echo.

REM Check if we're in the docs directory or project root
if exist conf.py (
    set DOCS_DIR=.
) else if exist docs\conf.py (
    set DOCS_DIR=docs
) else (
    echo Error: Cannot find docs directory!
    exit /b 1
)

REM Install dependencies if needed
echo Checking documentation dependencies...
pip show sphinx >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Sphinx and dependencies...
    pip install -r %DOCS_DIR%\requirements.txt
)

REM Clean previous builds
echo.
echo Cleaning previous builds...
if exist %DOCS_DIR%\_build rmdir /s /q %DOCS_DIR%\_build
if exist %DOCS_DIR%\api rmdir /s /q %DOCS_DIR%\api

REM Create API directory
mkdir %DOCS_DIR%\api

REM Auto-generate API documentation
echo.
echo Generating API documentation...
sphinx-apidoc -f -M -e -T -E -d 4 -o %DOCS_DIR%\api intellicrack

REM Build HTML documentation
echo.
echo Building HTML documentation...
sphinx-build -b html %DOCS_DIR% %DOCS_DIR%\_build\html

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo Documentation built successfully!
    echo ========================================
    echo.
    echo View at: file:///%cd:\=/%/%DOCS_DIR%/_build/html/index.html
    echo.
    set /p OPEN_BROWSER=Open in browser? (y/n): 
    if /i "%OPEN_BROWSER%"=="y" (
        start "" "%cd%\%DOCS_DIR%\_build\html\index.html"
    )
) else (
    echo.
    echo ========================================
    echo Documentation build failed!
    echo ========================================
    exit /b 1
)

echo.
pause