@echo off
REM Build documentation on Windows

echo Building Intellicrack Documentation...

REM Check if sphinx is installed
where sphinx-build >nul 2>nul
if %errorlevel% neq 0 (
    echo Sphinx not found. Installing documentation dependencies...
    pip install -r docs\requirements.txt
)

REM Clean previous builds
echo Cleaning previous builds...
if exist docs\_build rmdir /s /q docs\_build

REM Build HTML documentation
echo Building HTML documentation...
sphinx-build -b html docs docs\_build\html

if %errorlevel% equ 0 (
    echo.
    echo Documentation built successfully!
    echo View at: file:///%cd:\=/%/docs/_build/html/index.html
    echo.
    set /p OPEN_BROWSER=Open in browser? (y/n): 
    if /i "%OPEN_BROWSER%"=="y" (
        start "" "file:///%cd:\=/%/docs/_build/html/index.html"
    )
) else (
    echo Documentation build failed!
    exit /b 1
)