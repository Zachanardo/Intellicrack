@echo off
REM Setup script to install the pre-push git hook for Intellicrack

echo Setting up git pre-push hook...
echo.

REM Check if we're in scripts directory and go to parent
if exist "../.git" (
    cd ..
) else if not exist ".git" (
    echo ERROR: Not in a git repository root directory!
    echo Please run this from C:\Intellicrack or C:\Intellicrack\scripts
    exit /b 1
)

REM Create hooks directory if it doesn't exist
if not exist ".git\hooks" (
    mkdir ".git\hooks"
)

REM Create the pre-push hook
echo Creating pre-push hook...
(
echo #!/bin/sh
echo # Git pre-push hook to regenerate IntellicrackStructure files before pushing
echo # This ensures the directory tree documentation is current
echo.
echo echo "[PRE-PUSH] Regenerating Intellicrack directory structure files..."
echo.
echo # Change to repository root
echo cd "C:/Intellicrack" ^|^| exit 1
echo.
echo # Run the Python script to generate both HTA and TXT files
echo if python "scripts/generate_tree.py" 2^>/dev/null; then
echo     echo "[PRE-PUSH] Directory structure files regenerated successfully"
echo.
echo     # Check if either file has uncommitted changes
echo     HTA_CHANGED=false
echo     TXT_CHANGED=false
echo.
echo     if ! git diff --quiet "IntellicrackStructure.hta" 2^>/dev/null ^|^| ! git diff --cached --quiet "IntellicrackStructure.hta" 2^>/dev/null; then
echo         HTA_CHANGED=true
echo     fi
echo.
echo     if ! git diff --quiet "IntellicrackStructure.txt" 2^>/dev/null ^|^| ! git diff --cached --quiet "IntellicrackStructure.txt" 2^>/dev/null; then
echo         TXT_CHANGED=true
echo     fi
echo.
echo     if [ "$HTA_CHANGED" = true ] ^|^| [ "$TXT_CHANGED" = true ]; then
echo         echo ""
echo         echo "⚠️  WARNING: Directory structure files have uncommitted changes!"
echo         [ "$HTA_CHANGED" = true ] ^&^& echo "   - IntellicrackStructure.hta"
echo         [ "$TXT_CHANGED" = true ] ^&^& echo "   - IntellicrackStructure.txt"
echo         echo "   The directory structure has been updated but not committed."
echo         echo "   Consider running: git add IntellicrackStructure.* && git commit --amend"
echo         echo ""
echo         # Don't block the push, just warn
echo     fi
echo else
echo     echo "[PRE-PUSH] Warning: Could not regenerate directory structure files"
echo     echo "   Continuing with push anyway..."
echo fi
echo.
echo # Always allow push to continue
echo exit 0
) > ".git\hooks\pre-push"

echo ✅ Git pre-push hook installed successfully!
echo.
echo The hook will automatically regenerate both:
echo   - IntellicrackStructure.hta (interactive HTML version)
echo   - IntellicrackStructure.txt (plain text version)
echo every time you run 'git push'
echo.
echo If either file changes, you'll be warned to commit them.
echo.
pause
