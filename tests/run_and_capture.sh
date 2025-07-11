#!/bin/bash
# Script to run Intellicrack debug from WSL and capture output

echo "Running Intellicrack debug script from WSL..."
echo "============================================="

# Change to Windows directory
cd /mnt/c/Intellicrack

# Run the debug batch file using cmd.exe and capture output
echo "Launching DEBUG_INTEL_ARC.bat..."
cmd.exe /c "DEBUG_INTEL_ARC.bat" 2>&1 | tee debug_output_wsl.txt

echo ""
echo "============================================="
echo "Debug script finished. Checking for log files..."

# Find the latest arc_debug log
LATEST_LOG=$(ls -t arc_debug_*.txt 2>/dev/null | head -1)

if [ -n "$LATEST_LOG" ]; then
    echo "Found log file: $LATEST_LOG"
    echo ""
    echo "============================================="
    echo "LOG CONTENTS:"
    echo "============================================="
    cat "$LATEST_LOG"
else
    echo "No arc_debug log file found."
fi

echo ""
echo "============================================="
echo "End of output"