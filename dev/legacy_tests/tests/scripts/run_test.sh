#!/bin/bash
# Run Intellicrack test from WSL and capture output

cd /mnt/c/Intellicrack

echo "Launching Intellicrack on Windows..."
echo "===================================="

# Remove old output file if exists
rm -f output.log

# Run the Windows batch file
cmd.exe /c LAUNCH_TEST.bat

# Wait for execution to complete
echo "Waiting for execution..."
sleep 5

# Check if output file exists and display it
if [ -f "output.log" ]; then
    echo ""
    echo "===================================="
    echo "OUTPUT FROM INTELLICRACK:"
    echo "===================================="
    cat output.log
    echo ""
    echo "===================================="
else
    echo "ERROR: output.log not found"
fi
