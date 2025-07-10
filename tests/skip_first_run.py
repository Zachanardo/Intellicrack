#!/usr/bin/env python3
"""Create marker to skip first run setup"""
import os

# Create .first_run_complete marker file
marker_path = os.path.join(os.path.expanduser("~"), ".intellicrack", ".first_run_complete")
os.makedirs(os.path.dirname(marker_path), exist_ok=True)

with open(marker_path, 'w') as f:
    f.write("completed")

print(f"Created first run marker at: {marker_path}")