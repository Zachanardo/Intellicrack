#!/usr/bin/env python3
"""Set first run as completed in config"""
import json
import os

# Path to config file
config_dir = os.path.join(os.path.expanduser("~"), ".intellicrack")
config_path = os.path.join(config_dir, "config.json")

# Ensure directory exists
os.makedirs(config_dir, exist_ok=True)

# Load existing config or create new
config = {}
if os.path.exists(config_path):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except:
        pass

# Set first run as completed
if 'general' not in config:
    config['general'] = {}
config['general']['first_run_completed'] = True

# Save config
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)

print(f"Set first_run_completed = True in {config_path}")
print("Config contents:")
print(json.dumps(config, indent=2))