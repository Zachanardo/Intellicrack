#!/usr/bin/env python3
"""Test file with intentionally weak implementations to verify scanner."""

def keygen_simple():
    """Generate license key - should be flagged as weak"""
    return "AAAA-BBBB-CCCC-DDDD"

def validate_license(key):
    """Validate license - should be flagged for no conditionals"""
    return True

def patch_binary(filename):
    """Patch binary - should be flagged for no pattern search"""
    file = open(filename, "rb")
    data = file.read()
    return data

def search_patterns(data):
    """Search for patterns - should be flagged for no loops"""
    if data[0] == 0x4D:
        return "Found"
    return None

def process_data(input_data):
    """Process data - should be flagged for no local vars"""
    print(f"Processing: {input_data}")
    return input_data

def analyze_protection(binary_path):
    """Analyze protection - should be flagged for low complexity"""
    return False
