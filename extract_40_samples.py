"""Module to extract verification samples from scanner output.

This script reads the scanner output file, parses for security issues of specified severity,
and extracts the first 40 samples to a verification file.
"""

import re

with open("D:\\Intellicrack\\scanner_post_fix.txt", encoding="utf-8") as f:
    lines = f.readlines()

samples = []
current_file = None

for line in lines:
    if line.startswith("### File:"):
        match = re.search(r"### File: `([^`]+)`", line)
        if match:
            current_file = match.group(1)
    elif "####" in line and "`" in line and ("CRITICAL" in line or "HIGH" in line or "MEDIUM" in line):
        func_match = re.search(r"`([^`]+\(\))`.*?(CRITICAL|HIGH|MEDIUM).*?\(Line (\d+)\)", line)
        if func_match and current_file:
            func_name = func_match.group(1)
            severity = func_match.group(2)
            line_num = func_match.group(3)
            samples.append(f"{current_file}:{line_num} - {func_name}")
            if len(samples) >= 40:
                break

with open("D:\\Intellicrack\\verification_samples_post_p4.txt", "w", encoding="utf-8") as f:
    f.writelines(sample + "\n" for sample in samples)

print(f"Extracted {len(samples)} samples")
for i, sample in enumerate(samples, 1):
    print(f"{i}. {sample}")
