"""Extract 40 verification samples from P6 scanner output."""

import re


with open(r"D:\Intellicrack\scanner_p6_full.txt", encoding="utf-8") as f:
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
            samples.append(f"{current_file}:{line_num} - {func_name} - {severity}")
            if len(samples) >= 40:
                break

with open(r"D:\Intellicrack\verification_samples_p6.txt", "w", encoding="utf-8") as f:
    f.writelines(sample + "\n" for sample in samples)

print(f"Extracted {len(samples)} samples from P6 output")
for i, sample in enumerate(samples, 1):
    print(f"{i}. {sample}")
