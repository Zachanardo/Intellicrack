"""Extract sample verification report entries from the scanner output file.

This script reads the scanner_output_full.txt file and extracts unique file:line:function
entries from the verification report sections using regex patterns.
It limits output to the first 100 unique entries.
"""
import regex

with open('scanner_output_full.txt', encoding='utf-8') as f:
    content = f.read()

pattern = r'File: ([^\n]+)\n(?:.*?\n)*?#### \d+\. \[ \] `([^`]+)`[^\(]*\(Line (\d+)\)'
matches = re.findall(pattern, content)

seen = set()
for file, func, line in matches:
    key = (file.strip(), func.strip(), line.strip())
    if key not in seen:
        seen.add(key)
        print(f'{file.strip()}:{line.strip()}:{func.strip()}')
        if len(seen) >= 100:
            break
