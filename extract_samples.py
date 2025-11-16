import re

with open('scanner_output_full.txt', 'r', encoding='utf-8') as f:
    content = f.read()

pattern = r'File: ([^\n]+)\n(?:.*?\n)*?#### \d+\. \[ \] `([^`]+)`[^\(]*\(Line (\d+)\)'
matches = re.findall(pattern, content)

seen = set()
for file, func, line in matches:
    key = (file.strip(), func.strip(), line.strip())
    if key not in seen:
        seen.add(key)
        print(f'{file.strip()}:{line.strip()}:{func.strip()}')
        if len(seen) >= 50:
            break
