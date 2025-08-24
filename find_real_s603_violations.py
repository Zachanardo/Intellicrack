import os
import re

def find_real_s603_violations(directory):
    """Find subprocess calls that need shell=False and don't have nosec/noqa comments."""
    
    subprocess_patterns = [
        r'subprocess\.(run|call|check_call|check_output|Popen)\s*\(',
    ]
    
    violations = []
    
    for root, dirs, files in os.walk(directory):
        # Skip hidden directories and __pycache__
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.split('\n')
                        
                    for i, line in enumerate(lines, 1):
                        for pattern in subprocess_patterns:
                            if re.search(pattern, line):
                                # Skip if line has nosec or noqa comment
                                if '# nosec' in line or '# noqa' in line:
                                    continue
                                
                                # Look ahead for multi-line calls (up to 20 lines)
                                context_lines = lines[i-1:min(i+20, len(lines))]
                                context = '\n'.join(context_lines)
                                
                                # Check if shell parameter is specified
                                if 'shell=' not in context:
                                    # This might be a real violation
                                    violations.append((filepath, i, line.strip()))
                                    
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
    
    return violations

# Find real violations
violations = find_real_s603_violations('intellicrack')

print(f"Found {len(violations)} potential S603 violations (subprocess calls without shell parameter):\n")

for filepath, line_num, line in violations:
    rel_path = os.path.relpath(filepath, '.')
    print(f"{rel_path}:{line_num}: {line}")

# Group by file
from collections import defaultdict
file_counts = defaultdict(list)
for filepath, line_num, line in violations:
    file_counts[filepath].append((line_num, line))

print(f"\n\nViolations by file ({len(file_counts)} files):")
for filepath, occurrences in sorted(file_counts.items()):
    rel_path = os.path.relpath(filepath, '.')
    print(f"\n{rel_path} ({len(occurrences)} violations):")
    for line_num, line in occurrences[:5]:  # Show first 5
        print(f"  Line {line_num}: {line[:80]}...")