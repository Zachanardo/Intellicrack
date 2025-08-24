import os
import re

def find_subprocess_calls(directory):
    """Find all subprocess calls in Python files."""
    
    subprocess_patterns = [
        r'subprocess\.(run|call|check_call|check_output|Popen)\s*\(',
        r'subprocess\.run\s*\(',
        r'subprocess\.call\s*\(',
        r'subprocess\.Popen\s*\(',
    ]
    
    results = []
    
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
                                # Check if shell=False is explicitly set
                                # Look ahead a few lines for multi-line calls
                                context = '\n'.join(lines[i-1:min(i+10, len(lines))])
                                
                                # Check if shell is mentioned
                                if 'shell=' not in context:
                                    results.append((filepath, i, line.strip()))
                                elif 'shell=True' in context:
                                    results.append((filepath, i, line.strip() + " [shell=True]"))
                                
                                break
                                
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
    
    return results

# Find all subprocess calls
results = find_subprocess_calls('intellicrack')

print(f"Found {len(results)} subprocess calls that may need attention:\n")

for filepath, line_num, line in results:
    # Make path relative for readability
    rel_path = os.path.relpath(filepath, '.')
    print(f"{rel_path}:{line_num}: {line}")

# Count by file
from collections import defaultdict
file_counts = defaultdict(int)
for filepath, _, _ in results:
    file_counts[filepath] += 1

print(f"\n\nSummary by file ({len(file_counts)} files):")
for filepath, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True):
    rel_path = os.path.relpath(filepath, '.')
    print(f"  {count:3d} occurrences in {rel_path}")