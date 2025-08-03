import os
import re

stub_functions = []

# More comprehensive stub patterns
stub_patterns = [
    (r'^\s*pass\s*$', 'pass'),
    (r'^\s*return\s+None\s*$', 'return None'),
    (r'^\s*return\s+\[\]\s*$', 'return []'),
    (r'^\s*return\s+\{\}\s*$', 'return {}'),
    (r'^\s*return\s+\"\"\s*$', 'return ""'),
    (r'^\s*return\s+0\s*$', 'return 0'),
    (r'^\s*return\s+False\s*$', 'return False'),
    (r'^\s*raise\s+NotImplementedError', 'NotImplementedError'),
    (r'TODO|FIXME|STUB|XXX', 'TODO/FIXME'),
    (r'simulate|Simulate', 'simulate'),
    (r'mock|Mock', 'mock'),
    (r'fake|Fake', 'fake'),  
    (r'dummy|Dummy', 'dummy'),
    (r'placeholder|Placeholder', 'placeholder'),
    (r'hardcoded', 'hardcoded'),
    (r'example\.com|test\.com|localhost:1234', 'hardcoded URL'),
    (r'sleep\(', 'sleep simulation'),
    (r'random\.uniform|random\.randint', 'random simulation'),
    (r'# Simulated|# Fallback|# Mock|# Fake|# Dummy', 'comment indication')
]

for root, dirs, files in os.walk('intellicrack'):
    # Skip test directories
    if 'test' in root or '__pycache__' in root:
        continue
        
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for i, line in enumerate(lines):
                    # Look for function definitions
                    func_match = re.match(r'^(\s*)def\s+([a-zA-Z0-9_]+)\s*\(', line)
                    if func_match:
                        indent = func_match.group(1)
                        func_name = func_match.group(2)
                        
                        # Check next 10 lines for stub patterns
                        stub_found = False
                        stub_type = None
                        
                        for j in range(1, min(11, len(lines) - i)):
                            next_line = lines[i + j]
                            
                            # Skip if we've moved to a different indentation level (new function)
                            if re.match(r'^(\s*)def\s+', next_line):
                                break
                                
                            # Check each pattern
                            for pattern, pattern_type in stub_patterns:
                                if re.search(pattern, next_line):
                                    stub_found = True
                                    stub_type = pattern_type
                                    break
                                    
                            if stub_found:
                                break
                        
                        if stub_found:
                            relative_path = os.path.normpath(filepath).replace(os.sep, '/')
                            stub_functions.append(f'{func_name} - {relative_path} ({stub_type})')
                            
            except Exception as e:
                pass

# Sort and print results  
stub_functions.sort()

# Write to file
with open('ALL_STUB_FUNCTIONS.txt', 'w') as f:
    for func in stub_functions:
        f.write(func + '\n')
    f.write(f'\nTotal stub functions found: {len(stub_functions)}')

# Print summary
print(f"Extracted {len(stub_functions)} stub functions to ALL_STUB_FUNCTIONS.txt")
print("\nFirst 50 functions:")
for func in stub_functions[:50]:
    print(func)