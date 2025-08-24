import os
import ast

def find_try_except_pass(directory):
    """Find all try-except-pass blocks in Python files."""
    violations = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    tree = ast.parse(content)
                    
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Try):
                            for handler in node.handlers:
                                # Check if the except body only contains pass
                                if (len(handler.body) == 1 and 
                                    isinstance(handler.body[0], ast.Pass)):
                                    violations.append({
                                        'file': filepath,
                                        'line': handler.lineno
                                    })
                except Exception as e:
                    pass  # Skip files with parse errors
    
    return violations

# Find violations
violations = find_try_except_pass('intellicrack')

print(f"Found {len(violations)} S110 violations:")
for v in violations[:20]:  # Show first 20
    print(f"  {v['file']}:{v['line']}")