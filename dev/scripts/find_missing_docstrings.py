import os
import ast

class InitDocstringChecker(ast.NodeVisitor):
    def __init__(self):
        self.missing_docstrings = []
        self.current_file = ''
        
    def visit_FunctionDef(self, node):
        if node.name == '__init__':
            # Check if the first statement is a string (docstring)
            has_docstring = (
                node.body and 
                isinstance(node.body[0], ast.Expr) and 
                isinstance(node.body[0].value, (ast.Str, ast.Constant)) and
                isinstance(node.body[0].value.value if hasattr(node.body[0].value, 'value') else node.body[0].value.s, str)
            )
            if not has_docstring:
                self.missing_docstrings.append((self.current_file, node.lineno))
        self.generic_visit(node)

checker = InitDocstringChecker()
files_with_issues = {}

# Focus only on intellicrack directory
for root, dirs, files in os.walk('intellicrack'):
    # Skip specific directories
    if any(skip in root for skip in ['__pycache__', '.git']):
        continue
        
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                tree = ast.parse(content)
                checker.current_file = filepath
                checker.missing_docstrings = []
                checker.visit(tree)
                
                if checker.missing_docstrings:
                    files_with_issues[filepath] = [(filepath, line) for filepath, line in checker.missing_docstrings]
            except:
                pass

# Sort by number of missing docstrings
sorted_files = sorted(files_with_issues.items(), key=lambda x: len(x[1]), reverse=True)

print('Files with missing __init__ docstrings in intellicrack directory:')
print('=' * 80)
total = 0
for filepath, issues in sorted_files:
    count = len(issues)
    print(f'\n{filepath}: {count} missing')
    for _, line in issues:
        print(f'  - Line {line}')
    total += count
    
print(f'\nTotal files with issues: {len(files_with_issues)}')
print(f'Total missing docstrings: {total}')

# Create a summary file
with open('missing_docstrings_report.txt', 'w') as f:
    f.write('Missing __init__ Docstrings Report\n')
    f.write('=' * 80 + '\n\n')
    
    for filepath, issues in sorted_files:
        count = len(issues)
        f.write(f'{filepath}: {count} missing\n')
        for _, line in issues:
            f.write(f'  - Line {line}\n')
        f.write('\n')
        
    f.write(f'\nTotal files with issues: {len(files_with_issues)}\n')
    f.write(f'Total missing docstrings: {total}\n')