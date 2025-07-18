#!/usr/bin/env python3
import os
import ast

def check_syntax():
    error_count = 0
    total_files = 0
    
    for root, dirs, files in os.walk('intellicrack'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                total_files += 1
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        ast.parse(f.read())
                except SyntaxError as e:
                    error_count += 1
                    print(f"Syntax error in {filepath}: {e.msg} at line {e.lineno}")
                except UnicodeDecodeError:
                    print(f"Unicode error in {filepath}")
                except Exception as e:
                    print(f"Other error in {filepath}: {e}")
    
    print(f"\nSummary:")
    print(f"Total Python files: {total_files}")
    print(f"Files with syntax errors: {error_count}")
    print(f"Files fixed: {total_files - error_count}")
    
    if error_count == 0:
        print("🎉 ALL SYNTAX ERRORS FIXED!")
    else:
        print(f"❌ {error_count} files still have syntax errors")

if __name__ == "__main__":
    os.chdir('C:/Intellicrack')
    check_syntax()