"""Quick syntax validation for trial_reset_engine.py"""
import ast
import sys

try:
    with open('intellicrack/core/trial_reset_engine.py', 'r', encoding='utf-8') as f:
        code = f.read()

    ast.parse(code)
    print("✓ Syntax is valid")
    sys.exit(0)
except SyntaxError as e:
    print(f"✗ Syntax error at line {e.lineno}: {e.msg}")
    print(f"  {e.text}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
