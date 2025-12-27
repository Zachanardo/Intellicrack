"""Test file with deliberate code quality issues for MCP tool testing."""
import json  # Multiple imports on one line (ruff E401)
import os
import sys

import unused_module  # Unused import (ruff F401)


def badly_formatted_function(x, y, z):  # Missing spaces after commas (ruff E231)
    """Function with issues."""
    if x == y:  # Missing spaces around operator (ruff E225)
        return z
    else:
        return None


class poorly_named_class:  # Should be PascalCase (ruff N801)
    def __init__(self):
        pass

    def method_with_too_many_args(self, a, b, c, d, e, f, g, h, i, j, k):  # Too many arguments
        """Method that does nothing useful."""
        return a + b


def function_without_docstring(param1, param2):  # Missing docstring (pydocstyle D103)
    x = param1 + param2
    return x


def overly_complex_function(a, b, c, d, e):  # High cyclomatic complexity for mccabe
    """Function with high complexity for testing."""
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        return a + b + c + d + e
                    else:
                        return a + b + c + d
                else:
                    return a + b + c
            else:
                return a + b
        else:
            return a
    else:
        return 0


# Dead code - function never called
def unused_function():
    """This function is never used."""
    return "never called"


# Type annotation issues
def missing_type_hints(x, y):
    """Function missing type hints for mypy."""
    return x + y


# Security issue for bandit
password = "hardcoded_password_123"  # Hardcoded password (bandit B105)

if __name__ == "__main__":
    result = badly_formatted_function(1, 2, 3)
    print(result)
