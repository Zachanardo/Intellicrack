"""
Shared syntax highlighters for code editors.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from PyQt6.QtCore import QRegularExpression
from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat


class PythonHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for Python code"""

    def __init__(self, parent=None):
        """Initialize Python syntax highlighter with comprehensive language support."""
        super().__init__(parent)

        # Define highlighting rules
        self.highlighting_rules = []

        # Keyword format
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))  # Blue
        keyword_format.setFontWeight(QFont.Weight.Bold)

        keywords = [
            "and", "as", "assert", "break", "class", "continue", "def",
            "del", "elif", "else", "except", "exec", "finally", "for",
            "from", "global", "if", "import", "in", "is", "lambda",
            "not", "or", "pass", "print", "raise", "return", "try",
            "while", "with", "yield", "None", "True", "False"
        ]

        for keyword in keywords:
            pattern = QRegularExpression(f"\\b{keyword}\\b")
            self.highlighting_rules.append((pattern, keyword_format))

        # String format (single and double quotes)
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))  # Orange
        self.highlighting_rules.append((QRegularExpression('".*"'), string_format))
        self.highlighting_rules.append((QRegularExpression("'.*'"), string_format))

        # Triple-quoted strings
        self.highlighting_rules.append((QRegularExpression('""".*"""'), string_format))
        self.highlighting_rules.append((QRegularExpression("'''.*'''"), string_format))

        # Comment format
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))  # Green
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((QRegularExpression("#[^\\n]*"), comment_format))

        # Number format
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#B5CEA8"))  # Light green
        self.highlighting_rules.append((QRegularExpression("\\b[0-9]+\\.?[0-9]*\\b"), number_format))

        # Function format
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#DCDCAA"))  # Yellow
        self.highlighting_rules.append((QRegularExpression("\\b[A-Za-z_][A-Za-z0-9_]*(?=\\()"), function_format))

        # Class format
        class_format = QTextCharFormat()
        class_format.setForeground(QColor("#4EC9B0"))  # Cyan
        class_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((QRegularExpression("\\bclass\\s+[A-Za-z_][A-Za-z0-9_]*"), class_format))

        # Self format
        self_format = QTextCharFormat()
        self_format.setForeground(QColor("#9CDCFE"))  # Light blue
        self.highlighting_rules.append((QRegularExpression("\\bself\\b"), self_format))

        # Decorator format
        decorator_format = QTextCharFormat()
        decorator_format.setForeground(QColor("#FFD700"))  # Gold
        self.highlighting_rules.append((QRegularExpression("@[A-Za-z_][A-Za-z0-9_]*"), decorator_format))

        # Built-in functions
        builtin_format = QTextCharFormat()
        builtin_format.setForeground(QColor("#4FC1FF"))  # Bright blue
        builtins = [
            "abs", "all", "any", "bin", "bool", "bytearray", "bytes", "callable",
            "chr", "classmethod", "compile", "complex", "delattr", "dict", "dir",
            "divmod", "enumerate", "eval", "filter", "float", "format", "frozenset",
            "getattr", "globals", "hasattr", "hash", "help", "hex", "id", "input",
            "int", "isinstance", "issubclass", "iter", "len", "list", "locals",
            "map", "max", "memoryview", "min", "next", "object", "oct", "open",
            "ord", "pow", "print", "property", "range", "repr", "reversed",
            "round", "set", "setattr", "slice", "sorted", "staticmethod",
            "str", "sum", "super", "tuple", "type", "vars", "zip"
        ]

        for builtin in builtins:
            pattern = QRegularExpression(f"\\b{builtin}\\b")
            self.highlighting_rules.append((pattern, builtin_format))

    def highlightBlock(self, text):
        """Apply syntax highlighting to block"""
        # Single line rules
        for pattern, format in self.highlighting_rules:
            expression = QRegularExpression(pattern)
            match_iterator = expression.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

        self.setCurrentBlockState(0)

        # Multi-line strings
        self.match_multiline_string(text, QRegularExpression('"""'), 1, self.triple_double_quote_format)
        self.match_multiline_string(text, QRegularExpression("'''"), 2, self.triple_single_quote_format)

    def match_multiline_string(self, text, expression, state, format):
        """Handle multi-line string highlighting"""
        if self.previousBlockState() == state:
            start_index = 0
            add = 0
        else:
            match = expression.match(text)
            if match.hasMatch():
                start_index = match.capturedStart()
                add = match.capturedLength()
            else:
                start_index = -1
                add = 0

        while start_index >= 0:
            match = expression.match(text, start_index + add)
            end_index = match.capturedStart() if match.hasMatch() else -1

            if end_index == -1:
                self.setCurrentBlockState(state)
                comment_length = len(text) - start_index
            else:
                comment_length = end_index - start_index + match.capturedLength()

            self.setFormat(start_index, comment_length, format)
            match = expression.match(text, start_index + comment_length)
            start_index = match.capturedStart() if match.hasMatch() else -1


class JavaScriptHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for JavaScript/Frida code"""

    def __init__(self, parent=None):
        """Initialize JavaScript syntax highlighter with ES6+ language support."""
        super().__init__(parent)

        # Define highlighting rules
        self.highlighting_rules = []

        # Keyword format
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))  # Blue
        keyword_format.setFontWeight(QFont.Weight.Bold)

        keywords = [
            "break", "case", "catch", "class", "const", "continue", "debugger",
            "default", "delete", "do", "else", "export", "extends", "finally",
            "for", "function", "if", "import", "in", "instanceof", "let", "new",
            "return", "super", "switch", "this", "throw", "try", "typeof", "var",
            "void", "while", "with", "yield", "async", "await", "static"
        ]

        for keyword in keywords:
            pattern = QRegularExpression(f"\\b{keyword}\\b")
            self.highlighting_rules.append((pattern, keyword_format))

        # Literal values
        literal_format = QTextCharFormat()
        literal_format.setForeground(QColor("#569CD6"))  # Blue
        literals = ["true", "false", "null", "undefined"]

        for literal in literals:
            pattern = QRegularExpression(f"\\b{literal}\\b")
            self.highlighting_rules.append((pattern, literal_format))

        # String format (single, double quotes, and template literals)
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))  # Orange
        self.highlighting_rules.append((QRegularExpression('".*?"'), string_format))
        self.highlighting_rules.append((QRegularExpression("'.*?'"), string_format))
        self.highlighting_rules.append((QRegularExpression("`.*?`"), string_format))

        # Comment format
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))  # Green
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((QRegularExpression("//[^\\n]*"), comment_format))
        self.highlighting_rules.append((QRegularExpression("/\\*.*\\*/"), comment_format))

        # Number format
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#B5CEA8"))  # Light green
        self.highlighting_rules.append((QRegularExpression("\\b[0-9]+\\.?[0-9]*\\b"), number_format))
        self.highlighting_rules.append((QRegularExpression("\\b0x[0-9a-fA-F]+\\b"), number_format))

        # Function format
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#DCDCAA"))  # Yellow
        self.highlighting_rules.append((QRegularExpression("\\b[A-Za-z_$][A-Za-z0-9_$]*(?=\\()"), function_format))

        # Object/Class format
        class_format = QTextCharFormat()
        class_format.setForeground(QColor("#4EC9B0"))  # Cyan
        class_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((QRegularExpression("\\bclass\\s+[A-Za-z_$][A-Za-z0-9_$]*"), class_format))

        # Built-in objects
        builtin_format = QTextCharFormat()
        builtin_format.setForeground(QColor("#4FC1FF"))  # Bright blue
        builtins = [
            "Array", "Boolean", "Date", "Error", "Function", "JSON", "Math",
            "Number", "Object", "RegExp", "String", "Symbol", "Promise",
            "Set", "Map", "WeakSet", "WeakMap", "Proxy", "Reflect",
            "console", "window", "document", "alert", "confirm", "prompt"
        ]

        for builtin in builtins:
            pattern = QRegularExpression(f"\\b{builtin}\\b")
            self.highlighting_rules.append((pattern, builtin_format))

        # Operators
        operator_format = QTextCharFormat()
        operator_format.setForeground(QColor("#D4D4D4"))  # Light gray
        operators = [
            "\\+", "-", "\\*", "/", "%", "\\+\\+", "--", "=", "\\+=", "-=",
            "\\*=", "/=", "%=", "==", "!=", "===", "!==", "<", ">", "<=", ">=",
            "&&", "\\|\\|", "!", "&", "\\|", "\\^", "~", "<<", ">>", ">>>"
        ]

        for operator in operators:
            pattern = QRegularExpression(operator)
            self.highlighting_rules.append((pattern, operator_format))

        # Regex literals
        regex_format = QTextCharFormat()
        regex_format.setForeground(QColor("#FF6B6B"))  # Red
        self.highlighting_rules.append((QRegularExpression("/.*?/[gimuy]*"), regex_format))

        # Template literal expressions
        template_expr_format = QTextCharFormat()
        template_expr_format.setForeground(QColor("#FFD700"))  # Gold
        self.highlighting_rules.append((QRegularExpression("\\$\\{[^}]*\\}"), template_expr_format))

        # Arrow functions
        arrow_format = QTextCharFormat()
        arrow_format.setForeground(QColor("#C586C0"))  # Purple
        self.highlighting_rules.append((QRegularExpression("=>"), arrow_format))

        # Destructuring
        destructure_format = QTextCharFormat()
        destructure_format.setForeground(QColor("#9CDCFE"))  # Light blue
        self.highlighting_rules.append((QRegularExpression("\\[.*?\\]\\s*="), destructure_format))
        self.highlighting_rules.append((QRegularExpression("\\{.*?\\}\\s*="), destructure_format))

    def highlightBlock(self, text):
        """Apply syntax highlighting to block"""
        # Single line rules
        for pattern, format in self.highlighting_rules:
            expression = QRegularExpression(pattern)
            match_iterator = expression.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

        self.setCurrentBlockState(0)

        # Multi-line comments
        start_expression = QRegularExpression("/\\*")
        end_expression = QRegularExpression("\\*/")

        if self.previousBlockState() == 1:
            start = 0
            add = 0
        else:
            start = start_expression.indexIn(text)
            add = start_expression.matchedLength()

        while start >= 0:
            end = end_expression.indexIn(text, start + add)
            if end == -1:
                self.setCurrentBlockState(1)
                comment_length = len(text) - start
            else:
                comment_length = end - start + end_expression.matchedLength()

            self.setFormat(start, comment_length, self.multiline_comment_format)
            start = start_expression.indexIn(text, start + comment_length)
