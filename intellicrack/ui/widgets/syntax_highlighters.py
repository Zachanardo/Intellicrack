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

from PyQt5.QtCore import QRegExp
from PyQt5.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat


class PythonHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for Python code"""

    def __init__(self, document):
        super().__init__(document)

        # Define highlighting rules
        self.highlighting_rules = []

        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(86, 156, 214))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "and",
            "as",
            "assert",
            "break",
            "class",
            "continue",
            "def",
            "del",
            "elif",
            "else",
            "except",
            "False",
            "finally",
            "for",
            "from",
            "global",
            "if",
            "import",
            "in",
            "is",
            "lambda",
            "None",
            "nonlocal",
            "not",
            "or",
            "pass",
            "raise",
            "return",
            "True",
            "try",
            "while",
            "with",
            "yield",
        ]
        for keyword in keywords:
            pattern = QRegExp(f"\\b{keyword}\\b")
            self.highlighting_rules.append((pattern, keyword_format))

        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor(214, 157, 133))
        self.highlighting_rules.append((QRegExp('"[^"]*"'), string_format))
        self.highlighting_rules.append((QRegExp("'[^']*'"), string_format))

        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(106, 153, 85))
        self.highlighting_rules.append((QRegExp("#.*"), comment_format))

        # Functions
        function_format = QTextCharFormat()
        function_format.setForeground(QColor(220, 220, 170))
        self.highlighting_rules.append((QRegExp("\\b[A-Za-z0-9_]+(?=\\()"), function_format))

        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor(181, 206, 168))
        self.highlighting_rules.append((QRegExp("\\b[0-9]+\\b"), number_format))

        # Multi-line strings
        self.triple_single_quote_format = QTextCharFormat()
        self.triple_single_quote_format.setForeground(QColor(214, 157, 133))
        self.triple_double_quote_format = QTextCharFormat()
        self.triple_double_quote_format.setForeground(QColor(214, 157, 133))

    def highlightBlock(self, text):
        """Apply syntax highlighting to block"""
        # Single line rules
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

        self.setCurrentBlockState(0)

        # Multi-line strings
        self.match_multiline_string(text, QRegExp('"""'), 1, self.triple_double_quote_format)
        self.match_multiline_string(text, QRegExp("'''"), 2, self.triple_single_quote_format)

    def match_multiline_string(self, text, expression, state, format):
        """Handle multi-line string highlighting"""
        if self.previousBlockState() == state:
            start = 0
            add = 0
        else:
            start = expression.indexIn(text)
            add = expression.matchedLength()

        while start >= 0:
            end = expression.indexIn(text, start + add)
            if end == -1:
                self.setCurrentBlockState(state)
                comment_length = len(text) - start
            else:
                comment_length = end - start + expression.matchedLength()

            self.setFormat(start, comment_length, format)
            start = expression.indexIn(text, start + comment_length)


class JavaScriptHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for JavaScript/Frida code"""

    def __init__(self, document):
        super().__init__(document)

        # Define highlighting rules
        self.highlighting_rules = []

        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(86, 156, 214))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "break",
            "case",
            "catch",
            "class",
            "const",
            "continue",
            "debugger",
            "default",
            "delete",
            "do",
            "else",
            "export",
            "extends",
            "finally",
            "for",
            "function",
            "if",
            "import",
            "in",
            "instanceof",
            "let",
            "new",
            "return",
            "super",
            "switch",
            "this",
            "throw",
            "try",
            "typeof",
            "var",
            "void",
            "while",
            "with",
            "yield",
        ]
        for keyword in keywords:
            pattern = QRegExp(f"\\b{keyword}\\b")
            self.highlighting_rules.append((pattern, keyword_format))

        # Frida API objects (optional highlighting)
        frida_format = QTextCharFormat()
        frida_format.setForeground(QColor(156, 220, 254))
        frida_format.setFontWeight(QFont.Bold)
        frida_api = [
            "Interceptor",
            "Module",
            "Memory",
            "Process",
            "Thread",
            "NativePointer",
            "NativeFunction",
            "send",
            "recv",
            "console",
            "Java",
            "ObjC",
            "Stalker",
            "ApiResolver",
            "DebugSymbol",
        ]
        for api in frida_api:
            pattern = QRegExp(f"\\b{api}\\b")
            self.highlighting_rules.append((pattern, frida_format))

        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor(214, 157, 133))
        self.highlighting_rules.append((QRegExp('"[^"]*"'), string_format))
        self.highlighting_rules.append((QRegExp("'[^']*'"), string_format))

        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(106, 153, 85))
        self.highlighting_rules.append((QRegExp("//.*"), comment_format))

        # Functions
        function_format = QTextCharFormat()
        function_format.setForeground(QColor(220, 220, 170))
        self.highlighting_rules.append((QRegExp("\\b[A-Za-z0-9_]+(?=\\()"), function_format))

        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor(181, 206, 168))
        self.highlighting_rules.append((QRegExp("\\b[0-9]+\\b"), number_format))

        # Multi-line comments
        self.multiline_comment_format = QTextCharFormat()
        self.multiline_comment_format.setForeground(QColor(106, 153, 85))

    def highlightBlock(self, text):
        """Apply syntax highlighting to block"""
        # Single line rules
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

        self.setCurrentBlockState(0)

        # Multi-line comments
        start_expression = QRegExp("/\\*")
        end_expression = QRegExp("\\*/")

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
