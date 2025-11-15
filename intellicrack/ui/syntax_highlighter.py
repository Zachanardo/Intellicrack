"""Centralized syntax highlighting module for Intellicrack.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import re

from intellicrack.handlers.pyqt6_handler import (
    QColor,
    QFont,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextDocument,
)

logger = logging.getLogger(__name__)


class SyntaxHighlighter(QSyntaxHighlighter):
    """Unified syntax highlighter supporting multiple languages."""

    def __init__(self, document: QTextDocument, language: str = "python") -> None:
        """Initialize the syntax highlighter.

        Args:
            document: The text document to highlight
            language: Programming language to highlight

        """
        super().__init__(document)
        self.language = language.lower()
        self.rules: list[tuple[re.Pattern, QTextCharFormat]] = []
        self._setup_rules()

    def _setup_rules(self) -> None:
        """Set up highlighting rules based on the selected language."""
        if self.language == "python":
            self._setup_python_rules()
        elif self.language in {"javascript", "js"}:
            self._setup_javascript_rules()
        elif self.language == "json":
            self._setup_json_rules()
        elif self.language in {"assembly", "asm"}:
            self._setup_assembly_rules()
        elif self.language in {"c", "cpp"}:
            self._setup_c_rules()
        elif self.language in {"xml", "html"}:
            self._setup_xml_rules()
        elif self.language in {"shell", "bash"}:
            self._setup_shell_rules()
        else:
            logger.warning(f"Unsupported language: {self.language}, using default")
            self._setup_default_rules()

    def _create_format(self, color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
        """Create a text format with specified properties.

        Args:
            color: Color in hex format
            bold: Whether text should be bold
            italic: Whether text should be italic

        Returns:
            Configured text format

        """
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))

        if bold:
            text_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            text_format.setFontItalic(True)

        return text_format

    def _setup_python_rules(self) -> None:
        """Set up syntax highlighting rules for Python."""
        # Keywords
        keyword_format = self._create_format("#ff79c6", bold=True)
        keywords = [
            "\\bFalse\\b",
            "\\bNone\\b",
            "\\bTrue\\b",
            "\\band\\b",
            "\\bas\\b",
            "\\bassert\\b",
            "\\basync\\b",
            "\\bawait\\b",
            "\\bbreak\\b",
            "\\bclass\\b",
            "\\bcontinue\\b",
            "\\bdef\\b",
            "\\bdel\\b",
            "\\belif\\b",
            "\\belse\\b",
            "\\bexcept\\b",
            "\\bfinally\\b",
            "\\bfor\\b",
            "\\bfrom\\b",
            "\\bglobal\\b",
            "\\bif\\b",
            "\\bimport\\b",
            "\\bin\\b",
            "\\bis\\b",
            "\\blambda\\b",
            "\\bnonlocal\\b",
            "\\bnot\\b",
            "\\bor\\b",
            "\\bpass\\b",
            "\\braise\\b",
            "\\breturn\\b",
            "\\btry\\b",
            "\\bwhile\\b",
            "\\bwith\\b",
            "\\byield\\b",
        ]
        for keyword in keywords:
            self.rules.append((re.compile(keyword), keyword_format))

        # Built-in functions
        builtin_format = self._create_format("#8be9fd")
        builtins = [
            "\\babs\\b",
            "\\ball\\b",
            "\\bany\\b",
            "\\bbin\\b",
            "\\bbool\\b",
            "\\bbytearray\\b",
            "\\bbytes\\b",
            "\\bcallable\\b",
            "\\bchr\\b",
            "\\bclassmethod\\b",
            "\\bcompile\\b",
            "\\bcomplex\\b",
            "\\bdelattr\\b",
            "\\bdict\\b",
            "\\bdir\\b",
            "\\bdivmod\\b",
            "\\benumerate\\b",
            "\\beval\\b",
            "\\bexec\\b",
            "\\bfilter\\b",
            "\\bfloat\\b",
            "\\bformat\\b",
            "\\bfrozenset\\b",
            "\\bgetattr\\b",
            "\\bglobals\\b",
            "\\bhasattr\\b",
            "\\bhash\\b",
            "\\bhelp\\b",
            "\\bhex\\b",
            "\\bid\\b",
            "\\binput\\b",
            "\\bint\\b",
            "\\bisinstance\\b",
            "\\bissubclass\\b",
            "\\biter\\b",
            "\\blen\\b",
            "\\blist\\b",
            "\\blocals\\b",
            "\\bmap\\b",
            "\\bmax\\b",
            "\\bmemoryview\\b",
            "\\bmin\\b",
            "\\bnext\\b",
            "\\bobject\\b",
            "\\boct\\b",
            "\\bopen\\b",
            "\\bord\\b",
            "\\bpow\\b",
            "\\bprint\\b",
            "\\bproperty\\b",
            "\\brange\\b",
            "\\brepr\\b",
            "\\breversed\\b",
            "\\bround\\b",
            "\\bset\\b",
            "\\bsetattr\\b",
            "\\bslice\\b",
            "\\bsorted\\b",
            "\\bstaticmethod\\b",
            "\\bstr\\b",
            "\\bsum\\b",
            "\\bsuper\\b",
            "\\btuple\\b",
            "\\btype\\b",
            "\\bvars\\b",
            "\\bzip\\b",
        ]
        for builtin in builtins:
            self.rules.append((re.compile(builtin), builtin_format))

        # Decorators
        decorator_format = self._create_format("#50fa7b", italic=True)
        self.rules.append((re.compile(r"@\w+"), decorator_format))

        # Class names
        class_format = self._create_format("#f8f8f2", bold=True)
        self.rules.append((re.compile(r"\bclass\s+(\w+)"), class_format))

        # Function definitions
        function_format = self._create_format("#50fa7b", bold=True)
        self.rules.append((re.compile(r"\bdef\s+(\w+)"), function_format))

        # Numbers
        number_format = self._create_format("#bd93f9")
        self.rules.append((re.compile(r"\b[+-]?[0-9]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?0[xX][0-9A-Fa-f]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b"), number_format))

        # Strings
        string_format = self._create_format("#f1fa8c")
        self.rules.append((re.compile(r"\".*?\""), string_format))
        self.rules.append((re.compile(r"\'.*?\'"), string_format))
        self.rules.append((re.compile(r"\"\"\".*?\"\"\"", re.DOTALL), string_format))
        self.rules.append((re.compile(r"\'\'\'.*?\'\'\'", re.DOTALL), string_format))

        # Comments
        comment_format = self._create_format("#6272a4", italic=True)
        self.rules.append((re.compile(r"#[^\n]*"), comment_format))

        # Self
        self_format = self._create_format("#ff79c6", italic=True)
        self.rules.append((re.compile(r"\bself\b"), self_format))

    def _setup_javascript_rules(self) -> None:
        """Set up syntax highlighting rules for JavaScript."""
        # Keywords
        keyword_format = self._create_format("#ff79c6", bold=True)
        keywords = [
            "\\bbreak\\b",
            "\\bcase\\b",
            "\\bcatch\\b",
            "\\bclass\\b",
            "\\bconst\\b",
            "\\bcontinue\\b",
            "\\bdebugger\\b",
            "\\bdefault\\b",
            "\\bdelete\\b",
            "\\bdo\\b",
            "\\belse\\b",
            "\\bexport\\b",
            "\\bextends\\b",
            "\\bfinally\\b",
            "\\bfor\\b",
            "\\bfunction\\b",
            "\\bif\\b",
            "\\bimport\\b",
            "\\bin\\b",
            "\\binstanceof\\b",
            "\\blet\\b",
            "\\bnew\\b",
            "\\breturn\\b",
            "\\bsuper\\b",
            "\\bswitch\\b",
            "\\bthis\\b",
            "\\bthrow\\b",
            "\\btry\\b",
            "\\btypeof\\b",
            "\\bvar\\b",
            "\\bvoid\\b",
            "\\bwhile\\b",
            "\\bwith\\b",
            "\\byield\\b",
            "\\basync\\b",
            "\\bawait\\b",
            "\\bstatic\\b",
        ]
        for keyword in keywords:
            self.rules.append((re.compile(keyword), keyword_format))

        # Built-in objects and values
        builtin_format = self._create_format("#8be9fd")
        builtins = [
            "\\btrue\\b",
            "\\bfalse\\b",
            "\\bnull\\b",
            "\\bundefined\\b",
            "\\bArray\\b",
            "\\bBoolean\\b",
            "\\bDate\\b",
            "\\bError\\b",
            "\\bFunction\\b",
            "\\bJSON\\b",
            "\\bMath\\b",
            "\\bNumber\\b",
            "\\bObject\\b",
            "\\bRegExp\\b",
            "\\bString\\b",
            "\\bSymbol\\b",
            "\\bPromise\\b",
            "\\bMap\\b",
            "\\bSet\\b",
            "\\bWeakMap\\b",
            "\\bWeakSet\\b",
            "\\bconsole\\b",
            "\\bwindow\\b",
            "\\bdocument\\b",
        ]
        for builtin in builtins:
            self.rules.append((re.compile(builtin), builtin_format))

        # Function definitions
        function_format = self._create_format("#50fa7b", bold=True)
        self.rules.append((re.compile(r"\bfunction\s+(\w+)"), function_format))
        self.rules.append((re.compile(r"(\w+)\s*:\s*function"), function_format))
        self.rules.append((re.compile(r"(\w+)\s*=\s*function"), function_format))
        self.rules.append((re.compile(r"(\w+)\s*=\s*\(.*?\)\s*=>"), function_format))

        # Numbers
        number_format = self._create_format("#bd93f9")
        self.rules.append((re.compile(r"\b[+-]?[0-9]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?0[xX][0-9A-Fa-f]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b"), number_format))

        # Strings
        string_format = self._create_format("#f1fa8c")
        self.rules.append((re.compile(r"\".*?\""), string_format))
        self.rules.append((re.compile(r"\'.*?\'"), string_format))
        self.rules.append((re.compile(r"`.*?`"), string_format))

        # Comments
        comment_format = self._create_format("#6272a4", italic=True)
        self.rules.append((re.compile(r"//[^\n]*"), comment_format))
        self.rules.append((re.compile(r"/\*.*?\*/", re.DOTALL), comment_format))

    def _setup_json_rules(self) -> None:
        """Set up syntax highlighting rules for JSON."""
        # Keys
        key_format = self._create_format("#ff79c6")
        self.rules.append((re.compile(r"\"[^\"]*\"\s*:"), key_format))

        # Strings
        string_format = self._create_format("#f1fa8c")
        self.rules.append((re.compile(r":\s*\"[^\"]*\""), string_format))

        # Numbers
        number_format = self._create_format("#bd93f9")
        self.rules.append((re.compile(r"\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b"), number_format))

        # Booleans and null
        keyword_format = self._create_format("#8be9fd")
        self.rules.append((re.compile(r"\btrue\b|\bfalse\b|\bnull\b"), keyword_format))

        # Brackets
        bracket_format = self._create_format("#f8f8f2", bold=True)
        self.rules.append((re.compile(r"[\[\]{}]"), bracket_format))

    def _setup_assembly_rules(self) -> None:
        """Set up syntax highlighting rules for Assembly."""
        # Instructions
        instruction_format = self._create_format("#ff79c6", bold=True)
        instructions = [
            "\\bmov\\b",
            "\\bpush\\b",
            "\\bpop\\b",
            "\\blea\\b",
            "\\badd\\b",
            "\\bsub\\b",
            "\\bmul\\b",
            "\\bdiv\\b",
            "\\binc\\b",
            "\\bdec\\b",
            "\\band\\b",
            "\\bor\\b",
            "\\bxor\\b",
            "\\bnot\\b",
            "\\bshl\\b",
            "\\bshr\\b",
            "\\bjmp\\b",
            "\\bje\\b",
            "\\bjne\\b",
            "\\bjg\\b",
            "\\bjge\\b",
            "\\bjl\\b",
            "\\bjle\\b",
            "\\bcall\\b",
            "\\bret\\b",
            "\\bnop\\b",
            "\\bint\\b",
            "\\bcmp\\b",
            "\\btest\\b",
            "\\bxchg\\b",
        ]
        for inst in instructions:
            self.rules.append((re.compile(inst, re.IGNORECASE), instruction_format))

        # Registers
        register_format = self._create_format("#8be9fd")
        registers = [
            "\\beax\\b",
            "\\bebx\\b",
            "\\becx\\b",
            "\\bedx\\b",
            "\\besi\\b",
            "\\bedi\\b",
            "\\bebp\\b",
            "\\besp\\b",
            "\\brax\\b",
            "\\brbx\\b",
            "\\brcx\\b",
            "\\brdx\\b",
            "\\brsi\\b",
            "\\brdi\\b",
            "\\brbp\\b",
            "\\brsp\\b",
            "\\br8\\b",
            "\\br9\\b",
            "\\br10\\b",
            "\\br11\\b",
            "\\br12\\b",
            "\\br13\\b",
            "\\br14\\b",
            "\\br15\\b",
            "\\bal\\b",
            "\\bah\\b",
            "\\bbl\\b",
            "\\bbh\\b",
            "\\bcl\\b",
            "\\bch\\b",
            "\\bdl\\b",
            "\\bdh\\b",
        ]
        for reg in registers:
            self.rules.append((re.compile(reg, re.IGNORECASE), register_format))

        # Directives
        directive_format = self._create_format("#50fa7b", bold=True)
        self.rules.append((re.compile(r"\.[a-zA-Z]+"), directive_format))

        # Labels
        label_format = self._create_format("#f1fa8c", bold=True)
        self.rules.append((re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*:"), label_format))

        # Numbers
        number_format = self._create_format("#bd93f9")
        self.rules.append((re.compile(r"0x[0-9A-Fa-f]+"), number_format))
        self.rules.append((re.compile(r"\b[0-9]+\b"), number_format))

        # Comments
        comment_format = self._create_format("#6272a4", italic=True)
        self.rules.append((re.compile(r";[^\n]*"), comment_format))

    def _setup_c_rules(self) -> None:
        """Set up syntax highlighting rules for C/C++."""
        # Keywords
        keyword_format = self._create_format("#ff79c6", bold=True)
        keywords = [
            "\\bauto\\b",
            "\\bbreak\\b",
            "\\bcase\\b",
            "\\bchar\\b",
            "\\bconst\\b",
            "\\bcontinue\\b",
            "\\bdefault\\b",
            "\\bdo\\b",
            "\\bdouble\\b",
            "\\belse\\b",
            "\\benum\\b",
            "\\bextern\\b",
            "\\bfloat\\b",
            "\\bfor\\b",
            "\\bgoto\\b",
            "\\bif\\b",
            "\\bint\\b",
            "\\blong\\b",
            "\\bregister\\b",
            "\\breturn\\b",
            "\\bshort\\b",
            "\\bsigned\\b",
            "\\bsizeof\\b",
            "\\bstatic\\b",
            "\\bstruct\\b",
            "\\bswitch\\b",
            "\\btypedef\\b",
            "\\bunion\\b",
            "\\bunsigned\\b",
            "\\bvoid\\b",
            "\\bvolatile\\b",
            "\\bwhile\\b",
            "\\bclass\\b",
            "\\bnamespace\\b",
            "\\btemplate\\b",
            "\\bpublic\\b",
            "\\bprivate\\b",
            "\\bprotected\\b",
            "\\bvirtual\\b",
            "\\bfriend\\b",
            "\\binline\\b",
            "\\boperator\\b",
            "\\bthis\\b",
            "\\bnew\\b",
            "\\bdelete\\b",
            "\\btry\\b",
            "\\bcatch\\b",
            "\\bthrow\\b",
            "\\busing\\b",
            "\\btrue\\b",
            "\\bfalse\\b",
        ]
        for keyword in keywords:
            self.rules.append((re.compile(keyword), keyword_format))

        # Preprocessor
        preprocessor_format = self._create_format("#50fa7b", bold=True)
        self.rules.append((re.compile(r"#\w+"), preprocessor_format))

        # Numbers
        number_format = self._create_format("#bd93f9")
        self.rules.append((re.compile(r"\b[+-]?[0-9]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?0[xX][0-9A-Fa-f]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b"), number_format))

        # Strings
        string_format = self._create_format("#f1fa8c")
        self.rules.append((re.compile(r"\".*?\""), string_format))
        self.rules.append((re.compile(r"\'.*?\'"), string_format))

        # Comments
        comment_format = self._create_format("#6272a4", italic=True)
        self.rules.append((re.compile(r"//[^\n]*"), comment_format))
        self.rules.append((re.compile(r"/\*.*?\*/", re.DOTALL), comment_format))

    def _setup_xml_rules(self) -> None:
        """Set up syntax highlighting rules for XML/HTML."""
        # Tags
        tag_format = self._create_format("#ff79c6", bold=True)
        self.rules.append((re.compile(r"</?\\b[A-Za-z]+(?:\\s|>|/>)"), tag_format))

        # Attributes
        attribute_format = self._create_format("#50fa7b")
        self.rules.append((re.compile(r"\\b[A-Za-z]+(?=\\=)"), attribute_format))

        # Attribute values
        value_format = self._create_format("#f1fa8c")
        self.rules.append((re.compile(r"\".*?\"|\'.*?\'"), value_format))

        # Comments
        comment_format = self._create_format("#6272a4", italic=True)
        self.rules.append((re.compile(r"<!--.*?-->", re.DOTALL), comment_format))

        # CDATA
        cdata_format = self._create_format("#8be9fd")
        self.rules.append((re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL), cdata_format))

    def _setup_shell_rules(self) -> None:
        """Set up syntax highlighting rules for Shell/Bash."""
        # Keywords
        keyword_format = self._create_format("#ff79c6", bold=True)
        keywords = [
            "\\bif\\b",
            "\\bthen\\b",
            "\\belse\\b",
            "\\belif\\b",
            "\\bfi\\b",
            "\\bfor\\b",
            "\\bwhile\\b",
            "\\bdo\\b",
            "\\bdone\\b",
            "\\bcase\\b",
            "\\besac\\b",
            "\\bfunction\\b",
            "\\breturn\\b",
            "\\bin\\b",
            "\\bselect\\b",
            "\\buntil\\b",
            "\\bbreak\\b",
            "\\bcontinue\\b",
            "\\bexit\\b",
            "\\bexport\\b",
            "\\breadonly\\b",
            "\\blocal\\b",
            "\\bunset\\b",
            "\\bshift\\b",
        ]
        for keyword in keywords:
            self.rules.append((re.compile(keyword), keyword_format))

        # Built-in commands
        builtin_format = self._create_format("#8be9fd")
        builtins = [
            "\\becho\\b",
            "\\bprintf\\b",
            "\\bread\\b",
            "\\bcd\\b",
            "\\bpwd\\b",
            "\\bls\\b",
            "\\bmkdir\\b",
            "\\brm\\b",
            "\\bcp\\b",
            "\\bmv\\b",
            "\\btouch\\b",
            "\\bcat\\b",
            "\\bgrep\\b",
            "\\bsed\\b",
            "\\bawk\\b",
            "\\bfind\\b",
            "\\bsort\\b",
            "\\buniq\\b",
            "\\bcut\\b",
            "\\btr\\b",
            "\\bwc\\b",
            "\\bhead\\b",
            "\\btail\\b",
            "\\btee\\b",
            "\\bxargs\\b",
        ]
        for builtin in builtins:
            self.rules.append((re.compile(builtin), builtin_format))

        # Variables
        variable_format = self._create_format("#bd93f9")
        self.rules.append((re.compile(r"\$\w+|\$\{.*?\}"), variable_format))

        # Strings
        string_format = self._create_format("#f1fa8c")
        self.rules.append((re.compile(r"\".*?\""), string_format))
        self.rules.append((re.compile(r"\'.*?\'"), string_format))

        # Comments
        comment_format = self._create_format("#6272a4", italic=True)
        self.rules.append((re.compile(r"#[^\n]*"), comment_format))

    def _setup_default_rules(self) -> None:
        """Set up default syntax highlighting rules."""
        # Keywords (generic)
        keyword_format = self._create_format("#ff79c6", bold=True)
        keywords = [
            "\\bif\\b",
            "\\belse\\b",
            "\\bfor\\b",
            "\\bwhile\\b",
            "\\breturn\\b",
            "\\bfunction\\b",
            "\\bclass\\b",
            "\\bstruct\\b",
            "\\benum\\b",
            "\\btry\\b",
            "\\bcatch\\b",
            "\\bthrow\\b",
            "\\bpublic\\b",
            "\\bprivate\\b",
            "\\bstatic\\b",
        ]
        for keyword in keywords:
            self.rules.append((re.compile(keyword, re.IGNORECASE), keyword_format))

        # Numbers
        number_format = self._create_format("#bd93f9")
        self.rules.append((re.compile(r"\b[+-]?[0-9]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?0[xX][0-9A-Fa-f]+[lL]?\b"), number_format))
        self.rules.append((re.compile(r"\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b"), number_format))

        # Strings
        string_format = self._create_format("#f1fa8c")
        self.rules.append((re.compile(r"\".*?\""), string_format))
        self.rules.append((re.compile(r"\'.*?\'"), string_format))

        # Comments
        comment_format = self._create_format("#6272a4", italic=True)
        self.rules.append((re.compile(r"//[^\n]*"), comment_format))
        self.rules.append((re.compile(r"#[^\n]*"), comment_format))
        self.rules.append((re.compile(r"/\*.*?\*/", re.DOTALL), comment_format))

    def highlightBlock(self, text: str) -> None:
        """Apply syntax highlighting to a block of text.

        Args:
            text: Text block to highlight

        """
        for pattern, text_format in self.rules:
            expression = pattern
            match = expression.search(text)
            while match:
                start = match.start()
                length = match.end() - match.start()
                self.setFormat(start, length, text_format)
                match = expression.search(text, match.end())

    def set_language(self, language: str) -> None:
        """Change the highlighting language.

        Args:
            language: New language to use for highlighting

        """
        self.language = language.lower()
        self.rules.clear()
        self._setup_rules()
        self.rehighlight()


def create_highlighter(document: QTextDocument, language: str = "python") -> SyntaxHighlighter:
    """Create a syntax highlighter.

    Args:
        document: Text document to highlight
        language: Programming language

    Returns:
        Configured syntax highlighter

    """
    return SyntaxHighlighter(document, language)


def get_supported_languages() -> list[str]:
    """Get list of supported programming languages.

    Returns:
        List of supported language names

    """
    return ["python", "javascript", "js", "json", "assembly", "asm", "c", "cpp", "xml", "html", "shell", "bash"]


def detect_language(code: str) -> str:
    """Attempt to detect the programming language from code content.

    Args:
        code: Code content to analyze

    Returns:
        Detected language name or 'python' as default

    """
    code_lower = code.lower()

    # Python detection
    if any(keyword in code for keyword in ["def ", "import ", "from ", "class ", "self.", "__init__"]):
        return "python"

    # JavaScript detection
    if any(keyword in code for keyword in ["function ", "const ", "let ", "var ", "=>", "console."]):
        return "javascript"

    # JSON detection
    if code.strip().startswith("{") and code.strip().endswith("}"):
        try:
            import json

            json.loads(code)
            return "json"
        except (json.JSONDecodeError, ValueError, TypeError, ImportError) as e:
            logger.debug(f"Not valid JSON: {e}")

    # Assembly detection
    if any(keyword in code_lower for keyword in ["mov ", "push ", "pop ", "call ", "ret", "jmp "]):
        return "assembly"

    # C/C++ detection
    if any(keyword in code for keyword in ["#include", "int main", "void ", "printf", "cout", "namespace"]):
        return "c"

    # XML/HTML detection
    if code.strip().startswith("<") and code.strip().endswith(">"):
        return "xml"

    # Shell script detection
    if code.startswith("#!/") or any(keyword in code for keyword in ["echo ", "export ", "#!/bin/"]):
        return "shell"

    # Default to Python
    return "python"
