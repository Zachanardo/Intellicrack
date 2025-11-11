#!/usr/bin/env python3
"""Intellicrack Dependency Analyzer.

Scans the entire codebase to identify third-party imports and cross-references
them with installed packages to detect missing dependencies.
"""

import ast
import sys
from collections import defaultdict
from importlib.metadata import distributions
from pathlib import Path
from typing import Dict, List, Set, Tuple


class DependencyAnalyzer:
    """Analyzes Python code to identify and validate third-party dependencies."""

    def __init__(self, project_root: Path) -> None:
        """Initialize the dependency analyzer with project root path."""
        self.project_root = project_root
        self.local_modules = self._discover_local_modules()
        self.installed_packages = self._get_installed_packages()
        self.package_to_imports = self._build_package_import_map()
        self.stdlib_modules = self._get_stdlib_modules()

    def _discover_local_modules(self) -> Set[str]:
        """Discover all local module names in the project."""
        local_modules = set()
        exclude_dirs = {".pixi", ".venv", "build", "dist", "__pycache__", ".git", "tools", "target", ".pytest_cache", "htmlcov"}

        # Add the main package
        local_modules.add("intellicrack")

        # Find all Python packages (directories with __init__.py)
        for path in self.project_root.rglob("__init__.py"):
            if any(exclude in path.parts for exclude in exclude_dirs):
                continue

            # Get package path relative to project root
            relative = path.parent.relative_to(self.project_root)
            parts = relative.parts

            # Build module hierarchy
            for i in range(len(parts)):
                module_name = ".".join(parts[: i + 1])
                local_modules.add(module_name)

        # Also find individual .py files in intellicrack/ directory
        intellicrack_dir = self.project_root / "intellicrack"
        if intellicrack_dir.exists():
            for py_file in intellicrack_dir.rglob("*.py"):
                if any(exclude in py_file.parts for exclude in exclude_dirs):
                    continue
                # Add just the filename without .py as a potential module name
                module_name = py_file.stem
                if module_name != "__init__":
                    local_modules.add(module_name)

        return local_modules

    def _get_installed_packages(self) -> Dict[str, str]:
        """Get all installed packages and their versions."""
        packages = {}
        for dist in distributions():
            packages[dist.metadata["Name"].lower()] = dist.version
        return packages

    def _build_package_import_map(self) -> Dict[str, str]:
        """Build mapping from import names to package names."""
        import_map = {}

        for dist in distributions():
            package_name = dist.metadata["Name"].lower()

            # Add the package name itself
            import_map[package_name] = package_name
            import_map[package_name.replace("-", "_")] = package_name

            # Try to get top-level imports from metadata
            if dist.files:
                for file in dist.files:
                    parts = file.parts
                    if parts and not parts[0].endswith(".dist-info"):
                        top_level = parts[0].replace(".py", "")
                        if top_level and not top_level.startswith("_"):
                            import_map[top_level] = package_name

        return import_map

    def _get_stdlib_modules(self) -> Set[str]:
        """Get standard library module names."""
        stdlib = {
            # Common stdlib modules
            "abc",
            "aifc",
            "argparse",
            "array",
            "ast",
            "asynchat",
            "asyncio",
            "asyncore",
            "atexit",
            "audioop",
            "base64",
            "bdb",
            "binascii",
            "binhex",
            "bisect",
            "builtins",
            "bz2",
            "calendar",
            "cgi",
            "cgitb",
            "chunk",
            "cmath",
            "cmd",
            "code",
            "codecs",
            "codeop",
            "collections",
            "colorsys",
            "compileall",
            "concurrent",
            "configparser",
            "contextlib",
            "contextvars",
            "copy",
            "copyreg",
            "crypt",
            "csv",
            "ctypes",
            "curses",
            "dataclasses",
            "datetime",
            "dbm",
            "decimal",
            "difflib",
            "dis",
            "distutils",
            "doctest",
            "email",
            "encodings",
            "enum",
            "errno",
            "faulthandler",
            "fcntl",
            "filecmp",
            "fileinput",
            "fnmatch",
            "fractions",
            "ftplib",
            "functools",
            "gc",
            "getopt",
            "getpass",
            "gettext",
            "glob",
            "graphlib",
            "grp",
            "gzip",
            "hashlib",
            "heapq",
            "hmac",
            "html",
            "http",
            "idlelib",
            "imaplib",
            "imghdr",
            "imp",
            "importlib",
            "inspect",
            "io",
            "ipaddress",
            "itertools",
            "json",
            "keyword",
            "lib2to3",
            "linecache",
            "locale",
            "logging",
            "lzma",
            "mailbox",
            "mailcap",
            "marshal",
            "math",
            "mimetypes",
            "mmap",
            "modulefinder",
            "msilib",
            "msvcrt",
            "multiprocessing",
            "netrc",
            "nis",
            "nntplib",
            "numbers",
            "operator",
            "optparse",
            "os",
            "ossaudiodev",
            "parser",
            "pathlib",
            "pdb",
            "pickle",
            "pickletools",
            "pipes",
            "pkgutil",
            "platform",
            "plistlib",
            "poplib",
            "posix",
            "posixpath",
            "pprint",
            "profile",
            "pstats",
            "pty",
            "pwd",
            "py_compile",
            "pyclbr",
            "pydoc",
            "queue",
            "quopri",
            "random",
            "re",
            "readline",
            "reprlib",
            "resource",
            "rlcompleter",
            "runpy",
            "sched",
            "secrets",
            "select",
            "selectors",
            "shelve",
            "shlex",
            "shutil",
            "signal",
            "site",
            "smtpd",
            "smtplib",
            "sndhdr",
            "socket",
            "socketserver",
            "spwd",
            "sqlite3",
            "ssl",
            "stat",
            "statistics",
            "string",
            "stringprep",
            "struct",
            "subprocess",
            "sunau",
            "symtable",
            "sys",
            "sysconfig",
            "syslog",
            "tabnanny",
            "tarfile",
            "telnetlib",
            "tempfile",
            "termios",
            "test",
            "textwrap",
            "threading",
            "time",
            "timeit",
            "tkinter",
            "token",
            "tokenize",
            "tomllib",
            "trace",
            "traceback",
            "tracemalloc",
            "tty",
            "turtle",
            "turtledemo",
            "types",
            "typing",
            "unicodedata",
            "unittest",
            "urllib",
            "uu",
            "uuid",
            "venv",
            "warnings",
            "wave",
            "weakref",
            "webbrowser",
            "winreg",
            "winsound",
            "wsgiref",
            "xdrlib",
            "xml",
            "xmlrpc",
            "zipapp",
            "zipfile",
            "zipimport",
            "zlib",
        }
        return stdlib

    def extract_imports(self, file_path: Path) -> Set[str]:
        """Extract all import statements from a Python file."""
        imports = set()

        try:
            with open(file_path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(file_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_level = alias.name.split(".")[0]
                        imports.add(top_level)

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top_level = node.module.split(".")[0]
                        imports.add(top_level)

        except (SyntaxError, UnicodeDecodeError) as e:
            print(f"\033[93mWarning: Failed to parse {file_path}: {e}\033[0m", file=sys.stderr)

        return imports

    def classify_import(self, import_name: str) -> Tuple[str, str]:
        """Classify an import as 'local', 'stdlib', 'installed', or 'missing'.

        Returns (classification, package_name).
        """
        # Check if it's a local module
        if import_name in self.local_modules or import_name.startswith("intellicrack"):
            return ("local", import_name)

        # Check if it's a subdirectory of intellicrack/ (relative import)
        intellicrack_dir = self.project_root / "intellicrack" / import_name
        if intellicrack_dir.exists() and intellicrack_dir.is_dir():
            return ("local", import_name)

        # Check for common local module patterns
        local_prefixes = {"tests", "scripts", "examples", "docs"}
        if any(import_name.startswith(prefix) for prefix in local_prefixes):
            return ("local", import_name)

        # Check if it's stdlib (including builtins like __future__, __main__)
        if import_name in self.stdlib_modules or import_name.startswith("__"):
            return ("stdlib", import_name)

        # Check if it's an installed third-party package
        package_name = self.package_to_imports.get(import_name)
        if package_name and package_name in self.installed_packages:
            return ("installed", package_name)

        # Try direct package name match
        if import_name.lower() in self.installed_packages:
            return ("installed", import_name.lower())

        # Not found
        return ("missing", import_name)

    def analyze_project(self) -> Dict[str, List[Tuple[str, Path]]]:
        """Analyze all Python files in the project."""
        results = defaultdict(list)
        all_imports = defaultdict(set)

        # Find all Python files (excluding tests)
        python_files = []
        exclude_dirs = {".pixi", ".venv", "build", "dist", "__pycache__", ".git", "tools", "target", ".pytest_cache", "htmlcov", "tests"}

        for pattern in ["**/*.py", "**/*.pyw"]:
            for path in self.project_root.glob(pattern):
                # Skip if any excluded directory in path
                if any(exclude in path.parts for exclude in exclude_dirs):
                    continue
                python_files.append(path)

        print(f"\033[96mScanning {len(python_files)} Python files...\033[0m\n")

        # Analyze each file
        for file_path in python_files:
            imports = self.extract_imports(file_path)

            for import_name in imports:
                classification, package_name = self.classify_import(import_name)
                all_imports[classification].add(package_name)

                if classification == "missing":
                    results[classification].append((import_name, file_path))

        # Display summary
        self._print_summary(all_imports, results)

        return dict(results)

    def _print_summary(self, all_imports: Dict[str, Set[str]], results: Dict[str, List]) -> None:
        """Print analysis summary with colors."""
        print("\033[1;94m" + "=" * 80 + "\033[0m")
        print("\033[1;94m" + "INTELLICRACK DEPENDENCY ANALYSIS REPORT".center(80) + "\033[0m")
        print("\033[1;94m" + "=" * 80 + "\033[0m\n")

        # Local modules
        print(f"\033[1;96m Local Modules:\033[0m {len(all_imports.get('local', set()))}")
        if all_imports.get("local"):
            for module in sorted(all_imports["local"])[:10]:
                print(f"   {module}")
            if len(all_imports["local"]) > 10:
                print(f"  ... and {len(all_imports['local']) - 10} more")
        print()

        # Standard library
        print(f"\033[1;92mStandard Library Imports:\033[0m {len(all_imports.get('stdlib', set()))}")
        print()

        # Installed packages
        installed = all_imports.get("installed", set())
        print(f"\033[1;92mInstalled Third-Party Packages:\033[0m {len(installed)}")
        if installed:
            for package in sorted(installed)[:15]:
                version = self.installed_packages.get(package, "unknown")
                print(f"   {package} ({version})")
            if len(installed) > 15:
                print(f"  ... and {len(installed) - 15} more")
        print()

        # Missing packages
        missing = all_imports.get("missing", set())
        if missing:
            print(f"\033[1;91mMISSING DEPENDENCIES:\033[0m {len(missing)}")
            print("\033[1;91m" + "=" * 80 + "\033[0m")

            # Group by file
            missing_by_file = defaultdict(list)
            for import_name, file_path in results.get("missing", []):
                missing_by_file[file_path].append(import_name)

            for file_path, imports in sorted(missing_by_file.items()):
                rel_path = file_path.relative_to(self.project_root)
                print(f"\n\033[93m{rel_path}\033[0m")
                for imp in sorted(set(imports)):
                    print(f"  \033[91m[MISSING]\033[0m {imp}")

            print("\n\033[1;91m" + "=" * 80 + "\033[0m")
            print(f"\n\033[1;93mAction Required:\033[0m Install {len(missing)} missing packages")
            print(f"\033[93mMissing packages:\033[0m {', '.join(sorted(missing))}")
        else:
            print("\033[1;92mALL DEPENDENCIES SATISFIED!\033[0m")
            print("\033[1;92m" + "=" * 80 + "\033[0m")


def main() -> None:
    """Run the dependency analysis."""
    project_root = Path(__file__).parent.parent

    analyzer = DependencyAnalyzer(project_root)
    results = analyzer.analyze_project()

    # Exit with error code if missing dependencies
    if results.get("missing"):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
