# \!/usr/bin/env python3

# Standard library modules (don't need to be in dependencies)
STDLIB_MODULES = {
    "abc",
    "argparse",
    "ast",
    "asyncio",
    "atexit",
    "base64",
    "binascii",
    "cmd",
    "collections",
    "concurrent",
    "contextlib",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "difflib",
    "enum",
    "fnmatch",
    "functools",
    "gc",
    "getpass",
    "glob",
    "hashlib",
    "hmac",
    "http",
    "importlib",
    "inspect",
    "io",
    "ipaddress",
    "json",
    "linecache",
    "logging",
    "math",
    "mimetypes",
    "mmap",
    "multiprocessing",
    "os",
    "pathlib",
    "pickle",
    "platform",
    "queue",
    "random",
    "re",
    "resource",
    "secrets",
    "select",
    "shlex",
    "shutil",
    "signal",
    "socket",
    "socketserver",
    "sqlite3",
    "ssl",
    "string",
    "struct",
    "subprocess",
    "sys",
    "tempfile",
    "threading",
    "time",
    "tkinter",
    "traceback",
    "tracemalloc",
    "types",
    "typing",
    "unittest",
    "urllib",
    "uuid",
    "warnings",
    "weakref",
    "webbrowser",
    "winreg",
    "xml",
    "zipfile",
    "zlib",
}

# Read imported packages
with open("external_imports.txt", "r") as f:
    imported_packages = {line.strip().lower() for line in f if line.strip()}

# Filter out standard library and internal packages
third_party_imports = {
    pkg
    for pkg in imported_packages
    if pkg not in STDLIB_MODULES
    and pkg != "intellicrack"
    and pkg != "java"
    and pkg != "ghidra"
    and pkg != "coverage"
    and pkg != "pytest"
    and pkg
}

# Key packages declared in pyproject.toml (normalized to lowercase)
declared_packages = {
    "accelerate",
    "anthropic",
    "openai",
    "transformers",
    "huggingface_hub",
    "safetensors",
    "peft",
    "bitsandbytes",
    "angr",
    "claripy",
    "capstone",
    "keystone_engine",
    "binwalk",
    "volatility3",
    "yara-python",
    "lief",
    "pefile",
    "pyelftools",
    "z3-solver",
    "r2pipe",
    "frida",
    "frida-tools",
    "qiling",
    "python-fx",
    "manticore",
    "die-python",
    "mitmproxy",
    "scapy",
    "cryptography",
    "paramiko",
    "pyshark",
    "dpkt",
    "pycryptodome",
    "pyopenssl",
    "aiohttp",
    "requests",
    "boto3",
    "azure-storage-blob",
    "fastapi",
    "httpie",
    "joblib",
    "dask",
    "ray",
    "tensorflow_cpu",
    "torch",
    "torchvision",
    "torchaudio",
    "onnx",
    "onnxruntime",
    "pyopencl",
    "pymongo",
    "psycopg2_binary",
    "pyqt6",
    "pyqt6-sip",
    "pyqtgraph",
    "pillow",
    "graphviz",
    "pynput",
    "pyusb",
    "watchdog",
    "wmi",
    "flask",
    "flask_cors",
    "jinja2",
    "pdfkit",
    "reportlab",
    "weasyprint",
    "tinycss2",
    "xlsxwriter",
    "cairocffi",
    "setuptools",
    "wheel",
    "build",
    "cffi",
    "macholib",
    "networkx",
    "nltk",
    "rich",
    "tqdm",
    "jiter",
    "importlib_metadata",
    "idna",
    "amqp",
    "kombu",
    "keyring",
    "jmespath",
    "hyperframe",
    "celery",
    "click",
    "python-dotenv",
}


# Normalize package names for comparison
def normalize_name(name):
    return name.lower().replace("-", "_").replace("_", "")


normalized_declared = {normalize_name(pkg) for pkg in declared_packages}

# Check for missing packages
missing_packages = set()
for imported in third_party_imports:
    imported_norm = normalize_name(imported)

    # Check exact match first
    if imported_norm not in normalized_declared:
        # Check if it's a known alias
        aliases = {
            "crypto": "pycryptodome",
            "pil": "pillow",
            "yaml": "pyyaml",
            "sklearn": "scikit-learn",
            "cv2": "opencv-python",
            "numpy": "numpy",
            "pandas": "pandas",
            "matplotlib": "matplotlib",
            "seaborn": "seaborn",
            "scipy": "scipy",
            "unicorn": "unicorn",
            "sqlalchemy": "sqlalchemy",
            "uvicorn": "uvicorn",
            "jwt": "pyjwt",
            "jsonschema": "jsonschema",
        }

        if imported_norm in aliases:
            alias_norm = normalize_name(aliases[imported_norm])
            if alias_norm not in normalized_declared:
                missing_packages.add(f"{imported} (maps to {aliases[imported_norm]})")
        else:
            missing_packages.add(imported)

print("Third-party packages imported in code:")
for pkg in sorted(third_party_imports):
    print(f"  {pkg}")

print(f"\nTotal third-party imports: {len(third_party_imports)}")

if missing_packages:
    print(f"\nMissing from pyproject.toml ({len(missing_packages)} packages):")
    for pkg in sorted(missing_packages):
        print(f"  {pkg}")
else:
    print("\nAll imported packages are declared in pyproject.toml\\!")
