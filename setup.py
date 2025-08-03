#!/usr/bin/env python3
"""
Setup script for Intellicrack - Advanced binary analysis and exploitation platform.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from __init__.py
version_file = Path(__file__).parent / "intellicrack" / "__init__.py"
version = "1.0.0"  # Default version

if version_file.exists():
    with open(version_file, 'r') as f:
        content = f.read()
        import re
        version_match = re.search(r'__version__\s*=\s*["\']([^"\']*)["\']', content)
        if version_match:
            version = version_match.group(1)

# Read long description from README
readme_file = Path(__file__).parent / "README.md"
long_description = ""

if readme_file.exists():
    with open(readme_file, 'r', encoding='utf-8') as f:
        long_description = f.read()

# Modern packaging uses pyproject.toml - this is a compatibility stub
# For production installs, use: pip install .
requirements = []

setup(
    name="intellicrack",
    version=version,
    author="Intellicrack Development Team",
    author_email="dev@intellicrack.com",
    description="Advanced binary analysis and exploitation platform with AI-driven capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/intellicrack/intellicrack",
    packages=find_packages(exclude=["tests*", "dev*", "legacy_tests*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Disassemblers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: X11 Applications :: Qt",
        "Environment :: Win32 (MS Windows)",
        "Environment :: MacOS X",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-benchmark>=4.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-qt>=4.2.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
            "bandit>=1.7.0",
            "safety>=2.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
        "ai": [
            "transformers>=4.21.0",
            "torch>=1.12.0",
            "openai>=0.27.0",
            "anthropic>=0.3.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "intellicrack=intellicrack.cli.cli:main",
            "intellicrack-gui=intellicrack.ui.main_app:main",
            "intellicrack-ai=intellicrack.ai.ai_script_generator:main",
        ],
    },
    include_package_data=True,
    package_data={
        "intellicrack": [
            "data/*.json",
            "data/*.yml",
            "data/*.yaml",
            "templates/*.j2",
            "templates/*.txt",
            "ui/resources/*.png",
            "ui/resources/*.svg",
            "ui/resources/*.ico",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/intellicrack/intellicrack/issues",
        "Source": "https://github.com/intellicrack/intellicrack",
        "Documentation": "https://intellicrack.readthedocs.io/",
    },
    keywords="binary analysis exploitation reverse engineering AI automation security",
    zip_safe=False,
)