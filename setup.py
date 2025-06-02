#!/usr/bin/env python3
"""
Setup script for Intellicrack.

This script is used to install the Intellicrack package and its dependencies.
"""

import os
import sys
from setuptools import setup, find_packages

# Read the README file
def read_long_description():
    """Read the README file for long description."""
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Intellicrack - Advanced Binary Analysis and Security Research Framework"

# Read requirements
def read_requirements(filename='requirements.txt'):
    """Read requirements from file."""
    req_path = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(req_path):
        with open(req_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

# Package metadata
NAME = 'intellicrack'
VERSION = '0.1.0'
AUTHOR = 'Intellicrack Team'
AUTHOR_EMAIL = 'team@intellicrack.com'
DESCRIPTION = 'Advanced Binary Analysis and Security Research Framework'
LONG_DESCRIPTION = read_long_description()
URL = 'https://github.com/intellicrack/intellicrack'
LICENSE = 'MIT'

# Python version requirement
PYTHON_REQUIRES = '>=3.8'

# Package classifiers
CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'Intended Audience :: Science/Research',
    'Intended Audience :: Information Technology',
    'Topic :: Security',
    'Topic :: Software Development :: Disassemblers',
    'Topic :: Software Development :: Debuggers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: 3.12',
    'Operating System :: OS Independent',
    'Environment :: Console',
    'Environment :: X11 Applications :: Qt',
]

# Keywords
KEYWORDS = [
    'binary-analysis',
    'reverse-engineering',
    'security',
    'vulnerability-detection',
    'malware-analysis',
    'license-bypass',
    'protection-analysis',
    'symbolic-execution',
    'taint-analysis',
    'disassembly',
    'debugging',
    'exploitation'
]

# Entry points
ENTRY_POINTS = {
    'console_scripts': [
        'intellicrack=intellicrack.main:main',
        'intellicrack-cli=scripts.intellicrack_cli:main',
        'intellicrack-gui=intellicrack.ui.main_app:launch',
        'intellicrack-basic=scripts.run_analysis_cli:main',  # Keep old basic CLI
    ],
}

# Package data
PACKAGE_DATA = {
    'intellicrack': [
        'assets/*',
        'data/signatures/*',
        'data/templates/*',
        'plugins/frida_scripts/*.js',
        'plugins/ghidra_scripts/*.java',
        'plugins/custom_modules/*.py',
    ],
}

# Dependencies
INSTALL_REQUIRES = read_requirements('requirements.txt')

# Optional dependencies for different features
EXTRAS_REQUIRE = {
    'full': [
        'angr>=9.0.0',
        'manticore>=0.3.0',
        'miasm>=0.1.0',
        'qiling>=1.4.0',
        'unicorn>=2.0.0',
        'keystone-engine>=0.9.2',
        'ropper>=1.13.0',
        'pwntools>=4.0.0',
    ],
    'ml': [
        'tensorflow>=2.0.0',
        'torch>=1.0.0',
        'transformers>=4.0.0',
    ],
    'network': [
        'mitmproxy>=8.0.0',
        'pyshark>=0.5.0',
        'scapy>=2.4.0',
        'dpkt>=1.9.0',
    ],
    'dev': read_requirements('requirements-dev.txt') if os.path.exists('requirements-dev.txt') else [
        'pytest>=7.0.0',
        'pytest-cov>=4.0.0',
        'pytest-mock>=3.0.0',
        'black>=22.0.0',
        'flake8>=5.0.0',
        'mypy>=0.990',
        'sphinx>=5.0.0',
        'sphinx-rtd-theme>=1.0.0',
    ],
}

# All optional dependencies
EXTRAS_REQUIRE['all'] = list(set(sum(EXTRAS_REQUIRE.values(), [])))

def main():
    """Run setup."""
    setup(
        name=NAME,
        version=VERSION,
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        description=DESCRIPTION,
        long_description=LONG_DESCRIPTION,
        long_description_content_type='text/markdown',
        url=URL,
        license=LICENSE,
        classifiers=CLASSIFIERS,
        keywords=KEYWORDS,
        packages=find_packages(exclude=['tests', 'tests.*', 'docs', 'examples']),
        package_data=PACKAGE_DATA,
        include_package_data=True,
        install_requires=INSTALL_REQUIRES,
        extras_require=EXTRAS_REQUIRE,
        python_requires=PYTHON_REQUIRES,
        entry_points=ENTRY_POINTS,
        zip_safe=False,
        platforms=['any'],
        project_urls={
            'Bug Reports': f'{URL}/issues',
            'Documentation': f'{URL}/wiki',
            'Source': URL,
        },
    )

if __name__ == '__main__':
    main()