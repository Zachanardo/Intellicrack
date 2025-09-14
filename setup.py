#!/usr/bin/env python
"""Setup script for Intellicrack - Advanced Binary Analysis Framework

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from setuptools import setup, find_packages
import os
import sys
from pathlib import Path

# Read the long description from README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Parse requirements from requirements files
def parse_requirements(filename):
    """Parse requirements from requirements file"""
    requirements = []
    req_path = Path("requirements") / filename
    if req_path.exists():
        with open(req_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-r'):
                    requirements.append(line)
    return requirements

# Base requirements
install_requires = parse_requirements("base.txt") if (Path("requirements") / "base.txt").exists() else []

# Development requirements
extras_require = {
    'dev': parse_requirements("test.txt") if (Path("requirements") / "test.txt").exists() else [],
}

# Platform-specific requirements
if sys.platform == 'win32':
    platform_requires = [
        'pefile==2024.8.26',
        'wmi==1.5.1',
    ]
else:
    platform_requires = [
        'manticore==0.3.7',
    ]

install_requires.extend(platform_requires)

setup(
    name='intellicrack',
    version='0.1.0',
    author='Zachary Flint',
    author_email='zach.flint2@gmail.com',
    description='Intellicrack: Advanced Binary Analysis and Security Research Framework with AI-driven capabilities',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/zacharyflint/intellicrack',
    project_urls={
        'Bug Tracker': 'https://github.com/zacharyflint/intellicrack/issues',
        'Documentation': 'https://intellicrack.readthedocs.io',
        'Source Code': 'https://github.com/zacharyflint/intellicrack',
    },
    packages=find_packages(exclude=['tests', 'tests.*', 'docs', 'docs.*']),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Software Development :: Disassemblers',
        'Topic :: Software Development :: Debuggers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Operating System :: OS Independent',
        'Environment :: Console',
        'Environment :: X11 Applications :: Qt',
    ],
    python_requires='>=3.10,<3.14',
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points={
        'console_scripts': [
            'intellicrack=intellicrack.main:main',
            'intellicrack-cli=intellicrack.scripts.run_analysis_cli:main',
        ],
        'gui_scripts': [
            'intellicrack-gui=intellicrack.ui.main_app:launch',
        ],
    },
    package_data={
        'intellicrack': [
            'assets/*',
            'data/signatures/*',
            'data/templates/*',
            'plugins/custom_modules/*.py',
            'models/*.pkl',
            'models/*.joblib',
            'config/*.json',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        'binary-analysis',
        'reverse-engineering',
        'security',
        'vulnerability-detection',
        'malware-analysis',
        'ai-security',
        'exploit-development',
    ],
)