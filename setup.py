#!/usr/bin/env python3
"""
Sud0Hunt - Advanced Automated Bug Bounty Reconnaissance & Vulnerability Hunter
"""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open(os.path.join(this_directory, 'requirements.txt'), encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="sud0hunt",
    version="1.0.0",
    author="Sud0-x",
    author_email="sud0x.dev@proton.me",
    description="Advanced Automated Bug Bounty Reconnaissance & Vulnerability Hunter",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Sud0-x/Sud0Hunt",
    project_urls={
        "Bug Reports": "https://github.com/Sud0-x/Sud0Hunt/issues",
        "Source": "https://github.com/Sud0-x/Sud0Hunt",
        "Documentation": "https://github.com/Sud0-x/Sud0Hunt#readme",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.991",
        ],
    },
    entry_points={
        "console_scripts": [
            "sud0hunt=cli:main",
        ],
    },
    keywords=[
        "security", "bugbounty", "reconnaissance", "vulnerability-scanner",
        "penetration-testing", "subdomain-enumeration", "port-scanner",
        "web-security", "cybersecurity", "ethical-hacking"
    ],
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.json"],
    },
    zip_safe=False,
)
