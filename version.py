#!/usr/bin/env python3
"""
Version information for Sud0Hunt
"""

__version__ = "1.0.0"
__author__ = "Sud0-x"
__email__ = "sud0x.dev@proton.me"
__description__ = "Advanced Automated Bug Bounty Reconnaissance & Vulnerability Hunter"
__url__ = "https://github.com/Sud0-x/Sud0Hunt"
__license__ = "MIT"

# Version tuple for programmatic access
VERSION = tuple(map(int, __version__.split('.')))

# Build information
BUILD_DATE = "2025-01-02"
BUILD_HASH = "main"

def get_version():
    """Get the full version string"""
    return __version__

def get_version_info():
    """Get detailed version information"""
    return {
        "version": __version__,
        "author": __author__,
        "email": __email__,
        "description": __description__,
        "url": __url__,
        "license": __license__,
        "build_date": BUILD_DATE,
        "build_hash": BUILD_HASH
    }

def print_version():
    """Print version information"""
    info = get_version_info()
    print(f"Sud0Hunt v{info['version']}")
    print(f"Author: {info['author']} ({info['email']})")
    print(f"License: {info['license']}")
    print(f"URL: {info['url']}")
    print(f"Build: {info['build_date']} ({info['build_hash']})")

if __name__ == "__main__":
    print_version()
