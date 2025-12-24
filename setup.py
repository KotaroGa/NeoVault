
"""
Setup script for NeoVault installation.
Package configuration for PyPI distribution.
"""
from setuptools import setup, find_packages
import os

# Read the contents of README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Get version from src/core/__init__.py
def get_version():
    version_file = os.path.join("src", "core", "__init__.py")
    with open(version_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("__version__"):
                # __version__ = "0.3.0"
                return line.split("=")[1].strip().strip('"\'')
    return "0.3.0"

setup(
    name="neovault",
    version=get_version(),
    author="KotaroGa",
    author_email="",  # Opcional: añade tu email si quieres
    description="🔐 NeoVault - Secure File Vault (Matrix Edition)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/KotaroGa/neovault",
    project_urls={
        "Bug Tracker": "https://github.com/KotaroGa/NeoVault/issues",
        "Documentation": "https://github.com/KotaroGa/NeoVault#readme",
        "Source Code": "https://github.com/KotaroGa/NeoVault",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    keywords="vault, encryption, security, password-manager, cryptography, cli",
    package_dir={"": "src"},
    packages=find_packages(where="src", include=["core", "cli"]),
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "nvault=cli.main:main",
            "neovault=cli.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    license="MIT",
    platforms=["any"],
)