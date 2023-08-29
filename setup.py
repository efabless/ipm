#!/usr/bin/env python3
from setuptools import setup, find_packages

# from ipm import __version__

requirements = open("requirements.txt").read().strip().split("\n")

setup(
    name="ipm",
    packages=find_packages(),
    version="0.1.0",
    description="Open-source IPs Package Manager.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Zeyad Zaki",
    author_email="zeyadzaki@aucegypt.edu",
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
    ],
    entry_points={"console_scripts": ["ipm = ipm.__main__:cli"]},
    python_requires=">3.6",
)
