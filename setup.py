#!/usr/bin/env python3
import os
import subprocess
from setuptools import setup, find_packages

# from ipm import __version__

# requirements = open("requirements.txt").read().strip().split("\n")

__dir__ = os.path.abspath(os.path.dirname(__file__))
version = subprocess.check_output(
    [
        "python3",
        os.path.join(
            __dir__,
            "ipm",
            "__version__.py",
        ),
    ],
    encoding="utf8",
)

setup(
    name="efipm",
    packages=find_packages(),
    version=version,
    description="Open-source IPs Package Manager.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Efabless Corporation",
    author_email="contact@efabless.com",
    install_requires="requirements.txt",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
    ],
    entry_points={"console_scripts": ["ipm = ipm.__main__:cli"]},
    python_requires=">3.6",
)
