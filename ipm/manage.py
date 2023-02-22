#!/usr/bin/env python3
# Copyright 2022 Efabless Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import sys
import json
import tarfile
import pathlib
import requests
import tempfile
from typing import List

import rich
import click
import rich.tree
import rich.progress
from rich.console import Console

from .common import (
    get_IP_history,
    list_IPs_local,
    opt_ipm_iproot,
    list_IPs,
    install_IP,
    uninstall_IP,
    get_IP_list,
    check_IP,
    check_ipm_directory,
    precheck,
    check_JSON,
)


@click.command("ls-remote")
@opt_ipm_iproot
@click.option(
    "--category",
    required=False,
    help="Optionally provide the category (digital, comm, analog, dataconv)",
)
@click.option(
    "--technology",
    required=False,
    help="Optionally provide the technology (sky130, gf180mcu)",
)
def ls_remote_cmd(category, ipm_iproot, technology):
    """Lists all verified IPs in ipm main repository"""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        if category is not None:
            if category in ["digital", "comm", "analog", "dataconv"]:
                console.print(f"[green]Verified IPs for the {category} category:")
                list_IPs(console, ipm_iproot, remote=True, category=category)
            else:
                console.print(
                    "You entered a wrong category, invoke ipm ls --help for assistance"
                )
        elif technology is not None:
            if technology in ["sky130", "gf180mcu"]:
                console.print(f"[green]Verified IPs for the {technology} technology:")
                list_IPs(console, ipm_iproot, remote=True)
            else:
                console.print(
                    "You entered a wrong technology, invoke ipm ls --help for assistance"
                )
        else:
            console.print("[green]Verified IPs:")
            list_IPs(console, ipm_iproot, remote=True)


def ls_remote(category, ipm_iproot, technology):
    """Lists all verified IPs in ipm main repository"""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        if category is not None:
            if category in ["digital", "comm", "analog", "dataconv"]:
                console.print(f"[green]Verified IPs for the {category} category:")
                list_IPs(console, ipm_iproot, remote=True, category=category)
            else:
                console.print(
                    "You entered a wrong category, invoke ipm ls --help for assistance"
                )
        elif technology is not None:
            if technology in ["sky130", "gf180mcu"]:
                console.print(f"[green]Verified IPs for the {technology} technology:")
                list_IPs(console, ipm_iproot, remote=True)
            else:
                console.print(
                    "You entered a wrong technology, invoke ipm ls --help for assistance"
                )
        else:
            console.print("[green]Verified IPs:")
            list_IPs(console, ipm_iproot, remote=True)


@click.command("ls")
@opt_ipm_iproot
@click.option(
    "--category",
    required=False,
    help="Optionally provide the category (digital, comm, analog, dataconv)",
)
@click.option(
    "--technology",
    required=False,
    help="Optionally provide the technology (sky130, gf180mcu)",
)
def ls_cmd(category, ipm_iproot, technology):
    """Lists all locally installed IPs"""
    console = Console()
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        if category is not None:
            if category in ["digital", "comm", "analog", "dataconv"]:
                console.print(
                    f"[green]Installed IPs at {ipm_iproot} for the {category} category:"
                )
                list_IPs_local(console, ipm_iproot, remote=False, category=category)
            else:
                console.print(
                    "You entered a wrong category, invoke ipm ls --help for assistance"
                )
        elif technology is not None:
            if technology in ["sky130", "gf180mcu"]:
                console.print(
                    f"[green]Installed IPs at {ipm_iproot} for the {technology} technology:"
                )
                list_IPs_local(console, ipm_iproot, remote=False)
            else:
                console.print(
                    "You entered a wrong technology, invoke ipm ls --help for assistance"
                )
        else:
            console.print(f"[green]Installed IPs at {IPM_DIR_PATH}:")
            list_IPs_local(console, ipm_iproot, remote=False)


def ls(category, ipm_iproot, technology):
    """Lists all locally installed IPs"""
    console = Console()
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        if category is not None:
            if category in ["digital", "comm", "analog", "dataconv"]:
                console.print(
                    f"[green]Installed IPs at {ipm_iproot} for the {category} category:"
                )
                list_IPs_local(console, ipm_iproot, remote=False, category=category)
            else:
                console.print(
                    "You entered a wrong category, invoke ipm ls --help for assistance"
                )
        elif technology is not None:
            if technology in ["sky130", "gf180mcu"]:
                console.print(
                    f"[green]Installed IPs at {ipm_iproot} for the {technology} technology:"
                )
                list_IPs_local(console, ipm_iproot, remote=False)
            else:
                console.print(
                    "You entered a wrong technology, invoke ipm ls --help for assistance"
                )
        else:
            console.print(f"[green]Installed IPs at {IPM_DIR_PATH}:")
            list_IPs_local(console, ipm_iproot, remote=False)


@click.command("output")
@opt_ipm_iproot
def output_cmd(ipm_iproot):
    """(Default) Outputs the current IP installation path"""
    console = Console()
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        print(f"Your IPs will be installed at {IPM_DIR_PATH}")


def output(ipm_iproot):
    """(Default) Outputs the current IP installation path"""
    console = Console()
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        return IPM_DIR_PATH


@click.command("install")
@click.argument("ip")
@click.option(
    "--overwrite", required=False, is_flag=True, help="Updates all installed IPs"
)
@click.option("--technology", required=False, help="Install IP based on technology")
@click.option("--version", required=False, help="Install IP with a specific version")
@opt_ipm_iproot
def install_cmd(ip, ipm_iproot, overwrite, technology="sky130", version=None):
    """Install one of the verified IPs locally"""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        install(ip, ipm_iproot, overwrite, technology=technology, version=version)


def install(ip, ipm_iproot, overwrite, technology="sky130", version=None):
    """Install one of the verified IPs locally"""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        IP_list = get_IP_list(ipm_iproot, remote=True)
        if ip not in IP_list:
            print(
                "Please provide a valid IP name, to check all the available IPs invoke 'ipm ls'"
            )
        else:
            if overwrite:
                install_IP(
                    console,
                    ipm_iproot,
                    ip,
                    overwrite=True,
                    technology=technology,
                    version=version,
                )
            else:
                install_IP(
                    console,
                    ipm_iproot,
                    ip,
                    overwrite=False,
                    technology=technology,
                    version=version,
                )


@click.command("uninstall")
@click.argument("ip")
@opt_ipm_iproot
def uninstall_cmd(ip, ipm_iproot):
    """Uninstall one of the IPs installed locally"""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        IP_list = get_IP_list(ipm_iproot, remote=False)
        if ip not in IP_list:
            print(
                "Please provide a valid IP name, to check all installed IPs invoke 'ipm lls'"
            )
        else:
            uninstall_IP(console, ipm_iproot, ip)


@click.command("check")
@click.option(
    "--ip",
    required=False,
    help="Optionally provide an IP to check for its newer version",
)
@opt_ipm_iproot
def check_cmd(ip, ipm_iproot):
    """Check for new versions of all installed IPs or a specific IP."""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        IP_list = get_IP_list(ipm_iproot, remote=False)
        if ip is not None:
            if ip not in IP_list:
                print(
                    "Please provide a valid IP name, to check all installed IPs invoke 'ipm lls'"
                )
            else:
                check_IP(console, ipm_iproot, ip, update=False)
        else:
            check_IP(console, ipm_iproot, "all", update=False)


@click.command("update")
@click.option("--ip", required=False, help="Provide an IP to update")
@click.option("--all", required=False, is_flag=True, help="Updates all installed IPs")
@opt_ipm_iproot
def update_cmd(ip, all, ipm_iproot):
    """Update all installed IPs to their latest versions or a specific IP."""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        IP_list = get_IP_list(ipm_iproot, remote=False)
        if ip is not None:
            if ip not in IP_list:
                print(
                    "Please provide a valid IP name, to check all installed IPs invoke 'ipm lls'"
                )
            else:
                check_IP(console, ipm_iproot, ip, update=True)
        else:
            if all:
                check_IP(console, ipm_iproot, "all", update=True)
            else:
                console.print(
                    "Either provide an ip name or to update all installed IPs run 'ipm update --all'"
                )


def update(ip, all, ipm_iproot):
    """Update all installed IPs to their latest versions or a specific IP."""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        IP_list = get_IP_list(ipm_iproot, remote=False)
        if ip is not None:
            if ip not in IP_list:
                print(
                    "Please provide a valid IP name, to check all installed IPs invoke 'ipm lls'"
                )
            else:
                check_IP(console, ipm_iproot, ip, update=True)
        else:
            if all:
                check_IP(console, ipm_iproot, "all", update=True)
            else:
                console.print(
                    "Either provide an ip name or to update all installed IPs run 'ipm update --all'"
                )


@click.command("pre-check")
@opt_ipm_iproot
def precheck_cmd(ipm_iproot):
    """Update all installed IPs to their latest versions or a specific IP."""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        ip = input("Enter IP name: ")
        version = input("Enter IP version: ")
        gh_repo = input(
            'Enter the GH repo of the IP in the form "github.com/<username>/<project_name>": '
        )
        precheck(console, ipm_iproot, ip, version, gh_repo)


@click.command("ls-history")
@click.option("--ip", required=True, help="ip to get history of versions")
@opt_ipm_iproot
def history_cmd(ipm_iproot, ip):
    """list all versions of the IP"""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        get_IP_history(console, ipm_iproot, ip, remote=True)


def history(ipm_iproot, ip):
    """list all versions of the IP"""
    console = Console()
    valid = check_ipm_directory(console, ipm_iproot)
    if valid:
        get_IP_history(console, ipm_iproot, ip, remote=True)
