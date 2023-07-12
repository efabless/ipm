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
import click
from rich.console import Console

from .common import (
    check_ip_root_dir,
    check_ipm_directory,
    install_ip,
    list_ip_info,
    list_verified_ips,
    opt_ipm_root
)

@click.command("install")
@click.argument("ip")
@click.option("--version", required=False, help="Install IP with a specific version")
@click.option("--ip-root", required=False, default=os.path.join(os.path.expanduser("~"), ".ipm"), help="IP installation path")
@opt_ipm_root
def install_cmd(ip, ip_root, ipm_root, version=None):
    """Install one of the verified IPs locally"""
    # console = Console()
    install(
        ip, ipm_root, version=version, ip_root=ip_root
    )


def install(
    ip,
    ipm_root,
    version=None,
    ip_root=None,
):
    """Install one of the verified IPs locally"""
    valid = check_ipm_directory(ipm_root)
    valid_ip_dir = check_ip_root_dir(ip_root)
    if valid and valid_ip_dir:
        install_ip(
            ipm_root=ipm_root,
            ip_name=ip,
            ip_root=ip_root,
            version=version
        )

@click.command("ls-remote")
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
def ls_remote_cmd(category, technology):
    """Lists all verified IPs in ipm's database"""
    ls_remote(category, technology)

def ls_remote(category, technology):
    """Lists all verified IPs in ipm's database"""
    list_verified_ips(category, technology)

@click.command("info")
@click.argument("ip")
def info_cmd(ip):
    """list all versions and info of the IP"""
    info(ip)


def info(ip):
    """list all versions and info of the IP"""
    list_ip_info(ip)
