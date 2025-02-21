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

from .common import (
    check_ip_root_dir,
    check_ipm_directory,
    install_ip,
    install_using_dep_file,
    list_installed_ips,
    list_ip_info,
    list_verified_ips,
    opt_ipm_root,
    check_ip,
    rm_ip_from_project,
    uninstall_ip,
    update_ips,
)


@click.command("install")
@click.argument("ip")
@click.option("--version", required=False, help="Install a specific version")
@click.option("--include-drafts", is_flag=True, help="Allow installing draft versions")
@click.option("--local-file", required=False, help="Path to local verified_IPs.json")
@click.option(
    "--ip-root",
    required=False,
    default=os.path.join(os.getcwd(), "ip"),
    help="IP installation path",
)
@opt_ipm_root
def install_cmd(ip, ip_root, ipm_root=None, version=None, include_drafts=False, local_file=None):
    """Install one of the verified IPs locally."""
    install(ip, ipm_root, version=version, ip_root=ip_root, include_drafts=include_drafts, local_file=local_file)


def install(
    ip,
    ipm_root=None,
    version=None,
    ip_root=None,
    include_drafts=False,
    local_file=None,
):
    """Install one of the verified IPs locally"""
    # valid = check_ipm_directory(ipm_root)
    valid_ip_dir = check_ip_root_dir(ip_root)
    if valid_ip_dir:
        install_ip(ipm_root=ipm_root, ip_name=ip, ip_root=ip_root, version=version, include_drafts=include_drafts, local_file=local_file)


@click.command("uninstall")
@click.argument("ip")
@click.option(
    "--ip-root",
    required=False,
    default=os.path.join(os.getcwd(), "ip"),
    help="IP installation path",
)
@click.option("--version", required=False, help="Install IP with a specific version")
# @click.option(
#     "-f",
#     "--force",
#     is_flag=True,
#     # Translation of the line below: "if (!value) { ctx.abort() }"
#     callback=lambda ctx, _, value: value or ctx.abort(),
#     expose_value=False,
#     prompt="Uninstalling this IP may break all projects depending on it.\nIf you want to remove it from just one project, try 'ipm rm'.\nProceed?",
# )
@opt_ipm_root
def uninstall_cmd(ip, ipm_root, ip_root, version=None):
    """Uninstall local IP"""
    uninstall(ip, ipm_root, ip_root, version=version)


def uninstall(
    ip,
    ipm_root,
    ip_root,
    version=None,
):
    """Uninstall local IP"""
    # valid = check_ipm_directory(ipm_root)
    valid_ip_dir = check_ip_root_dir(ip_root)
    if valid_ip_dir:
        uninstall_ip(ipm_root=ipm_root, ip_name=ip, ip_root=ip_root, version=version)


@click.command("ls-remote")
@click.option(
    "--category",
    required=False,
    help="Optionally provide the category (digital, comm, analog, dataconv)",
)
@click.option(
    "--technology",
    required=False,
    help="Optionally provide the technology (sky130A, gf180mcuC)",
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


@click.command("ls", hidden=True)
# @opt_ipm_root
@click.option(
    "--ip-root", required=False, default=os.path.join(os.getcwd(), "ip"), help="IP path"
)
def ls_cmd(ip_root):
    """Lists all locally installed IPs"""
    ls(ip_root)


def ls(ip_root):
    """Lists all locally installed IPs"""
    # valid = check_ipm_directory(ipm_root)
    valid_ip_dir = check_ip_root_dir(ip_root)
    if valid_ip_dir:
        list_installed_ips(ip_root)


@click.command("install-dep")
@click.option(
    "--ip-root", required=False, default=os.path.join(os.getcwd(), "ip"), help="IP path"
)
@click.option("--include-drafts", is_flag=True, help="Allow installing draft versions")
@click.option("--local-file", required=False, help="Path to local verified_IPs.json")
@opt_ipm_root
def install_deps_cmd(ip_root, ipm_root, include_drafts=False, local_file=None):
    """Install verified IPs from dependencies json file"""
    install_deps(ip_root, ipm_root, include_drafts, local_file)


def install_deps(ip_root, ipm_root, include_drafts=False, local_file=None):
    """Install verified IPs from dependencies json file"""
    # valid = check_ipm_directory(ipm_root)
    valid_ip_dir = check_ip_root_dir(ip_root)
    if valid_ip_dir:
        install_using_dep_file(ip_root, ipm_root, include_drafts, local_file)


@click.command("rm", hidden=True)
@opt_ipm_root
@click.argument("ip")
@click.option(
    "--ip-root", required=False, default=os.path.join(os.getcwd(), "ip"), help="IP path"
)
def rm_cmd(ip_root, ip, ipm_root):
    """remove IP from project"""
    rm(ip_root, ip, ipm_root)


def rm(ip_root, ip, ipm_root):
    """remove IP from project"""
    valid_ip_dir = check_ip_root_dir(ip_root)
    valid = check_ipm_directory(ipm_root)
    if valid_ip_dir and valid:
        rm_ip_from_project(ip, ip_root, ipm_root)


# @click.command("check")
# @opt_ipm_root
# def check_cmd(ipm_root):
#     """Check for new versions of all installed IPs or a specific IP."""
#     valid = check_ipm_directory(ipm_root)
#     if valid:
#         check_ips(ipm_root)


@click.command("update")
@opt_ipm_root
@click.argument("ip", required=False)
@click.option(
    "--ip-root", required=False, default=os.path.join(os.getcwd(), "ip"), help="IP path"
)
@click.option("--include-drafts", is_flag=True, help="Allow installing draft versions")
@click.option("--local-file", required=False, help="Path to local verified_IPs.json")
def update_cmd(ipm_root, ip_root, ip, include_drafts=False, local_file=None):
    """Check for new versions of all installed IPs in project or a specific IP."""
    update(ipm_root, ip_root, ip, include_drafts, local_file)


def update(ipm_root, ip_root, ip, include_drafts=False, local_file=None):
    """Check for new versions of all installed IPs in project or a specific IP."""
    # valid = check_ipm_directory(ipm_root)
    valid_ip_dir = check_ip_root_dir(ip_root)
    if valid_ip_dir:
        update_ips(ipm_root, ip_root=ip_root, ip_to_update=ip, include_drafts=include_drafts, local_file=local_file)


@click.command("check-ip", hidden=True)
@click.option(
    "--ip-root",
    required=False,
    default=os.getcwd(),
    help="IP path",
)
@click.option(
    "--ip-name", required=False, help="IP name"
)
def check_ip_cmd(ip_root, ip_name):
    """Checks IPs for usability with IPM."""
    check_ip(ip_root, ip_name)
