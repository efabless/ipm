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
import json
import requests
import shutil
import tarfile
from datetime import datetime
from typing import Callable

import rich
from rich.table import Table
import click

# Datetime Helpers
ISO8601_FMT = "%Y-%m-%dT%H:%M:%SZ"


def date_to_iso8601(date: datetime) -> str:
    return date.strftime(ISO8601_FMT)


def date_from_iso8601(string: str) -> datetime:
    return datetime.strptime(string, ISO8601_FMT)


# ---

IPM_REPO_OWNER = os.getenv("IPM_REPO_OWNER") or "efabless"
IPM_REPO_NAME = os.getenv("IPM_REPO_NAME") or "ipm"
IPM_REPO_ID = f"{IPM_REPO_OWNER}/{IPM_REPO_NAME}"
IPM_REPO_HTTPS = f"https://github.com/{IPM_REPO_ID}"
IPM_REPO_API = f"https://api.github.com/repos/{IPM_REPO_ID}"
IPM_DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".ipm")

LOCAL_JSON_FILE_NAME = "Installed_IPs.json"
DEPENDENCIES_FILE_NAME = "dependencies.json"
REMOTE_JSON_FILE_NAME = (
    "https://raw.githubusercontent.com/efabless/ipm/main/Verified_IPs.json"
)

class LocalIP:
    def __init__(self, ip, ipm_iproot):
        self.ip = ip
        self.ipm_iproot = ipm_iproot

    def init_info(self, ip_root, technology="sky130", version=None):
        self.ip_root = ip_root
        local_json_file = os.path.join(self.ipm_iproot, LOCAL_JSON_FILE_NAME)
        with open(local_json_file) as json_file:
            data = json.load(json_file)
        for key, values in data.items():
            for value in values:
                if value["name"] == self.ip and value["technology"] == technology:
                    self.name = self.ip
                    self.repo = value["repo"]
                    self.version = value["version"]
                    self.date = value["date"]
                    self.author = value["author"]
                    self.email = value["email"]
                    self.category = key
                    self.type = value["type"]
                    self.status = value["status"]
                    self.width = value["width"]
                    self.height = value["height"]
                    self.technology = technology
                    self.tag = value["tag"]
                    self.cell_count = value["cell_count"]
                    self.clk_freq = value["clk_freq"]
                    self.license = value["license"]
        release_url = f"https://{self.repo}/releases/download/{self.version}/{self.version}.tar.gz"
        self.release_url = release_url

    def get_info(self, technology="sky130", version=None):
        local_json_file = os.path.join(self.ipm_iproot, LOCAL_JSON_FILE_NAME)
        with open(local_json_file) as json_file:
            data = json.load(json_file)
        for key, values in data.items():
            for value in values:
                if value["name"] == self.ip and value["technology"] == technology:
                    self.name = self.ip
                    self.repo = value["repo"]
                    self.version = value["version"]
                    self.date = value["date"]
                    self.author = value["author"]
                    self.email = value["email"]
                    self.category = key
                    self.type = value["type"]
                    self.status = value["status"]
                    self.width = value["width"]
                    self.height = value["height"]
                    self.technology = technology
                    self.tag = value["tag"]
                    self.cell_count = value["cell_count"]
                    self.clk_freq = value["clk_freq"]
                    self.license = value["license"]
                    self.ip_root = value["ip_root"]
                    if "dependencies" in value:
                        self.dependencies = value["dependencies"]
                    else:
                        self.dependencies = None
        release_url = f"https://{self.repo}/releases/download/{self.version}/{self.version}.tar.gz"
        self.release_url = release_url

    def get_info_from_atr(self, ip_info):
        ip_info_dict = {}
        for attribute in ip_info.__dict__:
            ip_info_dict[attribute] = getattr(ip_info, attribute)
        return ip_info_dict

    def add_ip_to_json(self, ip_info, ip_root):
        local_json_file = os.path.join(self.ipm_iproot, LOCAL_JSON_FILE_NAME)
        with open(local_json_file) as json_file:
            json_decoded = json.load(json_file)
        ip_info_dict = self.get_info_from_atr(ip_info)
        del ip_info_dict["release"]
        self.ip_root = os.path.abspath(ip_root)
        ip_info_dict["ip_root"] = self.ip_root

        json_decoded[ip_info_dict["category"]].append(ip_info_dict)

        with open(local_json_file, "w") as json_file:
            json.dump(json_decoded, json_file)

    def remove_ip_from_json(self):
        json_file = os.path.join(self.ipm_iproot, LOCAL_JSON_FILE_NAME)
        with open(json_file, 'r') as f:
            json_decoded = json.load(f)
        self.get_info()
        ip_info_dict = self.get_info_from_atr(self)
        ip_category = json_decoded[ip_info_dict["category"]]

        for ips in ip_category:
            if ips['name'] == ip_info_dict['name'] and ips['ip_root'] == self.ip_root:
                ip_category.remove(ips)
        json_decoded[ip_info_dict["category"]] = ip_category

        with open(json_file, "w") as json_file:
            json.dump(json_decoded, json_file)

    def remove_from_deps(self, deps_file):
        if deps_file:
            json_file = os.path.join(deps_file, DEPENDENCIES_FILE_NAME)
        else:
            json_file = os.path.join(self.ip_root, DEPENDENCIES_FILE_NAME)

        with open(json_file, 'r') as f:
            json_decoded = json.load(f)
        ip_info_dict = self.get_info_from_atr(self)
        ip_category = json_decoded["IP"]
        for ips in ip_category:
            if ips['name'] == ip_info_dict['name']:
                ip_category.remove(ips)
        json_decoded["IP"] = ip_category

        with open(json_file, "w") as json_file:
            json.dump(json_decoded, json_file)

    def create_deps(self, ip_info, deps_file):
        if deps_file:
            local_json_file = os.path.join(deps_file, DEPENDENCIES_FILE_NAME)
        else:
            local_json_file = os.path.join(self.ip_root, DEPENDENCIES_FILE_NAME)

        if os.path.exists(local_json_file):
            with open(local_json_file) as json_file:
                json_decoded = json.load(json_file)
        else:
            json_decoded = {
                "IP": []
            }
        ip_info_dict = self.get_info_from_atr(ip_info)
        tmp_dict = {
            "name": ip_info_dict["name"],
            "version": ip_info_dict["version"],
            "technology": ip_info_dict["technology"]
        }
        for ips in json_decoded['IP']:
            if not ips['name'] == ip_info_dict["name"]:
                json_decoded['IP'].append(tmp_dict)

        with open(local_json_file, "w") as json_file:
            json.dump(json_decoded, json_file)

class RemoteIP:
    def __init__(self, ip):
        self.ip = ip

    def get_info(self, console, technology="sky130", version=None):
        if os.environ['GITHUB_TOKEN']:
            headers = {"Authorization": f"token {os.environ['GITHUB_TOKEN']}"}
        else:
            console.print("[red]Can't find GITHUB_TOKEN in environment, please export your github token")
            console.print("[red]THIS IS A TEMP WORKAROUND")
            exit(1)
        resp = requests.get(REMOTE_JSON_FILE_NAME, headers=headers)
        if resp.status_code == 404:
            console.print("[red]Can't find remote file, you don't have access to IPM private repo, or GITHUB_TOKEN is wrong")
            exit(1)
        data = json.loads(resp.text)
        for key, values in data.items():
            for value in values:
                if value["name"] == self.ip and value["technology"] == technology:
                    self.name = self.ip
                    self.repo = value["repo"]
                    self.release = value["release"]
                    if version is None:
                        self.version = value["release"][-1]["version"]
                        self.date = value["release"][-1]["date"]
                    else:
                        for v in value["release"]:
                            if v["version"] == version:
                                self.version = v["version"]
                                self.date = v["date"]
                    self.author = value["author"]
                    self.email = value["email"]
                    self.category = key
                    self.type = value["type"]
                    self.status = value["status"]
                    self.width = value["width"]
                    self.height = value["height"]
                    self.technology = technology
                    self.tag = value["tag"]
                    self.cell_count = value["cell_count"]
                    self.clk_freq = value["clk_freq"]
                    self.license = value["license"]
                    if "dependencies" in value:
                        self.dependencies = value["dependencies"]
                    else:
                        self.dependencies = None
        release_url = f"https://{self.repo}/releases/download/{self.version}/{self.version}.tar.gz"
        self.release_url = release_url


def opt_ipm_iproot(function: Callable):
    function = click.option(
        "--ipm-iproot",
        required=False,
        default=os.getenv("IPM_IPROOT") or IPM_DEFAULT_HOME,
        help="Path to the IPM root where the IPs will reside",
        show_default=True,
    )(function)
    return function

def checkdir(path):
    return os.path.isdir(path)

def create_local_JSON(file_path):
    dictionary = {
        "analog": [],
        "comm": [],
        "dataconv": [],
        "digital": [],
        "technolgy": [],
    }
    with open(file_path, "w") as outfile:
        json.dump(dictionary, outfile)


def check_ipm_directory(console: rich.console.Console, ipm_iproot) -> bool:
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    JSON_FILE_PATH = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)

    if ipm_iproot == IPM_DEFAULT_HOME:
        if not os.path.exists(ipm_iproot):
            os.mkdir(ipm_iproot)
            create_local_JSON(JSON_FILE_PATH)
        else:  # .ipm folder exists
            if not os.path.exists(IPM_DIR_PATH):
                os.mkdir(IPM_DIR_PATH)
                create_local_JSON(JSON_FILE_PATH)
            else:  # .ipm/ipm folder exists
                if not os.path.exists(JSON_FILE_PATH):
                    create_local_JSON(JSON_FILE_PATH)
    else:
        if not os.path.exists(ipm_iproot):
            console.print(
                "[red]The IPM_IPROOT does not exist, please specify a correct IPM_IPROOT to continue"
            )
            return False
        else:
            if not os.path.exists(IPM_DIR_PATH):
                os.mkdir(IPM_DIR_PATH)
                create_local_JSON(JSON_FILE_PATH)
            else:  # <ipm_iproot>/ipm folder exists
                if not os.path.exists(JSON_FILE_PATH):
                    create_local_JSON(JSON_FILE_PATH)
    return True

def check_ip_root_dir(console: rich.console.Console, ip_root) -> bool:
    if not os.path.isdir(ip_root):
        console.print(f"[red] ip-root {ip_root} can't be found")
        return False
    else:
        return True


def list_IPs(console: rich.console.Console, ipm_iproot, remote, category="all"):
    if remote:
        if os.environ['GITHUB_TOKEN']:
            headers = {"Authorization": f"token {os.environ['GITHUB_TOKEN']}"}
        else:
            console.print("[red]Can't find GITHUB_TOKEN in environment, please export your github token")
            console.print("[red]THIS IS A TEMP WORKAROUND")
            exit(1)
        resp = requests.get(REMOTE_JSON_FILE_NAME, headers=headers)
        if resp.status_code == 404:
            console.print("[red]Can't find remote file, you don't have access to IPM private repo, or GITHUB_TOKEN is wrong")
            exit(1)
        data = json.loads(resp.text)
    else:
        JSON_FILE = os.path.join(ipm_iproot, LOCAL_JSON_FILE_NAME)
        with open(JSON_FILE) as json_file:
            data = json.load(json_file)

    table = Table()

    table.add_column("Category", style="cyan")
    table.add_column("IP Name", style="magenta")
    table.add_column("Version")
    table.add_column("Author")
    # table.add_column("Date")
    table.add_column("Type")
    table.add_column("Tag")
    # table.add_column("Cell count")
    # table.add_column("Clk freq (MHz)")
    table.add_column("Status")
    # table.add_column("Width (um)")
    # table.add_column("Height (um)")
    table.add_column("Technology", style="cyan")
    table.add_column("License", style="magenta")

    total_IPs = 0
    if category == "all":
        for key, values in data.items():
            for value in values:
                table.add_row(
                    key,
                    value["name"],
                    value["release"][-1]["version"],
                    value["author"],
                    # value["release"][-1]["date"],
                    value["type"],
                    ",".join(value["tag"]),
                    # value["cell_count"],
                    # value["clk_freq"],
                    value["status"],
                    # value["width"],
                    # value["height"],
                    value["technology"],
                    value["license"],
                )
            total_IPs = total_IPs + len(values)
        if total_IPs > 0:
            console.print(table)
            console.print(f"Total {total_IPs} IP(s)")
        else:
            console.print("[red]No IPs Found")
    else:
        for value in data[category]:
            table.add_row(
                key,
                value["name"],
                value["release"][-1]["version"],
                value["author"],
                # value["release"][-1]["date"],
                value["type"],
                ",".join(value["tag"]),
                # value["cell_count"],
                # value["clk_freq"],
                value["status"],
                # value["width"],
                # value["height"],
                value["technology"],
                value["license"],
            )
        total_IPs = total_IPs + len(data[category])
        if total_IPs > 0:
            console.print(table)
            console.print(f"Total {total_IPs} IP(s)")
        else:
            console.print("[red]No IPs Found")


def list_IPs_local(console: rich.console.Console, ipm_iproot, remote, category="all"):
    if remote:
        if os.environ['GITHUB_TOKEN']:
            headers = {"Authorization": f"token {os.environ['GITHUB_TOKEN']}"}
        else:
            console.print("[red]Can't find GITHUB_TOKEN in environment, please export your github token")
            console.print("[red]THIS IS A TEMP WORKAROUND")
            exit(1)
        resp = requests.get(REMOTE_JSON_FILE_NAME, headers=headers)
        if resp.status_code == 404:
            console.print("[red]Can't find remote file, you don't have access to IPM private repo, or GITHUB_TOKEN is wrong")
            exit(1)
        data = json.loads(resp.text)
    else:
        JSON_FILE = os.path.join(ipm_iproot, LOCAL_JSON_FILE_NAME)
        with open(JSON_FILE) as json_file:
            data = json.load(json_file)

    table = Table()

    table.add_column("Category", style="cyan")
    table.add_column("IP Name", style="magenta")
    table.add_column("Version")
    table.add_column("Author")
    # table.add_column("Date")
    table.add_column("Type")
    table.add_column("Tag")
    # table.add_column("Cell count")
    # table.add_column("Clk freq (MHz)")
    table.add_column("Status")
    # table.add_column("Width (um)")
    # table.add_column("Height (um)")
    table.add_column("Technology", style="cyan")
    table.add_column("License", style="magenta")
    table.add_column("IP path")

    total_IPs = 0
    if category == "all":
        for key, values in data.items():
            for value in values:
                table.add_row(
                    key,
                    value["name"],
                    value["version"],
                    value["author"],
                    # value["date"],
                    value["type"],
                    ",".join(value["tag"]),
                    # value["cell_count"],
                    # value["clk_freq"],
                    value["status"],
                    # value["width"],
                    # value["height"],
                    value["technology"],
                    value["license"],
                    value["ip_root"] + "/" + value["name"]
                )
            total_IPs = total_IPs + len(values)
        if total_IPs > 0:
            console.print(table)
            console.print(f"Total {total_IPs} IP(s)")
        else:
            console.print("[red]No IPs Found")
    else:
        for value in data[category]:
            table.add_row(
                key,
                value["name"],
                value["version"],
                value["author"],
                # value["date"],
                value["type"],
                ",".join(value["tag"]),
                # value["cell_count"],
                # value["clk_freq"],
                value["status"],
                # value["width"],
                # value["height"],
                value["technology"],
                value["license"],
                value["ip_root"] + "/" + value["name"]
            )
        total_IPs = total_IPs + len(data[category])
        if total_IPs > 0:
            console.print(table)
            console.print(f"Total {total_IPs} IP(s)")
        else:
            console.print("[red]No IPs Found")


# Gets a list of all available IP "names"
def get_IP_list(console, ipm_iproot, remote):
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    JSON_FILE = ""
    IP_list = []
    if remote:
        if os.environ['GITHUB_TOKEN']:
            headers = {"Authorization": f"token {os.environ['GITHUB_TOKEN']}"}
        else:
            console.print("[red]Can't find GITHUB_TOKEN in environment, please export your github token")
            console.print("[red]THIS IS A TEMP WORKAROUND")
            exit(1)
        resp = requests.get(REMOTE_JSON_FILE_NAME, headers=headers)
        if resp.status_code == 404:
            console.print("[red]Can't find remote file, you don't have access to IPM private repo, or GITHUB_TOKEN is wrong")
            exit(1)
        data = json.loads(resp.text)
    else:
        JSON_FILE = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)
        with open(JSON_FILE) as json_file:
            data = json.load(json_file)
    for key, values in data.items():
        for value in values:
            IP_list.append(value["name"])
    return IP_list


def get_IP_info(console: rich.console.Console, ipm_iproot, ip, remote):
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    JSON_FILE = ""
    # IP_list = []
    table = Table()
    table.add_column("Category", style="cyan")
    table.add_column("IP Name", style="magenta")
    table.add_column("Version")
    table.add_column("Author")
    table.add_column("Date")
    table.add_column("Type")
    table.add_column("Tag")
    table.add_column("Cell count")
    table.add_column("Clk freq (MHz)")
    table.add_column("Status")
    table.add_column("Width (um)")
    table.add_column("Height (um)")
    table.add_column("Technology", style="cyan")
    table.add_column("License", style="magenta")
    if remote:
        if os.environ['GITHUB_TOKEN']:
            headers = {"Authorization": f"token {os.environ['GITHUB_TOKEN']}"}
        else:
            console.print("[red]Can't find GITHUB_TOKEN in environment, please export your github token")
            console.print("[red]THIS IS A TEMP WORKAROUND")
            exit(1)
        resp = requests.get(REMOTE_JSON_FILE_NAME, headers=headers)
        if resp.status_code == 404:
            console.print("[red]Can't find remote file, you don't have access to IPM private repo, or GITHUB_TOKEN is wrong")
            exit(1)
        data = json.loads(resp.text)
    else:
        JSON_FILE = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)
        with open(JSON_FILE) as json_file:
            data = json.load(json_file)
    for key, values in data.items():
        for value in values:
            if value["name"] == ip:
                for i in range(0, len(value["release"])):
                    table.add_row(
                        key,
                        value["name"],
                        value["release"][i]["version"],
                        value["author"],
                        value["release"][i]["date"],
                        value["type"],
                        ",".join(value["tag"]),
                        value["cell_count"],
                        value["clk_freq"],
                        value["status"],
                        value["width"],
                        value["height"],
                        value["technology"],
                        value["license"],
                    )

    console.print(table)


def install_ip(
    console,
    ipm_iproot,
    ip,
    overwrite,
    technology,
    version,
    ip_root,
    deps_file,
    dependencies
):
    if ip and technology and version:
        install(
            console,
            ipm_iproot,
            ip,
            overwrite,
            technology,
            version,
            ip_root,
            deps_file
        )
        local_ip = LocalIP(ip, ipm_iproot)
        local_ip.get_info(technology=technology, version=version)
        if local_ip.dependencies:
            for d in local_ip.dependencies:
                d['path'] = os.path.join(f"{ip_root}/{ip}" , "ip")
                d['technology'] = technology
                dependencies.append(d)
    else:
        for d in dependencies:
            d['path'] = ip_root
    if dependencies:
        dep = dependencies.pop()
        if not checkdir(dep['path']):
            os.mkdir(dep['path'])
        install_ip(console, ipm_iproot, dep["name"], False, dep['technology'], dep["version"], dep['path'], dep['path'], dependencies)


def install(
    console,
    ipm_iproot,
    ip,
    overwrite,
    technology,
    version,
    ip_root,
    deps_file
):
    ip_path = os.path.join(ip_root, ip)
    if os.path.exists(ip_path):
        if len(os.listdir(ip_path)) != 0:
            if not overwrite:
                console.print(
                    f"There already exists a non-empty folder for the IP [green]{ip}",
                    f"at {ip_root}, to overwrite it add the option --overwrite",
                )
                return
            else:
                console.print(f"Removing exisiting IP {ip} at {ip_root}")
                local_ip = LocalIP(ip, ipm_iproot)
                local_ip.remove_ip_from_json()
                local_ip.remove_from_deps(deps_file)
                shutil.rmtree(ip_path)
        else:
            shutil.rmtree(ip_path)

    remote_ip = RemoteIP(ip)
    local_ip = LocalIP(ip, ipm_iproot)
    remote_ip.get_info(console, technology=technology, version=version)
    console.print(f"IP {ip} is getting installed at {ip_path}")
    response = requests.get(remote_ip.release_url, stream=True)
    if response.status_code == 404:
        console.print(
            f"[red]The IP {ip} version {remote_ip.version} could not be found remotely"
        )
        exit(1)
    elif response.status_code == 200:
        tarball_path = os.path.join(ip_root, f"{ip}.tar.gz")
        with open(tarball_path, "wb") as f:
            f.write(response.raw.read())
        file = tarfile.open(tarball_path)
        file.extractall(ip_root)
        file.close
        os.remove(tarball_path)
        console.print(
            f"[green]Successfully installed {ip} version {remote_ip.version} to the directory {ip_path}"
        )
        local_ip.add_ip_to_json(remote_ip, ip_root)
        local_ip.create_deps(remote_ip, deps_file)

def get_deps_from_json(console, deps_file):
    local_json_file = os.path.join(deps_file, DEPENDENCIES_FILE_NAME)

    if os.path.exists(local_json_file):
        with open(local_json_file) as json_file:
            json_decoded = json.load(json_file)
    else:
        console.print(f"[red]ERROR : {local_json_file} couldn't be found")
        exit(1)
    return json_decoded['IP']

def uninstall_ip(console: rich.console.Console, ipm_iproot, ip, ip_root, deps_file):
    ip_path = os.path.join(ip_root, ip)
    local_ip = LocalIP(ip, ipm_iproot)
    if os.path.exists(ip_path):
        local_ip.remove_ip_from_json()
        local_ip.remove_from_deps(deps_file)
        shutil.rmtree(ip_path, ignore_errors=False, onerror=None)
        console.print(
            f'[green]Successfully uninstalled {ip} version {local_ip.version}'
        )
    else:
        console.print(
            f"The IP {ip} was not found at the directory {ip_root}, you may have removed it manually or renamed the folder"
        )


def check_IP(console, ipm_iproot, ip, update=False, version=None, technology="sky130", ip_root=None):
    update_counter = 0
    if ip == "all":  # Checks or updates all installed IPs
        IP_list = get_IP_list(console, ipm_iproot, remote=False)
        if len(IP_list) == 0:  # No installed IPs
            if update:
                console.print("[red]No installed IPs to update")
            else:
                console.print("[red]No installed IPs to check")
        else:  # There are installed IPs
            console.print("Checking all Installed IP(s) for updates")
            for ip in IP_list:  # Loops on all available IPs
                local_ip = LocalIP(ip, ipm_iproot)
                local_ip.get_info(technology=technology, version=version)
                remote_ip = RemoteIP(ip)
                remote_ip.get_info(console, technology=technology, version=version)
                if version is None:
                    if (
                        local_ip.version
                        == remote_ip.version
                    ):  # IP is up to date
                        console.print(
                            f"[white]The IP [magenta]{ip}"
                            f"[white] is up to date; version {local_ip.version}"
                        )
                    else:
                        if (
                            update
                        ):  # If update flag is True it uninstalls the old version and installs the new one
                            console.print(f"Updating {ip}[white]...")
                            uninstall_ip(console, ipm_iproot, ip, local_ip.ip_root, deps_file=local_ip.ip_root)
                            install_ip(
                                console=console,
                                ipm_iproot=ipm_iproot,
                                ip=ip,
                                overwrite=True,
                                technology=technology,
                                version=remote_ip.version,
                                ip_root=local_ip.ip_root,
                                deps_file=local_ip.ip_root
                            )
                            update_counter = update_counter + 1
                        else:  # If it only needs a check it prints out a message to the user that there is a newer version
                            console.print(
                                f"[yellow]The IP [magenta]{ip}"
                                f"[yellow] has a newer version {remote_ip.version} to update the IP run [white]'ipm update --ip {ip}'"
                            )
                            update_counter = update_counter + 1
            if update_counter > 0:  # There were one or more out dated IP
                if update:
                    console.print(f"[green]Number of updated IP(s): {update_counter}")
                else:
                    console.print(
                        f"[red]There are newer versions for {update_counter} IP(s), to update them all run [white]'ipm update --all' "
                    )
            else:
                console.print("[green]All the installed IP(s) are up to date")

    else:  # Checks or Updates a single IP
        local_ip = LocalIP(ip, ipm_iproot)
        local_ip.get_info(technology=technology, version=version)
        remote_ip = RemoteIP(ip)
        remote_ip.get_info(console, technology=technology, version=version)
        if local_ip.version == version:
            console.print(
                f"[white]The IP [magenta]{ip}"
                f"[white] is up to date; version {local_ip.version}"
            )
        else:
            if update:
                console.print(f"Updating {ip}[white]...")
                uninstall_ip(console, ipm_iproot, ip, local_ip.ip_root, deps_file=local_ip.ip_root)
                install_ip(
                    console=console,
                    ipm_iproot=ipm_iproot,
                    ip=ip,
                    overwrite=True,
                    technology=technology,
                    version=version,
                    ip_root=local_ip.ip_root,
                    deps_file=local_ip.ip_root
                )
            else:
                console.print(
                    f"[yellow]The IP [magenta]{ip}"
                    f"[yellow] has a newer version {remote_ip.version} to update the IP run [white]'ipm update --ip {ip}'"
                )


def check_deps_file():
    pwd = os.getcwd()
    dep_file = f"{pwd}/ip/dependencies.json"
    if os.path.isfile(dep_file):
        return f"{pwd}/ip/"
    else:
        return None

def check_hierarchy(console, ip_path, ip, json_path):
    common_dirs = ["verify/beh_model", "fw", "hdl/rtl/bus_wrapper"]
    with open(json_path) as json_file:
        data = json.load(json_file)
    # check the folder hierarchy
    if data["type"] == "hard":
        ipm_dirs = ["hdl/gl", "timing/lib", "timing/sdf", "timing/spef", "layout/gds", "layout/lef"]
    elif data["type"] == "soft" and data["category"] == "digital":
        ipm_dirs = ["hdl/rtl/design", "verify/utb", "pnr"]
    if data["category"] == "analog":
        ipm_dirs = ["spice"]
    ipm_dirs = ipm_dirs + common_dirs
    ipm_files = [f"{ip}.json", "readme.md", "doc/datasheet.pdf"]
    flag = True
    for dirs in ipm_dirs:
        if not checkdir(os.path.join(ip_path, dirs)):
            console.print(
                f"[red]The directory {dirs} cannot be found under {ip_path} please refer to the ipm directory structure"
            )
            flag = False

    for files in ipm_files:
        if not os.path.exists(os.path.join(ip_path, files)):
            console.print(
                f"[red]The file {files} cannot be found under {ip_path} please refer to the ipm directory structure"
            )
            flag = False
    return flag


def check_JSON(console, JSON_path, ip):
    if not os.path.exists(JSON_path):
        console.print(
            f"[red]Can't find {JSON_path} please refer to the ipm directory structure (IP name {ip} might be wrong)"
        )
        return False
    json_fields = [
        "name",
        "repo",
        "version",
        "author",
        "email",
        "date",
        "type",
        "category",
        "status",
        "width",
        "height",
        "technology",
        "tag",
        "cell_count",
        "clk_freq",
        "license"
    ]
    flag = True
    with open(JSON_path) as json_file:
        json_decoded = json.load(json_file)

    if ip is not json_decoded["name"]:
        console.print(f"[red]The given IP name {ip} is not the same as the one in json file")
        flag = False

    for field in json_fields:
        if field not in json_decoded.keys():
            console.print(
                f"[red]The field '{field}' was not included in the {ip}.json file"
            )
            flag = False

    return flag


def package_check(console, ipm_iproot, ip, version, gh_repo):
    if gh_repo.startswith("https"):
        gh_repo_url = gh_repo
    else:
        gh_repo_url = f"https://{gh_repo}"
    release_tag_url = f"{gh_repo_url}/releases/tag/{version}"
    release_tarball_url = f"{gh_repo_url}/releases/download/{version}/{version}.tar.gz"
    IPM_DIR_PATH = os.path.join(ipm_iproot)
    package_check_path = os.path.join(IPM_DIR_PATH, f"{ip}_pre-check")
    ip_path = os.path.join(package_check_path, ip)
    if checkdir(package_check_path):
        shutil.rmtree(package_check_path)

    console.print("[magenta][STEP 1]:", "Checking the GH repo")
    repo_response = requests.get(gh_repo_url, stream=True)
    if repo_response.status_code == 404:
        console.print(f"[red]There GH repo {gh_repo} does not exist")
    elif repo_response.status_code == 200:  # The repo exists, check for the release
        console.print(
            "[magenta][STEP 2]:",
            f"Checking for the release with the tag {version}",
        )
        release_tag_response = requests.get(release_tag_url, stream=True)
        if release_tag_response.status_code == 404:
            console.print(
                f"[red]There is no release tagged {version} in the GH repo {gh_repo}"
            )
        elif (
            release_tag_response.status_code == 200
        ):  # Release exists, check for tarball
            console.print(
                "[magenta][STEP 3]:", f'Checking for the tarball named "{version}.tar.gz"'
            )
            release_tarball_response = requests.get(release_tarball_url, stream=True)
            if release_tarball_response.status_code == 404:
                console.print(
                    f"[red]The tarball '{version}.tar.gz' was not found in the release tagged {version} in the GH repo {gh_repo}"
                )
            elif (
                release_tarball_response.status_code == 200
            ):  # Tarball exists under the correct tag name, download it under IPM_Directory/<ip>_pre-check
                os.mkdir(package_check_path)
                tarball_path = os.path.join(package_check_path, f"{version}.tar.gz")
                with open(tarball_path, "wb") as f:
                    f.write(release_tarball_response.raw.read())
                file = tarfile.open(tarball_path)
                file.extractall(package_check_path)
                file.close
                os.remove(tarball_path)
                console.print(
                    "[magenta][STEP 4]:", "Checking the JSON file content"
                )
                json_path = os.path.join(ip_path, f"{ip}.json")
                valid_JSON = check_JSON(console, json_path, ip)
                if valid_JSON:
                    console.print(
                        "[magenta][STEP 5]:", "Checking the hierarchy of the directory"
                    )
                    valid_hierarchy = check_hierarchy(
                        console, ip_path, ip, json_path
                    )  # Checks if folder's hierarchy is valid
                    if valid_hierarchy:
                        console.print(
                            "[green]IP pre-check was successful you can now submit your IP"
                        )
                shutil.rmtree(package_check_path)
