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
import json
import os
import tarfile
from typing import Callable
import click
import requests
from rich.console import Console

GITHUB_TOKEN = os.environ['GITHUB_TOKEN']
VERIFIED_JSON_FILE_URL = (
    "https://raw.githubusercontent.com/efabless/ipm/refactor_code/verified_IPs.json"
)
LOCAL_JSON_FILE_NAME = "Installed_IPs.json"
DEPENDENCIES_FILE_NAME = "dependencies.json"
IPM_DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".ipm")

def opt_ipm_root(function: Callable):
    function = click.option(
        "--ipm-root",
        required=False,
        default=os.getenv("IPM_ROOT") or IPM_DEFAULT_HOME,
        help="Path to the IPM root where the IPs will reside",
        show_default=True,
    )(function)
    return function

class Logger:
    def __init__(self) -> None:
        self.console = Console()

    def print_err(self, err_string):
        self.console.print(f"[red]{err_string}")

    def print_warn(self, warn_string):
        self.console.print(f"[orange]{warn_string}")

    def print_info(self, info_string):
        self.console.print(f"{info_string}")

    def print_success(self, info_string):
        self.console.print(f"[green]{info_string}")


class IPInfo:
    def __init__(self):
        pass

    def get_verified_ip_info(self, ip_name):
        logger = Logger()
        if GITHUB_TOKEN:
            headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        else:
            logger.print_err("Can't find GITHUB_TOKEN in environment, please export your github token")
            logger.print_err("THIS IS A TEMP WORKAROUND")
            exit(1)
        resp = requests.get(VERIFIED_JSON_FILE_URL, headers=headers)
        if resp.status_code == 404:
            logger.print_err("Can't find remote file, you don't have access to IPM private repo, or GITHUB_TOKEN is wrong")
            exit(1)
        data = json.loads(resp.text)
        if ip_name:
            return data[ip_name]
        else:
            return data

    def get_installed_ip_info(self, ip_name, ipm_root):
        logger = Logger()
        local_json_file = os.path.join(ipm_root, LOCAL_JSON_FILE_NAME)
        if not os.path.exists(local_json_file):
            logger.print_err(f"Can't find {local_json_file}")
        with open(local_json_file) as json_file:
            data = json.load(json_file)
        if ip_name:
            return data[ip_name]
        else:
            return data

    def get_dependencies(self, ip_name, version, dependencies_list):
        ip_info = self.get_verified_ip_info(ip_name)
        release = ip_info['release'][version]
        if "dependencies" in release:
            dependencies = ip_info['release'][version]['dependencies']
            for dep_name, dep_version in dependencies.items():
                if {dep_name, dep_version} not in dependencies_list:
                    dependencies_list.append({dep_name: dep_version})
                    self.get_dependencies(dep_name, dep_version, dependencies_list)
        else:
            return {ip_name, version}

class IP:
    def __init__(self, ip_name=None, ip_root=None, ipm_root=None, version=None):
        self.ip_name = ip_name
        self.ip_root = ip_root
        self.ipm_root = ipm_root
        self.version = version

    def check_install_root(self):
        if not os.path.exists(f"{self.ipm_root}/{self.ip_name}"):
            os.mkdir(f"{self.ipm_root}/{self.ip_name}")
        if not os.path.exists(f"{self.ipm_root}/{self.ip_name}/{self.version}"):
            os.mkdir(f"{self.ipm_root}/{self.ip_name}/{self.version}")
            return True
        else:
            return False

def create_dependencies_file(ip_name, version, ip_root):
    dependencies_file_path = os.path.join(ip_root, DEPENDENCIES_FILE_NAME)
    if os.path.exists(dependencies_file_path):
        with open(dependencies_file_path) as json_file:
            json_decoded = json.load(json_file)
    else:
        json_decoded = {
            "IP": []
        }
    tmp_dict = {
        ip_name: version
    }
    if len(json_decoded['IP']) > 0:
        for ips in json_decoded['IP']:
            if not ips['name'] == ip_name:
                json_decoded['IP'].append(tmp_dict)
    else:
        json_decoded['IP'].append(tmp_dict)

    with open(dependencies_file_path, "w") as json_file:
        json.dump(json_decoded, json_file)

def get_latest_version(data):
    last_key = None
    for key, value in data.items():
        last_key = key

    return last_key

def install_ip(ip_name, version, ip_root, ipm_root):
    logger = Logger()
    ip_info = IPInfo()
    dependencies_list = []
    ip_info.get_dependencies(ip_name, version, dependencies_list)
    dependencies_list.append({ip_name: version})
    for dep in dependencies_list:
        for ip_name, version in dep.items():
            verified_ip_info = ip_info.get_verified_ip_info(ip_name)
            if not version:
                version = get_latest_version(verified_ip_info['release'])
            ip = IP(ip_name, ip_root, ipm_root, version)
            if ip.check_install_root():
                ip_install_root = f"{ipm_root}/{ip_name}/{version}"
                logger.print_info(f"Installing IP {ip_name} at {ipm_root} and creating simlink to {ip_root}")
                release_url = f"https://{verified_ip_info['repo']}/releases/download/{version}/{version}.tar.gz"
                response = requests.get(release_url, stream=True)
                if response.status_code == 404:
                    logger.print_err(f"The IP {ip_name} version {version} could not be found remotely")
                    exit(1)
                elif response.status_code == 200:
                    tarball_path = os.path.join(ip_install_root, f"{version}.tar.gz")
                    with open(tarball_path, "wb") as f:
                        f.write(response.raw.read())
                    file = tarfile.open(tarball_path)
                    file.extractall(ip_install_root)
                    file.close
                    os.remove(tarball_path)
                    logger.print_success(f"Successfully installed {ip_name} version {version}")

            else:
                logger.print_info(f"Found IP {ip_name} locally")
            if os.path.exists(f"{ip_root}/{ip_name}"):
                os.unlink(f"{ip_root}/{ip_name}")
            os.symlink(f"{ipm_root}/{ip_name}/{version}", f"{ip_root}/{ip_name}")
            logger.print_success(f"Created simlink to {ip_name} IP at {ip_root}")

def check_ipm_directory(ipm_root) -> bool:
    logger = Logger()
    if ipm_root == IPM_DEFAULT_HOME:
        if os.path.isdir(ipm_root):
            return True
        else:
            os.mkdir(ipm_root)
            return True
    else:
        if os.path.isdir(ipm_root):
            return True
        else:
            logger.print_err(f"Can't find directory {ipm_root}, please specify a correct IPM_ROOT to continue")
            return False

def check_ip_root_dir(ip_root) -> bool:
    logger = Logger()
    if not os.path.isdir(ip_root):
        logger.print_err(f"[red] ip-root {ip_root} can't be found")
        return False
    else:
        return True
