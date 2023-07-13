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
import shutil
import sys
import tarfile
from typing import Callable
import click
import requests
from rich.console import Console
from rich.table import Table

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

    def get_verified_ip_info(self, ip_name=None):
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
            if ip_name in data:
                return data[ip_name]
            else:
                logger.print_err(f"Please provide a valid IP, {ip_name} is not a verified IP")
                exit(1)
        else:
            return data

    def get_installed_ips(self, ipm_root):
        installed_ips = []
        for root, directories, files in os.walk(ipm_root):
            ip_names = directories
            break
        for ips in ip_names:
            for root, directories, files in os.walk(os.path.join(ipm_root, ips)):
                installed_ips.append({ips: directories})
                break
        return installed_ips

    def get_installed_ip_info(self, ipm_root):
        installed_ips = self.get_installed_ips(ipm_root)
        installed_ips_arr = []
        for ips in installed_ips:
            for ip_name, ip_version in ips.items():
                for version in ip_version:
                    json_file = f"{ipm_root}/{ip_name}/{version}/{ip_name}.json"
                    with open(json_file) as f:
                        data = json.load(f)
                    installed_ips_arr.append({data['name']: data})
        return installed_ips_arr

    def get_installed_ip_info_from_simlink(self, ip_root, ip_name):
        logger = Logger()
        json_file = f"{ip_root}/{ip_name}/{ip_name}.json"
        if os.path.exists(json_file):
            with open(json_file) as f:
                data = json.load(f)
            return {data['name']: data}
        else:
            logger.print_err(f"Couldn't find {json_file}")
            exit(1)

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

    def create_dependencies_file(self):
        dependencies_file_path = os.path.join(self.ip_root, DEPENDENCIES_FILE_NAME)
        if os.path.exists(dependencies_file_path):
            with open(dependencies_file_path) as json_file:
                json_decoded = json.load(json_file)
        else:
            json_decoded = {
                "IP": []
            }
        tmp_dict = {
            self.ip_name: self.version
        }
        flag = True
        if len(json_decoded['IP']) > 0:
            for ips in json_decoded['IP']:
                for name, version in ips.items():
                    if name == self.ip_name:
                        flag = False
            if flag:
                json_decoded['IP'].append(tmp_dict)
        else:
            json_decoded['IP'].append(tmp_dict)

        with open(dependencies_file_path, "w") as json_file:
            json.dump(json_decoded, json_file)

    def remove_from_dependencies_file(self):
        logger = Logger()
        dependencies_file_path = os.path.join(self.ip_root, DEPENDENCIES_FILE_NAME)
        if os.path.exists(dependencies_file_path):
            with open(dependencies_file_path) as json_file:
                json_decoded = json.load(json_file)
            ip_category = json_decoded["IP"]
            for ips in ip_category:
                for ips_name, ip_version in ips.items():
                    if ips_name == self.ip_name:
                        ip_category.remove({ips_name: ip_version})
                json_decoded["IP"] = ip_category

            with open(dependencies_file_path, "w") as json_file:
                json.dump(json_decoded, json_file)
        else:
            logger.print_err(f"Couldn't find {DEPENDENCIES_FILE_NAME} file")

    def create_table(self, ip_list, version=None, extended=False, local=False):
        table = Table()
        logger = Logger()
        console = Console()

        table.add_column("IP Name", style="magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Version")
        table.add_column("Author")
        table.add_column("Type")
        table.add_column("Tag")
        table.add_column("Status")
        if extended:
            table.add_column("Cell count")
            table.add_column("Clk freq (MHz)")
            table.add_column("Width (um)")
            table.add_column("Height (um)")
        table.add_column("Technology", style="cyan")
        table.add_column("License", style="magenta")

        for ips in ip_list:
            for key, value in ips.items():
                version_list = []
                table_list = []
                if not local:
                    if not version:
                        version_list.append(get_latest_version(value['release']))
                    else:
                        for versions, data in value['release'].items():
                            version_list.append(versions)
                else:
                    version_list.append(value['version'])
                for versions in version_list:
                    table_list.append(key)
                    table_list.append(value['category'])
                    table_list.append(versions)
                    table_list.append(value["author"])
                    if not local:
                        table_list.append(value['release'][versions]["type"])
                        table_list.append(",".join(value["tag"]))
                        table_list.append(value['release'][versions]["status"])
                        if extended:
                            table_list.append(value['release'][versions]["cell_count"])
                            table_list.append(value['release'][versions]["clk_freq"])
                            table_list.append(value['release'][versions]["width"])
                            table_list.append(value['release'][versions]["height"])
                    if local:
                        table_list.append(value["type"])
                        table_list.append(",".join(value["tag"]))
                        table_list.append(value["status"])
                        if extended:
                            table_list.append(value["cell_count"])
                            table_list.append(value["clk_freq"])
                            table_list.append(value["width"])
                            table_list.append(value["height"])
                    table_list.append(value["technology"])
                    table_list.append(value["license"])
                    table.add_row(*table_list)
                    table_list = []

        if len(ip_list) > 0:
            console.print(table)
            logger.print_info(f"Total number of IPs: {len(ip_list)}")
        else:
            logger.print_err("No IPs found")

def query_yes_no(question, default="yes"):
    # from https://stackoverflow.com/questions/3041986/apt-command-line-interface-like-yes-no-input
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == "":
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' " "(or 'y' or 'n').\n")

def get_latest_version(data):
    last_key = None
    for key, value in data.items():
        last_key = key

    return last_key

def install_ip(ip_name, version, ip_root, ipm_root):
    logger = Logger()
    ip_info = IPInfo()
    dependencies_list = []
    verified_ip_info = ip_info.get_verified_ip_info(ip_name)
    if not version:
        version = get_latest_version(verified_ip_info['release'])
    ip_info.get_dependencies(ip_name, version, dependencies_list)
    dependencies_list.append({ip_name: version})
    for dep in dependencies_list:
        for dep_name, version in dep.items():
            verified_ip_info = ip_info.get_verified_ip_info(dep_name)
            if not version:
                version = get_latest_version(verified_ip_info['release'])
            ip = IP(dep_name, ip_root, ipm_root, version)
            if ip.check_install_root():
                ip_install_root = f"{ipm_root}/{dep_name}/{version}"
                logger.print_info(f"Installing IP {dep_name} at {ipm_root} and creating simlink to {ip_root}")
                release_url = f"https://{verified_ip_info['repo']}/releases/download/{version}/{version}.tar.gz"
                response = requests.get(release_url, stream=True)
                if response.status_code == 404:
                    logger.print_err(f"The IP {dep_name} version {version} could not be found remotely")
                    shutil.rmtree(ip_install_root)
                    exit(1)
                elif response.status_code == 200:
                    tarball_path = os.path.join(ip_install_root, f"{version}.tar.gz")
                    with open(tarball_path, "wb") as f:
                        f.write(response.raw.read())
                    file = tarfile.open(tarball_path)
                    file.extractall(ip_install_root)
                    file.close
                    os.remove(tarball_path)
                    logger.print_success(f"Successfully installed {dep_name} version {version}")

            else:
                logger.print_info(f"Found IP {dep_name} locally")
            if os.path.exists(f"{ip_root}/{dep_name}"):
                os.unlink(f"{ip_root}/{dep_name}")
            os.symlink(f"{ipm_root}/{dep_name}/{version}", f"{ip_root}/{dep_name}")
            logger.print_success(f"Created simlink to {dep_name} IP at {ip_root}")
            if dep_name == ip_name:
                ip.create_dependencies_file()

def uninstall_ip(ip_name, version, ipm_root):
    logger = Logger()
    ip_info = IPInfo()
    dependencies_list = []
    verified_ip_info = ip_info.get_verified_ip_info(ip_name)
    if not version:
        version = get_latest_version(verified_ip_info['release'])
    ip_info.get_dependencies(ip_name, version, dependencies_list)
    dependencies_list.append({ip_name: version})
    if query_yes_no(f"uninstalling {ip_name} will end up with broken simlinks if used in any project, and will uninstall all dependencies of IP"):
        for dep in dependencies_list:
            for dep_name, version in dep.items():
                ip_root = f"{ipm_root}/{dep_name}"
                if os.path.exists(ip_root):
                    shutil.rmtree(ip_root)
        logger.print_success(f"Successfully uninstalled {ip_name}")

def rm_ip_from_project(ip_name, ip_root):
    ip = IP(ip_name, ip_root)
    ip_info = IPInfo()
    logger = Logger()
    installed_ip_info = ip_info.get_installed_ip_info_from_simlink(ip_root, ip_name)
    dep_arr = []
    ip_info = ip_info.get_dependencies(ip_name, installed_ip_info[ip_name]['version'], dep_arr)
    dep_arr.append({ip_name: installed_ip_info[ip_name]['version']})
    for d in dep_arr:
        for dep_name, dep_version in d.items():
            uninstall_ip_root = f"{ip_root}/{dep_name}"
            if os.path.exists(uninstall_ip_root):
                os.unlink(uninstall_ip_root)
    ip.remove_from_dependencies_file()
    logger.print_success(f"removed IP {ip_name} and dependencies from project")

def install_using_dep_file(ip_root, ipm_root):
    logger = Logger()
    json_file = f"{ip_root}/{DEPENDENCIES_FILE_NAME}"
    if os.path.exists(json_file):
        logger.print_info(f"using {json_file} to download IPs")
        with open(json_file) as f:
            data = json.load(f)
        for ips in data['IP']:
            for ip_name, ip_version in ips.items():
                install_ip(ip_name, ip_version, ip_root, ipm_root)
    else:
        logger.print_err(f"Can't find {DEPENDENCIES_FILE_NAME} file in {ip_root}")
        exit(1)

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

def list_verified_ips(category=None, technology=None):
    ip_info = IPInfo()
    ip = IP()
    verified_ips = ip_info.get_verified_ip_info()
    ip_list = []
    for ip_name, ip_data in verified_ips.items():
        if category and not technology:
            if ip_data['category'] == category:
                ip_list.append({ip_name: ip_data})
        elif technology and not category:
            if ip_data['technology'] == technology:
                ip_list.append({ip_name: ip_data})
        elif technology and category:
            if ip_data['category'] == category and ip_data['technology'] == technology:
                ip_list.append({ip_name: ip_data})
        else:
            ip_list.append({ip_name: ip_data})

    ip.create_table(ip_list)

def list_ip_info(ip_name):
    ip_info = IPInfo()
    ip = IP(ip_name)
    ip_data = ip_info.get_verified_ip_info(ip_name)
    ip_list = [{ip_name: ip_data}]
    ip.create_table(ip_list, "all", True)

def list_installed_ips(ipm_root):
    ip_info = IPInfo()
    ip = IP()
    ip_data = ip_info.get_installed_ip_info(ipm_root)
    ip.create_table(ip_data, local=True, extended=True)

def check_ips(ipm_root, update=False, ip_root=None):
    ip_info = IPInfo()
    logger = Logger()
    installed_ips = ip_info.get_installed_ips(ipm_root)
    for ips in installed_ips:
        for ip_name, ip_version in ips.items():
            verified_ip_info = ip_info.get_verified_ip_info(ip_name)
            version = get_latest_version(verified_ip_info['release'])
            if version not in ip_version:
                if update:
                    install_ip(ip_name, version, ip_root, ipm_root)
                else:
                    logger.print_info(f"IP {ip_name} has a newer version [magenta]{version}[/magenta], to update use command ipm update")
