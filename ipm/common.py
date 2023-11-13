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

# import bus_wrapper_gen

try:
    GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
except KeyError:
    console = Console()
    console.print(
        "[red]Can't find GITHUB_TOKEN in environment, please export your github token"
    )
    exit(1)
VERIFIED_JSON_FILE_URL = (
    "https://raw.githubusercontent.com/efabless/ipm/main/verified_IPs.json"
)
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

    def print_step(self, info_string):
        self.console.print(f"[magenta]{info_string}")


class IPInfo:
    def __init__(self):
        pass

    @staticmethod
    def get_verified_ip_info(ip_name=None):
        """get ip info from remote verified backend

        Args:
            ip_name (str, optional): name of the ip. Defaults to None.

        Returns:
            dict: info of ip
        """
        logger = Logger()
        if GITHUB_TOKEN:
            headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        else:
            logger.print_err(
                "Can't find GITHUB_TOKEN in environment, please export your github token"
            )
            logger.print_err("THIS IS A TEMP WORKAROUND")
            exit(1)
        resp = requests.get(VERIFIED_JSON_FILE_URL, headers=headers)
        if resp.status_code == 404:
            logger.print_err(
                "Can't find remote file, you don't have access to IPM private repo, or GITHUB_TOKEN is wrong"
            )
            exit(1)
        data = json.loads(resp.text)
        if ip_name:
            if ip_name in data:
                return data[ip_name]
            else:
                logger.print_err(
                    f"Please provide a valid IP, {ip_name} is not a verified IP"
                )
                exit(1)
        else:
            return data

    @staticmethod
    def get_installed_ips(ipm_root):
        """gets all installed ips under ipm_root

        Args:
            ipm_root (str): path to ipm_root

        Returns:
            list: list of all installed ips
        """
        installed_ips = []
        for root, directories, files in os.walk(ipm_root):
            ip_names = directories
            break
        for ips in ip_names:
            for root, directories, files in os.walk(os.path.join(ipm_root, ips)):
                installed_ips.append({ips: directories})
                break
        return installed_ips

    @staticmethod
    def get_installed_ip_info(ipm_root):
        """gets the info of the installed ips from <ip>.json

        Args:
            ipm_root (str): path to ipm_root

        Returns:
            list: list of dicts of all installed ips and their data
        """
        installed_ips = IPInfo.get_installed_ips(ipm_root)
        installed_ips_arr = []
        for ips in installed_ips:
            for ip_name, ip_version in ips.items():
                for version in ip_version:
                    json_file = f"{ipm_root}/{ip_name}/{version}/{ip_name}.json"
                    with open(json_file) as f:
                        data = json.load(f)
                    installed_ips_arr.append({data["info"]["name"]: data})
        return installed_ips_arr

    @staticmethod
    def get_installed_ip_info_from_simlink(ip_root, ip_name):
        """gets info of a specific ip from <ip>.json

        Args:
            ip_root (str): path to ip_root
            ip_name (str): name of ip

        Returns:
            dict: info of the ip
        """
        logger = Logger()
        json_file = f"{ip_root}/{ip_name}/{ip_name}.json"
        if os.path.exists(json_file):
            with open(json_file) as f:
                data = json.load(f)
            return {data["info"]["name"]: data}
        else:
            logger.print_err(f"Couldn't find {json_file}")
            exit(1)

    @staticmethod
    def get_installed_ip_dependencies_from_simlink(ipm_root, ip_name, version):
        """gets info of a specific ip from <ip>.json

        Args:
            ip_root (str): path to ip_root
            ip_name (str): name of ip

        Returns:
            dict: info of the ip
        """
        json_file = f"{ipm_root}/{ip_name}/{version}/ip/dependencies.json"
        if os.path.exists(json_file):
            with open(json_file) as f:
                data = json.load(f)
            return data

    @staticmethod
    def get_dependencies(ip_name, version, dependencies_list, ipm_root):
        """gets the dependencies of ip from the remote database using recursion

        Args:
            ip_name (str): name of ip
            version (str): version of ip
            dependencies_list (list): list of dependencies

        Returns:
            dict: name and version of each dependency
        """
        ip_info = IPInfo.get_installed_ip_dependencies_from_simlink(
            ipm_root, ip_name, version
        )
        if ip_info:
            for dep in ip_info["IP"]:
                for dep_name, dep_version in dep.items():
                    if {dep_name, dep_version} not in dependencies_list:
                        dependencies_list.append({dep_name: dep_version})
                        IPInfo.get_dependencies(
                            dep_name,
                            dep_version,
                            dependencies_list,
                            ipm_root,
                        )
        else:
            return {ip_name, version}


class IP:
    def __init__(self, ip_name=None, ip_root=None, ipm_root=None, version=None):
        self.ip_name = ip_name
        self.ip_root = ip_root
        self.ipm_root = ipm_root
        self.version = version

    def check_install_root(self):
        """checks the install root if it exists, if not it will create it

        Returns:
            bool: True if it didn't exist and is created, False if it exists
        """
        if not os.path.exists(f"{self.ipm_root}/{self.ip_name}/{self.version}"):
            os.makedirs(f"{self.ipm_root}/{self.ip_name}/{self.version}")
            return True
        else:
            return False

    def update_dependencies_file(self):
        """creates a json file that has all the dependencies of the project"""
        dependencies_file_path = os.path.join(self.ip_root, DEPENDENCIES_FILE_NAME)
        if os.path.exists(dependencies_file_path):
            with open(dependencies_file_path) as json_file:
                json_decoded = json.load(json_file)
        else:
            json_decoded = {"IP": []}
        tmp_dict = {self.ip_name: self.version}
        flag = True
        if len(json_decoded["IP"]) > 0:
            for ips in json_decoded["IP"]:
                for name, version in ips.items():
                    if name == self.ip_name:
                        if version == self.version:
                            flag = False
                        else:
                            json_decoded["IP"].remove({name: version})
            if flag:
                json_decoded["IP"].append(tmp_dict)
        else:
            json_decoded["IP"].append(tmp_dict)

        with open(dependencies_file_path, "w") as json_file:
            json.dump(json_decoded, json_file)

    def remove_from_dependencies_file(self):
        """removes the ip from the dependencies file of the project"""
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

    @staticmethod
    def create_table(ip_list, version=None, extended=False, local=False):
        """creates table using rich tables

        Args:
            ip_list (list): list of ips
            version (str, optional): version of ip. Defaults to None.
            extended (bool, optional): extended table (has more info). Defaults to False.
            local (bool, optional): gets the info from local install. Defaults to False.
        """
        table = Table()
        logger = Logger()
        console = Console()

        table.add_column("IP Name", style="magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Version")
        table.add_column("Owner")
        table.add_column("Type")
        table.add_column("Tags")
        table.add_column("Status")
        if extended:
            table.add_column("Bus")
            table.add_column("Cell count")
            table.add_column("Clk freq (MHz)")
            table.add_column("Width (um)")
            table.add_column("Height (um)")
            table.add_column("Voltage (v)")
        table.add_column("Technology", style="cyan")
        table.add_column("License", style="magenta")

        for ips in ip_list:
            for key, value in ips.items():
                version_list = []
                table_list = []
                if not local:
                    if not version:
                        version_list.append(get_latest_version(value["release"]))
                    else:
                        for versions, data in value["release"].items():
                            version_list.append(versions)
                else:
                    version_list.append(value["info"]["version"])
                for versions in version_list:
                    if not local:
                        table_list.append(key)
                        table_list.append(value["category"])
                        table_list.append(versions)
                        table_list.append(value["owner"])
                        table_list.append(value["release"][versions]["type"])
                        table_list.append(",".join(value["tags"]))
                        table_list.append(value["release"][versions]["status"])
                        if extended:
                            table_list.append(
                                ",".join(value["release"][versions]["bus"])
                            )
                            table_list.append(value["release"][versions]["cell_count"])
                            table_list.append(
                                value["release"][versions]["clock_freq_mhz"]
                            )
                            table_list.append(value["release"][versions]["width"])
                            table_list.append(value["release"][versions]["height"])
                            table_list.append(
                                ",".join(value["release"][versions]["supply_voltage"])
                            )
                        table_list.append(value["technology"])
                        table_list.append(value["license"])
                    if local:
                        table_list.append(key)
                        table_list.append(value["info"]["category"])
                        table_list.append(versions)
                        table_list.append(value["info"]["owner"])
                        table_list.append(value["info"]["type"])
                        table_list.append(",".join(value["info"]["tags"]))
                        table_list.append(value["info"]["status"])
                        if extended:
                            table_list.append(",".join(value["info"]["bus"]))
                            table_list.append(value["info"]["cell_count"])
                            table_list.append(value["info"]["clock_freq_mhz"])
                            table_list.append(value["info"]["width"])
                            table_list.append(value["info"]["height"])
                            table_list.append(",".join(value["info"]["supply_voltage"]))
                        table_list.append(value["info"]["technology"])
                        table_list.append(value["info"]["license"])
                    table.add_row(*table_list)
                    table_list = []

        if len(ip_list) > 0:
            console.print(table)
            logger.print_info(f"Total number of IPs: {len(ip_list)}")
        else:
            logger.print_err("No IPs found")

    def download_tarball(self, verified_ip, dest_path):
        """downloads the release tarball

        Args:
            release_url (str): url of the release tarball
            dest_path (str): path to destination of download

        Returns:
            bool: True if downloaded, False if failed to download
        """
        logger = Logger()
        return_status = True
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
        }
        params = {"per_page": 100, "page": 1}
        release_url = "https://api.github.com/repos/efabless/EF_IPs/releases"
        response = requests.get(
            release_url, stream=True, headers=headers, params=params
        )
        release_data = response.json()
        for data in release_data:
            if self.ip_name in data["tarball_url"].split("/")[-1]:
                for assets in data["assets"]:
                    for asset_name, asset_value in assets.items():
                        if (
                            asset_name == "name"
                            and asset_value == f"{self.version}.tar.gz"
                        ):
                            asset_id = assets["id"]
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/octet-stream",
        }
        try:
            release_url = f"https://api.github.com/repos/efabless/EF_IPs/releases/assets/{asset_id}"
        except NameError:
            logger.print_err("Could not find asset")
            return_status = False
        response = requests.get(release_url, stream=True, headers=headers)
        if response.status_code == 404:
            shutil.rmtree(dest_path)
            logger.print_err(
                "Couldn't download IP, make sure you have access to the repo and you have GITHUB_TOKEN exported"
            )
            return_status = False
        elif response.status_code == 200:
            tarball_path = os.path.join(dest_path, f"{self.version}.tar.gz")
            with open(tarball_path, "wb") as f:
                f.write(response.raw.read())
            file = tarfile.open(tarball_path)
            file.extractall(dest_path)
            file.close
            os.remove(tarball_path)
            return_status = True
        if return_status:
            return True
        else:
            shutil.rmtree(os.path.dirname(dest_path))
            exit(1)

    # def generate_bus_wrapper(self, verified_ip_info):
    #     if "generic" in verified_ip_info["release"][self.version]["bus"]:
    #         ip_install_root = f"{self.ipm_root}/{self.ip_name}/{self.version}"
    #         bus_wrapper_dir = f"{ip_install_root}/hdl/rtl/bus_wrapper"
    #         fw_dir = f"{ip_install_root}/fw"
    #         os.makedirs(bus_wrapper_dir, exist_ok=True)
    #         os.makedirs(fw_dir, exist_ok=True)
    #         bus_wrapper_ip = bus_wrapper_gen.IP(
    #             f"{ip_install_root}/{self.ip_name}.json"
    #         )
    #         org_stdout = sys.stdout
    #         with open(f"{bus_wrapper_dir}/{self.ip_name}_wb.v", "w") as f:
    #             sys.stdout = f
    #             bus_wrapper_gen.WB_Wrapper(bus_wrapper_ip).print()
    #             sys.stdout = org_stdout
    #         with open(f"{bus_wrapper_dir}/{self.ip_name}_ahbl.v", "w") as f:
    #             sys.stdout = f
    #             bus_wrapper_gen.AHBL_Wrapper(bus_wrapper_ip).print()
    #             sys.stdout = org_stdout
    #         with open(f"{bus_wrapper_dir}/{self.ip_name}_apb.v", "w") as f:
    #             sys.stdout = f
    #             bus_wrapper_gen.APB_Wrapper(bus_wrapper_ip).print()
    #             sys.stdout = org_stdout
    #         with open(f"{fw_dir}/{self.ip_name}.c", "w") as f:
    #             sys.stdout = f
    #             bus_wrapper_gen.APB_Wrapper(bus_wrapper_ip).gen_driver(self.ip_name)
    #             sys.stdout = org_stdout


class Checks:
    def __init__(self, ipm_root, ip_name, version, gh_url) -> None:
        if gh_url.startswith("https"):
            self.gh_url = gh_url
        else:
            self.gh_url = f"https://{gh_url}"
        self.release_tag_url = f"{self.gh_url}/releases/tag/{version}"
        self.release_tarball_url = (
            f"{self.gh_url}/releases/download/{version}/{version}.tar.gz"
        )
        self.package_check_path = os.path.join(ipm_root, f"{ip_name}_pre-check")
        if os.path.exists(self.package_check_path):
            shutil.rmtree(self.package_check_path)
        self.version = version
        self.ipm_root = ipm_root
        self.ip_name = ip_name

    def check_url(self, url):
        """checks if url can be accessed

        Args:
            url (str): url to be accessed

        Returns:
            bool: True if can be accessed, False if failed to access
        """
        repo_response = requests.get(url, stream=True)
        if repo_response.status_code == 404:
            return False
        elif repo_response.status_code == 200:
            return True

    def download_check_tarball(self):
        """downloads the tarball of package checker"""
        ip = IP(self.ip_name, ipm_root=self.ipm_root, version=self.version)
        os.mkdir(self.package_check_path)
        ip.download_tarball(
            self.release_tarball_url,
            self.package_check_path,
        )

    def check_json(self):
        """checks the json if it has all the variables needed

        Returns:
            bool: True if all json fields exist, False if they don't
        """
        logger = Logger()
        json_path = f"{self.package_check_path}/{self.ip_name}.json"
        if not os.path.exists(json_path):
            logger.print_err(
                f"Can't find {json_path} please refer to the ipm directory structure (IP name {self.ip_name} might be wrong)"
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
            "tags",
            "cell_count",
            "clock_freq_mhz",
            "license",
        ]
        flag = True
        with open(json_path) as json_file:
            json_decoded = json.load(json_file)

        if self.ip_name != json_decoded["name"]:
            logger.print_err(
                f"The given IP name {self.ip_name} is not the same as the one in json file"
            )
            flag = False

        for field in json_fields:
            if field not in json_decoded.keys():
                logger.print_err(
                    f"The field '{field}' was not included in the {self.ip_name}.json file"
                )
                flag = False

        return flag

    def check_hierarchy(self):
        """checks the hierarchy of the ip, depending on the ip type

        Returns:
            bool: True if hierarchy is correct, False if it is not
        """
        logger = Logger()
        json_path = f"{self.package_check_path}/{self.ip_name}.json"
        ip_path = f"{self.package_check_path}"
        common_dirs = ["verify/beh_model", "fw", "hdl/rtl/bus_wrapper"]
        with open(json_path) as json_file:
            data = json.load(json_file)
        # check the folder hierarchy
        if data["type"] == "hard":
            ipm_dirs = [
                "hdl/gl",
                "timing/lib",
                "timing/sdf",
                "timing/spef",
                "layout/gds",
                "layout/lef",
            ]
        elif data["type"] == "soft" and data["category"] == "digital":
            ipm_dirs = ["hdl/rtl/design", "verify/utb", "pnr"]
        if data["category"] == "analog":
            ipm_dirs = ["spice"]
        ipm_dirs = ipm_dirs + common_dirs
        ipm_files = [f"{self.ip_name}.json", "readme.md", "doc/datasheet.pdf"]
        flag = True
        for dirs in ipm_dirs:
            if not os.path.exists(os.path.join(ip_path, dirs)):
                logger.print_err(
                    f"The directory {dirs} cannot be found under {ip_path} please refer to the ipm directory structure"
                )
                flag = False

        for files in ipm_files:
            if not os.path.exists(os.path.join(ip_path, files)):
                logger.print_err(
                    f"The file {files} cannot be found under {ip_path} please refer to the ipm directory structure"
                )
                flag = False
        return flag


def change_dir_to_readonly(dir):
    """Recursively checks a directory and its subdirectories for files that should be readonly, and then changes any non-readonly files to readonly.

    Args:
        directory_name: The name of the directory to check.
    """
    for file_name in os.listdir(dir):
        file_path = os.path.join(dir, file_name)
        if os.path.isfile(file_path):
            if os.access(file_path, os.W_OK):
                os.chmod(file_path, 0o400)
        else:
            change_dir_to_readonly(file_path)


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
    """gets the latest version of the ip

    Args:
        data (dict): info of the ip to get the latest version

    Returns:
        str: latest version of the ip
    """
    last_key = None
    for key, value in data.items():
        last_key = key

    return last_key


def install_ip(ip_name, version, ip_root, ipm_root):
    """installs the ip tarball

    Args:
        ip_name (str): name of the ip to get installed
        version (str): version of the ip
        ip_root (str): path to the project ip dict
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    dependencies_list = []
    verified_ip_info = IPInfo.get_verified_ip_info(ip_name)
    if not version:
        version = get_latest_version(verified_ip_info["release"])
    elif version not in verified_ip_info["release"]:
        logger.print_err(f"Version {version} can't be found")
        exit(1)

    download_ip(ip_name, version, ip_root, ipm_root, logger)
    IPInfo.get_dependencies(ip_name, version, dependencies_list, ipm_root)
    ip = IP(ip_name, ip_root, ipm_root, version)
    ip.update_dependencies_file()
    for dep in dependencies_list:
        for dep_name, version in dep.items():  # can use .key and .value
            download_ip(dep_name, version, ip_root, ipm_root, logger)
    change_dir_to_readonly(ipm_root)


def download_ip(dep_name, version, ip_root, ipm_root, logger):
    verified_ip_info = IPInfo.get_verified_ip_info(dep_name)
    if not version:
        version = get_latest_version(verified_ip_info["release"])
    ip = IP(dep_name, ip_root, ipm_root, version)
    if ip.check_install_root():
        ip_install_root = f"{ipm_root}/{dep_name}/{version}"
        logger.print_info(
            f"Installing IP [cyan]{dep_name}[/cyan] at {ipm_root} and creating simlink to {ip_root}"
        )
        ip.download_tarball(verified_ip_info, ip_install_root)
        # ip.generate_bus_wrapper(verified_ip_info)
    else:
        logger.print_info(f"Found IP [cyan]{dep_name}[/cyan] locally")
    if ipm_root != ip_root:
        if os.path.exists(f"{ip_root}/{dep_name}"):
            os.unlink(f"{ip_root}/{dep_name}")
        os.symlink(f"{ipm_root}/{dep_name}/{version}", f"{ip_root}/{dep_name}")
        logger.print_success(f"Created simlink to {dep_name} IP at {ip_root}")
    else:
        logger.print_success(f"Downloaded IP at {ipm_root}")


def uninstall_ip(ip_name, version, ipm_root):
    """uninstalls the ip tarball

    Args:
        ip_name (str): name of the ip to get installed
        version (str): version of the ip
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    dependencies_list = []
    verified_ip_info = IPInfo.get_verified_ip_info(ip_name)
    if not version:
        version = get_latest_version(verified_ip_info["release"])
    IPInfo.get_dependencies(ip_name, version, dependencies_list, ipm_root)
    dependencies_list.append({ip_name: version})
    if query_yes_no(
        f"uninstalling {ip_name} might end up with broken simlinks if used in any project, and will uninstall all dependencies of IP"
    ):
        for dep in dependencies_list:
            for dep_name, version in dep.items():
                ip_root = f"{ipm_root}/{dep_name}"
                if os.path.exists(ip_root):
                    shutil.rmtree(ip_root)
        logger.print_success(f"Successfully uninstalled {ip_name}")


def rm_ip_from_project(ip_name, ip_root, ipm_root):
    """removes the simlink of the ip from project and removes it from dependencies file

    Args:
        ip_name (str): name of the ip to get installed
        ip_root (str): path to the project ip dict
    """
    ip = IP(ip_name, ip_root)
    logger = Logger()
    installed_ip_info = IPInfo.get_installed_ip_info_from_simlink(ip_root, ip_name)
    dep_arr = []
    IPInfo.get_dependencies(
        ip_name, installed_ip_info[ip_name]["info"]["version"], dep_arr, ipm_root
    )
    dep_arr.append({ip_name: installed_ip_info[ip_name]["info"]["version"]})
    for d in dep_arr:
        for dep_name, dep_version in d.items():
            uninstall_ip_root = f"{ip_root}/{dep_name}"
            if os.path.exists(uninstall_ip_root):
                os.unlink(uninstall_ip_root)
    ip.remove_from_dependencies_file()
    logger.print_success(f"removed IP {ip_name} and dependencies from project")


def install_using_dep_file(ip_root, ipm_root):
    """install the ip from the dependencies file, assuming the dependencies file is under ip_root

    Args:
        ip_root (str): path to the project ip dir
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    json_file = f"{ip_root}/{DEPENDENCIES_FILE_NAME}"
    if os.path.exists(json_file):
        logger.print_info(f"using {json_file} to download IPs")
        with open(json_file) as f:
            data = json.load(f)
        for ips in data["IP"]:
            for ip_name, ip_version in ips.items():
                install_ip(ip_name, ip_version, ip_root, ipm_root)
        change_dir_to_readonly(ipm_root)
    else:
        logger.print_err(f"Can't find {DEPENDENCIES_FILE_NAME} file in {ip_root}")
        exit(1)


def check_ipm_directory(ipm_root) -> bool:
    """checks the ipm_root directory, if it doesn't exist it creates it

    Args:
        ipm_root (str): path to common installation path

    Returns:
        bool: True if it exists, False if it doesn't
    """
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
            logger.print_err(
                f"Can't find directory {ipm_root}, please specify a correct IPM_ROOT to continue"
            )
            return False


def check_ip_root_dir(ip_root) -> bool:
    """checks the ip_root directory, if it doesn't exist it creates it

    Args:
        ip_root (str): path to the project ip dict

    Returns:
        bool: True if it exists, False if it doesn't
    """
    logger = Logger()
    if not os.path.isdir(ip_root):
        logger.print_info(f"ip-root {ip_root} can't be found, will create ip directory")
        os.mkdir(ip_root)
        return True
    else:
        return True


def list_verified_ips(category=None, technology=None):
    """creates a table of all verified remote ips

    Args:
        category (str, optional): filter the ips by category. Defaults to None.
        technology (str, optional): filter the ips by technology. Defaults to None.
    """
    verified_ips = IPInfo.get_verified_ip_info()
    ip_list = []
    for ip_name, ip_data in verified_ips.items():
        if category and not technology:
            if ip_data["category"] == category:
                ip_list.append({ip_name: ip_data})
        elif technology and not category:
            if ip_data["technology"] == technology or ip_data["technology"] == "n/a":
                ip_list.append({ip_name: ip_data})
        elif technology and category:
            if ip_data["category"] == category and (
                ip_data["technology"] == technology or ip_data["technology"] == "n/a"
            ):
                ip_list.append({ip_name: ip_data})
        else:
            ip_list.append({ip_name: ip_data})

    IP.create_table(ip_list)


def list_ip_info(ip_name):
    """gets all info about a specific ip (extended version)

    Args:
        ip_name (str): name of ip to get info
    """
    logger = Logger()
    ip_data = IPInfo.get_verified_ip_info(ip_name)
    ip_list = [{ip_name: ip_data}]
    logger.print_success(f"Description: {ip_data['description']}")
    IP.create_table(ip_list, "all", True)


def list_installed_ips(ipm_root):
    """creates a table of all locally installed ips

    Args:
        ipm_root (str): path to common installation path
    """
    ip_data = IPInfo.get_installed_ip_info(ipm_root)
    IP.create_table(ip_data, local=True, extended=True)


def check_ips(ipm_root, update=False, ip_root=None):
    """checks if the ips installed have newer versions

    Args:
        ipm_root (str): path to common installation path
        update (bool, optional): if True, will check and update. Defaults to False.
        ip_root (str, optional): path to the project ip dict. Defaults to None.
    """
    logger = Logger()
    installed_ips = IPInfo.get_installed_ips(ipm_root)
    for ips in installed_ips:
        for ip_name, ip_version in ips.items():
            verified_ip_info = IPInfo.get_verified_ip_info(ip_name)
            version = get_latest_version(verified_ip_info["release"])
            if version not in ip_version:
                if update:
                    install_ip(ip_name, version, ip_root, ipm_root)
                else:
                    logger.print_info(
                        f"IP {ip_name} has a newer version [magenta]{version}[/magenta], to update use command ipm update"
                    )
            else:
                logger.print_info(
                    f"IP {ip_name} is the newest version [magenta]{version}[/magenta]."
                )


def package_check(ipm_root, ip, version, gh_repo):
    """checks that the remote package of an ip is ready for submission to ipm

    Args:
        ipm_root (str): path to common installation path
        ip (str): ip name to check
        version (str): version of ip to check
        gh_repo (str): url to github repo
    """
    checker = Checks(ipm_root, ip, version, gh_repo)
    logger = Logger()

    logger.print_step("[STEP 1]: Checking the Github repo")
    if not checker.check_url(checker.gh_url):
        logger.print_err(f"Github repo {gh_repo} does not exist")
        exit(1)

    logger.print_step(f"[STEP 2]: Checking for the release with the tag {version}")
    if not checker.check_url(checker.release_tag_url):
        logger.print_err(
            f"There is no release tagged {version} in the Github repo {gh_repo}"
        )
        exit(1)

    logger.print_step(
        f"[STEP 3]: Checking Checking for the tarball named {version}.tar.gz"
    )
    if not checker.check_url(checker.release_tarball_url):
        logger.print_err(
            f"The tarball '{version}.tar.gz' was not found in the release tagged {version} in the GH repo {gh_repo}"
        )
        exit(1)

    checker.download_check_tarball()
    logger.print_step("[STEP 4]: Checking the JSON file content")
    if not checker.check_json():
        exit(1)

    logger.print_step("[STEP 5]: Checking the hierarchy of the directory")
    if not checker.check_hierarchy():
        exit(1)

    logger.print_success("IP pre-check was successful you can now submit your IP")
    shutil.rmtree(checker.package_check_path)
