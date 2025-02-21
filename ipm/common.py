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
import re
import sys
import json
import shutil
import tarfile
import tempfile
import hashlib
import pathlib
import requests
import subprocess
from dataclasses import dataclass
from typing import Callable, ClassVar, Dict, Iterable, Optional, Tuple

import ssl
import click
import httpx
import yaml
from rich.console import Console
from rich.table import Table
from bs4 import BeautifulSoup

from .__version__ import __version__
from .version_check import check_for_updates

# import bus_wrapper_gen

VERIFIED_JSON_FILE_URL = (
    "https://raw.githubusercontent.com/efabless/ipm/main/verified_IPs.json"
)
DEPENDENCIES_FILE_NAME = "dependencies.json"
IPM_DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".ipm")
PLATFORM_IP_URL = "https://platform.efabless.com/design_catalog/ip_block"


def opt_ipm_root(function: Callable):
    function = click.option(
        "--ipm-root",
        required=False,
        default=os.getenv("IPM_ROOT") or None,
        help="Path to the IPM root where the IPs will reside",
        show_default=True,
    )(function)
    return function


class GitHubSession(httpx.Client):
    class Token(object):
        override: ClassVar[Optional[str]] = None

        @classmethod
        def get_gh_token(Self) -> Optional[str]:
            token = None

            # 0. Lowest priority: ghcli
            try:
                token = subprocess.check_output(
                    [
                        "gh",
                        "auth",
                        "token",
                    ],
                    encoding="utf8",
                ).strip()
            except FileNotFoundError:
                pass
            except subprocess.CalledProcessError:
                pass

            # 1. Higher priority: environment GITHUB_TOKEN
            env_token = os.getenv("GITHUB_TOKEN")
            if env_token is not None and env_token.strip() != "":
                token = env_token

            # 2. Highest priority: the -t flag
            if Self.override is not None:
                token = Self.override

            return token

    def __init__(
        self,
        *,
        follow_redirects: bool = True,
        github_token: Optional[str] = None,
        ssl_context=None,
        **kwargs,
    ):
        if ssl_context is None:
            try:
                import truststore

                ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            except ImportError:
                pass

        try:
            super().__init__(
                follow_redirects=follow_redirects,
                verify=ssl_context,
                **kwargs,
            )
        except ValueError as e:
            if "Unknown scheme for proxy URL" in e.args[0] and "socks://" in e.args[0]:
                print(
                    f"Invalid SOCKS proxy: IPM only supports http://, https:// and socks5:// schemes: {e.args[0]}",
                    file=sys.stderr,
                )
                exit(-1)
            else:
                raise e from None
        github_token = github_token or GitHubSession.Token.get_gh_token()
        self.github_token = github_token

        raw_headers = {
            "User-Agent": type(self).get_user_agent(),
        }
        if github_token is not None:
            raw_headers["Authorization"] = f"Bearer {github_token}"
        self.headers = httpx.Headers(raw_headers)

    @classmethod
    def get_user_agent(Self) -> str:
        return f"ipm/{__version__}"

    def throw_status(self, r: httpx.Response, purpose: str):
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise RuntimeError(
                    f"Failed to {purpose}: Make sure that GITHUB_TOKEN is set and has the proper permissions (404)"
                )
            elif e.response.status_code == 401:
                raise RuntimeError(
                    f"Failed to {purpose} IP releases: GITHUB_TOKEN is invalid (401)"
                )
            else:
                raise RuntimeError(f"Failed to {purpose} ({e.response.status_code})")


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
    cache: ClassVar[Optional[dict]] = None

    @classmethod
    def get_verified_ip_info(Self, ip_name=None, include_drafts=False, local_file=None):
        """Get IP info from remote or local verified backend.

        Args:
            ip_name (str, optional): Name of the IP. Defaults to None.
            include_drafts (bool): Whether to include draft releases. Defaults to False.
            local_file (str, optional): Path to a local verified_IPs.json file. Defaults to None.

        Returns:
            dict: Info of the IP.
        """
        logger = Logger()
        data = Self.cache

        # Check for a local verified_IPs.json file
        if local_file and os.path.exists(local_file):
            logger.print_info(f"Using local verified_IPs.json at {local_file}")
            with open(local_file, "r") as f:
                data = json.load(f)
        else:
            session = GitHubSession()
            if data is None:
                resp = session.get(VERIFIED_JSON_FILE_URL)
                session.throw_status(resp, "download IP release index")
                data = resp.json()
                Self.cache = data

        if ip_name:
            if ip_name in data:
                ip_info = data[ip_name]
                releases = ip_info.get("release", {})

                # Filter for non-draft releases if include_drafts is False
                if not include_drafts:
                    releases = {
                        version: info
                        for version, info in releases.items()
                        if not info.get("draft", False)
                    }

                return {**ip_info, "release": releases}
            else:
                logger.print_err(f"IP {ip_name} not found in the release list.")
                exit(1)
        else:
            return data

    @staticmethod
    def get_installed_ips(ip_root):
        """gets all installed ips under ipm_root

        Args:
            ip_root (str): Path to the IPM root where the IPs are installed.

        Returns:
            list: List of installed IP names.
        """
        logger = Logger()
        dependencies_file = os.path.join(ip_root, "dependencies.json")
        
        if not os.path.exists(dependencies_file):
            logger.print_err(
                f"'dependencies.json' not found at {dependencies_file}. "
                "This could mean either no IPs are installed in your project or you are not in the project root."
            )
            return []  # Return an empty list if the file doesn't exist

        with open(dependencies_file, "r", encoding="utf8") as f:
            dependencies_data = json.load(f)

        # Extract the IP names
        ip_objects = dependencies_data.get("IP", [])
        ip_names = [list(ip.keys())[0] for ip in ip_objects]  # Get the key (name) from each dictionary

        return ip_names

    @staticmethod
    def get_installed_ip_info(ip_root):
        """gets the info of the installed ips from <ip>.json

        Args:
            ip_root (str): path to ip_root

        Returns:
            list: list of dicts of all installed ips and their data
        """
        logger = Logger()
        installed_ips = IPInfo.get_installed_ips(ip_root)
        installed_ips_arr = []
        for ip_name in installed_ips:
            # for ip_name in ips:
            json_file = f"{ip_root}/{ip_name}/{ip_name}.json"
            yaml_file = f"{ip_root}/{ip_name}/{ip_name}.yaml"
            config_path = None
            if os.path.exists(json_file):
                config_path = json_file
            elif os.path.exists(yaml_file):
                config_path = yaml_file
            else:
                logger.print_err(
                    f"Can't find {json_file} or {yaml_file}. Please refer to the IPM directory structure (IP name {ip_name} might be wrong)."
                )
                return False

            if config_path.endswith(".json"):
                with open(config_path) as config_file:
                    data = json.load(config_file)
            else:
                with open(config_path) as config_file:
                    data = yaml.safe_load(config_file)
            # with open(json_file) as f:
            #     data = json.load(f)
            installed_ips_arr.append({data["info"]["name"]: data})
        return installed_ips_arr


def indent(depth: int) -> str:
    return "  " * depth


@dataclass
class IPRoot:
    ipm_root: str
    path: str

    def __post_init__(self):
        pathlib.Path(self.path).mkdir(parents=True, exist_ok=True)
        gitignore_path = os.path.join(self.path, ".gitignore")
        with open(gitignore_path, "w") as gitignore_file:
            gitignore_file.write("*\n")
            gitignore_file.write("!dependencies.json\n")
            gitignore_file.write("!.gitignore\n")

    @property
    def dependencies_path(self) -> str:
        """
        Returns:
            str: the path to the ``dependencies.json`` for this ip root
        """
        return os.path.join(self.path, DEPENDENCIES_FILE_NAME)

    def get_dependencies_object(self) -> dict:
        """
        Creates a dependencies object for this root, which is:

        * The parsed contents of ``self.dependencies_path`` if it exists
        * Otherwise

        Returns:
            dict: The dependencies object
        """
        json_decoded = {"IP": []}

        if os.path.exists(self.dependencies_path):
            with open(self.dependencies_path) as json_file:
                json_decoded = json.load(json_file)
        return json_decoded

    def try_add(self, ip: "IP", include_drafts=False, local_file=None):
        """
        Attempts to add the IP ``ip`` to this IP root, by adding it to the
        dependencies object and calling :meth:`update_paths`\\.

        If any of these occur:
        * The IP or any of its dependencies cannot be downloaded for any reason
        * Adding this IP causes an unsatisfiable dependency set
        * Any OS permission error

        A ``RuntimeError`` is thrown and the changes are not committed to the
        ``dependencies.json`` file.

        Args:
            ip (IP): The :class:`IP` object to attempt to add.
        """
        logger = Logger()
        dependencies_object = self.get_dependencies_object()

        tmp_dict = {ip.ip_name: ip.version}
        flag = True
        if len(dependencies_object["IP"]) > 0:
            for ips in dependencies_object["IP"]:
                for name, version in ips.items():
                    if name == ip.ip_name:
                        if version == ip.version:
                            flag = False
                        else:
                            dependencies_object["IP"].remove({name: version})
            if flag:
                dependencies_object["IP"].append(tmp_dict)
        else:
            dependencies_object["IP"].append(tmp_dict)

        try:
            logger.print_info("* Updating IP root…")
            self.update_paths(dependencies_object, include_drafts, local_file)
        except Exception as e:
            logger.print_err("* An exception occurred, attempting to roll back…")
            try:
                self.update_paths()
            except Exception as e2:
                logger.print_err(f"* Failed to roll back: {e2}")
            raise e from None

        with open(self.dependencies_path, "w") as json_file:
            json.dump(dependencies_object, json_file)
        logger.print_success(f"* Added {ip.full_name} to {self.dependencies_path}.")

    def try_remove(self, ip: "IP", include_drafts=False, local_file=None):
        """
        Attempts to add the IP ``ip`` to this IP root, by adding it to the
        dependencies object and calling :meth:`update_paths`\\.

        If any of these occur:
        * ``self.dependencies_path`` does not exist
        * ``self.dependencies_path`` was modified externally and introduced
          an unsatisfiable dependency set
        * Any OS permission error

        A ``RuntimeError`` is thrown and the changes are not committed to the
        ``dependencies.json`` file.

        Args:
            ip (IP): The :class:`IP` object to attempt to remove.
        """
        logger = Logger()
        if not os.path.exists(self.dependencies_path):
            raise RuntimeError(f"Couldn't find {DEPENDENCIES_FILE_NAME} file")
        dependencies_object = self.get_dependencies_object()
        ip_category = dependencies_object["IP"]
        for ips in ip_category:
            for ips_name, ip_version in ips.items():
                if ips_name == ip.ip_name:
                    ip_category.remove({ips_name: ip_version})
            dependencies_object["IP"] = ip_category

        try:
            logger.print_info("* Updating IP root…")
            self.update_paths(dependencies_object, include_drafts, local_file)
        except Exception as e:
            logger.print_err("* An exception occurred, attempting to roll back…")
            try:
                self.update_paths()
            except Exception as e2:
                logger.print_err(f"* Failed to roll back: {e2}")
            raise e from None

        with open(self.dependencies_path, "w") as json_file:
            json.dump(dependencies_object, json_file)
        logger.print_success(f"* Removed {ip.full_name} from {self.dependencies_path}.")

    def get_installed_ips(self) -> Dict[str, "IP"]:
        """
        Returns:
            dict: The IPs installed in this root (as IP objects), indexed by their names
        """
        final = {}
        dependencies_object = self.get_dependencies_object()
        ip_category = dependencies_object["IP"]
        for ips in ip_category:
            for ip_name, ip_version in ips.items():
                final[ip_name] = IP.find_verified_ip(ip_name, ip_version, self.ipm_root, self.path)
        return final

    def update_paths(
        self,
        dependency_dict: Optional[dict] = None,
        include_drafts=False,
        local_file=None
    ):
        """
        Updates the paths of this IP root based on the dependency object, i.e.,
        make reality match the ``dependencies.json``\\.

        If called with a dictionary object, the update will be attempted with
        that dictionary instead. This is useful if you want to try the changes
        before writing them to ``dependencies.json`` (see :meth:`try_add` and
        :meth:`try_remove`\\).

        Args:
            dependency_dict (dict | None): An optional override for ``dependencies.json``
        """
        if dependency_dict is None:
            dependency_dict = self.get_dependencies_object()
        deps = self._resolve_dependencies(
            self.dependencies_path,
            dependency_dict,
            include_drafts=include_drafts,
            local_file=local_file
        )
        deps_by_name = {ip.ip_name: ip for ip in deps}
        for element, path in self._get_symlinked_ips():
            if element not in deps_by_name:
                os.remove(path)

    def _install_ip(self, ip: "IP", depth: int = 0):
        ip.install(depth)
        path_in_ip_root = os.path.join(self.path, ip.ip_name)
        if self.ipm_root:
            if os.path.exists(path_in_ip_root):
                os.unlink(path_in_ip_root)
            os.symlink(
                ip.path_in_ipm_root,
                path_in_ip_root,
            )

    def _get_symlinked_ips(self) -> Iterable[Tuple[str, str]]:
        for element in os.listdir(self.path):
            element_path = os.path.join(self.path, element)
            if not os.path.islink(element_path):
                continue
            if not os.path.isdir(element_path):
                continue
            if not os.path.realpath(element_path).startswith(self.ipm_root):
                continue
            yield (element, element_path)

    def _resolve_dependencies(
        self,
        requester: str,
        dependency_dict: dict,
        include_drafts=False,
        local_file=None
    ):
        logger = Logger()
        so_far: Dict[str, Tuple["IP", str]] = {}

        def _recursive(
            requester: str,
            dependency_dict: dict,
            depth=0,
        ):
            if len(dependency_dict["IP"]):
                logger.print_info(
                    f"{indent(depth)}* Resolving dependencies for [cyan]{requester}[/cyan]…"
                )
            for dep in dependency_dict["IP"]:
                for dep_name, dep_version in dep.items():
                    logger.print_info(
                        f"{indent(depth+1)}* Resolving [cyan]{dep_name}@{dep_version}[/cyan]…"
                    )
                    # Detect an unsatisfiable condition, i.e., two different IPs
                    # (including the IP Root itself) requesting two different
                    # versions of the same IP
                    tup = so_far.get(dep_name)
                    if tup is not None:
                        found, found_requester = tup
                        if found.version != dep_version:
                            raise RuntimeError(
                                f"Dependency {dep_name}@{dep_version} requested by {requester} conflicts with {found.ip_name}@{found.version} requested by {found_requester}"
                            )
                        else:
                            logger.print_info(f"{indent(depth+1)}* Already fetched.")
                    else:
                        dependency = IP.find_verified_ip(
                            dep_name, dep_version, self.ipm_root, self.path, include_drafts, local_file
                        )
                        self._install_ip(dependency, depth + 1)
                        so_far[dep_name] = (dependency, requester)
                        _recursive(
                            dependency.ip_name,
                            dependency._get_dependency_dict(),
                            depth + 1,
                        )

        _recursive(requester, dependency_dict)
        logger.print_success("* Dependencies resolved.")
        return [t[0] for _, t in so_far.items()]


def get_terminal_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80  # Default width if terminal size can't be determined


@dataclass
class IP:
    ip_name: str
    version: str
    repo: str
    ipm_root: Optional[str] = None
    sha256: Optional[str] = None
    ip_root: Optional[str] = None

    @classmethod
    def find_verified_ip(
        Self,
        ip_name: str,
        version: Optional[str],
        ipm_root: Optional[str],
        ip_root: Optional[str],
        include_drafts=False,
        local_file=None,
    ):
        """Finds an IP in the release index and returns it as an IP object.

        Args:
            ip_name (str): The name of the IP.
            version (str, optional): The version of the IP. Defaults to None.
            include_drafts (bool): Whether to include draft releases. Defaults to False.
            local_file (str, optional): Path to a local verified_IPs.json file. Defaults to None.

        Returns:
            IP: The IP object generated.
        """
        meta = IPInfo.get_verified_ip_info(ip_name, include_drafts, local_file=local_file)
        releases = meta["release"]

        if version is None:
            filtered_releases = {}
            if include_drafts:
                # Include all releases, regardless of the "draft" status
                for v, info in releases.items():
                    filtered_releases[v] = info
            else:
                # Include only non-draft releases
                for v, info in releases.items():
                    if not info.get("draft", False):  # Default to False if "draft" key is missing
                        filtered_releases[v] = info
            
            version = get_latest_version(filtered_releases)

        if version not in releases:
            raise RuntimeError(f"Version {version} of {ip_name} not found in IP index")

        release = releases[version]
        repo = meta["repo"]
        if repo.startswith("github.com/"):
            repo = repo[len("github.com/") :]

        return Self(ip_name, version, repo, ipm_root, release.get("sha256", None), ip_root)

    # ---
    @property
    def full_name(self) -> str:
        return f"{self.ip_name}@{self.version}"

    @property
    def path_in_ipm_root(self) -> Optional[str]:
        ipmr = self.ipm_root
        if ipmr is not None:
            return os.path.join(ipmr, self.ip_name, self.version)
        else:
            return os.path.join(self.ip_root, self.ip_name)

    def install(self, depth: int = 0):
        if self.path_in_ipm_root is None:
            raise RuntimeError("Cannot install without an IPM root")

        logger = Logger()
        if not os.path.isdir(self.path_in_ipm_root):
            logger.print_info(
                f"{indent(depth)}* Installing IP [cyan]{self.full_name}[/cyan] at {self.path_in_ipm_root}…"
            )
            self.download_tarball(self.path_in_ipm_root)
            # change_dir_to_readonly(self.ipm_root)

    @property
    def installed(self):
        return self.path_in_ipm_root is not None and os.path.exists(
            self.path_in_ipm_root
        )

    def uninstall(self):
        if self.path_in_ipm_root is None:
            raise ValueError("Cannot uninstall IP without IPM root")
        shutil.rmtree(self.path_in_ipm_root)

    def _get_dependency_dict(self) -> dict:
        if not self.path_in_ipm_root:
            raise ValueError("Cannot get dependencies for IP without an IPM root")
        if not self.installed:
            self.install()

        json_path = os.path.join(self.path_in_ipm_root, "ip", "dependencies.json")
        try:
            return json.load(open(json_path, encoding="utf8"))
        except FileNotFoundError:
            return {"IP": []}

    @staticmethod
    def create_table(ip_list, version=None, extended=False, local=False):
        """Creates table using rich tables

        Args:
            ip_list (list): list of ips
            version (str, optional): version of ip. Defaults to None.
            extended (bool, optional): extended table (has more info). Defaults to False.
            local (bool, optional): gets the info from local install. Defaults to False.
        """
        # Define columns with their priorities and fixed widths
        columns = [
            ("IP Name", "magenta", 50, 1),
            ("Category", "cyan", 1, 2),
            ("Type", None, 8, 3),
            ("maturity", None, 10, 4),
            ("Tags", None, 20, 5),
            ("Version", None, 10, 6),
            ("Owner", None, 15, 7),
            ("Technology", "cyan", 15, 8),
            ("License", "magenta", 10, 9),
            ("Width (um)", None, 10, 10),
            ("Height (um)", None, 10, 11),
            ("Voltage (v)", None, 10, 12),
            ("Clk freq (MHz)", None, 15, 13),
        ]

        terminal_width = get_terminal_width()
        total_width = 0
        included_columns = []

        # Sort columns by priority and select columns that fit within the terminal width
        columns = sorted(columns, key=lambda x: x[3])
        for col_name, col_style, col_width, _ in columns:
            if col_width and total_width + col_width <= terminal_width:
                total_width += col_width
                included_columns.append((col_name, col_style, col_width))

        table = Table()
        logger = Logger()
        console = Console()

        # Add selected columns to the table
        for col_name, col_style, _ in included_columns:
            table.add_column(col_name, style=col_style)

        for ips in ip_list:
            for key, value in ips.items():
                version_list = []
                if not local:
                    if not version:
                        version_list.append(get_latest_version(value["release"]))
                    else:
                        for versions, data in value["release"].items():
                            version_list.append(versions)
                else:
                    version_list.append(value["info"]["version"])
                for versions in version_list:
                    table_list = []
                    if not local:
                        data_dict = {
                            "IP Name": key,
                            "Category": value["category"],
                            "Type": value["release"][versions]["type"],
                            "maturity": value["release"][versions]["maturity"],
                            "Tags": ",".join(value["tags"]),
                            "Version": versions,
                            "Owner": value["owner"],
                            "Technology": value["technology"],
                            "License": value["license"],
                            "Width (um)": value["release"][versions]["width"],
                            "Height (um)": value["release"][versions]["height"],
                            "Voltage (v)": ",".join(
                                value["release"][versions]["supply_voltage"]
                            ),
                            "Clk freq (MHz)": value["release"][versions][
                                "clock_freq_mhz"
                            ],
                        }
                    if local:
                        data_dict = {
                            "IP Name": key,
                            "Category": value["info"]["category"],
                            "Type": value["info"]["type"],
                            "maturity": value["info"]["maturity"],
                            "Tags": ",".join(value["info"]["tags"]),
                            "Version": versions,
                            "Owner": value["info"]["owner"],
                            "Technology": value["info"]["technology"],
                            "License": value["info"]["license"],
                            "Width (um)": value["info"]["width"],
                            "Height (um)": value["info"]["height"],
                            # "Voltage (v)": ",".join(value["info"]["supply_voltage"]),
                            "Clk freq (MHz)": value["info"]["clock_freq_mhz"],
                        }

                    for col_name, _, _ in included_columns:
                        table_list.append(str(data_dict[col_name]))

                    table.add_row(*table_list)

        if len(ip_list) > 0:
            console.print(table)
            logger.print_info(f"Total number of IPs: {len(ip_list)}")
        else:
            logger.print_err("No IPs found")

    def download_tarball(self, dest_path, no_verify_hash=False):
        """downloads the release tarball

        Args:
            dest_path (str): path to destination of download
            no_verify_hash (bool): whether to verify the sha256 of the download or not
        """

        d = tempfile.TemporaryDirectory()
        tgz_path = os.path.join(d.name, "asset.tar.gz")
        try:
            session = GitHubSession()

            releases = []
            last_response = [{}]
            page = 1
            while len(last_response) != 0:
                params = {"per_page": 100, "page": page}
                release_url = f"https://api.github.com/repos/{self.repo}/releases"
                response = session.get(
                    release_url,
                    params=params,
                )
                session.throw_status(response, "download IP releases")
                last_response = response.json()
                releases += last_response
                page += 1

            asset_id = None
            for release in releases:
                if self.ip_name in release["tarball_url"].split("/")[-1]:
                    for assets in release["assets"]:
                        for asset_name, asset_value in assets.items():
                            if (
                                asset_name == "name"
                                and asset_value == f"{self.version}.tar.gz"
                            ):
                                asset_id = assets["id"]
            if asset_id is None:
                raise RuntimeError(
                    f"IP {self.ip_name}@{self.version} not found in the releases of repo {self.repo}"
                )

            release_url = (
                f"https://api.github.com/repos/{self.repo}/releases/assets/{asset_id}"
            )

            with session.stream(
                "GET",
                release_url,
                headers={
                    "Accept": "application/octet-stream",
                },
            ) as r, open(tgz_path, "wb") as tgz:
                session.throw_status(r, "download the release tarball")
                for chunk in r.iter_bytes(chunk_size=8192):
                    tgz.write(chunk)

            if not no_verify_hash:
                sha256 = hashlib.sha256(open(tgz_path, "rb").read()).hexdigest()
                if sha256 != self.sha256:
                    if self.sha256 is None:
                        raise RuntimeError(
                            f"Refusing to unpack tarball for {self.full_name}: Missing 'sha256' field in release\n"
                            + f"\tURL:       {release_url}\n"
                            + f"\tGot:       {sha256}\n"
                            + "\tPlease submit an issue to the IPM repository."
                        )
                    else:
                        raise RuntimeError(
                            f"Hash mismatch for {self.full_name}'s download:\n"
                            + f"\tURL:       {release_url}\n"
                            + f"\tExpecting: {self.sha256}\n"
                            + f"\tGot:       {sha256}"
                        )

            with tarfile.open(tgz_path, mode="r:gz") as tf:
                r.raise_for_status()
                tf.extractall(dest_path)
        except Exception as e:
            d.cleanup()
            shutil.rmtree(os.path.dirname(dest_path), ignore_errors=True)
            raise e from None

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
    def __init__(
        self,
        ip_root,
        ip_name,
        version=None,
        category=None,
        maturity=None,
        technology=None,
        type=None,
    ) -> None:
        self.version = version
        self.ip_name = ip_name
        self.category = category
        self.maturity = maturity
        self.technology = technology
        self.type = type
        self.ip_root = ip_root

    def check_url(self, url):
        """checks if url can be accessed

        Args:
            url (str): url to be accessed

        Returns:
            bool: True if can be accessed, False if failed to access
        """

        logger = Logger()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            repo_response = GitHubSession().get(url)
            return (repo_response.status_code // 100) == 2
        except Exception as e:
            logger.print_err(f"Failed to access URL: {url}. Error: {str(e)}")
            return False

    def check_yaml(self):
        """checks the json if it has all the variables needed

        Returns:
            bool: True if all json fields exist, False if they don't
        """
        logger = Logger()
        yaml_path = f"{self.ip_root}/{self.ip_name}.yaml"
        if not os.path.exists(yaml_path):
            logger.print_err(
                f"Can't find {yaml_path} please refer to the ipm directory structure (IP name {self.ip_name} might be wrong)"
            )
            return False
        yaml_fields = [
            "name",
            "description",
            "repo",
            "owner",
            "license",
            "author",
            "email",
            "version",
            "date",
            "category",
            "tags",
            "bus",
            "type",
            "maturity",
            "width",
            "height",
            "technology",
            "digital_supply_voltage",
            "analog_supply_voltage",
            "clock_freq_mhz",
            "cell_count",
        ]
        flag = True
        with open(yaml_path) as json_file:
            data = yaml.safe_load(json_file)
            info = data.get("info", {})

        if self.ip_name != info["name"]:
            logger.print_err(
                f"The given IP name {self.ip_name} is not the same as the one in yaml file"
            )
            flag = False

        if not self.check_url(info["repo"]):
            logger.print_err(f"The repo {info['repo']} is incorrect")
            flag = False

        for field in yaml_fields:
            if field not in info:
                logger.print_err(
                    f"The field '{field}' was not included in the {self.ip_name}.yaml file"
                )
                flag = False

        if flag:
            self.gh_url = info["repo"]
            self.version = info["version"]
            self.maturity = info["maturity"]
            self.category = info["category"]
            self.technology = info["technology"]
            self.type = info["type"]

        return flag

    def check_hierarchy(self):
        """checks the hierarchy of the ip, depending on the ip type

        Returns:
            bool: True if hierarchy is correct, False if it is not
        """
        logger = Logger()
        common_dirs = ["verify/beh_model", "fw", "hdl/rtl/bus_wrapper"]
        # check the folder hierarchy
        if self.type == "hard":
            ipm_dirs = [
                "hdl/gl",
                "timing/lib",
                "timing/sdf",
                "timing/spef",
                "layout/gds",
                "layout/lef",
            ]
        elif self.type == "soft" and self.category == "digital":
            ipm_dirs = ["verify/utb"]
        if self.category == "analog":
            ipm_dirs = ["spice"]
        ipm_dirs = ipm_dirs + common_dirs
        ipm_files = [f"{self.ip_name}.yaml", "README.md", "doc/datasheet.pdf"]
        flag = True
        for dirs in ipm_dirs:
            if not os.path.exists(os.path.join(self.ip_root, dirs)):
                logger.print_err(
                    f"The directory {dirs} cannot be found under {self.ip_root} please refer to the ipm directory structure"
                )
                flag = False

        for files in ipm_files:
            if not os.path.exists(os.path.join(self.ip_root, files)):
                logger.print_err(
                    f"The file {files} cannot be found under {self.ip_root} please refer to the ipm directory structure"
                )
                flag = False
        return flag

    def read_readme(self, file_path):
        """Reads the content of a README file."""
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()

    def has_minimum_word_count(self, content, min_words=100):
        """Checks if the content has at least min_words words."""
        words = content.split()
        return len(words) >= min_words

    def check_required_sections(self, content, sections):
        """Checks if the content includes specific sections and returns any missing ones."""
        missing_sections = []
        for section in sections:
            if not re.search(
                rf"^\s*#*\s*{re.escape(section)}", content, re.MULTILINE | re.IGNORECASE
            ):
                missing_sections.append(section)
        return missing_sections

    def analyze_readme(self):
        """Analyzes the README file for significant documentation."""
        file_path = os.path.join(self.ip_root, "README.md")
        content = self.read_readme(file_path)
        logger = Logger()
        # Check if README has significant content
        if not self.has_minimum_word_count(content):
            logger.print_err(
                f"The README file does not meet the minimum word count requirement."
            )
            return False

        # Define required sections
        required_sections = [
            "Overview",
            "Installation",
            "Features",
            "Block Diagram",
            "Pin Description",
            "Specifications",
            "Timing Diagram",
            "Tapeout History",
        ]

        # Check for missing sections
        missing_sections = self.check_required_sections(content, required_sections)
        if missing_sections:
            logger.print_err(
                f"The README file is missing the following sections: {', '.join(missing_sections)}"
            )
            return False

        return True


def change_dir_to_readonly(dir):
    """Recursively checks a directory and its subdirectories for files that should be readonly, and then changes any non-readonly files to readonly.

    Args:
        directory_name: The name of the directory to check.
    """
    for file_name in os.listdir(dir):
        if "ipm_package.json" not in file_name:
            file_path = os.path.join(dir, file_name)
            if os.path.isfile(file_path):
                if os.access(file_path, os.W_OK):
                    os.chmod(file_path, 0o400)
            else:
                change_dir_to_readonly(file_path)


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


def install_ip(ip_name, version, ip_root, ipm_root, include_drafts, local_file):
    """installs the ip tarball

    Args:
        ip_name (str): name of the ip to get installed
        version (str): version of the ip
        ip_root (str): path to the project ip dict
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    check_for_updates(logger)

    root = IPRoot(ipm_root, ip_root)

    try:
        ip = IP.find_verified_ip(ip_name, version, ipm_root, ip_root, include_drafts, local_file)
        root.try_add(ip)
    except RuntimeError as e:
        logger.print_err(e)
        exit(-1)


def uninstall_ip(ip_name, version, ipm_root, ip_root):
    """uninstalls the ip tarball from an ipm root

    Args:
        ip_name (str): name of the ip to get installed
        version (str): version of the ip
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    check_for_updates(logger)

    try:
        ip = IP.find_verified_ip(ip_name, version, ipm_root, ip_root)
        if not ip.installed:
            logger.print_info("Nothing to uninstall.")
        else:
            ip.uninstall()

            logger.print_success(f"Successfully uninstalled {ip_name}")
    except RuntimeError as e:
        logger.print_err(e)
        exit(-1)


def rm_ip_from_project(ip_name, ip_root, ipm_root):
    """removes the symbolic link of the ip from project and removes it from dependencies file

    Args:
        ip_name (str): name of the ip to get installed
        ip_root (str): path to the project ip dict
    """
    logger = Logger()
    check_for_updates(logger)
    root = IPRoot(ipm_root, ip_root)
    try:
        installed = root.get_installed_ips()
        if ip_name not in installed:
            raise RuntimeError(f"{ip_name} not found in {root.dependencies_path}")
        root.try_remove(installed[ip_name])
    except RuntimeError as e:
        logger.print_err(e)
        exit(-1)


def install_using_dep_file(ip_root, ipm_root, include_drafts=False, local_file=None):
    """install the ip from the dependencies file, assuming the dependencies file is under ip_root

    Args:
        ip_root (str): path to the project ip dir
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    check_for_updates(logger)
    root = IPRoot(ipm_root, ip_root)

    try:
        if os.path.exists(root.dependencies_path):
            root.update_paths(include_drafts=include_drafts, local_file=local_file)
        else:
            raise RuntimeError(f"{root.dependencies_path} not found.")
    except RuntimeError as e:
        logger.print_err(e)
        exit(1)


def check_ipm_directory(ipm_root) -> bool:
    """checks the ipm_root directory, if it doesn't exist it creates it

    Args:
        ipm_root (str): path to common installation path

    Returns:
        bool: True if it exists, False if it doesn't
    """
    logger = Logger()
    check_for_updates(logger)
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
    check_for_updates(logger)
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
    response = requests.get(PLATFORM_IP_URL)
    logger = Logger()
    check_for_updates(logger)
    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the webpage
        soup = BeautifulSoup(response.content, "html.parser")
        platform_ips = []
        links = soup.find_all("a")
        for link in links:
            href = link.get("href")
            if "/design_catalog/ip_block/" in href:
                text = link.text
                if "View Details" not in text and "\n\n" not in text:
                    platform_ips.append(text.upper())

    for ip_name, ip_data in verified_ips.items():
        if ip_name.upper() in platform_ips:
            if category and not technology:
                if ip_data["category"] == category:
                    ip_list.append({ip_name: ip_data})
            elif technology and not category:
                if (
                    ip_data["technology"] == technology
                    or ip_data["technology"] == "n/a"
                ):
                    ip_list.append({ip_name: ip_data})
            elif technology and category:
                if ip_data["category"] == category and (
                    ip_data["technology"] == technology
                    or ip_data["technology"] == "n/a"
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
    check_for_updates(logger)
    ip_data = IPInfo.get_verified_ip_info(ip_name)
    ip_list = [{ip_name: ip_data}]
    logger.print_success(f"Description: {ip_data['description']}")
    IP.create_table(ip_list, "all", True)


def list_installed_ips(ip_root):
    """creates a table of all locally installed ips

    Args:
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    check_for_updates(logger)
    ip_data = IPInfo.get_installed_ip_info(ip_root)
    IP.create_table(ip_data, local=True, extended=True)


def update_ips(ipm_root, ip_root=None, ip_to_update=None, include_drafts=False, local_file=None):
    """checks if the ips installed have newer versions

    Args:
        ipm_root (str): path to common installation path
        update (bool, optional): if True, will check and update. Defaults to False.
        ip_root (str, optional): path to the project ip dict. Defaults to None.
        update_ip (str, optional): Name of the IP to be updated. Defaults to None.
    """
    logger = Logger()
    check_for_updates(logger)
    root = IPRoot(ipm_root, ip_root)
    installed_ips = root.get_dependencies_object()

    if ip_to_update:
        ip_found = False
        for ips in installed_ips["IP"]:
            if ip_to_update in ips:
                ip_found = True
                break
        if not ip_found:
            logger.print_err(f"The IP '{ip_to_update}' is not installed.")
            return

    if len(installed_ips["IP"]) > 0:
        for ips in installed_ips["IP"]:
            for ip_name, ip_version in ips.items():
                if ip_to_update and ip_name != ip_to_update:
                    continue  # Skip IPs that do not match the update_ip argument
                verified_ip_info = IPInfo.get_verified_ip_info(ip_name, include_drafts, local_file)
                version = get_latest_version(verified_ip_info["release"])
                if version not in ip_version:
                    logger.print_info(
                        f"Updating IP {ip_name} to [magenta]{version}[/magenta]…"
                    )
                    ip = IP.find_verified_ip(ip_name, version, ipm_root, ip_root, include_drafts, local_file)
                    root.try_add(ip)
                else:
                    logger.print_info(
                        f"IP {ip_name} is the newest version [magenta]{version}[/magenta]."
                    )
    else:
        logger.print_warn("No IPs in your project to be updated.")


def check_ip(ip_root, ip_name=None):
    logger = Logger()

    # Step 1: check Yaml file
    if not ip_name:
        yaml_info_file = os.path.join(ip_root, f"{os.path.basename(ip_root)}.yaml")
    else:
        yaml_info_file = os.path.join(ip_root, f"{ip_name}.yaml")
    logger.print_step("[STEP 1]: Check if Yaml file exists")
    if os.path.exists(yaml_info_file):
        logger.print_success(f"Yaml file exists at {yaml_info_file}")
    else:
        logger.print_err(f"Can't find Yaml file at {yaml_info_file}")
        exit(1)

    # Step 2: Check content of Yaml file
    logger.print_step("[STEP 2]: Check content of Yaml file")
    checker = Checks(ip_root, ip_name)
    if checker.check_yaml():
        logger.print_success("Yaml content check passed")
    else:
        logger.print_err("Yaml content check failed")
        exit(1)

    # Step 3: Check Hierarchy
    logger.print_step("[STEP 3]: Check IP hierarchy")
    if checker.check_hierarchy():
        logger.print_success("Hierarchy check passed")
    else:
        logger.print_err("Hierarchy check failed")
        exit(1)

    # Step 3: Check README
    logger.print_step("[STEP 4]: check README documentation")
    if checker.analyze_readme():
        logger.print_success("The README file contains significant documentation.")
    else:
        logger.print_err("The README is missing documentation")
        exit(1)
