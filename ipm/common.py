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
import shutil
import tarfile
import tempfile
import hashlib
import pathlib
from dataclasses import dataclass
from typing import Callable, ClassVar, Dict, Iterable, Optional, Tuple

import click
import httpx
from rich.console import Console
from rich.table import Table

# import bus_wrapper_gen

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


class GitHubSession(httpx.Client):
    def __init__(self, follow_redirects=True, **kwargs) -> None:
        super().__init__(follow_redirects=follow_redirects, **kwargs)
        headers_raw = {
            "User-Agent": "Efabless IPM",
        }
        token = os.getenv("GITHUB_TOKEN", None)
        if token is not None:
            headers_raw["Authorization"] = f"Bearer {token}"
        self.headers = httpx.Headers(headers_raw)

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
    def get_verified_ip_info(Self, ip_name=None):
        """get ip info from remote verified backend

        Args:
            ip_name (str, optional): name of the ip. Defaults to None.

        Returns:
            dict: info of ip
        """
        logger = Logger()
        data = Self.cache
        session = GitHubSession()
        if data is None:
            resp = session.get(VERIFIED_JSON_FILE_URL)
            session.throw_status(resp, "download IP release index")

            data = resp.json()
            if os.getenv("IPM_DEBUG_USE_LOCAL_VERIFIED_IPS", "0") == "1":
                local = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "verified_IPs.json",
                )
                data = json.load(open(local, encoding="utf8"))
            Self.cache = data

        if ip_name:
            if ip_name in data:
                return data[ip_name]
            else:
                logger.print_err(f"IP {ip_name} not found in the release list.")
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


def indent(depth: int) -> str:
    return "  " * depth


@dataclass
class IPRoot:
    ipm_root: str
    path: str

    def __post_init__(self):
        pathlib.Path(self.path).mkdir(parents=True, exist_ok=True)

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

    def try_add(self, ip: "IP"):
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
            self.update_paths(dependencies_object)
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

    def try_remove(self, ip: "IP"):
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
            self.update_paths(dependencies_object)
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
                final[ip_name] = IP.find_verified_ip(ip_name, ip_version, self.ipm_root)
        return final

    def update_paths(
        self,
        dependency_dict: Optional[dict] = None,
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
        )
        deps_by_name = {ip.ip_name: ip for ip in deps}
        for element, path in self._get_symlinked_ips():
            if element not in deps_by_name:
                os.remove(path)

    def _install_ip(self, ip: "IP", depth: int = 0):
        ip.install(depth)
        path_in_ip_root = os.path.join(self.path, ip.ip_name)
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
                            dep_name, dep_version, self.ipm_root
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


@dataclass
class IP:
    ip_name: str
    version: str
    repo: str
    ipm_root: Optional[str] = None
    sha256: Optional[str] = None

    @classmethod
    def find_verified_ip(
        Self,
        ip_name: str,
        version: Optional[str],
        ipm_root: Optional[str],
    ):
        """
        Finds an IP in the release index and returns it as a :class:`IP` object.

        If an IP or version are not found, a ``RuntimeError`` is raised.

        Args:
            ip_name (str): The name/id of the IP
            version (str | None): The version of the IP. If omitted, the latest will be fetched.
            ipm_root (str | None): The IPM root to associate with this IP for installation and such.

        Returns:
            IP: The IP object generated
        """
        meta = IPInfo.get_verified_ip_info(ip_name)
        releases = meta["release"]
        if version is None:
            version = get_latest_version(releases)
        elif version not in releases:
            raise RuntimeError(f"Version {version} of {ip_name} not found in IP index")
        release = releases[version]
        if release["status"] != "verified":
            raise RuntimeError(
                f"{ip_name}@{version} is not verified and cannot be used."
            )
        repo: str = meta["repo"]
        if repo.startswith("github.com/"):
            repo = repo[len("github.com/") :]
        ip = Self(ip_name, version, repo, ipm_root, release.get("sha256", None))
        return ip

    # ---
    @property
    def full_name(self) -> str:
        return f"{self.ip_name}@{self.version}"

    @property
    def path_in_ipm_root(self) -> Optional[str]:
        ipmr = self.ipm_root
        if ipmr is not None:
            return os.path.join(ipmr, self.ip_name, self.version)

    def install(self, depth: int = 0):
        if self.path_in_ipm_root is None:
            raise RuntimeError("Cannot install without an IPM root")

        logger = Logger()
        if not os.path.isdir(self.path_in_ipm_root):
            logger.print_info(
                f"{indent(depth)}* Installing IP [cyan]{self.full_name}[/cyan] at {self.ipm_root}…"
            )
            self.download_tarball(self.path_in_ipm_root)
            change_dir_to_readonly(self.ipm_root)

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

        repo_response = GitHubSession().get(url)
        return (repo_response.status_code // 100) == 2

    def download_check_tarball(self):
        """downloads the tarball of package checker"""
        ip = IP(self.ip_name, ipm_root=self.ipm_root, version=self.version)
        ip.download_tarball(
            self.package_check_path,
            no_verify_hash=True,
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

    root = IPRoot(ipm_root, ip_root)

    try:
        ip = IP.find_verified_ip(ip_name, version, ipm_root)
        root.try_add(ip)
    except RuntimeError as e:
        logger.print_err(e)
        exit(-1)


def uninstall_ip(ip_name, version, ipm_root):
    """uninstalls the ip tarball from an ipm root

    Args:
        ip_name (str): name of the ip to get installed
        version (str): version of the ip
        ipm_root (str): path to common installation path
    """
    logger = Logger()

    try:
        ip = IP.find_verified_ip(ip_name, version, ipm_root)
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
    root = IPRoot(ipm_root, ip_root)
    try:
        installed = root.get_installed_ips()
        if ip_name not in installed:
            raise RuntimeError(f"{ip_name} not found in {root.dependencies_path}")
        root.try_remove(installed[ip_name])
    except RuntimeError as e:
        logger.print_err(e)
        exit(-1)


def install_using_dep_file(ip_root, ipm_root):
    """install the ip from the dependencies file, assuming the dependencies file is under ip_root

    Args:
        ip_root (str): path to the project ip dir
        ipm_root (str): path to common installation path
    """
    logger = Logger()
    root = IPRoot(ipm_root, ip_root)

    try:
        if os.path.exists(root.dependencies_path):
            root.update_paths()
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
                    logger.print_info(
                        f"Updating IP {ip_name} to [magenta]{version}[/magenta]…"
                    )
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
        gh_repo (str): url to github repo (MINUS the scheme)
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
