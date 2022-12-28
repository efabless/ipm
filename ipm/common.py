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
import json
import pathlib
import requests
import shutil
import tarfile
from datetime import datetime
import http.client
from functools import partial
from typing import Optional, Callable, List, Dict

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

IPM_REPO_OWNER = os.getenv("IPM_REPO_OWNER") or "marwaneltoukhy"
IPM_REPO_NAME = os.getenv("IPM_REPO_NAME") or "ipm"
IPM_REPO_ID = f"{IPM_REPO_OWNER}/{IPM_REPO_NAME}"
IPM_REPO_HTTPS = f"https://github.com/{IPM_REPO_ID}"
IPM_REPO_API = f"https://api.github.com/repos/{IPM_REPO_ID}"
IPM_DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".ipm")

LOCAL_JSON_FILE_NAME = "Installed_IPs.json"
REMOTE_JSON_FILE_NAME = "https://raw.githubusercontent.com/marwaneltoukhy/ipm/main/Verified_IPs.json"

def opt_ipm_iproot(function: Callable):
    function = click.option(
        "--ipm-iproot",
        required=False,
        default=os.getenv("IPM_IPROOT") or IPM_DEFAULT_HOME,
        help="Path to the IPM root where the IPs will reside",
        show_default=True,
    )(function)
    return function

def create_local_JSON(file_path):
    dictionary = {
    "analog": [],
    "comm": [],
    "dataconv": [],    
    "digital" : []
    }
    with open(file_path, "w") as outfile:
        json.dump(dictionary, outfile)

def check_ipm_directory(console: rich.console.Console, ipm_iproot) -> bool:
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    JSON_FILE_PATH = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)

    if ipm_iproot == IPM_DEFAULT_HOME:
        if not os.path.exists(ipm_iproot):
            os.mkdir(ipm_iproot)
            os.mkdir(IPM_DIR_PATH)
            create_local_JSON(JSON_FILE_PATH)
        else: # .ipm folder exists
            if not os.path.exists(IPM_DIR_PATH): 
                os.mkdir(IPM_DIR_PATH)
                create_local_JSON(JSON_FILE_PATH)
            else: # .ipm/ipm folder exists 
                if not os.path.exists(JSON_FILE_PATH):
                    create_local_JSON(JSON_FILE_PATH)
    else:
        if not os.path.exists(ipm_iproot):
            console.print(f"[red]The IPM_IPROOT does not exist, please specify a correct IPM_IPROOT to continue")
            return False
        else:
            if not os.path.exists(IPM_DIR_PATH):
                os.mkdir(IPM_DIR_PATH)
                create_local_JSON(JSON_FILE_PATH)
            else: #<ipm_iproot>/ipm folder exists
                if not os.path.exists(JSON_FILE_PATH):
                    create_local_JSON(JSON_FILE_PATH)
    return True

def list_IPs(console:rich.console.Console, ipm_iproot, remote, category="all"):
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')

    JSON_FILE = ""
    if remote:
        resp = requests.get(REMOTE_JSON_FILE_NAME)
        data = json.loads(resp.text)
    else:
        JSON_FILE = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)
        with open(JSON_FILE) as json_file:
            data = json.load(json_file)
    

    table = Table()

    table.add_column("Category", style="cyan")
    table.add_column("IP Name", style="magenta")
    table.add_column("Version")
    table.add_column("Author")
    table.add_column("Date")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Width (mm)")
    table.add_column("Height (mm)")

    total_IPs = 0
    if category == "all":
        for key, values in data.items():
            for value in values:
                table.add_row(key, value['name'], value['version'], value['author'], value['date'], value['type'], value['status'], value['width'], value['height'])
            total_IPs = total_IPs + len(values)
        if total_IPs > 0:
            console.print(table)
            console.print(f'Total {total_IPs} IP(s)')
        else:
            console.print('[red]No IPs Found')
    else: 
        for value in data[category]:
            table.add_row(key, value['name'], value['version'], value['author'], value['date'], value['type'],  value['status'], value['width'], value['height'])
        total_IPs = total_IPs + len(data[category])
        if total_IPs > 0:
            console.print(table)
            console.print(f'Total {total_IPs} IP(s)')
        else:
            console.print('[red]No IPs Found')

# Gets a list of all available IP "names"
def get_IP_list(ipm_iproot, remote):
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    JSON_FILE = ""
    IP_list = [] 
    if remote:
        resp = requests.get(REMOTE_JSON_FILE_NAME)
        data = json.loads(resp.text)
    else:
        JSON_FILE = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)
        with open(JSON_FILE) as json_file:
            data = json.load(json_file)
    for key, values in data.items():
        for value in values:
            IP_list.append(value['name'])
    return IP_list

def get_ip_info(ip, ipm_iproot, remote):
    ip_info = {}
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    JSON_FILE = ""

    if remote:
        resp = requests.get(REMOTE_JSON_FILE_NAME)
        data = json.loads(resp.text)
    else:
        JSON_FILE = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)
        with open(JSON_FILE) as json_file:
            data = json.load(json_file)
    for key, values in data.items():
        for value in values:
            if value['name'] == ip:
                ip_info['name'] = ip
                ip_info['repo'] = value['repo']
                ip_info['version'] = value['version']
                ip_info['author'] = value['author']
                ip_info['email'] = value['email']
                ip_info['category'] = key
                ip_info['date'] = value['date']
                ip_info['type'] = value['type']
                ip_info['status'] = value['status']
                ip_info['width'] = value['width']
                ip_info['height'] = value['height']
    release_url = f"https://{ip_info['repo']}/archive/refs/tags/{ip_info['version']}.tar.gz"  
    ip_info['release_url'] = release_url
    return ip_info

def add_IP_to_JSON(ipm_iproot, ip, ip_info):
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    JSON_FILE = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)
    with open(JSON_FILE) as json_file:
        json_decoded = json.load(json_file)

    json_decoded[ip_info['category']].append(ip_info)

    with open(JSON_FILE, 'w') as json_file:
        json.dump(json_decoded, json_file)

def remove_IP_from_JSON(ipm_iproot, ip, ip_info):
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    JSON_FILE = os.path.join(IPM_DIR_PATH, LOCAL_JSON_FILE_NAME)
    with open(JSON_FILE) as json_file:
        json_decoded = json.load(json_file)

    json_decoded[ip_info['category']].remove(ip_info)

    with open(JSON_FILE, 'w') as json_file:
        json.dump(json_decoded, json_file)


def install_IP(console: rich.console.Console, ipm_iproot, ip, overwrite):
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    ip_path=os.path.join(IPM_DIR_PATH, ip)
    if os.path.exists(ip_path):
        if len(os.listdir(ip_path)) != 0:
            if not overwrite:
                console.print(f"There already exists a non-empty folder for the IP [green]{ip}", f"at {IPM_DIR_PATH}, to overwrite it add the option --overwrite")
                return
            else:
                console.print(f"Removing exisiting IP {ip} at {IPM_DIR_PATH}")
                ip_info = get_ip_info(ip, ipm_iproot, remote=False)
                remove_IP_from_JSON(ipm_iproot, ip, ip_info)
                shutil.rmtree(ip_path)
        else:
            shutil.rmtree(ip_path)
        
    ip_info = get_ip_info(ip, ipm_iproot, remote=True)
    response = requests.get(ip_info['release_url'], stream=True)
    if response.status_code == 404:
        print(f"The IP {ip} version {ip_info['version']} could not be found remotely")
    elif response.status_code == 200:
        os.mkdir(ip_path)
        tarball_path = os.path.join(ip_path, f"{ip}.tar.gz")
        with open(tarball_path, 'wb') as f:
            f.write(response.raw.read())
        file = tarfile.open(tarball_path)
        file.extractall(ip_path)
        file.close
        os.remove(tarball_path)
        console.print(f"[green]Successfully installed {ip} version {ip_info['version']} to the directory {ip_path}")
        add_IP_to_JSON(ipm_iproot, ip, ip_info)

def uninstall_IP(console: rich.console.Console, ipm_iproot, ip):
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    ip_path=os.path.join(IPM_DIR_PATH, ip)
    ip_info = get_ip_info(ip, ipm_iproot, remote=False)
    if os.path.exists(ip_path):
        remove_IP_from_JSON(ipm_iproot, ip, ip_info)
        shutil.rmtree(ip_path, ignore_errors=False, onerror=None)
        console.print(f'[green]Successfully uninstalled {ip} version {ip_info["version"]}')
    else:
        console.print(f'The IP {ip} was not found at the directory {IPM_DIR_PATH}, you may have removed it manually or renamed the folder')

def check_IP(console, ipm_iproot, ip, update=False):
    update_counter = 0
    if ip == "all": # Checks or updates all installed IPs
        IP_list = get_IP_list(ipm_iproot, remote=False)
        if len(IP_list) == 0: # No installed IPs
            if update:
                console.print("[red]No installed IPs to update")
            else:
                console.print("[red]No installed IPs to check")
        else: # There are installed IPs
            console.print("Checking all Installed IP(s) for updates")
            for ip in IP_list: # Loops on all available IPs
                ip_info_local = get_ip_info(ip, ipm_iproot, remote=False)
                ip_info_remote = get_ip_info(ip, ipm_iproot, remote=True)
                if ip_info_local['version'] == ip_info_remote['version']: # IP is up to date
                    console.print(f"[white]The IP [magenta]{ip}" f"[white] is up to date; version {ip_info_local['version']}") 
                else:
                    if update: # If update flag is True it uninstalls the old version and installs the new one
                        console.print(f"Updating {ip}[white]...")
                        uninstall_IP(console, ipm_iproot, ip)
                        install_IP(console, ipm_iproot, ip)
                        update_counter = update_counter + 1
                    else: # If it only needs a check it prints out a message to the user that there is a newer version
                        console.print(f"[yellow]The IP [magenta]{ip}" f"[yellow] has a newer version {ip_info_remote['version']} to update the IP run [white]'ipm update --ip {ip}'")
                        update_counter = update_counter + 1
            if update_counter > 0: # There were one or more out dated IP
                if update: 
                   console.print(f"[green]Number of updated IP(s): {update_counter}")
                else:
                    console.print(f"[red]There are newer versions for {update_counter} IP(s), to update them all run [white]'ipm update --all' ")
            else:
                console.print(f"[green]All the installed IP(s) are up to date")

    else: # Checks or Updates a single IP
        ip_info_local = get_ip_info(ip, ipm_iproot, remote=False)
        ip_info_remote = get_ip_info(ip, ipm_iproot, remote=True)
        if ip_info_local['version'] == ip_info_remote['version']:
            console.print(f"[white]The IP [magenta]{ip}" f"[white] is up to date; version {ip_info_local['version']}") 
        else:
            if update:
                console.print(f"Updating {ip}[white]...")
                uninstall_IP(console, ipm_iproot, ip)
                install_IP(console, ipm_iproot, ip)
            else:
                console.print(f"[yellow]The IP [magenta]{ip}" f"[yellow] has a newer version {ip_info_remote['version']} to update the IP run [white]'ipm update --ip {ip}'")

def check_hierarchy(console, ip_path, ip):
    # check the folder hierarchy
    ipm_dirs = ['sdf', 'verify', 'spice', 'gds', 'lef', 'lib', 'doc', 'hdl', 'spef']
    hdl_path = os.path.join(ip_path, 'hdl')
    hdl_dirs = ['src', 'gl']
    ipm_files = [f'{ip}.json', 'readme.md']
    flag = True
    for root, dirs, files in os.walk(ip_path):
        if root == ip_path:
            for f in ipm_files:
                if f not in files:
                    console.print(f"[red]The file {f} cannot be found under {ip_path} please refer to the ipm directory structure") 
                    flag = False
            for d in ipm_dirs:
                if d not in dirs:
                    console.print(f"[red]The directory {d} cannot be found under {ip_path} please refer to the ipm directory structure") 
                    flag = False
        
        if root == hdl_path:
            for d in hdl_dirs:
                if d not in dirs:
                    console.print(f"[red]The directory {d} cannot be found under {hdl_path} please refer to the ipm directory structure") 
                    flag = False
    
    return flag

def check_JSON(console, JSON_path, ip):
    json_fields = ['name', 'repo', 'version', 'author', 'email', 'date', 'type', 'category', 'status', 'width', 'height']
    flag = True
    with open(JSON_path) as json_file:
        json_decoded = json.load(json_file)
    
    for field in json_fields:
        if field not in json_decoded.keys():
            console.print(f"[red]The field '{field}' was not included in the {ip}.json file")
            flag = False
    
    return flag

def precheck(console, ipm_iproot, ip, version, gh_repo):
    gh_repo_url = f"https://{gh_repo}"
    release_tag_url = f"{gh_repo_url}/releases/tag/{ip}-{version}"
    release_tarball_url = f"{gh_repo_url}/releases/download/{ip}-{version}/{ip}.tar.gz"
    IPM_DIR_PATH = os.path.join(ipm_iproot, 'ipm')
    precheck_path=os.path.join(IPM_DIR_PATH, f'{ip}_pre-check')
    ip_path=os.path.join(precheck_path, ip)

    console.print('[magenta][STEP 1]:', 'Checking the GH repo')
    repo_response = requests.get(gh_repo_url, stream=True)
    if repo_response.status_code == 404:
        console.print(f"[red]There GH repo {gh_repo} does not exist")
    elif repo_response.status_code == 200: # The repo exists, check for the release
        console.print('[magenta][STEP 2]:', f'Checking for the release with the tag {ip}-{version}')
        release_tag_response = requests.get(release_tag_url, stream=True)
        if release_tag_response.status_code == 404: 
            console.print(f"[red]There is no release tagged {ip}-{version} in the GH repo {gh_repo}")
        elif release_tag_response.status_code == 200: # Release exists, check for tarball 
            console.print('[magenta][STEP 3]:', f'Checking for the tarball named "{ip}.tar.gz"')
            release_tarball_response = requests.get(release_tarball_url, stream=True)
            if release_tarball_response.status_code == 404:
                console.print(f"[red]The tarball '{ip}.tar.gz' was not found in the release tagged {ip}-{version} in the GH repo {gh_repo}")  
            elif release_tarball_response.status_code == 200: # Tarball exists under the correct tag name, download it under IPM_Directory/<ip>_pre-check
                os.mkdir(precheck_path)
                tarball_path = os.path.join(precheck_path, f"{ip}.tar.gz")
                with open(tarball_path, 'wb') as f:
                    f.write(release_tarball_response.raw.read())
                file = tarfile.open(tarball_path)
                file.extractall(precheck_path)
                file.close
                os.remove(tarball_path)
                console.print('[magenta][STEP 4]:', f'Checking the hierarchy of the directory')
                valid_hierarchy = check_hierarchy(console, ip_path, ip) # Checks if folder's hierarchy is valid
                if valid_hierarchy:
                    console.print('[magenta][STEP 5]:', f'Checking the JSON file content')
                    JSON_path = os.path.join(ip_path, f'{ip}.json')
                    valid_JSON = check_JSON(console, JSON_path, ip)
                    if valid_JSON:
                        console.print('[green]IP pre-check was successful you can now submit your IP through....')






            

        
        


        
        
    