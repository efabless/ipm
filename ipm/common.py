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
import requests
from rich.console import Console

GITHUB_TOKEN = os.environ['GITHUB_TOKEN']
VERIFIED_JSON_FILE_URL = (
    "https://raw.githubusercontent.com/efabless/ipm/main/Verified_IPs.json"
)
LOCAL_JSON_FILE_NAME = "Installed_IPs.json"


class Logger:
    def __init__(self) -> None:
        self.console = Console()

    def print_err(self, err_string):
        self.console.print(f"[red]{err_string}")
    
    def print_warn(self, warn_string):
        self.console.print(f"[orange]{warn_string}")

    def print_info(self, info_string):
        self.console.print(f"{info_string}")


class IPInfo:
    def __init__(self):
        pass

    def get_verified_ip(self, ip_name, technology="sky130"):
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
            return self.get_ip_from_data(data, ip_name, technology)
        else:
            return data
                
    def get_installed_ip(self, ip_name, ipm_root, technology="sky130"):
        logger = Logger()
        local_json_file = os.path.join(ipm_root, LOCAL_JSON_FILE_NAME)
        if not os.path.exists(local_json_file):
            logger.print_err(f"Can't find {local_json_file}")
        with open(local_json_file) as json_file:
            data = json.load(json_file)
        if ip_name:
            return self.get_ip_from_data(data, ip_name, technology)
        else:
            return data
        
    
    def get_ip_from_data(self, data, ip_name, technology):
        for key, values in data.items():
            for value in values:
                if value["name"] == ip_name and value["technology"] == technology:
                    return value

class IP:
    def __init__(self, ip_name=None, ip_root=None, ipm_root=None):
        self.ip_name = ip_name
        self.ip_root = ip_root
        self.ipm_root = ipm_root

    def init_ip(self):
