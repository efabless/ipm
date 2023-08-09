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
import click
from click_default_group import DefaultGroup

from . import __version__
from .manage import (
    ls_remote_cmd,
    ls_cmd,
    install_cmd,
    uninstall_cmd,
    rm_cmd,
    check_cmd,
    update_cmd,
    package_check_cmd,
    info_cmd,
    install_deps_cmd,
)


@click.group(
    cls=DefaultGroup,
    default="output",
    default_if_no_args=True,
)
@click.version_option(__version__)
def cli():
    pass


cli.add_command(ls_remote_cmd)
cli.add_command(ls_cmd)
cli.add_command(install_cmd)
cli.add_command(uninstall_cmd)
cli.add_command(rm_cmd)
cli.add_command(check_cmd)
cli.add_command(update_cmd)
cli.add_command(package_check_cmd)
cli.add_command(info_cmd)
cli.add_command(install_deps_cmd)


if __name__ == "__main__":
    cli()
