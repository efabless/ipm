# Copyright 2024 Efabless Corporation
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
{
  lib,
  buildPythonPackage,
  click,
  click-default-group,
  beautifulsoup4,
  pyyaml,
  rich,
  httpx,
  pcpp,
  zstandard,
  truststore,
  nix-gitignore,
  poetry-core,
}:
let self = buildPythonPackage  {
  pname = "ipm";
  version = (builtins.fromTOML (builtins.readFile ./pyproject.toml)).tool.poetry.version;
  format = "pyproject";

  src = nix-gitignore.gitignoreSourcePure ./.gitignore ./.;

  nativeBuildInputs = [
    poetry-core
  ];

  doCheck = false;

  propagatedBuildInputs = [
    click
    click-default-group
    beautifulsoup4
    pyyaml
    rich
    httpx
    pcpp
    zstandard
    truststore
  ] ++ httpx.optional-dependencies.socks;
  
  meta = with lib; {
    mainProgram = "ipm";
    description = "Version manager and builder for open-source PDKs";
    homepage = "https://github.com/efabless/ipm";
    license = licenses.asl20;
    platforms = platforms.darwin ++ platforms.linux;
  };
}; in self
