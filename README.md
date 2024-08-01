# IPM
IPM is an open-source ChipIgnite Program IPs Package Manager; it is meant to provide a mean for distributing high quality IPs. IPM is tied to the IPs that can be found in [Efabless Market Place](https://platform.efabless.com/design_catalog/ip_block).

## Installation

IPM is now on PyPi, you can install it using this command:

```bash
pip install ipmgr
```

To verify it is working run: 

```bash
ipm --version
``` 

# Usage

## List all available IPs
You can do that by visiting the [Efabless Market Place](https://platform.efabless.com/design_catalog/ip_block), Or using this command
```bash
ipm ls-remote
``` 

## Get more info about a specific IP from the CLI
```bash
ipm info <ip_name>
```

## Install IP
```bash
ipm install <IP_NAME> [OPTIONS]
``` 
**Options:**

  `--version`   Install IP with a specific version

  `--ip-root`   IP installation path [default: `{PWD}/ip`]

  `--ipm-root`  Path to the IPM root where the IPs will reside  [default: `~/.ipm`]

  `--help`          Show this message and exit

> [!NOTE]  
> IPM installs the IPs in a shared directory `ipm-root` which is by default set to `~/.ipm`, then it will create a symlink to `ip-root` which is by default set to `{PWD}/ip`.

> [!TIP]  
> IPM will create a `dependencies.json` file under `ip-root`, which will have all the IPs that you used in your project. Push this file to your repo in order to have a reproducible project.

## Install IPs from dependencies file
```bash
ipm install-dep [OPTIONS]
``` 
**Options:**

  `--ip-root`    IP path [default: `{PWD}/ip/dependencies.json`]

  `--ipm-root`  Path to the IPM root where the IPs will reside  [default: `~/.ipm`]

  `--help`           Show this message and exit
> [!NOTE]
> This will download the IPs in the `dependencies.json`, with the same versions that it used inside the file

## Uninstalling IPs
```bash
ipm uninstall <IP_NAME> [OPTIONS]
``` 
**Options:**

  `--version`     Uninstall IP with a specific version

  `-f, --force` Forces the uninstall

  `--ipm-root`   Path to the IPM root where the IPs will reside  [default: `~/.ipm`]

  `--help`            Show this message and exit
> [!TIP]
> It is advised to use this command rather than deleting the IP manually

## Remove IP from project
```bash
ipm rm <IP_NAME> [OPTIONS]
```
**Options:**

  `--ipm-root`  Path to the IPM root where the IPs are installed  [default: `~/.ipm`]

  `--ip-root`      IP path [default: `{PWD}/ip`]

  `--help`             Show this message and exit

## Update IP
```bash
ipm update [IP_NAME][OPTIONS]
``` 
**Options:**

  `--ipm-root`  Path to the IPM root where the IPs will reside  [default: `~/.ipm`]

  `--ip-root`    IP path [default: `{PWD}/ip`]

  `--help`           Show this message and exit

> [!NOTE]
> If an IP_NAME is provided it will only update this IP, if not it will update all installed IPs

## Adding your IP to IPM

> [!CAUTION]
> The next part is a WIP, and for now only Efabless can add IPs to IPM and the market place. If you are interested in adding your own IP please contact Efabess.

To add your own IP to our package manager, you should follow these steps:

### 1. Package your IP with the following folder structure:

All IPs must include:

    - readme.md
    - <ip>.json
    - doc/datasheet.pdf
    - hdl/rtl/bus_wrapper **optional**
    - fw
    - verify/beh_model

All digital and analog hard IPs must include:
    
    - hdl/gl
    - timing/lib
    - timing/sdf
    - timing/spef
    - layout/gds
    - layout/lef

All Analog IPs must include:

    - spice

All soft digital IPs must include:

    - hdl/rtl/design
    - verify
    - pnr **optional**
    - verify/utb

Directory structure should look like:

```
├── readme.md
├── <ip>.json
├── doc\
│   └── datasheet.pdf
├── layout\
│   ├── gds\
│   └── lef\
├── timing\
│   ├── lib\
│   ├── spef\
│   └── sdf\
├── spice\
├── hdl\ 
│   ├── rtl\
│   │   ├── bus_wrapper\
│   │   └── design\
│   └── gl\
├── fw\
├── verify\
│   ├── utb\
│   └── beh_model\
└── pnr\
```

**NOTE**

- `verify` directory should include basic unit tests to help the designers build their verification
- `bus_wrapper` directory contains RTL for IP wrappers to ease system bus connection
- `fw` directory contains device drivers (`.c` and `.h` files)

### 2. IP metadata file structure

Your ```<ip>.json``` file should look like:

```
{
    "info": {
        "name": "<ip name>",
        "description": "<ip_description>",
        "repo": "<src repo>",
        "owner": "<owner of IP>",
        "license": "<license of IP>",
        "author": "<author of IP>",
        "email": "<email of author/owner>",
        "version": "<IP version>",
        "date": "<mm-dd-yyyy>",
        "category": "<analog/digital/AMS>",
        "tags": [
            "<tags for ip>"
        ],
        "bus": [
            "<APB|AHBL|WB|generic>"
        ],
        "type": "<hard|soft|firm|hybrid",
        "maturity": "<Verified|FPGA Validated|SI Validated|Production Ready>",
        "cell_count": "<number of cells in ip>",
        "width": "<width of IP in um>",
        "height": "<height of IP in um>",
        "technology": "<sky130A|sky130B|gf180mcuC|gf180mcuD|n/a>",
        "clock_freq_mhz": "<clock frequency of IP>",
        "supply_voltage": [
            "<supply voltage of IP>"
        ]
    }
}
```

**All the above fields must be included in your file**

### 3. Create tarball
Compress your folder into a tarball (tar.gz) with the name ```<version>.tar.gz```, where `version` is the version of your release, you can do that by running:
```bash
cd <ip_directory>
tar czf <version>.tar.gz *
``` 
### 4. Create release 
create a new release in your GH repo with the tag ```<version>``` and add the tarball created there to the release's assets
### 5. IPM package_check
Once you are done you can run a package_check function locally by running ```ipm package-check``` which checks that you’ve completed the above steps successfully. Options for ```IP name```, ```version``` and the ```GH repo``` are required

**NOTE: THIS IS STILL A WIP**

### 6. Submit
If the pre-check was successful you can submit your IP through the form ......

IPM team will then perform set of sanity checks to ensure the quality of the submitted IP. This checker shall ensure:
- That the IP is LVS clean
- That the IP is DRC clean

## Additional Docs
- [Awesome Sky130 IPs](https://github.com/shalan/Awesome-Sky130-IPs)
- [Sky130 Open-source IP Catalog](https://github.com/efabless/skywater-pdk-central/blob/main/design-ip.md)
