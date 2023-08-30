# ipm
IPM is an open-source IPs Package Manager; it is meant to provide a mean for distributing high quality open-source IPs.

## ACCESS TO PRIVATE REPOS
**This is temporary step until IPM is publicly announced and IPs are all public**

### Create Github Token
To create a Personal Github Token [Follow this link](https://github.com/settings/tokens), make sure to check the boxes `repo`, `workflow` and `write:packages`.

### Export Github Token
```bash
export GITHUB_TOKEN=<your_github_token>
```

### Give Github Access to ssh public key
Generate your public ssh key on your machine, then [Follow this link](https://github.com/settings/keys) to add it to your github account.

## Installation

1.	Clone the IPM GH repository 
```bash
git clone https://github.com/efabless/ipm.git
``` 
2.	Navigate to the cloned directory and install using pip
```bash
cd ipm
pip install .
``` 
3.	To verify it is working run: 
```bash
ipm --version
``` 

## Usage

### Listing all Verified IPs
```bash
ipm ls-remote
``` 
Lists all verified IPs supported by IPM, and verified by efabless, it shows the primary details about the IPs.

### Getting more info about an IP
```bash
ipm info <ip_name>
```
Gives more details about a specific IP.

### Listing Installed IPs
```bash
ipm ls
``` 
Lists all locally installed IPs on the machine.

### Installing an IP
```bash
ipm install <ip_name> [OPTIONS]
``` 
Installs the IP by default in `{PWD}/ip`, you can also specify the ip installation directory using `--ip-root`. The user must provide a valid `ip_name`, to check all available IPs run `ipm ls-remote`. 
To install a specific version of the IP you can specify it using `--version <version>`
While IPM is installing the IP, if the IP's bus is `generic` it will create bus wrappers for `AHBL`, `APB`, `WB` and will create firmware `fw`, using [bus wrapper generator tool](https://github.com/efabless/bus_wrapper_gen)

### Installing IPs from dependencies file
```bash
ipm install-dep <ip_name> [OPTIONS]
``` 
Installs IPs specified in a dependencies file, by default it looks in `{PWD}/ip/dependencies.json`. You can specify the dependencies file location using `--ip-root`

### Uninstalling an IP
```bash
ipm uninstall <ip_name>
``` 
Uninstalls a locally installed IP. The user must provide a valid installed ```ip_name```, to check all installed IPs run ```ipm ls```. It is advised to always use this function when you wish to remove an IP. If you deleted the folder manually or renamed it this function may face errors

### Remove IP from project
```bash
ipm rm <ip_name>
```
Removes the IP from the project, but doesn't uninstall it from the machine, to uninstall from machine use `ipm uninstall`, it is advised to `rm` from project before uninstalling.

### Checking for Updates
```bash
ipm check [OPTIONS]
``` 
Checks if there are newer versions available for the installed IPs. The function by default checks all the installed IPs for updates.

### Updating Installed IP
```bash
ipm update [OPTIONS]
``` 
Updates the IP if an update is available.

## Adding your IP to IPM
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
        "status": "<Verified|FPGA Validated|SI Validated|Production Ready>",
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
