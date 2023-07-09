# ipm
IPM is an open-source IPs Package Manager; it is meant to provide a mean for distributing high quality open-source IPs.

## Installation

1.	Clone the IPM GH repository 
```bash
git clone https://github.com/efabless/ipm.git
``` 
2.	Navigate to the cloned directory and install using pip
```bash
cd <cloned_folder_name>
pip install .
``` 
3.	To verify it is working run: 
```bash
ipm --version
``` 

## Usage

### IPM_IPROOT
IPM requires an IP Root. This IP root is where all your IPs will be installed and it can be anywhere on your computer, but by default it's the folder ```~/.ipm``` in your home directory. If you have the variable ```IPM_IPROOT``` set, ipm will use that instead. You can also manually override both values by supplying the ```--ipm-iproot``` command line argument. To check where is your current root just run ```ipm``` in your terminal and it should display where the IPs will be installed 

### Listing all Verified IPs
```bash
ipm ls-remote
``` 
Shows all the verified IPs saved in a json file in the main GH repository of the project ```Verified_IPs.json```. The function lists all the IPs in a tabular format sorted by the IP category and gives you all the required information about the IP; name, version, category...etc.

### Listing Installed IPs
```bash
ipm ls
``` 
Lists all locally installed IPs at the ```IPM_IPROOT```. IPM creates a local json file named ```Installed_IPs.json``` this file is how the manager keeps track of all your installed IPs and their versions so you should not edit that file!

### Installing an IP
```bash
ipm install <ip_name> [OPTIONS] --overwrite
``` 
Installs the IP in the IP root. The user must provide a valid `ip_name`, to check all available IPs run `ipm ls`. If there exists a non-empty folder of the IP in the IP root, the install function will not work and if the user wishes to overwrite the existing folder he should pass the option `--overwrite`
To install a specific version of the IP you can specify it using `--version <version>`
**NOTE** you can see all versions of IP using `ipm info --ip <ip name>`

### Installing IPs from dependencies file
```bash
ipm install-dep <ip_name> [OPTIONS] --overwrite
``` 
There has to be a dependencies file that should be provided in the `--ip-root` path

### Uninstalling an IP
```bash
ipm uninstall <ip_name>
``` 
Uninstalls a locally installed IP. The user must provide a valid installed ```ip_name```, to check all installed IPs run ```ipm ls```. It is advised to always use this function when you wish to remove an IP, as this function updates the ```Installed_IPs.json``` file as well. If you deleted the folder manually or renamed it this function may face errors

### Checking for Updates
```bash
ipm check [OPTIONS] --ip
``` 
Checks if there are newer versions available for the installed IPs. The function by default checks all the installed IPs for updates and if you wish to check for a certain IP pass the option ```--ip``` followed by the IP name. Note this function does not update the IPs, you can update them using the following function

### Updating Installed IP
```bash
ipm update [OPTIONS] --ip --all
``` 
Updates the IP if an update is available, by uninstalling the old version and installing the new one. You can pass the option ```--all``` to update all out dated IPs at once. The ```update``` and ```check``` functions depend on comparing the version of the installed IP against the version of the IP in the verified IPs list 

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
    "name" : "spm",
    "repo": "github.com/shalan/spm",
    "author" : "shalan",
    "email": "mshalan@aucegypt.edu",
    "version" : "0.9",
    "date": "9-21-2022",
    "category": "digital",
    "tag": ["BUS"],
    "type": "hard",
    "status": "SI_validated",
    "width": "0.25",
    "height": "0.2",
    "technology": "sky130",
    "cell_count": 200,
    "clk_freq": 10,
    "license": "public"
}
```
**NOTE**

`date` should be in the form: `mm-dd-yyyy`

`category` can be `digital, analog, AMS`

`tag` for `digital` can be a combination of `processor, comm, memory, BUS, acceleration, ... `

`tag` for `analog` can be a combination of `clocking, power, dataconv, sensor, sigcond, rf, ... `

`tag` for `other` can be a combination of `peripheral, graphics, security, automotive, AI, ... `

*You can use any combination of tags*

`type` can be `hard/soft`

`status` can be `verified, FPGA_validated, SI_validated, production_ready`

`width` and `height` should be in `um`

`clk_freq` should be in `MHz`

`license` can be `pulic/private`

**All the above fields must be included in your file**

### 3. Create tarball
Compress your folder into a tarball (tar.gz) with the name ```<version>.tar.gz```, where `version` is the version of your release, you can do that by running:
```bash
tar czf <version>.tar.gz <structured_IP_folder_name>
``` 
### 4. Create release 
create a new release in your GH repo with the tag ```<version>``` and add the tarball created there to the release's assets
### 5. IPM package_check
Once you are done you can run a package_check function locally by running ```ipm package-check``` which checks that you’ve completed the above steps successfully. Options for ```IP name```, ```version``` and the ```GH repo``` are required
### 6. Submit
If the pre-check was successful you can submit your IP through the form ......

IPM team will then perform set of sanity checks to ensure the quality of the submitted IP. This checker shall ensure:
- That the IP is LVS clean
- That the IP is DRC clean

## Additional Docs
- [Awesome Sky130 IPs](https://github.com/shalan/Awesome-Sky130-IPs)
- [Sky130 Open-source IP Catalog](https://github.com/efabless/skywater-pdk-central/blob/main/design-ip.md)
