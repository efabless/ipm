# ipm
IPM is an open-source IPs Package Manager; it is meant to provide a mean for distributing high quality open-source IPs.

## Installation

1.	Clone the IPM GH repository 
```bash
git clone https://github.com/shalan/ipm
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
ipm ls
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
Installs the IP in the IP root. The user must provide a valid ```ip_name```, to check all available IPs run ```ipm ls```. If there exists a non-empty folder of the IP in the IP root, the install function will not work and if the user wishes to overwrite the existing folder he should pass the option     -```--overwrite``` 

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

1.	Package your IP with the following folder structure:
```
├── readme.md
├── ip.json
├── doc\
├── gds\
├── lef\
├── lib\ 
├── sdf\
├── spef\
├── spice\
├── hdl\ 
│   ├── src\
│   └── gl\
└── verify\
```
2. Your ```<ip>.json``` file should look like:
```
{
    "name" : "ADC8_SAR",
    "repo": "github.com/shalan/spm",
    "author" : "shalan",
    "email": "mshalan@aucegypt.edu",
    "version" : "0.9",
    // m-d-y
    "date": "9-21-2022",
    // digital, analog, dataconv, comm, rf, ...
    "category": "dataconv",
    // hard/soft
    "type": "hard",
    // np (not proven), fpga (proven), silicon (proven), 
    "status": "silicon",
    // width and height in mm
    "width": "0.25",
    "height": "0.2"
}
```
NOTE: All the above fields must be included in your file

3. Compress your folder into a tarball (tar.gz) with the name ```default.tar.gz``` you can do that by running:
```bash
tar czf default.tar.gz <structured_IP_folder_name>
``` 
4. Create a new release in your GH repo with the tag ```<ip_name>-<version>``` and add the tarball created there to the release's assets
5. Once you are done you can run a precheck function locally by running ```ipm pre-check``` which checks that you’ve completed the above steps successfully. This function will require the ```IP name```, ```version``` and the ```GH repo``` as input from the user
6.	If the pre-check was successful you can submit your IP through the form ......

IPM team will then perform set of sanity checks to ensure the quality of the submitted IP. This checker shall ensure:
- That the IP is LVS clean
- That the IP is DRC clean

## Additional Docs
- [Awesome Sky130 IPs](https://github.com/shalan/Awesome-Sky130-IPs)
- [Sky130 Open-source IP Catalog](https://github.com/efabless/skywater-pdk-central/blob/main/design-ip.md)
