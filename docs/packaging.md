# Packing IPs for disstribution
Each IP shall have its own public GH repo for development. The repo shall have a CI that creates a compressed tarball after the structure outlined [here](ip_package.md) and added to the releases.
- The tarball in the release should be named:
```default.tar.gz```

A cli will be developed to enable anyone to submit an IP for distribution.

- `ipm ip create new_ip.yaml`
- `ipm ip update new_ip.yaml`

Note: Internally the repo url is used as an IP ID.

`ipm` team will perform set of sanity checks to ensure the quality of the submmitted IP. This checker shall ensure:

- The correctness of the directory structure
- The existance of all file types as per the IP type.
- That the IP is LVS clean
- That the IP is DRC clean

## new_ip.json
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
    "maturity": "silicon",
    // width and height in mm
    "width": "0.25",
    "height": "0.2"
}

```

