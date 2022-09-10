# Packing IPs for disstribution
Each IP shall have its own public GH repo for development. The repo shall have a CI that creates a compressed tarball after the structure outlined [here](ip_package.md) and added to the releases.

A cli will be developed to enable anyone to submit an IP for distribution.
- `ipm ip create new_ip.yaml`
- `ipm ip update new_ip.yaml`

Internally the repo url is used as an IP ID.

## new_ip.yaml

```
ADC8_SAR:
  repo: github.com/shalan/spm
  author: shalan
  email: mshalan@aucegypt.edu
  ver: 0.9
  # m-d-y
  date: 10-19-2022
  # hard/soft
  type: hard
  # digital, analog, dataconv, comm, rf, ...
  category: dataconv
  # np (not proven), fpga (proven), silicon (proven), 
  status: silicon
  # width and height in mm
  width: 0.25
  height: 0.2
  
```

