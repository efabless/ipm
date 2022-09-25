# IP Package 
## Folder Structure
```
├── readme.md
├── ip.yaml
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
## ip.yaml
```
ADC8_SAR:
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
