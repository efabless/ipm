# IP Package 
## Folder Structure
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

## ip.json
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
