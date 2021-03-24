# O.MG-Extractor

The O.MG cable is a wireless-enabled keystroke injection attack platform released by Hak5 and MG. It uses ducky code to send keystrokes to the connected device.

This tool will attempt to connect to and recover data from a cable even if the cable has been "nuked"

### Usage

```
➜ python3 omg_extract.py -h                   
usage: omg_extract.py [-h] [-d DEVICE] [-o OUTPUT] [-f FILE]

Extract Payloads from an O.mg Cable

optional arguments:
  -h, --help            show this help message and exit
  -d DEVICE, --device DEVICE
                        USB Device to read "/dev/ttyUSB0"
  -o OUTPUT, --output OUTPUT
                        Firmware bin file
  -f FILE, --file FILE  Read an existing firware dump


```


### Examples

Dump cable firmware to a file and parse it. 

`python3 omg_extract.py --device /dev/ttyUSB0 --output cable_dump.bin`

Parse an existing firmware dump file

`python3 omg_extract.py -f cable_dump.bin`