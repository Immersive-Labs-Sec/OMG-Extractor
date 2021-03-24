#!/usr/bin/env python3
#
# O.MG Cable firware extraction and analysis tool
# Copyright (C) 2021 Kevin Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/OMG-Extractor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import sys
import pprint
import esptool
import argparse
from io import StringIO


MODE_PATTERN = b'MODE ([1-2])\x00'
SSID_PATTERN = b'SSID (.*)\x00PASS'
PASS_PATTERN = b'PASS (.*)\x00MODE'
FLASH_SIZE = "0x1A7DDB"

# Firmware 1.5.3
PAYLOAD_OFFSETS = [
    0xB0000,
    0xB4000,
    0xB8000,
    0xBC000,
    0xC0000,
    0xC4000,
    0xC8000
    ]

NAME_OFFSET = 0x17c004
DESCRIPTION_OFFSET = 0x17c024
MAC_OFFSETS = [0xFE492, 0xFD429]


class Capturing(list):
    """
    We use this like a context manager to get the output from esptool
    """
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        del self._stringio
        sys.stdout = self._stdout


def dump_firmware(dev_name, firmware_bin, verbose=False):

    device_info = {
        "hardware": {
            "ChipID": "Unknown",
            "MAC": "Unknown"
        },
        "MAC": "Unknown",
        "Name": "Unknown",
        "Description": "Unknown",
        "Mode": "Unknown",
        "SSID": "Unknown",
        "Pass": "Unknown",
        "scripts": []
    }

    if dev_name:

        # Connect to the programmer dump ~ 2mb of data.
        print(f"[+] Connecting to {dev_name}")

        # Read Device Info
        with Capturing() as esp_results:
            command = ['--baud', '115200', '--port', dev_name, '--no-stub', 'chip_id' ]
            try:
                esptool.main(command)
            except Exception as err:
                print(err)
                print(f"[!] Unable to find an OMG Cable on {dev_name}")

        for element in esp_results:
            if element.startswith("MAC"):
                device_info['hardware']['MAC'] = element.split(": ")[-1]
            if element.startswith("Chip ID: "):
                device_info['hardware']['ChipID'] = element.split(": ")[-1]

        print("[+] Found Device")
        print(f"  [-] Chip ID: {device_info['hardware']['ChipID']}")
        print(f"  [-] MAC: {device_info['hardware']['MAC']}")

        print(f"[+] Dumping firmware to {firmware_bin}")
        print("  [!] You will have to reconnect the cable to try again")
        print("  [-] This will take a minute or 2")

        try:
            command = ['--baud', '115200', '--port', dev_name, 'read_flash', '0x0', FLASH_SIZE, firmware_bin]

            if verbose:
                esptool.main(command)
            else:
                with Capturing() as esp_results:
                    esptool.main(command)

            print("  [-] Success")
        except Exception as err:
            print(f"[!] Error reading firmware: {err}")
            return device_info

    print("[+] Reading Firmware from {firmware_bin}")

    with open(firmware_bin, "rb") as firmware_dump:
        raw_firmware = firmware_dump.read()

        print("  [-] Searching for Cable Mode")
        cable_mode = re.search(MODE_PATTERN, raw_firmware)

        # Find the WiFi Mode
        if cable_mode:
            if cable_mode.group(1) == "2":
                wifi_mode = "Access Point"
            else:
                wifi_mode = "Station Mode"

            device_info['Mode'] = wifi_mode

        # Search for SSID Details
        print("  [-] Searching for SSID Details")
        ssid = re.search(SSID_PATTERN, raw_firmware).group(1)
        if ssid:
            device_info['SSID'] = ssid

        ssid_pass = re.search(PASS_PATTERN, raw_firmware).group(1)
        if ssid_pass:
            device_info["Pass"] = ssid_pass

        # Find MAC at offset
        mac_bytes = raw_firmware[MAC_OFFSETS[0]:MAC_OFFSETS[0]+6]
        mac_string = ":".join([hex(x)[2:] for x in mac_bytes])
        device_info['MAC'] = mac_string.upper()

        # User Set Name and Description
        device_info['Name'] = raw_firmware[NAME_OFFSET:NAME_OFFSET+20].rstrip(b'\x00')
        device_info['Description'] = raw_firmware[DESCRIPTION_OFFSET:DESCRIPTION_OFFSET+20].rstrip(b'\x00')

        # Extract Payloads
        print("  [-] Searching for Payloads")
        # Make this a single regex with multiple matches?

        payload_counter = 0
        for offset in PAYLOAD_OFFSETS:
            raw_script = raw_firmware[offset: offset+4000]
            filtered_script = raw_script.rstrip(b'\xff')
            device_info['scripts'].append(filtered_script)
            payload_counter += 1

    return device_info


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Payloads from an O.mg Cable')
    parser.add_argument('-d', '--device', help='USB Device to read "/dev/ttyUSB0"',
                        default="/dev/ttyUSB0")
    parser.add_argument('-o', '--output', help="Firmware bin file", default="cable.bin")

    parser.add_argument('-f', '--file', help="Read an existing firware dump")

    args = parser.parse_args()

    if args.file:
        dev_name = None
        bin_file = args.file
    else:
        dev_name = args.device
        bin_file = args.output

    device_info = dump_firmware(dev_name, bin_file)
    pprint.pprint(device_info)
