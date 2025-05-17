#!/usr/bin/env python3

import asyncio
import json
import math
import os
import sys
import time
from typing import Dict, List, Optional, Set, Tuple
from collections import deque
import select
import struct

import bleak
from bleak import BleakScanner, BleakClient
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.box import ROUNDED, HEAVY, SIMPLE
from rich import box


# Helper functions
def format_time_ago(seconds: float) -> str:
    """Format a time duration in seconds into a human-readable string"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"


# Constants
SETTINGS_FILE = "settings.json"
HISTORY_FILE = "devices_history.json"
AIRTAG_IDENTIFIERS = [
    "apple",
    "airtag",
    "find my",
    "locate",
    "tracker",
    "tag",
    "tile",
    "chipolo",
    "samsung tag",
    "smarttag",
]  # Identifiers to detect AirTags and other trackers
FIND_MY_UUIDS = [
    "7DFC9000",
    "7DFC9001",
    "FD44",
    "05AC",
    "74278BDA",
    "0000FD44",
    "FD5A",
    "0000180A",
    "0000180F",
    "7DFC9002",
    "7DFC9003",
    "74278BDA-B644-4520-8F0C-720EAF059935",
]  # Apple and other tracker related UUIDs
SCAN_INTERVAL = 1.0  # Scan interval in seconds
DEFAULT_RSSI_AT_ONE_METER = -59  # Default RSSI at 1 meter for Bluetooth LE
DEFAULT_DISTANCE_N_VALUE = 2.0  # Default environmental factor for distance calculation
RSSI_HISTORY_SIZE = 20  # Increased number of RSSI readings to keep for better smoothing
SCAN_MODE = "active"  # Can be "active" or "passive"
SCAN_DURATION = 10.0  # Duration of each scan in seconds
DETECTION_THRESHOLD = -85  # RSSI threshold for considering a device in range
SCAN_PARAMETERS = {
    "timeout": 5.0,
    "windown": 0x0100,  # Window parameter for scanning
    "interval": 0x0060,  # Interval parameter for scanning (smaller value = more aggressive)
    "filters": None,  # No filters for maximum detection
    "active": True,  # Active scanning for more data
}

# Company identifiers (Bluetooth SIG assigned numbers)
COMPANY_IDENTIFIERS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x00D2: "Sony",
    0x0499: "Ruuvi Innovations",
    0x0059: "Nordic Semiconductor",
    0x0001: "Ericsson",
    0x0002: "Intel",
    0x0087: "Garmin",
    0x0157: "Anhui Huami",
    0x038F: "Xiaomi",
    0x02D0: "Tile",
    0x0157: "Fitbit",
    0x012D: "Sony Ericsson",
    0x008A: "Tencent",
    0x000D: "Vivo",
    0x01D7: "Qualcomm",
    0x0BDA: "Samsung Electronics",
    0x0131: "Cypress Semiconductor",
    0x010C: "Chipolo",
    0x0A12: "Cambridge Silicon Radio",
    0x008C: "Bose",
    0x0590: "Logitech",
    0x0180: "LG Electronics",
    0x003B: "Hewlett-Packard",
    0x00F0: "GN Netcom (Jabra)",
    0x0154: "Amazon",
    0x0217: "Anker",
    0x0053: "Nokia",
    0x001D: "Qualcomm",
    0x0030: "ST Microelectronics",
    0x0198: "Fossil",
    0x010F: "Huawei",
    0x0214: "OPPO",
    0x018D: "Realme",
    0x000C: "OnePlus",
    0x057C: "Lenovo",
    0x01A9: "Dell",
    0x0D13: "Roku",
    0x008D: "Sonos",
    0x04C6: "JBL",
    0x012C: "Sonoff",
    0x0150: "TP-Link",
    0x0151: "Tuya",
    0x01DF: "FitBit",
    0x054C: "Sony",
    0x022B: "iTag",
    0x022A: "Nutale",
    0x02FF: "NUT",
    0x07BA: "Radbeacon",
    0x0183: "PEBBLEBEE",
}

# Device types based on services or characteristics
DEVICE_TYPES = {
    "FE9F": "Apple Continuity",
    "180F": "Battery Service",
    "1812": "HID (Human Interface Device)",
    "180A": "Device Information",
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time",
    "180D": "Heart Rate",
    "1813": "Scan Parameters",
    "1819": "Location and Navigation",
    "181C": "User Data",
    "181D": "Weight Scale",
    "181E": "Bond Management",
    "181F": "Continuous Glucose Monitoring",
    "1826": "Fitness Machine",
    "1827": "Mesh Provisioning",
    "1828": "Mesh Proxy",
    "183A": "Environmental Sensing",
    "181A": "Environmental Sensing",
    "FDCD": "Tile Tag",
    "FD5A": "Samsung SmartTag",
    "74278BDA": "Apple Find My",
    "0000180A": "Device Information",
    "0000180F": "Battery Service",
    "00001802": "Immediate Alert (Tracking)",
    "0000FD44": "Apple Nearby",
    "0000FD5A": "Samsung Find",
}

# Apple specific service flags for device type identification
APPLE_DEVICE_TYPES = {
    0x01: "iMac",
    0x02: "MacBook",
    0x03: "iPhone",
    0x04: "iPad",
    0x05: "Apple Watch",
    0x06: "Apple TV",
    0x07: "iPod",
    0x08: "HomePod",
    0x09: "AirPods",
    0x0A: "AirTag",
    0x0B: "Apple Pencil",
    0x0C: "Apple Vision Pro",
    0x0D: "Apple Beats",
    0x0E: "Apple Keyboard",
    0x0F: "Apple Network Adapter",
    0x10: "Apple Magic Mouse",
    0x11: "Apple Magic Trackpad",
    0x12: "AirPods Pro",
    0x13: "AirPods Max",
    0x14: "AirPods 2nd Gen",
    0x15: "AirPods 3rd Gen",
}

# Tracking device types
TRACKING_DEVICE_TYPES = {
    "AIRTAG": {
        "company_id": 0x004C,
        "identifiers": ["airtag", "apple tag", "find my tag"],
        "uuids": ["7DFC9000", "7DFC9001", "0000FD44"],
        "data_patterns": [
            {"offset": 0, "value": 0x12, "mask": 0xFF},
            {"offset": 1, "value": 0x19, "mask": 0xFF},
            {"offset": 2, "value": 0x0A, "mask": 0x0F},
        ],
    },
    "SAMSUNG_SMARTTAG": {
        "company_id": 0x0075,
        "identifiers": ["samsung tag", "smarttag", "smart tag", "galaxy tag"],
        "uuids": ["FD5A", "0000FD5A"],
        "data_patterns": [],
    },
    "TILE": {
        "company_id": 0x02D0,
        "identifiers": ["tile", "tile tracker"],
        "uuids": ["FDCD", "FEED"],
        "data_patterns": [],
    },
    "CHIPOLO": {
        "company_id": 0x0131,
        "identifiers": ["chipolo"],
        "uuids": ["FEE1", "FEE0"],
        "data_patterns": [],
    },
}


class Device:
    def __init__(
        self,
        address: str,
        name: str,
        rssi: int,
        manufacturer_data: Optional[Dict] = None,
        service_data: Optional[Dict] = None,
        service_uuids: Optional[List] = None,
    ):
        self.address = address
        self.name = name or "Unknown"
        self.rssi = rssi
        self.rssi_history = deque([rssi], maxlen=RSSI_HISTORY_SIZE)
        self.manufacturer_data = manufacturer_data or {}
        self.service_data = service_data or {}
        self.service_uuids = service_uuids or []
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.is_airtag = self._check_if_airtag()
        self.calibrated_n_value = DEFAULT_DISTANCE_N_VALUE
        self.calibrated_rssi_at_one_meter = DEFAULT_RSSI_AT_ONE_METER

        # Extract extended information
        self.manufacturer = self._extract_manufacturer()
        self.device_type = self._extract_device_type()
        self.device_details = self._extract_detailed_info()

    def update(
        self,
        rssi: int,
        manufacturer_data: Optional[Dict] = None,
        service_data: Optional[Dict] = None,
        service_uuids: Optional[List] = None,
    ):
        self.rssi = rssi
        self.rssi_history.append(rssi)
        if manufacturer_data:
            self.manufacturer_data = manufacturer_data
        if service_data:
            self.service_data = service_data
        if service_uuids:
            self.service_uuids = service_uuids
        self.last_seen = time.time()

        # Update extracted information
        self.manufacturer = self._extract_manufacturer()
        self.device_type = self._extract_device_type()
        self.device_details = self._extract_detailed_info()

    def _extract_manufacturer(self) -> str:
        """Extract manufacturer information from BLE advertisement data"""
        for company_id in self.manufacturer_data:
            if company_id in COMPANY_IDENTIFIERS:
                return COMPANY_IDENTIFIERS[company_id]

        # Try to guess from name or address
        if self.name:
            name_lower = self.name.lower()
            for keyword, company in [
                ("apple", "Apple"),
                ("iphone", "Apple"),
                ("ipad", "Apple"),
                ("macbook", "Apple"),
                ("imac", "Apple"),
                ("watch", "Apple"),
                ("airtag", "Apple"),
                ("airpod", "Apple"),
                ("samsung", "Samsung"),
                ("galaxy", "Samsung"),
                ("xiaomi", "Xiaomi"),
                ("mi ", "Xiaomi"),
                ("huawei", "Huawei"),
                ("sony", "Sony"),
                ("bose", "Bose"),
                ("beats", "Apple/Beats"),
                ("fitbit", "Fitbit"),
                ("garmin", "Garmin"),
                ("tile", "Tile"),
                ("polar", "Polar"),
                ("jbl", "JBL"),
                ("lg", "LG"),
                ("oneplus", "OnePlus"),
                ("oppo", "OPPO"),
                ("vivo", "Vivo"),
            ]:
                if keyword in name_lower:
                    return company

        # Check MAC address OUI (first three bytes)
        if ":" in self.address:
            oui = self.address.split(":")[:3]
            # OUI matching could be implemented with a database
            # This is a simplified example
            oui_str = "".join(oui).upper()
            if oui_str.startswith("AC"):
                return "Apple"
            elif oui_str.startswith("00:0D:4B"):
                return "Roku"
            elif oui_str.startswith("00:1A:11"):
                return "Google"

        return "Unknown"

    def _extract_device_type(self) -> str:
        """Extract device type from BLE advertisement data"""
        device_type = "BLE Device"

        # Check service UUIDs for known device types
        if self.service_uuids:
            for uuid in self.service_uuids:
                uuid_upper = uuid.upper()
                # Health & Fitness devices
                if "180D" in uuid_upper:  # Heart Rate service
                    return "Heart Rate Monitor"
                elif "1826" in uuid_upper:  # Fitness Machine service
                    return "Fitness Equipment"
                elif "1809" in uuid_upper:  # Health Thermometer service
                    return "Health Thermometer"
                elif (
                    "183A" in uuid_upper or "181A" in uuid_upper
                ):  # Environmental Sensing
                    return "Environmental Sensor"
                elif "1819" in uuid_upper:  # Location and Navigation
                    return "Location Tracker"

        # Check for Apple device type flag in manufacturer data
        if 76 in self.manufacturer_data and len(self.manufacturer_data[76]) > 2:
            apple_type_byte = self.manufacturer_data[76][2] & 0x0F
            if apple_type_byte in APPLE_DEVICE_TYPES:
                device_type = APPLE_DEVICE_TYPES[apple_type_byte]

                # For AirPods, try to get more specific model
                if apple_type_byte == 0x09 and len(self.manufacturer_data[76]) >= 4:
                    # The 4th byte can sometimes identify specific AirPods models
                    model_byte = self.manufacturer_data[76][3] & 0x0F
                    if model_byte == 0x01:
                        return "AirPods 1st Gen"
                    elif model_byte == 0x02:
                        return "AirPods 2nd Gen"
                    elif model_byte == 0x03:
                        return "AirPods Pro"
                    elif model_byte == 0x04:
                        return "AirPods Max"
                    elif model_byte == 0x05:
                        return "AirPods 3rd Gen"

        # Check the name for more specific information
        if self.name:
            name_lower = self.name.lower()

            # Prioritize name over manufacturer data for Apple devices
            if "iphone" in name_lower:
                # Try to extract iPhone model
                if "12" in name_lower:
                    return "iPhone 12"
                elif "13" in name_lower:
                    return "iPhone 13"
                elif "14" in name_lower:
                    return "iPhone 14"
                elif "15" in name_lower:
                    return "iPhone 15"
                elif "11" in name_lower:
                    return "iPhone 11"
                elif "xs" in name_lower:
                    return "iPhone XS"
                elif "xr" in name_lower:
                    return "iPhone XR"
                elif "se" in name_lower:
                    return "iPhone SE"
                elif "x" in name_lower:
                    return "iPhone X"
                return "iPhone"
            elif "ipad" in name_lower:
                # Try to extract iPad model
                if "pro" in name_lower:
                    return "iPad Pro"
                elif "air" in name_lower:
                    return "iPad Air"
                elif "mini" in name_lower:
                    return "iPad Mini"
                return "iPad"
            elif "macbook" in name_lower or "mac book" in name_lower:
                if "pro" in name_lower:
                    return "MacBook Pro"
                elif "air" in name_lower:
                    return "MacBook Air"
                return "MacBook"
            elif "imac" in name_lower:
                return "iMac"
            elif "mac mini" in name_lower or "macmini" in name_lower:
                return "Mac Mini"
            elif "apple watch" in name_lower or (
                "watch" in name_lower and self.manufacturer == "Apple"
            ):
                # Try to identify Apple Watch series
                if "series 8" in name_lower or "s8" in name_lower:
                    return "Apple Watch S8"
                elif "series 7" in name_lower or "s7" in name_lower:
                    return "Apple Watch S7"
                elif "series 6" in name_lower or "s6" in name_lower:
                    return "Apple Watch S6"
                elif "series 5" in name_lower or "s5" in name_lower:
                    return "Apple Watch S5"
                elif "se" in name_lower:
                    return "Apple Watch SE"
                elif "ultra" in name_lower:
                    return "Apple Watch Ultra"
                return "Apple Watch"
            elif "airpod" in name_lower:
                if "pro" in name_lower:
                    if "2" in name_lower:
                        return "AirPods Pro 2"
                    return "AirPods Pro"
                elif "max" in name_lower:
                    return "AirPods Max"
                elif "3" in name_lower:
                    return "AirPods 3rd Gen"
                elif "2" in name_lower:
                    return "AirPods 2nd Gen"
                return "AirPods"
            elif "airtag" in name_lower:
                return "AirTag"
            elif "beats" in name_lower:
                if "studio" in name_lower:
                    return "Beats Studio"
                elif "solo" in name_lower:
                    return "Beats Solo"
                elif "flex" in name_lower:
                    return "Beats Flex"
                elif "fit" in name_lower:
                    return "Beats Fit Pro"
                elif "pill" in name_lower:
                    return "Beats Pill"
                return "Beats Headphones"

            # Non-Apple devices with enhanced detection
            elif "samsung" in name_lower:
                if "watch" in name_lower:
                    if "galaxy" in name_lower:
                        return "Samsung Galaxy Watch"
                    return "Samsung Smartwatch"
                elif "bud" in name_lower or "earbud" in name_lower:
                    if "pro" in name_lower:
                        return "Samsung Galaxy Buds Pro"
                    elif "live" in name_lower:
                        return "Samsung Galaxy Buds Live"
                    return "Samsung Galaxy Buds"
                elif "tag" in name_lower or "smart tag" in name_lower:
                    return "Samsung SmartTag"
            elif "galaxy" in name_lower and "bud" in name_lower:
                return "Samsung Galaxy Buds"
            elif "google" in name_lower:
                if "pixel bud" in name_lower:
                    return "Google Pixel Buds"
                elif "nest" in name_lower:
                    return "Google Nest Device"
            elif "nest" in name_lower:
                return "Google Nest Device"
            elif (
                "xiaomi" in name_lower or "mi " in name_lower or "mi band" in name_lower
            ):
                if "band" in name_lower:
                    return "Xiaomi Mi Band"
                if "bud" in name_lower:
                    return "Xiaomi Earbuds"
            elif "fitbit" in name_lower:
                if "versa" in name_lower:
                    return "Fitbit Versa"
                elif "sense" in name_lower:
                    return "Fitbit Sense"
                elif "charge" in name_lower:
                    return "Fitbit Charge"
                return "Fitbit Tracker"
            elif "amazfit" in name_lower:
                return "Amazfit Smartwatch"
            elif "oneplus" in name_lower and "bud" in name_lower:
                return "OnePlus Buds"
            elif "sony" in name_lower:
                if "wh-1000" in name_lower:
                    return "Sony WH-1000 Headphones"
                elif "wf" in name_lower and (
                    "bud" in name_lower or "earphone" in name_lower
                ):
                    return "Sony WF Earbuds"
                return "Sony Audio Device"
            elif "bose" in name_lower:
                if "qc" in name_lower or "quietcomfort" in name_lower:
                    return "Bose QuietComfort"
                return "Bose Audio Device"
            elif "jabra" in name_lower:
                if "elite" in name_lower:
                    return "Jabra Elite Earbuds"
                return "Jabra Headset"
            elif "watch" in name_lower or "band" in name_lower:
                return "Smartwatch/Fitness Band"
            elif (
                "headphone" in name_lower
                or "earphone" in name_lower
                or "earbud" in name_lower
                or "bud" in name_lower
                or "hearable" in name_lower
            ):
                return "Headphones/Earbuds"
            elif "speaker" in name_lower:
                return "Bluetooth Speaker"
            elif "tag" in name_lower or "tracker" in name_lower:
                if "tile" in name_lower:
                    return "Tile Tracker"
                elif "chipolo" in name_lower:
                    return "Chipolo Tracker"
                return "Bluetooth Tracker"
            elif "tv" in name_lower:
                return "Smart TV"
            elif "roku" in name_lower:
                return "Roku Device"
            elif "remote" in name_lower:
                return "Remote Control"
            elif "keyboard" in name_lower:
                return "Bluetooth Keyboard"
            elif "mouse" in name_lower:
                return "Bluetooth Mouse"
            elif "car" in name_lower or "auto" in name_lower:
                return "Car Accessory"
            elif "phone" in name_lower:
                return "Smartphone"
            elif "pad" in name_lower or "tablet" in name_lower:
                return "Tablet"
            elif "camera" in name_lower:
                return "Bluetooth Camera"
            elif "printer" in name_lower:
                return "Bluetooth Printer"
            elif "scale" in name_lower:
                return "Smart Scale"
            elif "lock" in name_lower:
                return "Smart Lock"
            elif "door" in name_lower or "bell" in name_lower:
                return "Smart Doorbell"
            elif "light" in name_lower or "bulb" in name_lower:
                return "Smart Light"
            elif "therm" in name_lower:
                return "Smart Thermostat"
            elif "sensor" in name_lower:
                return "IoT Sensor"

        # Check manufacturer data for device type clues
        for company_id in self.manufacturer_data:
            # Samsung devices
            if company_id == 0x0075 or company_id == 0x0BDA:
                if device_type == "BLE Device":
                    data = self.manufacturer_data[company_id]
                    if len(data) > 3:
                        device_byte = data[2] if len(data) > 2 else 0x00
                        if device_byte == 0x01:
                            return "Samsung Phone"
                        elif device_byte == 0x02:
                            return "Samsung Tablet"
                        elif device_byte == 0x03:
                            return "Samsung Watch"
                        elif device_byte == 0x04:
                            return "Samsung Buds"
                        elif device_byte == 0x05:
                            return "Samsung SmartTag"
                        return "Samsung Device"

            # Tile trackers
            elif company_id == 0x02D0:
                return "Tile Tracker"

            # Chipolo trackers
            elif company_id == 0x010C:
                return "Chipolo Tracker"

            # Fitbit devices
            elif company_id == 0x01DF or company_id == 0x0157:
                return "Fitbit Device"

        # Check for specific iBeacon/Eddystone formats
        for company_id, data in self.manufacturer_data.items():
            # Apple iBeacon format
            if (
                company_id == 0x004C
                and len(data) >= 23
                and data[0] == 0x02
                and data[1] == 0x15
            ):
                return "iBeacon"

            # Eddystone format
            if company_id == 0x00E0 and len(data) >= 20:
                return "Eddystone Beacon"

        # Keep the Apple device type from manufacturer data if we didn't find a better match
        return device_type

    def _extract_detailed_info(self) -> str:
        """Extract detailed information from BLE advertisement data"""
        details = []

        # Add MAC address short form
        if ":" in self.address:
            mac_parts = self.address.split(":")
            details.append(f"MAC: {':'.join(mac_parts[-3:])}")

        # Parse Apple specific data
        if 76 in self.manufacturer_data:
            apple_data = self.manufacturer_data[76]

            # Try to extract Apple model details
            if len(apple_data) > 5:
                try:
                    # AirTag and Find My protocol specifics
                    if apple_data[0] == 0x12 and apple_data[1] == 0x19:
                        details.append("Find My Network")

                        # Try to extract AirTag status bits if available
                        if len(apple_data) >= 6:
                            status_byte = apple_data[5]
                            if status_byte & 0x01:
                                details.append("Separated Mode")
                            if status_byte & 0x02:
                                details.append("Play Sound")

                    # AirPods battery levels
                    elif len(apple_data) >= 13 and (
                        apple_data[0] == 0x07 or apple_data[0] == 0x01
                    ):
                        if apple_data[1] == 0x19:
                            left_battery = apple_data[6] & 0x0F
                            right_battery = (apple_data[6] & 0xF0) >> 4
                            case_battery = apple_data[7] & 0x0F
                            if left_battery < 0x0F and right_battery < 0x0F:
                                details.append(
                                    f"L:{left_battery*10}% R:{right_battery*10}% C:{case_battery*10}%"
                                )

                            # Extract AirPods case status
                            case_status = apple_data[8] & 0x03
                            if case_status == 0x01:
                                details.append("Case: Open")
                            elif case_status == 0x02:
                                details.append("Case: Closed")

                            # Extract in-ear detection status if available
                            if len(apple_data) >= 11:
                                ear_status = apple_data[10] & 0x03
                                if ear_status == 0x01:
                                    details.append("In-Ear: Left")
                                elif ear_status == 0x02:
                                    details.append("In-Ear: Right")
                                elif ear_status == 0x03:
                                    details.append("In-Ear: Both")

                    # Apple Watch info
                    elif apple_data[0] == 0x10 and len(apple_data) >= 8:
                        watch_status = apple_data[6]
                        if watch_status & 0x01:
                            details.append("Watch: Unlocked")
                        if watch_status & 0x02:
                            details.append("Watch: Active")
                        watch_battery = apple_data[7] & 0x0F
                        if watch_battery <= 10:
                            details.append(f"Battery: {watch_battery*10}%")

                    # iPhone/iPad info
                    elif apple_data[0] == 0x0C and len(apple_data) >= 5:
                        phone_status = apple_data[4]
                        if phone_status & 0x01:
                            details.append("Unlocked")
                except:
                    pass

        # Extract service data details
        for uuid, data in self.service_data.items():
            if "1809" in uuid.upper():  # Health Thermometer
                try:
                    if len(data) >= 2:
                        temp = struct.unpack("<h", data[:2])[0] / 100.0
                        details.append(f"Temp: {temp}°C")
                except:
                    pass

            elif "2A6D" in uuid.upper() or "2A6E" in uuid.upper():  # Pressure
                try:
                    if len(data) >= 4:
                        pressure = struct.unpack("<f", data[:4])[0]
                        details.append(f"Pressure: {pressure} Pa")
                except:
                    pass

            elif "180F" in uuid.upper():  # Battery Service
                try:
                    if len(data) >= 1:
                        battery = data[0]
                        details.append(f"Battery: {battery}%")
                except:
                    pass

            elif "1826" in uuid.upper():  # Fitness Machine Service
                try:
                    if len(data) >= 2:
                        # Various fitness machine data could be extracted here
                        details.append("Fitness Data")
                except:
                    pass

            elif "FD5A" in uuid.upper():  # Samsung SmartTag
                details.append("SmartTag")

            elif "FDCD" in uuid.upper():  # Tile
                details.append("Tile Tracker")

        # Signal stability
        stability = self.signal_stability
        if stability < 2.0:
            details.append(f"Signal: Stable({stability:.1f})")
        elif stability < 5.0:
            details.append(f"Signal: Moderate({stability:.1f})")
        else:
            details.append(f"Signal: Unstable({stability:.1f})")

        # Add tx power if available
        if "180A" in [uuid[-4:].upper() for uuid in self.service_uuids]:
            # This is an approximation; actual TX power would need connection
            details.append("Tx Power: Standard")

        # Attempt to extract device firmware/hardware version info
        if "180A" in [uuid[-4:].upper() for uuid in self.service_uuids]:
            # Device Information service present
            details.append("Has Device Info")

        # Check for iBeacon data pattern
        for company_id, data in self.manufacturer_data.items():
            if (
                company_id == 0x004C
                and len(data) >= 23
                and data[0] == 0x02
                and data[1] == 0x15
            ):
                # iBeacon format detected
                try:
                    # Extract UUID from iBeacon format
                    uuid_bytes = data[2:18]
                    uuid_str = "".join(f"{b:02x}" for b in uuid_bytes)
                    uuid_formatted = f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"

                    # Extract Major and Minor values
                    major = (data[18] << 8) | data[19]
                    minor = (data[20] << 8) | data[21]
                    details.append(f"iBeacon: {major}.{minor}")
                except:
                    details.append("iBeacon")

        # Add service UUIDs if present
        if self.service_uuids and len(self.service_uuids) > 0:
            known_services = []
            for uuid in self.service_uuids:
                uuid_short = uuid[-4:].upper()
                if uuid_short in DEVICE_TYPES:
                    known_services.append(DEVICE_TYPES[uuid_short])

            if known_services:
                services_str = ", ".join(
                    known_services[:2]
                )  # Limit to first 2 services
                if len(known_services) > 2:
                    services_str += f" +{len(known_services)-2}"
                details.append(f"Services: {services_str}")

        # Check for specific trackers
        if self.is_airtag:
            tracker_type = self.get_tracker_type()
            if (
                tracker_type != "Not a tracker"
                and "Find My Network" not in details
                and "AirTag" not in details
            ):
                details.append(f"Tracker: {tracker_type}")

        # Make string from details
        if details:
            return " | ".join(details)
        return ""

    def _check_if_airtag(self) -> bool:
        """Check if device is potentially an AirTag or other tracking device"""
        # First check if name contains any tracker identifiers
        if self.name and any(
            identifier in self.name.lower() for identifier in AIRTAG_IDENTIFIERS
        ):
            return True

        # Check for specific tracking devices based on detailed patterns
        for tracker_type, tracker_info in TRACKING_DEVICE_TYPES.items():
            # Check manufacturer ID
            if tracker_info["company_id"] in self.manufacturer_data:
                data = self.manufacturer_data[tracker_info["company_id"]]

                # Check data patterns if available
                if tracker_info["data_patterns"]:
                    pattern_matches = True
                    for pattern in tracker_info["data_patterns"]:
                        offset = pattern["offset"]
                        if (
                            len(data) <= offset
                            or (data[offset] & pattern["mask"]) != pattern["value"]
                        ):
                            pattern_matches = False
                            break
                    if pattern_matches:
                        return True

                # If no specific pattern defined but company ID matches, check UUIDs
                for uuid in self.service_uuids:
                    if any(
                        tracker_uuid in uuid.upper()
                        for tracker_uuid in tracker_info["uuids"]
                    ):
                        return True

        # Check for Apple-specific identifiers (Find My network)
        if 76 in self.manufacturer_data:  # Apple's company identifier (0x004C)
            data = self.manufacturer_data[76]

            # Find My network signals
            if len(data) > 2:
                # Various Find My patterns
                if (data[0] == 0x12 and data[1] == 0x19) or (data[0] == 0x10):
                    return True

                # Check for AirTag type identifier
                if len(data) > 3 and data[2] & 0x0F == 0x0A:  # AirTag type is 0x0A
                    return True

                # Check for other Apple tracking-related patterns
                if data[0] in [0x02, 0x05, 0x07, 0x0F] and len(data) >= 5:
                    # These values are often associated with tracking in Apple devices
                    return True

        # Check service UUIDs for Find My related services
        for uuid in self.service_uuids:
            uuid_upper = uuid.upper()
            for find_my_id in FIND_MY_UUIDS:
                if find_my_id in uuid_upper:
                    return True

        # Look for specific service data patterns
        for service_uuid, service_data in self.service_data.items():
            # Check for specific service data patterns related to tracking
            if service_uuid.upper() in ["FD5A", "FDCD", "7DFC9000", "FD44", "0000FD44"]:
                return True

        return False

    def get_tracker_type(self) -> str:
        """Identify the specific type of tracking device"""
        if not self.is_airtag:
            return "Not a tracker"

        # Check for AirTag
        if self.manufacturer == "Apple":
            if "airtag" in self.name.lower() or (
                76 in self.manufacturer_data
                and len(self.manufacturer_data[76]) > 2
                and self.manufacturer_data[76][2] & 0x0F == 0x0A
            ):
                return "Apple AirTag"
            return "Apple Find My Device"

        # Samsung SmartTag
        if self.manufacturer == "Samsung" or any(
            tag in self.name.lower()
            for tag in ["smarttag", "samsung tag", "galaxy tag"]
        ):
            return "Samsung SmartTag"

        # Tile trackers
        if self.manufacturer == "Tile" or "tile" in self.name.lower():
            return "Tile Tracker"

        # Chipolo trackers
        if "chipolo" in self.name.lower():
            return "Chipolo Tracker"

        # Generic tracker if we can't identify the specific type
        return "Unknown Tracker"

    @property
    def smooth_rssi(self) -> float:
        """Get smoothed RSSI value using Kalman-inspired filtering for better stability"""
        if not self.rssi_history:
            return self.rssi

        # Use more sophisticated smoothing algorithm for better stability
        # This is a simplified Kalman-inspired approach for RSSI

        # First remove outliers (more than 15 dBm from median)
        if len(self.rssi_history) >= 5:
            median_rssi = sorted(self.rssi_history)[len(self.rssi_history) // 2]
            filtered_values = [
                r for r in self.rssi_history if abs(r - median_rssi) <= 15
            ]
            if filtered_values:  # Ensure we still have values after filtering
                rssi_values = filtered_values
            else:
                rssi_values = list(self.rssi_history)
        else:
            rssi_values = list(self.rssi_history)

        # Calculate weighted average (more recent values have higher weight)
        if len(rssi_values) <= 2:
            # Simple average for small number of readings
            return sum(rssi_values) / len(rssi_values)

        # Weighted average based on recency
        total_weight = 0
        weighted_sum = 0
        for i, rssi in enumerate(rssi_values):
            # Exponential weighting - more recent values get higher weight
            weight = math.exp(0.5 * i / len(rssi_values))
            weighted_sum += rssi * weight
            total_weight += weight

        return weighted_sum / total_weight if total_weight else self.rssi

    @property
    def distance(self) -> float:
        """Calculate approximate distance with improved environment correction"""
        if self.smooth_rssi == 0:
            return float("inf")

        # Get environment-specific parameters (different for indoors vs outdoors)
        env_factor = self.calibrated_n_value

        # Apply signal strength correction based on device type and environment
        # Different device types and environments affect signal differently
        rssi_correction = 0

        # Adjust for known device types
        if self.device_type.lower() in ["airtag", "apple airtag"]:
            # AirTags tend to have stronger signals
            rssi_correction = -2  # Subtract 2 dBm (signal appears stronger than it is)
        elif "tag" in self.device_type.lower() or "tracker" in self.device_type.lower():
            # Other trackers may need different adjustments
            rssi_correction = -1

        # Adjust environment factor based on signal stability
        stability = self.signal_stability
        if stability > 8:
            # Very unstable signal, likely multipath interference (indoors)
            env_factor = max(env_factor, 3.0)  # Increase path loss exponent
        elif stability < 3:
            # Very stable signal, likely line-of-sight (outdoors)
            env_factor = min(env_factor, 2.2)  # Decrease path loss exponent

        # Apply corrections to RSSI
        corrected_rssi = self.smooth_rssi + rssi_correction

        # Enhanced log-distance path loss model with adjustment for close proximity
        if corrected_rssi > self.calibrated_rssi_at_one_meter - 5:
            # Device is very close (< 1m), use linear interpolation for higher accuracy
            # This addresses the limitation of the log model at close range
            signal_ratio = (self.calibrated_rssi_at_one_meter - corrected_rssi) / 5.0
            return max(0.1, signal_ratio)  # Range: 0.1 to 1.0 meters
        else:
            # Standard log-distance path loss model for normal ranges
            distance = 10 ** (
                (self.calibrated_rssi_at_one_meter - corrected_rssi) / (10 * env_factor)
            )

            # Add slight correction for very far distances to account for noise floor
            if distance > 10:
                # Exponential limitation to prevent unrealistic distances due to noise
                distance = 10 + 5 * (1 - math.exp(-(distance - 10) / 20))

            return max(0.1, distance)  # Ensure positive distance

    def calibrate_distance(self, known_distance: float):
        """Calibrate distance calculation for this device at a known distance"""
        if self.smooth_rssi != 0 and known_distance > 0:
            # Calculate N factor based on known distance
            self.calibrated_n_value = abs(
                (self.calibrated_rssi_at_one_meter - self.smooth_rssi)
                / (10 * math.log10(known_distance))
            )

            # Validate and limit to reasonable ranges (1.0 to 4.0)
            self.calibrated_n_value = max(1.0, min(4.0, self.calibrated_n_value))

            # Also update the RSSI at one meter based on the measurement
            # This is especially useful for the first calibration point
            if known_distance == 1.0:
                self.calibrated_rssi_at_one_meter = self.smooth_rssi
            elif known_distance < 1.0:
                # If we have a closer measurement, extrapolate to 1m
                self.calibrated_rssi_at_one_meter = self.smooth_rssi - (
                    10 * self.calibrated_n_value * math.log10(known_distance)
                )

            return True
        return False

    def calibrate_rssi_at_one_meter(self, rssi_at_one_meter: int):
        """Set the RSSI value at one meter for this device"""
        self.calibrated_rssi_at_one_meter = rssi_at_one_meter
        return True

    @property
    def signal_stability(self) -> float:
        """Calculate signal stability as improved noise metric"""
        if len(self.rssi_history) < 3:
            return 0.0

        # Calculate standard deviation of RSSI values
        mean = sum(self.rssi_history) / len(self.rssi_history)
        variance = sum((x - mean) ** 2 for x in self.rssi_history) / len(
            self.rssi_history
        )
        std_dev = math.sqrt(variance)

        # Calculate rate of change (first derivative)
        rssi_list = list(self.rssi_history)
        deltas = [
            abs(rssi_list[i] - rssi_list[i - 1]) for i in range(1, len(rssi_list))
        ]
        avg_delta = sum(deltas) / len(deltas) if deltas else 0

        # Combined stability metric (weighted sum of std dev and rate of change)
        # Lower values indicate more stable signal
        stability_metric = (0.7 * std_dev) + (0.3 * avg_delta)

        return stability_metric

    @property
    def signal_quality(self) -> float:
        """Assess signal quality on a scale of 0-100%"""
        # Start with base quality from RSSI
        if self.smooth_rssi >= -50:
            base_quality = 100  # Excellent signal
        elif self.smooth_rssi >= -65:
            base_quality = 80  # Very good signal
        elif self.smooth_rssi >= -75:
            base_quality = 60  # Good signal
        elif self.smooth_rssi >= -85:
            base_quality = 40  # Fair signal
        else:
            base_quality = 20  # Poor signal

        # Reduce quality based on signal stability
        stability = self.signal_stability
        stability_factor = max(
            0, 1 - (stability / 10)
        )  # 0 if very unstable, 1 if stable

        # Reduce quality based on duration (better assessment over time)
        # More time means more confident assessment
        duration = self.seen_duration
        duration_factor = min(
            1.0, duration / 30
        )  # Up to 30 seconds to reach max confidence

        # Calculate final quality score
        quality = base_quality * stability_factor * duration_factor

        return min(100, max(0, quality))

    @property
    def seen_duration(self) -> float:
        """Calculate how long this device has been observed"""
        return self.last_seen - self.first_seen

    def to_dict(self) -> Dict:
        """Convert device to dictionary for storage"""
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "manufacturer_data": {
                str(k): list(v) for k, v in self.manufacturer_data.items()
            },
            "service_data": {k: list(v) for k, v in self.service_data.items()},
            "service_uuids": self.service_uuids,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_airtag": self.is_airtag,
            "distance": self.distance,
            "calibrated_n_value": self.calibrated_n_value,
            "calibrated_rssi_at_one_meter": self.calibrated_rssi_at_one_meter,
            "manufacturer": self.manufacturer,
            "device_type": self.device_type,
            "device_details": self.device_details,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Device":
        """Create device from dictionary"""
        device = cls(
            address=data["address"],
            name=data["name"],
            rssi=data["rssi"],
            manufacturer_data={
                int(k): bytes(v) for k, v in data.get("manufacturer_data", {}).items()
            },
            service_data={k: bytes(v) for k, v in data.get("service_data", {}).items()},
            service_uuids=data.get("service_uuids", []),
        )
        device.first_seen = data["first_seen"]
        device.last_seen = data["last_seen"]
        if "calibrated_n_value" in data:
            device.calibrated_n_value = data["calibrated_n_value"]
        if "calibrated_rssi_at_one_meter" in data:
            device.calibrated_rssi_at_one_meter = data["calibrated_rssi_at_one_meter"]
        return device


class TagFinder:
    def __init__(self):
        self.console = Console()
        self.devices: Dict[str, Device] = {}
        self.settings = self._load_settings()
        self.history: List[Dict] = self._load_history()
        self.current_adapter = None
        self.scanning = False
        self.airtag_only_mode = self.settings.get("airtag_only_mode", False)
        self.selected_device = None
        self.adaptive_mode = self.settings.get("adaptive_mode", True)
        self.calibration_mode = self.settings.get("calibration_mode", False)
        self.layout = self._create_layout()
        self.device_map = {}  # Map index to device address for selection
        self.input_buffer = ""  # Buffer for multi-digit input
        self.last_key_time = time.time()  # Last time a key was pressed

        # Selection cursor properties
        self.cursor_position = 0  # Current position in device list for tabbing
        self.selection_mode = False  # Whether we're in tab-based selection mode

        # For persistent device IDs
        self.next_device_id = 0  # Next ID to assign to a new device
        self.device_ids = {}  # Maps device address to its assigned ID

    def _create_layout(self) -> Layout:
        """Create the layout for the UI"""
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=7),
        )
        layout["main"].split_row(
            Layout(name="devices", ratio=4),
            Layout(name="details", ratio=2, visible=False),
        )
        return layout

    def _load_settings(self) -> Dict:
        """Load settings from JSON file"""
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                pass
        return {}

    def _save_settings(self):
        """Save settings to JSON file"""
        with open(SETTINGS_FILE, "w") as f:
            json.dump(self.settings, f, indent=2)

    def _load_history(self) -> List:
        """Load device history from JSON file"""
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r") as f:
                    data = json.load(f)
                    # Ensure we return a list even if the file contains a dict
                    if isinstance(data, dict):
                        return [data]
                    elif isinstance(data, list):
                        return data
                    else:
                        return []
            except (json.JSONDecodeError, Exception):
                # Handle any errors by returning an empty list
                return []
        return []

    async def _save_history(self):
        """Save device history to JSON file"""
        try:
            # Convert current devices to dict and add to history
            current_devices_data = []
            for device in self.devices.values():
                current_devices_data.append(device.to_dict())

            # Ensure history is a list
            if not isinstance(self.history, list):
                self.history = []

            # Add to history
            self.history.extend(current_devices_data)

            # Save to file - ensure we're not duplicating entries
            unique_entries = {}
            for entry in self.history:
                try:
                    address = entry["address"]
                    timestamp = entry["last_seen"]
                    key = f"{address}_{timestamp}"
                    unique_entries[key] = entry
                except (KeyError, TypeError):
                    # Skip malformed entries
                    continue

            # Save only unique entries
            with open(HISTORY_FILE, "w") as f:
                json.dump(list(unique_entries.values()), f, indent=2)

            self.console.print(
                f"[green]Saved {len(current_devices_data)} devices to history[/]"
            )
        except Exception as e:
            self.console.print(f"[bold red]Error saving history: {e}[/]")
            # Try to create a new file if something went wrong
            try:
                with open(HISTORY_FILE, "w") as f:
                    json.dump([], f)
            except:
                pass

    async def list_adapters(self):
        """List all available Bluetooth adapters"""
        # Clear terminal before showing adapter list
        self.console.clear()

        # Different methods for different platforms
        adapters = []

        try:
            if sys.platform == "darwin":  # macOS
                # On macOS, we can use system_profiler
                import subprocess

                result = subprocess.run(
                    ["system_profiler", "SPBluetoothDataType"],
                    capture_output=True,
                    text=True,
                )
                output = result.stdout

                # Parse the output for Bluetooth controller info
                if "Bluetooth Controller" in output:
                    controller_section = output.split("Bluetooth Controller")[1].split(
                        "\n\n"
                    )[0]
                    address = None
                    name = "Apple Bluetooth"

                    if "Address:" in controller_section:
                        address_line = [
                            l for l in controller_section.split("\n") if "Address:" in l
                        ]
                        if address_line:
                            address = address_line[0].split("Address:")[1].strip()

                    adapters.append({"address": address, "name": name})

            elif sys.platform == "linux":
                # On Linux, we can use hcitool
                import subprocess

                result = subprocess.run(
                    ["hcitool", "dev"], capture_output=True, text=True
                )
                output = result.stdout

                for line in output.split("\n"):
                    if "hci" in line:
                        parts = line.strip().split("\t")
                        if len(parts) >= 3:
                            adapters.append(
                                {
                                    "address": parts[2],
                                    "name": f"Bluetooth Adapter ({parts[1]})",
                                }
                            )

            elif sys.platform == "win32":
                # On Windows, we can use Bleak's internal API
                from bleak.backends.winrt.scanner import BleakScannerWinRT

                scanner = BleakScannerWinRT()
                await scanner._ensure_adapter()
                adapters.append(
                    {"address": "default", "name": "Windows Bluetooth Adapter"}
                )

        except Exception as e:
            self.console.print(f"[bold yellow]Error listing adapters: {e}[/]")

        # If no adapters found, add a default one
        if not adapters:
            adapters.append({"address": "default", "name": "Default Bluetooth Adapter"})

        # Display adapters table
        table = Table(title="Available Bluetooth Adapters", box=box.ROUNDED)
        table.add_column("Index", style="cyan")
        table.add_column("Address", style="green")
        table.add_column("Name", style="magenta")

        for i, adapter in enumerate(adapters):
            is_current = (
                "[bold green]⟹[/]" if adapter["address"] == self.current_adapter else ""
            )
            table.add_row(
                str(i),
                adapter["address"] or "Unknown",
                f"{adapter['name']} {is_current}",
            )

        self.console.print(table)

        choice = self.console.input(
            "[bold blue]Select adapter index (or Enter to skip): [/]"
        )
        if choice.isdigit() and 0 <= int(choice) < len(adapters):
            self.current_adapter = adapters[int(choice)]["address"]
            self.settings["adapter"] = self.current_adapter
            self._save_settings()
            self.console.print(
                f"[bold green]Selected adapter: {adapters[int(choice)]['name']}[/]"
            )

    def generate_device_table(self, devices: Dict[str, Device]) -> Table:
        """Generate a table of devices for display"""
        # Create a responsive table that adapts to available space
        table = Table(
            title="[bold]Bluetooth Devices[/]",
            box=ROUNDED,
            highlight=True,
            title_style="bold cyan",
            border_style="blue",
            expand=True,  # Make table expand to fill available width
        )

        # Determine if we have a selected device - make some columns optional
        has_selected = (
            self.selected_device is not None and self.selected_device in self.devices
        )

        # Add columns with responsive width settings
        table.add_column("Name", style="cyan", ratio=4, no_wrap=False)
        table.add_column("Type", ratio=2, no_wrap=False)

        # Always show MAC address column
        table.add_column("MAC", ratio=2, no_wrap=False)

        # Only show manufacturer column if space permits or no device is selected
        if not has_selected or self.console.width > 100:
            table.add_column("Manufacturer", ratio=2, no_wrap=False)

        # Separate RSSI and Signal columns
        table.add_column("RSSI", justify="right", ratio=1)
        table.add_column("Signal", justify="right", ratio=1)
        table.add_column("Distance", justify="right", ratio=1)

        # Only show seen time column if no device is selected
        if not has_selected or self.console.width > 120:
            table.add_column("Seen", justify="right", ratio=1)

        # Always show details but adjust width based on available space
        if self.console.width > 140:
            table.add_column("Details", ratio=4, no_wrap=False)
        else:
            table.add_column("Details", ratio=3, no_wrap=False)

        # Sort devices by RSSI (closest first)
        sorted_devices = sorted(devices.values(), key=lambda d: d.rssi, reverse=True)

        # Store sorted list for tab-based selection
        self.sorted_device_list = sorted_devices

        # Reset device map for this display
        device_map = {}
        # Track visible devices for UI count
        visible_devices = 0

        for i, device in enumerate(sorted_devices):
            # Skip non-AirTags if in AirTag only mode
            if self.airtag_only_mode and not device.is_airtag:
                continue

            # Get the persistent device ID
            device_id = self.device_ids.get(device.address, 999)  # Fallback ID

            # Map persistent ID to device address for selection
            device_map[device_id] = device.address

            # Format ID for display with padding based on number of digits
            if device_id < 10:
                idx_display = f"[{device_id}]"
            elif device_id < 100:
                idx_display = f"[{device_id:2}]"
            else:
                idx_display = f"[{device_id:3}]"

            visible_devices += 1

            distance = f"{device.distance:.2f}m" if device.distance < 100 else "Unknown"
            seen_time = f"{device.seen_duration:.1f}s"

            # Color code RSSI for signal strength
            rssi_str = str(int(device.smooth_rssi))
            if device.smooth_rssi > -60:
                rssi_color = "green"
            elif device.smooth_rssi > -80:
                rssi_color = "yellow"
            else:
                rssi_color = "red"

            # Color code for AirTags
            name_color = "bright_cyan" if device.is_airtag else "white"

            # Highlight selected device
            style = "on blue" if device.address == self.selected_device else ""

            # Highlight current cursor position in tab-selection mode
            if (
                self.selection_mode
                and i == self.cursor_position
                and len(sorted_devices) > 0
            ):
                style = "on green"
                # Map the cursor position to this device for easy selection with Enter
                self.cursor_device = device.address

            # Display detailed information without the seen time
            details = device.device_details if device.device_details else ""

            # Format MAC address - just show last 6 characters for better readability
            mac_display = (
                device.address.split(":")[-3:]
                if ":" in device.address
                else device.address[-6:]
            )
            if isinstance(mac_display, list):
                mac_display = ":".join(mac_display)

            # Get signal quality as a percentage
            signal_quality = f"{device.signal_quality:.0f}%"

            # Color code signal quality
            if device.signal_quality > 70:
                signal_color = "green"
            elif device.signal_quality > 40:
                signal_color = "yellow"
            else:
                signal_color = "red"

            # Build row data based on which columns are enabled
            row_data = [
                Text(f"{idx_display} {device.name}", style=f"{name_color} {style}"),
                device.device_type,
                mac_display,  # Add MAC address column
            ]

            # Add manufacturer column if it exists
            if not has_selected or self.console.width > 100:
                row_data.append(device.manufacturer)

            # Always add RSSI, signal quality, and distance
            row_data.extend(
                [
                    Text(rssi_str, style=f"{rssi_color} {style}"),
                    Text(signal_quality, style=f"{signal_color} {style}"),
                    distance,
                ]
            )

            # Add seen time if column exists
            if not has_selected or self.console.width > 120:
                row_data.append(seen_time)

            # Always add details
            row_data.append(details)

            # Add the row with the correct data
            table.add_row(*row_data, style=style)

        if not sorted_devices or visible_devices == 0:
            # Create empty row data based on how many columns we have
            empty_row = ["No devices found"]
            empty_columns = (
                len(table.columns) - 1
            )  # -1 because we already added "No devices found"

            for _ in range(empty_columns):
                empty_row.append("")

            table.add_row(*empty_row)

        # Store the device map for index-based selection
        self.device_map = device_map

        return table

    def generate_header(self) -> Panel:
        """Generate header panel"""
        return Panel(
            "[bold cyan]TagFinder[/] - Bluetooth Device Scanner",
            style="bold",
            box=SIMPLE,
        )

    def generate_status_panel(self) -> Panel:
        """Generate a status panel with commands"""
        airtag_mode = "[green]ON[/]" if self.airtag_only_mode else "[red]OFF[/]"
        adaptive_mode = "[green]ON[/]" if self.adaptive_mode else "[red]OFF[/]"
        calibration_mode = "[green]ON[/]" if self.calibration_mode else "[red]OFF[/]"

        # Create responsive panels for controls and settings
        # Create a layout to hold both panels side by side
        layout = Layout()

        # Split the layout based on available width
        if self.console.width > 100:
            # If we have enough space, show controls and settings side by side
            layout.split_row(
                Layout(name="controls", ratio=1),
                Layout(name="settings", ratio=1),
            )

            # Controls panel
            controls_panel = Panel(
                "\n".join(
                    [
                        "[bold cyan]Controls:[/]",
                        " [bold blue]s[/] - Start/Stop scanning",
                        " [bold blue]a[/] - Toggle AirTag only mode",
                        " [bold blue]d[/] - Toggle adaptive mode",
                        " [bold blue]c[/] - Toggle calibration mode",
                        " [bold blue]l[/] - List Bluetooth adapters",
                        " [bold blue]z[/] - Analyze & Summarize findings",
                        " [bold blue]q[/] - Quit",
                    ]
                ),
                title="[bold blue]TagFinder Controls[/]",
                border_style="blue",
                box=ROUNDED,
                expand=True,
            )

            # Settings panel
            settings_panel = Panel(
                "\n".join(
                    [
                        f"[bold]Status:[/] [yellow]Idle[/]",
                        f"[bold]AirTag mode:[/] {airtag_mode}",
                        f"[bold]Adaptive:[/] {adaptive_mode}",
                        f"[bold]Calibration:[/] {calibration_mode}",
                        f"[bold]Adapter:[/] {self.current_adapter or 'Default'}",
                    ]
                ),
                title="[bold green]Current Settings[/]",
                border_style="green",
                box=ROUNDED,
                expand=True,
            )

            layout["controls"].update(controls_panel)
            layout["settings"].update(settings_panel)

            return layout
        else:
            # For narrower screens, use a single combined panel
            return Panel(
                "\n".join(
                    [
                        "[bold cyan]Controls:[/]",
                        " [bold blue]s[/] - Scan [bold blue]a[/] - AirTag mode [bold blue]d[/] - Adaptive",
                        " [bold blue]c[/] - Calibration [bold blue]l[/] - Adapters [bold blue]z[/] - Analyze [bold blue]q[/] - Quit",
                        "",
                        f"[bold]Status:[/] [yellow]Idle[/] | AirTag: {airtag_mode} | Adaptive: {adaptive_mode} | Calib: {calibration_mode}",
                        f"[bold]Adapter:[/] {self.current_adapter or 'Default'}",
                    ]
                ),
                title="[bold blue]TagFinder Controls[/]",
                border_style="blue",
                box=ROUNDED,
                expand=True,
            )

    def generate_device_details(self, device: Device) -> Panel:
        """Generate detail panel for selected device"""
        # Create a text object to build up the details panel
        details_text = Text()
        details_text.append("\n")  # Start with a newline for spacing

        # Basic Device Info section
        details_text.append("◉ ", style="bold green")
        details_text.append("Basic Info", style="bold yellow")
        details_text.append("\n")

        details_text.append(f"  Name: ", style="bold")
        details_text.append(f"{device.name or 'Unknown'}\n")

        details_text.append(f"  Address: ", style="bold")
        details_text.append(f"{device.address}\n")

        details_text.append(f"  Manufacturer: ", style="bold")
        details_text.append(f"{device.manufacturer}\n")

        details_text.append(f"  Device Type: ", style="bold")
        details_text.append(f"{device.device_type}\n")

        # Add tracker identification if it's a tracking device
        if device.is_airtag:
            tracker_type = device.get_tracker_type()
            details_text.append(f"  Tracker Type: ", style="bold red")
            details_text.append(f"{tracker_type}\n", style="bold red")

        # Signal Information section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Signal Data", style="bold yellow")
        details_text.append("\n")

        details_text.append(f"  Current RSSI: ", style="bold")
        # Color code based on signal strength
        rssi_style = (
            "green" if device.rssi > -70 else "yellow" if device.rssi > -85 else "red"
        )
        details_text.append(f"{device.rssi} dBm\n", style=rssi_style)

        details_text.append(f"  Smoothed RSSI: ", style="bold")
        smooth_rssi_style = (
            "green"
            if device.smooth_rssi > -70
            else "yellow" if device.smooth_rssi > -85 else "red"
        )
        details_text.append(f"{device.smooth_rssi:.1f} dBm\n", style=smooth_rssi_style)

        details_text.append(f"  Signal Quality: ", style="bold")
        quality = device.signal_quality
        quality_style = "green" if quality > 70 else "yellow" if quality > 40 else "red"
        details_text.append(f"{quality:.1f}%\n", style=quality_style)

        details_text.append(f"  Signal Stability: ", style="bold")
        stability = device.signal_stability
        stability_style = (
            "green" if stability < 3 else "yellow" if stability < 6 else "red"
        )
        details_text.append(f"{stability:.1f}\n", style=stability_style)

        # Distance Estimation section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Distance Estimation", style="bold yellow")
        details_text.append("\n")

        details_text.append(f"  Estimated Distance: ", style="bold")
        distance = device.distance
        distance_label = f"{distance:.2f} meters"
        if distance < 1:
            distance_label += f" ({distance * 100:.0f} cm)"
        distance_style = (
            "green" if distance < 2 else "yellow" if distance < 5 else "red"
        )
        details_text.append(f"{distance_label}\n", style=distance_style)

        details_text.append(f"  Calibration Values: ", style="bold")
        details_text.append(
            f"N={device.calibrated_n_value:.2f}, RSSI@1m={device.calibrated_rssi_at_one_meter}\n"
        )

        # Time Information section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Timing Information", style="bold yellow")
        details_text.append("\n")

        details_text.append(f"  First Seen: ", style="bold")
        first_seen_ago = time.time() - device.first_seen
        details_text.append(
            f"{time.strftime('%H:%M:%S', time.localtime(device.first_seen))} "
            f"({format_time_ago(first_seen_ago)})\n"
        )

        details_text.append(f"  Last Seen: ", style="bold")
        last_seen_ago = time.time() - device.last_seen
        details_text.append(
            f"{time.strftime('%H:%M:%S', time.localtime(device.last_seen))} "
            f"({format_time_ago(last_seen_ago)})\n"
        )

        details_text.append(f"  Tracked Duration: ", style="bold")
        details_text.append(f"{format_time_ago(device.seen_duration)}\n")

        # Technical Details section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Technical Details", style="bold yellow")
        details_text.append("\n")

        # Service UUIDs
        if device.service_uuids:
            truncated = len(device.service_uuids) > 5
            service_uuids = device.service_uuids[:5]  # Limit to first 5 UUIDs
            details_text.append(f"  Service UUIDs: ", style="bold")
            for i, uuid in enumerate(service_uuids):
                if i > 0:
                    details_text.append(", ")
                # Highlight known tracking UUIDs in red
                if any(known_uuid in uuid.upper() for known_uuid in FIND_MY_UUIDS):
                    details_text.append(uuid, style="bold red")
                else:
                    details_text.append(uuid)
            if truncated:
                details_text.append(f" +{len(device.service_uuids) - 5} more")
            details_text.append("\n")

        # Manufacturer Data
        if device.manufacturer_data:
            details_text.append(f"  Manufacturer Data: ", style="bold")
            mfg_data_entries = []
            for company_id, data in device.manufacturer_data.items():
                if company_id in COMPANY_IDENTIFIERS:
                    company_name = COMPANY_IDENTIFIERS[company_id]
                    mfg_data_str = (
                        f"{company_name} (0x{company_id:04X}): {data.hex()[:16]}"
                    )
                    if len(data.hex()) > 16:
                        mfg_data_str += "..."
                    mfg_data_entries.append(mfg_data_str)
                else:
                    mfg_data_str = f"0x{company_id:04X}: {data.hex()[:16]}"
                    if len(data.hex()) > 16:
                        mfg_data_str += "..."
                    mfg_data_entries.append(mfg_data_str)

            details_text.append(", ".join(mfg_data_entries[:2]))
            if len(mfg_data_entries) > 2:
                details_text.append(f" +{len(mfg_data_entries) - 2} more")
            details_text.append("\n")

        # Additional Details
        if device.device_details:
            details_text.append(f"  Additional Details: ", style="bold")
            details_text.append(f"{device.device_details}\n")

        # Actions Section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Available Actions", style="bold yellow")
        details_text.append("\n")
        details_text.append("  [b] ", style="bold cyan")
        details_text.append("Back to device list\n")

        # Return the details panel
        return Panel(
            details_text,
            title=f"[bold green]Device Details: {device.name or 'Unknown'}[/]",
            border_style="green",
            box=ROUNDED,
        )

    def summarize_findings(self):
        """Summarize findings from history or current scan with options for overall summary or device details"""
        # Clear terminal before showing summary
        self.console.clear()

        all_devices = []

        # Add current devices
        for device in self.devices.values():
            all_devices.append(device.to_dict())

        # Add history devices if available
        if self.history:
            all_devices.extend(self.history)

        # Deduplicate by address
        unique_devices = {}
        for device in all_devices:
            addr = device["address"]
            if (
                addr not in unique_devices
                or device["last_seen"] > unique_devices[addr]["last_seen"]
            ):
                unique_devices[addr] = device

        if not unique_devices:
            self.console.print("[yellow]No devices found in history or current scan[/]")
            return

        # Show summary options
        self.console.print("[bold cyan]Summary Options:[/]")
        self.console.print("[1] Overall Summary Analytics")
        self.console.print("[2] Detailed Device Summary")

        choice = self.console.input("[bold blue]Select an option (1/2): [/]")

        if choice == "1":
            self._show_overall_summary(unique_devices)
        elif choice == "2":
            self._show_device_selection(unique_devices)
        else:
            self.console.print("[yellow]Invalid option. Showing overall summary.[/]")
            self._show_overall_summary(unique_devices)

    def _show_overall_summary(self, unique_devices):
        """Show overall statistics and analytics for all devices"""
        # Count and categorize
        total_devices = len(unique_devices)
        airtags = [d for d in unique_devices.values() if d.get("is_airtag", False)]
        strongest_signal = min(d["rssi"] for d in unique_devices.values())
        closest_device = [
            d for d in unique_devices.values() if d["rssi"] == strongest_signal
        ][0]

        # Find average, min, max distances
        distances = [
            d.get("distance", float("inf"))
            for d in unique_devices.values()
            if isinstance(d.get("distance"), (int, float)) and d.get("distance") < 100
        ]

        avg_distance = sum(distances) / len(distances) if distances else 0
        min_distance = min(distances) if distances else 0
        max_distance = max(distances) if distances else 0

        # Device type statistics
        device_types = {}
        manufacturers = {}

        for device in unique_devices.values():
            device_type = device.get("device_type", "Unknown")
            if device_type in device_types:
                device_types[device_type] += 1
            else:
                device_types[device_type] = 1

            manufacturer = device.get("manufacturer", "Unknown")
            if manufacturer in manufacturers:
                manufacturers[manufacturer] += 1
            else:
                manufacturers[manufacturer] = 1

        # Sort by frequency
        top_types = sorted(device_types.items(), key=lambda x: x[1], reverse=True)[:5]
        top_manufacturers = sorted(
            manufacturers.items(), key=lambda x: x[1], reverse=True
        )[:5]

        # Time-based statistics
        now = time.time()
        first_seen = min(d.get("first_seen", now) for d in unique_devices.values())
        scan_duration = now - first_seen

        # Recently active devices (within last 5 minutes)
        recent_devices = [
            d
            for d in unique_devices.values()
            if now - d.get("last_seen", 0) < 300  # 5 minutes
        ]

        # Display summary
        summary_text = [
            f"[bold cyan]Basic Statistics:[/]",
            f"[bold]Total unique devices:[/] {total_devices}",
            f"[bold]AirTags/Find My devices:[/] {len(airtags)}",
            f"[bold]Recently active devices:[/] {len(recent_devices)}",
            f"[bold]Scan duration:[/] {scan_duration:.1f} seconds",
            "",
            f"[bold cyan]Proximity Analysis:[/]",
            f"[bold]Closest device:[/] {closest_device.get('name', 'Unknown')} ({closest_device['address']})",
            f"[bold]Closest signal strength:[/] {strongest_signal} dBm",
            f"[bold]Estimated distance:[/] {10 ** ((DEFAULT_RSSI_AT_ONE_METER - strongest_signal) / (10 * DEFAULT_DISTANCE_N_VALUE)):.2f} meters",
            f"[bold]Average distance:[/] {avg_distance:.2f} meters",
            f"[bold]Min distance:[/] {min_distance:.2f} meters",
            f"[bold]Max distance:[/] {max_distance:.2f} meters",
            "",
            f"[bold cyan]Device Type Distribution:[/]",
        ]

        # Add device type distribution
        for device_type, count in top_types:
            percentage = (count / total_devices) * 100
            summary_text.append(f"[bold]{device_type}:[/] {count} ({percentage:.1f}%)")

        summary_text.append("")
        summary_text.append(f"[bold cyan]Manufacturer Distribution:[/]")

        # Add manufacturer distribution
        for manufacturer, count in top_manufacturers:
            percentage = (count / total_devices) * 100
            summary_text.append(f"[bold]{manufacturer}:[/] {count} ({percentage:.1f}%)")

        # Add security warning if AirTags are found
        if airtags:
            summary_text.append("")
            summary_text.append(
                f"[bold red]Security Warning:[/] {len(airtags)} tracking devices detected"
            )

            # List the tracking devices
            for i, device in enumerate(airtags[:3], 1):  # Show top 3
                device_type = device.get("device_type", "Unknown Tracker")
                last_seen_ago = now - device.get("last_seen", now)
                summary_text.append(
                    f"  {i}. [bold yellow]{device.get('name', 'Unnamed')}[/] - "
                    f"{device_type} - Last seen {format_time_ago(last_seen_ago)} ago"
                )

            if len(airtags) > 3:
                summary_text.append(
                    f"  ...and {len(airtags) - 3} more tracking devices"
                )

        # Create the panel
        summary = Panel(
            "\n".join(summary_text),
            title="[bold green]Overall Scan Summary[/]",
            border_style="green",
            box=ROUNDED,
        )

        self.console.print(summary)

    def _show_device_selection(self, unique_devices):
        """Show a device selection interface and then detailed info for the selected device"""
        # Create a table to display the devices
        table = Table(
            title="[bold]Available Devices[/]",
            box=ROUNDED,
            highlight=True,
            title_style="bold cyan",
            border_style="blue",
        )

        # Add columns
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name", style="green")
        table.add_column("Type", style="magenta")
        table.add_column("Manufacturer")
        table.add_column("RSSI", justify="right")
        table.add_column("Last Seen")

        # Add rows
        device_map = {}
        for i, (addr, device) in enumerate(
            sorted(
                unique_devices.items(),
                key=lambda x: x[1].get("rssi", -999),
                reverse=True,
            )
        ):
            if i >= 30:  # Limit to top 30 devices to avoid overflow
                break

            device_id = i + 1
            device_map[device_id] = addr

            name = device.get("name", "Unknown")
            device_type = device.get("device_type", "BLE Device")
            manufacturer = device.get("manufacturer", "Unknown")
            rssi = device.get("rssi", "N/A")

            # Format last seen time
            last_seen = device.get("last_seen", time.time())
            last_seen_ago = time.time() - last_seen
            last_seen_str = format_time_ago(last_seen_ago) + " ago"

            # Highlight AirTags/trackers
            row_style = "bold red" if device.get("is_airtag", False) else ""

            table.add_row(
                str(device_id),
                name,
                device_type,
                manufacturer,
                str(rssi),
                last_seen_str,
                style=row_style,
            )

        # Display the table
        self.console.print(table)

        # Ask user to select a device
        device_choice = self.console.input(
            "\n[bold blue]Enter device ID for detailed info (or q to quit): [/]"
        )

        if device_choice.lower() == "q":
            return

        try:
            device_id = int(device_choice)
            if device_id in device_map:
                selected_addr = device_map[device_id]
                selected_device = unique_devices[selected_addr]
                self._show_detailed_device_info(selected_device)
            else:
                self.console.print(
                    "[yellow]Invalid device ID. Returning to main menu.[/]"
                )
        except ValueError:
            self.console.print("[yellow]Invalid input. Returning to main menu.[/]")

    def _show_detailed_device_info(self, device_data):
        """Show comprehensive details about a selected device"""
        # Clear the screen for detailed view
        self.console.clear()

        # Create a Device object from the dictionary if it's in dictionary form
        if isinstance(device_data, dict):
            try:
                device = Device.from_dict(device_data)
            except Exception as e:
                # If conversion fails, work with the raw dictionary
                self.console.print(
                    f"[yellow]Warning: Could not convert to Device object: {e}[/]"
                )
                device = None
        else:
            device = device_data

        # If we couldn't create a Device object, show basic info from the dictionary
        if device is None:
            self._show_raw_device_info(device_data)
            return

        # Create a rich text object for the detailed info
        details_text = Text()

        # Device Identification Section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Device Identification", style="bold yellow")
        details_text.append("\n\n")

        details_text.append(f"Name: ", style="bold")
        details_text.append(f"{device.name or 'Unknown'}\n")

        details_text.append(f"Address: ", style="bold")
        details_text.append(f"{device.address}\n")

        details_text.append(f"Device Type: ", style="bold")
        details_text.append(f"{device.device_type}\n")

        details_text.append(f"Manufacturer: ", style="bold")
        details_text.append(f"{device.manufacturer}\n")

        # If it's a tracker, add a warning section
        if device.is_airtag:
            tracker_type = device.get_tracker_type()
            details_text.append("\n")
            details_text.append(
                "⚠️  TRACKING DEVICE DETECTED  ⚠️", style="bold white on red"
            )
            details_text.append("\n")
            details_text.append(f"Tracker Type: ", style="bold red")
            details_text.append(f"{tracker_type}\n", style="bold red")

        # Signal Information Section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Signal Information", style="bold yellow")
        details_text.append("\n\n")

        details_text.append(f"RSSI Value: ", style="bold")
        rssi_style = (
            "green" if device.rssi > -70 else "yellow" if device.rssi > -85 else "red"
        )
        details_text.append(f"{device.rssi} dBm\n", style=rssi_style)

        details_text.append(f"Signal Quality: ", style="bold")
        quality = device.signal_quality
        quality_style = "green" if quality > 70 else "yellow" if quality > 40 else "red"
        details_text.append(f"{quality:.1f}%\n", style=quality_style)

        details_text.append(f"Signal Stability: ", style="bold")
        stability = device.signal_stability
        stability_style = (
            "green" if stability < 3 else "yellow" if stability < 6 else "red"
        )
        details_text.append(f"{stability:.1f}\n", style=stability_style)

        details_text.append(f"Estimated Distance: ", style="bold")
        distance = device.distance
        distance_label = f"{distance:.2f} meters"
        if distance < 1:
            distance_label += f" ({distance * 100:.0f} cm)"
        distance_style = (
            "green" if distance < 2 else "yellow" if distance < 5 else "red"
        )
        details_text.append(f"{distance_label}\n", style=distance_style)

        # Time Information
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Time Information", style="bold yellow")
        details_text.append("\n\n")

        details_text.append(f"First Seen: ", style="bold")
        first_seen_ago = time.time() - device.first_seen
        details_text.append(
            f"{time.strftime('%H:%M:%S', time.localtime(device.first_seen))} "
            f"({format_time_ago(first_seen_ago)} ago)\n"
        )

        details_text.append(f"Last Seen: ", style="bold")
        last_seen_ago = time.time() - device.last_seen
        details_text.append(
            f"{time.strftime('%H:%M:%S', time.localtime(device.last_seen))} "
            f"({format_time_ago(last_seen_ago)} ago)\n"
        )

        details_text.append(f"Tracked Duration: ", style="bold")
        details_text.append(f"{format_time_ago(device.seen_duration)}\n")

        # Technical Details Section
        details_text.append("\n◉ ", style="bold green")
        details_text.append("Technical Details", style="bold yellow")
        details_text.append("\n\n")

        # Extract as many details as we can
        extracted_details = device.device_details
        if extracted_details:
            details_text.append(f"Extracted Data: ", style="bold")
            details_text.append(f"{extracted_details}\n")

        # Service UUIDs
        if device.service_uuids:
            details_text.append(f"Service UUIDs: ", style="bold")
            details_text.append("\n")
            for i, uuid in enumerate(device.service_uuids):
                # Highlight known tracking UUIDs in red
                if any(known_uuid in uuid.upper() for known_uuid in FIND_MY_UUIDS):
                    details_text.append(f"  {i+1}. {uuid}", style="bold red")
                else:
                    details_text.append(f"  {i+1}. {uuid}")

                # Add service name if known
                uuid_short = uuid[-4:].upper()
                if uuid_short in DEVICE_TYPES:
                    details_text.append(f" - {DEVICE_TYPES[uuid_short]}")
                details_text.append("\n")

        # Manufacturer Data
        if device.manufacturer_data:
            details_text.append(f"Manufacturer Data: ", style="bold")
            details_text.append("\n")
            for company_id, data in device.manufacturer_data.items():
                company_name = COMPANY_IDENTIFIERS.get(
                    company_id, f"Unknown (0x{company_id:04X})"
                )
                details_text.append(f"  • {company_name}: ", style="bold")

                # Show first 16 bytes with possible interpretation
                hex_data = data.hex()
                details_text.append(f"{hex_data}\n")

                # Try to interpret the data
                try:
                    if company_id == 0x004C:  # Apple
                        if len(data) >= 2:
                            if data[0] == 0x12 and data[1] == 0x19:
                                details_text.append(
                                    "    ↳ Apple Find My Network Advertisement\n"
                                )
                            elif data[0] == 0x10:
                                details_text.append("    ↳ Apple Watch Advertisement\n")
                            elif data[0] == 0x07 and data[1] == 0x19:
                                details_text.append(
                                    "    ↳ AirPods Status Information\n"
                                )
                            elif data[0] == 0x02 and data[1] == 0x15:
                                details_text.append("    ↳ iBeacon Advertisement\n")
                except:
                    pass

        # Show in a panel
        detail_panel = Panel(
            details_text,
            title=f"[bold green]Detailed Device Info: {device.name or 'Unknown'}[/]",
            border_style="green",
            box=ROUNDED,
            width=100,
            expand=False,
        )

        self.console.print(detail_panel)

        # Show advice for trackers if applicable
        if device.is_airtag:
            tracker_advice = Panel(
                "\n".join(
                    [
                        "[bold white]This appears to be a tracking device.[/] If you don't recognize it, consider:",
                        "• Check if it's moving with you over time (could indicate unwanted tracking)",
                        "• Look for physical devices in your belongings, vehicle, etc.",
                        "• For AirTags: iPhone users will receive alerts, Android users can download Apple's Tracker Detect app",
                        "• For unknown trackers: Consider using a Bluetooth scanner app to locate the physical device",
                        "• Report suspicious tracking to local authorities",
                    ]
                ),
                title="[bold red]Tracker Detection Advice[/]",
                border_style="red",
                box=ROUNDED,
            )
            self.console.print(tracker_advice)

        # Wait for key press to continue
        self.console.print("\n[bold blue]Press any key to return...[/]")

        # Non-blocking wait for key press
        if sys.platform == "win32":
            import msvcrt

            msvcrt.getch()
        else:
            try:
                import termios
                import tty

                # Save old terminal settings
                old_settings = termios.tcgetattr(sys.stdin)
                try:
                    # Set terminal to raw mode
                    tty.setraw(sys.stdin.fileno(), termios.TCSANOW)
                    sys.stdin.read(1)
                finally:
                    # Restore terminal settings
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except:
                # Fallback if terminal handling fails
                input()

    def _show_raw_device_info(self, device_data):
        """Show raw device data when we can't convert to a Device object"""
        # Handle the case where we only have dictionary data

        # Create a formatted view of the device data
        details = []

        details.append(f"[bold]Name:[/] {device_data.get('name', 'Unknown')}")
        details.append(f"[bold]Address:[/] {device_data.get('address', 'Unknown')}")
        details.append(f"[bold]Type:[/] {device_data.get('device_type', 'Unknown')}")
        details.append(
            f"[bold]Manufacturer:[/] {device_data.get('manufacturer', 'Unknown')}"
        )
        details.append(f"[bold]RSSI:[/] {device_data.get('rssi', 'Unknown')}")

        if "distance" in device_data:
            distance = device_data["distance"]
            details.append(f"[bold]Estimated Distance:[/] {distance:.2f} meters")

        if "first_seen" in device_data:
            first_seen = device_data["first_seen"]
            first_seen_ago = time.time() - first_seen
            details.append(
                f"[bold]First Seen:[/] {time.strftime('%H:%M:%S', time.localtime(first_seen))} "
                f"({format_time_ago(first_seen_ago)} ago)"
            )

        if "last_seen" in device_data:
            last_seen = device_data["last_seen"]
            last_seen_ago = time.time() - last_seen
            details.append(
                f"[bold]Last Seen:[/] {time.strftime('%H:%M:%S', time.localtime(last_seen))} "
                f"({format_time_ago(last_seen_ago)} ago)"
            )

        if "is_airtag" in device_data and device_data["is_airtag"]:
            details.append(f"[bold red]⚠️ This appears to be a tracking device ⚠️[/]")

        # Display all available fields
        details.append("\n[bold cyan]All available data:[/]")
        for key, value in device_data.items():
            if key not in [
                "name",
                "address",
                "device_type",
                "manufacturer",
                "rssi",
                "distance",
                "first_seen",
                "last_seen",
                "is_airtag",
                "manufacturer_data",
                "service_data",
                "service_uuids",
            ]:
                details.append(f"[bold]{key}:[/] {value}")

        # Create a panel to show the details
        detail_panel = Panel(
            "\n".join(details),
            title=f"[bold green]Device Information[/]",
            border_style="green",
            box=ROUNDED,
        )

        self.console.print(detail_panel)

        # Wait for key press to continue
        self.console.print("\n[bold blue]Press any key to return...[/]")

        # Non-blocking wait for key press
        if sys.platform == "win32":
            import msvcrt

            msvcrt.getch()
        else:
            try:
                import termios
                import tty

                old_settings = termios.tcgetattr(sys.stdin)
                try:
                    tty.setraw(sys.stdin.fileno(), termios.TCSANOW)
                    sys.stdin.read(1)
                finally:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except:
                input()

    async def discovery_callback(self, device, advertisement_data):
        """Callback for BleakScanner when a device is discovered"""
        # Check if this is a new device
        is_new_device = device.address not in self.devices

        if is_new_device:
            # Create new device instance
            self.devices[device.address] = Device(
                address=device.address,
                name=device.name,
                rssi=advertisement_data.rssi,
                manufacturer_data=advertisement_data.manufacturer_data,
                service_data=advertisement_data.service_data,
                service_uuids=advertisement_data.service_uuids,
            )

            # Assign a persistent device ID if it doesn't have one yet
            if device.address not in self.device_ids:
                self.device_ids[device.address] = self.next_device_id
                self.next_device_id += 1
        else:
            # Update existing device with new data
            self.devices[device.address].update(
                rssi=advertisement_data.rssi,
                manufacturer_data=advertisement_data.manufacturer_data,
                service_data=advertisement_data.service_data,
                service_uuids=advertisement_data.service_uuids,
            )

            # Apply adaptive calibration if enabled
            if self.adaptive_mode:
                # If signal is strong and we can assume it's close
                dev = self.devices[device.address]
                if dev.rssi > -55 and dev.signal_stability < 3.0:
                    # Device is probably around 1m, adjust RSSI@1m
                    dev.calibrated_rssi_at_one_meter = dev.smooth_rssi

    async def calibrate_device(self, device: Device):
        """Calibrate the selected device"""
        # Clear terminal before calibration
        self.console.clear()

        # Restore terminal settings for proper input
        if sys.platform != "win32":
            try:
                import termios
                import tty

                old_settings = termios.tcgetattr(sys.stdin)
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except:
                pass

        self.console.print(
            Panel.fit(
                f"[bold green]Calibrating Device: {device.name}[/]",
                title="Calibration Mode",
                border_style="green",
            )
        )

        self.console.print("\n[bold]Device Information:[/]")
        self.console.print(f"  Name: {device.name}")
        self.console.print(f"  Type: {device.device_type}")
        self.console.print(f"  Address: {device.address}")
        self.console.print(f"  Current RSSI: {device.rssi} dBm")
        self.console.print(f"  Current distance estimate: {device.distance:.2f} meters")

        self.console.print(
            "\n[bold yellow]Place the device at a known distance and enter the distance in meters:[/]"
        )

        try:
            distance = float(self.console.input("[bold]Distance (meters): [/]"))
            if distance <= 0:
                self.console.print("[bold red]Distance must be positive[/]")
                return

            # Collect multiple RSSI readings
            self.console.print(
                f"[yellow]Collecting RSSI readings at {distance}m distance...[/]"
            )

            # Start a quick scan to collect fresh readings
            scanner_kwargs = {}
            if self.current_adapter:
                scanner_kwargs["adapter"] = self.current_adapter

            # Scan for a few seconds to get fresh readings for Linux
            if sys.platform.startswith("linux"):
                # On Linux, use a different approach to avoid BlueZ errors
                try:
                    # Create a scanner without starting it immediately
                    scanner = BleakScanner(**scanner_kwargs)

                    # Collect readings over time without starting/stopping scanner multiple times
                    for _ in range(5):
                        # Just wait and let the discovery_callback update the device
                        await asyncio.sleep(1.0)
                        # Check if the device is still in our devices dictionary
                        if device.address in self.devices:
                            updated_device = self.devices[device.address]
                            self.console.print(
                                f"Current RSSI: {updated_device.rssi} dBm"
                            )
                        else:
                            self.console.print(
                                "[yellow]Device not in range, waiting...[/]"
                            )
                except Exception as e:
                    self.console.print(f"[yellow]Warning during calibration: {e}[/]")
            else:
                # For other platforms, use the original approach
                try:
                    async with BleakScanner(**scanner_kwargs) as scanner:
                        # Wait for some readings
                        for _ in range(5):
                            # Scan for the specific device
                            discovered = await scanner.find_device_by_address(
                                device.address, timeout=1.0
                            )
                            if discovered:
                                self.console.print(f"Current RSSI: {device.rssi} dBm")
                            await asyncio.sleep(1)
                except Exception as e:
                    self.console.print(f"[yellow]Warning during calibration: {e}[/]")

            if device.calibrate_distance(distance):
                self.console.print(f"[bold green]Calibration successful:[/]")
                self.console.print(f"  N-Value: {device.calibrated_n_value:.2f}")
                self.console.print(f"  RSSI@1m: {device.calibrated_rssi_at_one_meter}")

                # Update global settings with new calibration values
                self.settings["distance_n_value"] = device.calibrated_n_value
                self.settings["rssi_at_one_meter"] = device.calibrated_rssi_at_one_meter
                self._save_settings()

                # Also update any device-specific calibration
                if "device_calibration" not in self.settings:
                    self.settings["device_calibration"] = {}

                self.settings["device_calibration"][device.address] = {
                    "n_value": device.calibrated_n_value,
                    "rssi_at_one_meter": device.calibrated_rssi_at_one_meter,
                    "name": device.name,
                    "type": device.device_type,
                }
                self._save_settings()
            else:
                self.console.print("[bold red]Calibration failed[/]")

            # Wait for user to press a key before continuing
            self.console.print("\n[yellow]Press any key to continue...[/]")
            if sys.platform == "win32":
                import msvcrt

                msvcrt.getch()
            else:
                sys.stdin.read(1)

            # Clear terminal after calibration is finished
            self.console.clear()
        except ValueError:
            self.console.print("[bold red]Invalid distance value[/]")

    async def start_scan(self):
        """Start BLE scanning with enhanced parameters for maximum range"""
        # Clear terminal before starting scan
        self.console.clear()

        # Start a fresh scan with no devices
        self.devices = {}
        self.scanning = True
        self.selected_device = None
        self.selection_mode = False
        self.cursor_position = 0

        # Note: We intentionally don't reset device_ids here to maintain
        # the same IDs for devices discovered in subsequent scans

        # Set up scanner with advanced parameters
        scanner_kwargs = {}

        # Use specific adapter if available
        if self.current_adapter:
            scanner_kwargs["adapter"] = self.current_adapter

        # Apply advanced scanning parameters from settings or defaults
        scan_settings = self.settings.get("scan_parameters", SCAN_PARAMETERS)

        # Set scanning mode (active scans get more data but less range sometimes)
        scanner_kwargs["scanning_mode"] = self.settings.get("scan_mode", SCAN_MODE)

        # Set detection callback and timeout
        scanner_kwargs["detection_callback"] = self.discovery_callback
        scanner_kwargs["timeout"] = scan_settings.get(
            "timeout", SCAN_PARAMETERS["timeout"]
        )

        # Set additional platform-specific parameters where possible
        if hasattr(bleak.backends, "bluezdbus") and sys.platform.startswith("linux"):
            # For Linux systems with BlueZ - can set more aggressive parameters
            scanner_kwargs["bluez"] = {
                "interval": scan_settings.get("interval", SCAN_PARAMETERS["interval"]),
                "window": scan_settings.get("windown", SCAN_PARAMETERS["windown"]),
                "passive": not scan_settings.get("active", SCAN_PARAMETERS["active"]),
            }
        elif hasattr(bleak.backends, "corebluetooth") and sys.platform == "darwin":
            # For macOS systems - can set some CoreBluetooth parameters
            # CoreBluetooth doesn't expose as many parameters as BlueZ
            scanner_kwargs["cb"] = {
                "use_bdaddr": True,  # Use Bluetooth address when available
                "duration": SCAN_DURATION,  # Duration in seconds for scan
            }

        try:
            self.console.print("[green]Starting enhanced range scan...[/]")
            self.console.print(
                f"[yellow]Adapter: {self.current_adapter or 'Default'}[/]"
            )
            self.console.print(
                f"[yellow]Mode: {scanner_kwargs.get('scanning_mode', 'Default')}[/]"
            )

            # Handle Linux BlueZ backend specifically to avoid InProgress errors
            if sys.platform.startswith("linux"):
                scanner = None
                try:
                    # Create scanner without starting it yet
                    scanner = BleakScanner(**scanner_kwargs)
                    # Start scanning explicitly
                    await scanner.start()
                    self.last_scan_refresh = time.time()

                    # Use Rich Live display to update the UI
                    with Live(self._update_ui(), refresh_per_second=4) as live:
                        while self.scanning:
                            # Update UI with our new scanning layout
                            live.update(self._update_ui())

                            # Handle input processing
                            await self._process_input()

                            # Periodically refresh the scan on Linux
                            if time.time() - self.last_scan_refresh > SCAN_DURATION:
                                try:
                                    # Restart scanner carefully to avoid BlueZ errors
                                    await scanner.stop()
                                    await asyncio.sleep(1.0)  # Allow BlueZ to settle
                                    await scanner.start()
                                    self.last_scan_refresh = time.time()
                                    self.console.print(
                                        "[yellow]Refreshing scan...[/]", end="\r"
                                    )
                                except Exception as e:
                                    self.console.print(
                                        f"[yellow]Scan refresh warning: {e}[/]",
                                        end="\r",
                                    )
                                    self.last_scan_refresh = (
                                        time.time()
                                    )  # Still update time to avoid rapid retries

                            # Short sleep to avoid high CPU usage
                            await asyncio.sleep(0.1)
                finally:
                    # Ensure scanner is properly closed
                    if scanner is not None:
                        try:
                            await scanner.stop()
                        except Exception:
                            pass
            else:
                # For non-Linux platforms, use the original approach
                async with BleakScanner(**scanner_kwargs) as scanner:
                    # Use Rich Live display to update the UI
                    with Live(self._update_ui(), refresh_per_second=4) as live:
                        while self.scanning:
                            # Update UI with our new scanning layout
                            live.update(self._update_ui())

                            # Handle input processing
                            await self._process_input()

                            # Periodically refresh the scanner to improve detection rate
                            if hasattr(self, "last_scan_refresh"):
                                time_since_refresh = (
                                    time.time() - self.last_scan_refresh
                                )
                                if time_since_refresh > SCAN_DURATION:
                                    # Restart scanner periodically to prevent device cache issues
                                    await scanner.stop()
                                    await asyncio.sleep(0.5)
                                    await scanner.start()
                                    self.last_scan_refresh = time.time()
                                    self.console.print(
                                        "[yellow]Refreshing scan...[/]", end="\r"
                                    )
                            else:
                                self.last_scan_refresh = time.time()

                            # Short sleep to avoid high CPU usage
                            await asyncio.sleep(0.1)
        finally:
            # Clear the terminal when finishing scan
            self.console.clear()

            # Save results to history
            await self._save_history()

            # Handle calibration if flagged
            if (
                self.calibration_mode
                and self.selected_device
                and self.selected_device in self.devices
            ):
                await self.calibrate_device(self.devices[self.selected_device])
                self.calibration_mode = False

    async def _process_input(self):
        """Process keyboard input non-blockingly"""
        # Clear input buffer if it's been more than 3 seconds since last keypress
        if (
            hasattr(self, "input_buffer")
            and self.input_buffer
            and time.time() - self.last_key_time > 3.0
        ):
            self.input_buffer = ""

        # Simple non-blocking keyboard input
        if sys.platform == "win32":
            # Windows-specific input handling
            if msvcrt.kbhit():
                key = msvcrt.getch().decode().lower()
                await self._handle_key_input(key)
        else:
            # Unix-like systems (Mac/Linux)
            try:
                # Put terminal in raw mode to read keys without needing Enter
                import termios
                import tty

                # Save old terminal settings
                old_settings = termios.tcgetattr(sys.stdin)
                try:
                    # Set terminal to raw mode
                    tty.setraw(sys.stdin.fileno(), termios.TCSANOW)

                    # Check if there's input available without blocking
                    rlist, _, _ = select.select([sys.stdin], [], [], 0)
                    if rlist:
                        key = sys.stdin.read(1).lower()
                        await self._handle_key_input(key)
                finally:
                    # Restore terminal settings
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except (ImportError, termios.error):
                # Fall back to regular input if terminal handling fails
                rlist, _, _ = select.select([sys.stdin], [], [], 0)
                if rlist:
                    key = sys.stdin.read(1).lower()
                    await self._handle_key_input(key)

    async def _handle_key_input(self, key):
        """Handle keyboard input during scanning"""
        # Always handle these keys
        if key == "q":
            self.scanning = False
        elif key == "b":
            self.selected_device = None
            self.input_buffer = ""  # Clear input buffer
            self.selection_mode = False
        elif key == "t":  # Enter tab selection mode
            self.selection_mode = True
            self.cursor_position = 0
        elif key == "\t" or key == " ":  # Tab or space to navigate to next device
            if (
                self.selection_mode
                and hasattr(self, "sorted_device_list")
                and len(self.sorted_device_list) > 0
            ):
                self.cursor_position = (self.cursor_position + 1) % len(
                    self.sorted_device_list
                )
        elif key == "\r" or key == "\n":  # Enter to select the device under cursor
            if self.selection_mode and hasattr(self, "cursor_device"):
                self.selected_device = self.cursor_device
                self.selection_mode = False
        elif key.isdigit():
            # Start buffer or append to existing
            if time.time() - self.last_key_time < 2.0:
                # Within 2 seconds, append to current buffer
                self.input_buffer += key
            else:
                # Start new input buffer
                self.input_buffer = key

            self.last_key_time = time.time()

            # Try to process the input buffer
            try:
                device_idx = int(self.input_buffer)

                # Check if this device exists in our map
                if device_idx in self.device_map:
                    # Valid device ID - select it
                    self.selected_device = self.device_map[device_idx]
                    # Clear buffer only after successful selection
                    self.input_buffer = ""
                    self.selection_mode = False
            except ValueError:
                # Invalid buffer content
                pass

    def _update_ui(self) -> Layout:
        """Update the UI layout"""
        if self.scanning:
            # Create scanning-specific layout
            scanning_layout = Layout()

            # Create a combined control and settings panel for the header
            airtag_mode = "[green]ON[/]" if self.airtag_only_mode else "[red]OFF[/]"
            adaptive_mode = "[green]ON[/]" if self.adaptive_mode else "[red]OFF[/]"
            calibration_mode = (
                "[green]ON[/]" if self.calibration_mode else "[red]OFF[/]"
            )

            # Calculate scan duration if we've been scanning
            scan_time = time.time() - min(
                [d.first_seen for d in self.devices.values()], default=time.time()
            )
            scan_duration = f"[bold green]{scan_time:.1f}s[/]"
            device_count = len(self.devices)

            # Create the scanning controls panel
            # Check if a device is selected
            selected_info = ""
            input_status = ""

            # Show current input buffer if there's something in it
            if hasattr(self, "input_buffer") and self.input_buffer:
                input_status = (
                    f"\n[bold magenta]◉ SELECTING DEVICE ID: {self.input_buffer} ◉[/]"
                )

            # Show selection mode status
            if self.selection_mode:
                selection_info = f"\n[bold green]◉ TAB SELECTION MODE: Use Tab to navigate, Enter to select ◉[/]"
                if not input_status:
                    input_status = selection_info
                else:
                    input_status += selection_info

            # Show selected device info
            if self.selected_device and self.selected_device in self.devices:
                selected_device = self.devices[self.selected_device]
                selected_info = f"\n[bold yellow]Selected device:[/] {selected_device.name} ({selected_device.address[-8:]})"

            # Create a control panel with just the controls
            controls_panel = Panel(
                "\n".join(
                    [
                        "[bold cyan]Controls:[/]",
                        " [bold blue]q[/] - Quit scanning and save",
                        " [bold blue]0-9[/] - Select device by ID [italic](persistent IDs)[/]",
                        " [bold blue]t[/] - Enter tab selection mode",
                        " [bold blue]Tab/Space[/] - Navigate devices in tab mode",
                        " [bold blue]Enter[/] - Select highlighted device",
                        " [bold blue]b[/] - Back to all devices",
                        "",
                        f"{input_status.strip() if input_status else ''}",
                    ]
                ),
                title="[bold blue]TagFinder Controls[/]",
                border_style="blue",
                box=ROUNDED,
                expand=True,
            )

            # Create a settings panel with current settings and status
            settings_panel = Panel(
                "\n".join(
                    [
                        f"[bold]Status:[/] [green]Scanning...[/]",
                        f"[bold]Duration:[/] {scan_duration}",
                        f"[bold]Devices found:[/] {device_count}",
                        "",
                        f"[bold]AirTag mode:[/] {airtag_mode}",
                        f"[bold]Adaptive:[/] {adaptive_mode}",
                        f"[bold]Calibration:[/] {calibration_mode}",
                        f"[bold]Adapter:[/] {self.current_adapter or 'Default'}",
                        "",
                        f"{selected_info.strip() if selected_info else ''}",
                    ]
                ),
                title="[bold green]Current Settings[/]",
                border_style="green",
                box=ROUNDED,
                expand=True,
            )

            # Create a layout for the top area that holds both panels side by side
            top_panel = Layout()
            top_panel.split_row(
                Layout(name="controls_panel", ratio=1),
                Layout(name="settings_panel", ratio=1),
            )

            top_panel["controls_panel"].update(controls_panel)
            top_panel["settings_panel"].update(settings_panel)

            # Create the main scanning layout
            if self.selected_device and self.selected_device in self.devices:
                # When a device is selected, show detailed view with controls, details and table
                scanning_layout.split(
                    Layout(name="controls", size=12),
                    Layout(name="main_content", ratio=1),
                )

                # Split the main content area to show device details and table
                scanning_layout["main_content"].split_row(
                    Layout(name="device_details", ratio=2),
                    Layout(name="devices", ratio=3),
                )

                scanning_layout["controls"].update(top_panel)
                scanning_layout["device_details"].update(
                    self.generate_device_details(self.devices[self.selected_device])
                )
                scanning_layout["devices"].update(
                    self.generate_device_table(self.devices)
                )
            else:
                # Normal layout when no device is selected
                scanning_layout.split(
                    Layout(name="controls", size=12),
                    Layout(name="devices", ratio=1),
                )

                scanning_layout["controls"].update(top_panel)
                scanning_layout["devices"].update(
                    self.generate_device_table(self.devices)
                )

            return scanning_layout
        else:
            # Use normal layout when not scanning
            # Create a simplified header for the top
            self.layout["header"].update(
                Panel(
                    f"[bold cyan]TagFinder[/] - Bluetooth Device Scanner",
                    style="bold",
                    box=SIMPLE,
                )
            )

            # Update devices table with responsive layout
            self.layout["devices"].update(self.generate_device_table(self.devices))

            # The footer now might return a Layout object instead of a Panel if in split mode
            status_panel = self.generate_status_panel()
            self.layout["footer"].update(status_panel)

            # Update device details if a device is selected
            if self.selected_device and self.selected_device in self.devices:
                self.layout["details"].visible = True
                self.layout["details"].update(
                    self.generate_device_details(self.devices[self.selected_device])
                )
            else:
                self.layout["details"].visible = False

            return self.layout

    async def main(self):
        """Main application entry point"""
        # Clear terminal at startup
        self.console.clear()

        self.console.print(
            Panel.fit("[bold cyan]TagFinder - Bluetooth Device Scanner[/]", box=ROUNDED)
        )

        # Initialize with settings
        if "adapter" in self.settings:
            self.current_adapter = self.settings["adapter"]

        # Apply custom calibration values if available
        if "distance_n_value" in self.settings:
            DEFAULT_DISTANCE_N_VALUE = self.settings["distance_n_value"]
        if "rssi_at_one_meter" in self.settings:
            DEFAULT_RSSI_AT_ONE_METER = self.settings["rssi_at_one_meter"]

        while True:
            # Display status and wait for command
            self.console.print(self.generate_status_panel())
            cmd = self.console.input("[bold blue]Enter command: [/]").strip().lower()

            if cmd == "q":
                # Save any unsaved settings before exit
                self._save_settings()
                # Clear terminal before exit
                self.console.clear()
                break
            elif cmd == "s":
                self.console.print("[green]Starting scan... Press 'q' to stop.[/]")
                await self.start_scan()
            elif cmd == "a":
                # Clear terminal before toggle
                self.console.clear()
                self.airtag_only_mode = not self.airtag_only_mode
                self.settings["airtag_only_mode"] = self.airtag_only_mode
                self._save_settings()
                self.console.print(
                    f"[bold]AirTag only mode: {'[green]ON[/]' if self.airtag_only_mode else '[red]OFF[/]'} - Settings saved"
                )
            elif cmd == "d":
                # Clear terminal before toggle
                self.console.clear()
                self.adaptive_mode = not self.adaptive_mode
                self.settings["adaptive_mode"] = self.adaptive_mode
                self._save_settings()
                self.console.print(
                    f"[bold]Adaptive distance: {'[green]ON[/]' if self.adaptive_mode else '[red]OFF[/]'} - Settings saved"
                )
            elif cmd == "l":
                await self.list_adapters()
                # Settings are saved in list_adapters() if adapter is changed
            elif cmd == "z":
                # Run enhanced summary with options
                self.summarize_findings()
            elif cmd == "c":
                # Clear terminal before toggle
                self.console.clear()
                self.calibration_mode = not self.calibration_mode
                self.settings["calibration_mode"] = self.calibration_mode
                self._save_settings()
                self.console.print(
                    f"[bold]Calibration mode: {'[green]ON[/]' if self.calibration_mode else '[red]OFF[/]'} - Settings saved"
                )
            else:
                # Clear terminal before showing error
                self.console.clear()
                self.console.print(
                    "[yellow]Unknown command. Use 's', 'a', 'd', 'c', 'l', 'z', or 'q'.[/]"
                )

        self.console.print("[green]Exiting TagFinder...[/]")


if __name__ == "__main__":
    try:
        # Enable asyncio for terminal input on Windows
        if sys.platform == "win32":
            import msvcrt

            asyncio.get_event_loop_policy().set_event_loop(asyncio.ProactorEventLoop())

        finder = TagFinder()
        asyncio.run(finder.main())
    except KeyboardInterrupt:
        print("\n[green]Exiting TagFinder...[/]")
    except Exception as e:
        print(f"[bold red]Error: {e}[/]")
