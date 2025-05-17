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

# Import OrPattern for passive scanning on Linux
from bleak.backends.bluezdbus.advertisement_monitor import OrPattern
from bleak.assigned_numbers import AdvertisementDataType


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
    "airtag",
    "find my",
    "apple tag",
    "locate me",
    "findmy",
]  # Focused identifiers for AirTags and Find My devices
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
    "74278BDA-B644",
    "FD-44",
    "D0611E78",
    "9FA480E0",
    "FD5A",
    "8667556C",
]  # Apple and other tracker related UUIDs
SCAN_INTERVAL = 0.5  # Scan interval in seconds (reduced for more frequent updates)
DEFAULT_RSSI_AT_ONE_METER = -59  # Default RSSI at 1 meter for Bluetooth LE
DEFAULT_DISTANCE_N_VALUE = 2.0  # Default environmental factor for distance calculation
RSSI_HISTORY_SIZE = 20  # Increased number of RSSI readings to keep for better smoothing
SCAN_MODE = "active"  # Can be "active" or "passive"
SCAN_DURATION = 15.0  # Increased duration of each scan in seconds to catch more devices
DETECTION_THRESHOLD = -95  # Lowered RSSI threshold for detecting more distant devices
NEW_DEVICE_TIMEOUT = 300  # Time in seconds to display a device as "NEW" (5 minutes)
SCAN_PARAMETERS = {
    "timeout": 10.0,  # Increased timeout for scanning
    "window": 0x0100,  # Window parameter for scanning
    "interval": 0x0040,  # Reduced interval for more aggressive scanning
    "filters": None,  # No filters for maximum detection
    "active": True,  # Active scanning for more data
    "extended": True,  # Use extended scanning where available
    "passive_workaround": True,  # Try passive scanning if active fails to find devices
}

# Additional scanning parameters for maximum range
ADVANCED_SCAN_SETTINGS = {
    "multi_adapter": True,  # Try to use multiple Bluetooth adapters if available
    "extended_retries": 3,  # Number of retries for extended range
    "combine_results": True,  # Combine results from different scan methods
    "use_extended_features": True,  # Use extended BLE features on supported platforms
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

# Add more confidence levels to tracker detection
TRACKING_CONFIDENCE = {"CONFIRMED": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNLIKELY": 4}

# Add detection patterns for Apple Find My network
FIND_MY_DATA_PATTERNS = [
    {"offset": 0, "value": 0x12, "mask": 0xFF},  # First byte 0x12
    {"offset": 1, "value": 0x19, "mask": 0xFF},  # Second byte 0x19
    {"offset": 0, "value": 0x10, "mask": 0xFF},  # First byte 0x10 (alternate pattern)
    {"offset": 0, "value": 0x0F, "mask": 0xFF},  # First byte 0x0F (another pattern)
]


class Device:
    def __init__(
        self,
        address: str,
        name: str,
        rssi: int,
        manufacturer_data: Optional[Dict] = None,
        service_data: Optional[Dict] = None,
        service_uuids: Optional[List] = None,
        is_new: bool = False,
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
        self.tracker_confidence = self._calculate_tracker_confidence()
        self.calibrated_n_value = DEFAULT_DISTANCE_N_VALUE
        self.calibrated_rssi_at_one_meter = DEFAULT_RSSI_AT_ONE_METER
        self.is_new = is_new  # Flag to mark if this is a newly discovered device

        # For proximity tracking
        self.previous_distance = None
        self.distance_trend = []  # Stores recent distance changes
        self.last_trend_update = time.time()

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
        is_new: Optional[bool] = None,
    ):
        self.rssi = rssi
        self.rssi_history.append(rssi)
        if manufacturer_data:
            self.manufacturer_data = manufacturer_data
        if service_data:
            self.service_data = service_data
        if service_uuids:
            self.service_uuids = service_uuids
        if is_new is not None:
            self.is_new = is_new
        self.last_seen = time.time()

        # Recalculate tracker detection with new data
        self.is_airtag = self._check_if_airtag()
        self.tracker_confidence = self._calculate_tracker_confidence()

        # Update extracted information
        self.manufacturer = self._extract_manufacturer()
        self.device_type = self._extract_device_type()
        self.device_details = self._extract_detailed_info()

        # Update proximity trend if this device has been tracked before
        if self.previous_distance is not None:
            self.update_proximity_trend()

    def _extract_manufacturer(self) -> str:
        """Extract manufacturer information from BLE advertisement data"""
        # First check for official manufacturer ID (most reliable)
        for company_id in self.manufacturer_data:
            if company_id in COMPANY_IDENTIFIERS:
                return COMPANY_IDENTIFIERS[company_id]

        # Be very conservative with name-based identification
        if self.name:
            name_lower = self.name.lower()

            # Only use exact manufacturer names that are very unlikely to be ambiguous
            exact_manufacturer_matches = {
                "apple": "Apple",
                "iphone": "Apple",
                "macbook": "Apple",
                "airpods": "Apple",
                "airtag": "Apple",
                "samsung": "Samsung",
                "galaxy": "Samsung",
                "huawei": "Huawei",
                "xiaomi": "Xiaomi",
                "sony": "Sony",
                "bose": "Bose",
                "fitbit": "Fitbit",
                "garmin": "Garmin",
                "tile": "Tile",
            }

            # Check for exact name matches only
            for keyword, manufacturer in exact_manufacturer_matches.items():
                # Use exact word boundaries to avoid false positives
                if keyword == name_lower or f" {keyword} " in f" {name_lower} ":
                    return manufacturer

            # For devices with clear model designations
            if (
                name_lower.startswith("iphone")
                or name_lower.startswith("ipad")
                or name_lower.startswith("macbook")
            ):
                return "Apple"

        # Check MAC address OUI (first three bytes) - only for well-known Apple prefixes
        if ":" in self.address:
            apple_ouis = ["ac:de:48", "a8:86:dd", "a4:83:e7", "7c:d1:c3", "f0:dc:e2"]
            address_start = self.address.lower()[:8]  # Get first 3 bytes with colons
            if any(address_start.startswith(oui) for oui in apple_ouis):
                return "Apple"

        # Default to Unknown if we don't have high confidence
        return "Unknown"

    def _extract_device_type(self) -> str:
        """Extract device type from BLE advertisement data"""
        device_type = "Unknown"

        # Start with the most reliable signals: Apple device type flags
        if 76 in self.manufacturer_data and len(self.manufacturer_data[76]) > 2:
            apple_type_byte = self.manufacturer_data[76][2] & 0x0F
            if apple_type_byte in APPLE_DEVICE_TYPES:
                # This is very reliable - use it
                device_type = APPLE_DEVICE_TYPES[apple_type_byte]

                # For AirPods, get more specific model if available
                if apple_type_byte == 0x09 and len(self.manufacturer_data[76]) >= 4:
                    model_byte = self.manufacturer_data[76][3] & 0x0F
                    airpod_types = {
                        0x01: "AirPods 1st Gen",
                        0x02: "AirPods 2nd Gen",
                        0x03: "AirPods Pro",
                        0x04: "AirPods Max",
                        0x05: "AirPods 3rd Gen",
                    }
                    if model_byte in airpod_types:
                        return airpod_types[model_byte]

        # Check service UUIDs for known device types (reliable for standardized services)
        if self.service_uuids:
            service_type_mapping = {
                "180D": "Heart Rate Monitor",
                "1826": "Fitness Equipment",
                "183A": "Environmental Sensor",
                "181A": "Environmental Sensor",
                "1819": "Location Tracker",
                "FDCD": "Tile Tracker",
                "FD5A": "Samsung SmartTag",
            }

            for uuid in self.service_uuids:
                uuid_short = uuid[-4:].upper()
                if uuid_short in service_type_mapping:
                    return service_type_mapping[uuid_short]

        # Name-based identification (only for very specific, clear device names)
        if self.name:
            name_lower = self.name.lower()

            # Precise Apple product identification
            if name_lower == "airtag" or (
                len(name_lower) >= 6 and name_lower.startswith("airtag ")
            ):
                return "AirTag"

            # Use exact matches with distinctive product names
            if name_lower.startswith("airpods pro"):
                return "AirPods Pro"
            elif name_lower.startswith("airpods max"):
                return "AirPods Max"
            elif name_lower.startswith("airpods"):
                return "AirPods"

            # Distinctive Samsung products
            if name_lower.startswith("galaxy buds"):
                return "Samsung Galaxy Buds"
            elif name_lower == "galaxy smarttag" or name_lower == "smarttag":
                return "Samsung SmartTag"

            # Specific tracker products
            if name_lower == "tile" or name_lower.startswith("tile "):
                return "Tile Tracker"
            elif name_lower == "chipolo" or name_lower.startswith("chipolo "):
                return "Chipolo Tracker"

        # Check manufacturer data for company-specific device bytes (for known formats)
        for company_id in self.manufacturer_data:
            data = self.manufacturer_data[company_id]

            # Samsung devices with known format
            if company_id == 0x0075 and len(data) > 3:
                samsung_device_types = {
                    0x01: "Samsung Phone",
                    0x02: "Samsung Tablet",
                    0x03: "Samsung Watch",
                    0x04: "Samsung Buds",
                    0x05: "Samsung SmartTag",
                }
                device_byte = data[2] if len(data) > 2 else 0
                if device_byte in samsung_device_types:
                    return samsung_device_types[device_byte]

            # Apple iBeacon format
            if (
                company_id == 0x004C
                and len(data) >= 23
                and data[0] == 0x02
                and data[1] == 0x15
            ):
                return "iBeacon"

            # Tile tracker
            if company_id == 0x02D0:
                return "Tile Tracker"

            # Chipolo tracker
            if company_id == 0x010C:
                return "Chipolo Tracker"

        # If we got a device type from Apple manufacturer data but didn't find anything more specific
        if device_type != "Unknown":
            return device_type

        # Return a generic BLE device type
        return "BLE Device"

    def _extract_detailed_info(self) -> str:
        """Extract detailed information from BLE advertisement data"""
        details = []

        # Check if this is a new device AND it's within the timeout period
        # Only show NEW label for specified timeout period
        if (
            getattr(self, "is_new", False)
            and time.time() - getattr(self, "first_seen", time.time())
            <= NEW_DEVICE_TIMEOUT
        ):
            details.append("NEW DEVICE")

        # Don't add tracking device info to details anymore - we show this in the Track Prob column

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
                                details.append("Separated")
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
                                    f"Batt: L:{left_battery*10}% R:{right_battery*10}% C:{case_battery*10}%"
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
                        status_info = []
                        if watch_status & 0x01:
                            status_info.append("Unlocked")
                        if watch_status & 0x02:
                            status_info.append("Active")
                        if status_info:
                            details.append(f"Watch: {', '.join(status_info)}")

                        watch_battery = apple_data[7] & 0x0F
                        if watch_battery <= 10:
                            details.append(f"Battery: {watch_battery*10}%")

                    # iPhone/iPad info
                    elif apple_data[0] == 0x0C and len(apple_data) >= 5:
                        phone_status = apple_data[4]
                        if phone_status & 0x01:
                            details.append("Status: Unlocked")
                except:
                    pass

        # Extract battery information - prioritize this
        battery_info = None
        for uuid, data in self.service_data.items():
            if "180F" in uuid.upper():  # Battery Service
                try:
                    if len(data) >= 1:
                        battery = data[0]
                        battery_info = f"Battery: {battery}%"
                except:
                    pass

        if battery_info:
            details.append(battery_info)

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
                    # Extract Major and Minor values
                    major = (data[18] << 8) | data[19]
                    minor = (data[20] << 8) | data[21]
                    details.append(f"iBeacon: {major}.{minor}")
                except:
                    details.append("iBeacon")

        # Add tx power if available and not already showing battery
        if (
            "180A" in [uuid[-4:].upper() for uuid in self.service_uuids]
            and not battery_info
        ):
            # Only show Tx power if we don't have battery info
            details.append("Tx Power: Standard")

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

        # Make string from details
        if details:
            return " | ".join(details)
        return ""

    def _check_if_airtag(self) -> bool:
        """Check if device is potentially an AirTag or other tracking device with enhanced detection"""
        # Store verification flags with confidence levels
        evidence = {
            "name_match": False,
            "apple_manufacturer": False,
            "find_my_pattern": False,
            "airtag_pattern": False,
            "known_uuid": False,
            "service_data": False,
            "nearby_interaction": False,
        }

        # Check manufacturer first - must be Apple for AirTags
        if 76 in self.manufacturer_data:  # Apple's company identifier (0x004C)
            evidence["apple_manufacturer"] = True

            # Now check Apple-specific data patterns with high confidence
            data = self.manufacturer_data[76]

            # Only proceed with pattern matching if we have enough data
            if len(data) > 2:
                # Check all known Find My patterns
                for pattern in FIND_MY_DATA_PATTERNS:
                    offset = pattern["offset"]
                    value = pattern["value"]
                    mask = pattern["mask"]

                    if offset < len(data) and (data[offset] & mask) == value:
                        evidence["find_my_pattern"] = True
                        break

                # Exact Find My network pattern (highest confidence)
                if len(data) > 1 and data[0] == 0x12 and data[1] == 0x19:
                    evidence["find_my_pattern"] = True

                    # Exact AirTag identifier pattern
                    if len(data) > 3 and data[2] & 0x0F == 0x0A:  # AirTag type is 0x0A
                        evidence["airtag_pattern"] = True

                # Check for Nearby Interaction protocol (also used by Find My)
                if len(data) > 2 and data[0] == 0x0F:
                    evidence["nearby_interaction"] = True

        # If name contains clear AirTag identifiers
        if self.name and any(
            identifier in self.name.lower() for identifier in AIRTAG_IDENTIFIERS
        ):
            evidence["name_match"] = True

        # Check for Find My Network specific UUIDs (high confidence indicators)
        for uuid in self.service_uuids:
            uuid_upper = uuid.upper()
            for find_my_id in FIND_MY_UUIDS:
                if find_my_id in uuid_upper:
                    evidence["known_uuid"] = True
                    break

        # Check for specific service data patterns related to Find My network
        for service_uuid, _ in self.service_data.items():
            service_uuid_upper = service_uuid.upper()
            if any(find_my_id in service_uuid_upper for find_my_id in FIND_MY_UUIDS):
                evidence["service_data"] = True
                break

        # Apply decision rules for classification:

        # Definite AirTag/Find My device (extremely high confidence)
        if (
            (evidence["apple_manufacturer"] and evidence["find_my_pattern"])
            or (evidence["apple_manufacturer"] and evidence["airtag_pattern"])
            or (
                evidence["apple_manufacturer"]
                and evidence["known_uuid"]
                and evidence["name_match"]
            )
            or (
                evidence["apple_manufacturer"]
                and evidence["nearby_interaction"]
                and evidence["known_uuid"]
            )
        ):
            return True

        # High confidence Find My device
        if (
            (evidence["apple_manufacturer"] and evidence["known_uuid"])
            or (evidence["apple_manufacturer"] and evidence["service_data"])
            or (evidence["name_match"] and evidence["known_uuid"])
        ):
            return True

        # For non-Apple manufacturers, require stronger evidence for trackers
        if not evidence["apple_manufacturer"]:
            # Check for specific non-Apple tracking devices
            for tracker_type, tracker_info in TRACKING_DEVICE_TYPES.items():
                if tracker_type == "AIRTAG":
                    continue  # Already handled above

                # Verify manufacturer ID matches
                if tracker_info["company_id"] in self.manufacturer_data:
                    # For non-Apple devices, require exact UUID matches
                    for uuid in self.service_uuids:
                        uuid_upper = uuid.upper()
                        for tracker_uuid in tracker_info["uuids"]:
                            if tracker_uuid in uuid_upper:
                                # Verify with name match for higher confidence
                                if self.name and any(
                                    identifier in self.name.lower()
                                    for identifier in tracker_info["identifiers"]
                                ):
                                    return True

        # Default to false - require explicit evidence
        return False

    def _calculate_tracker_confidence(self) -> int:
        """Calculate confidence level for tracker detection (0 = confirmed, 4 = unlikely)"""
        if not self.is_airtag:
            return TRACKING_CONFIDENCE["UNLIKELY"]

        # Count evidence points
        evidence_points = 0

        # Check manufacturer - Apple devices get points
        if 76 in self.manufacturer_data:
            evidence_points += 1

            # Check for Find My pattern in manufacturer data
            data = self.manufacturer_data[76]
            if len(data) > 1:
                if data[0] == 0x12 and data[1] == 0x19:  # Classic Find My pattern
                    evidence_points += 3

                # AirTag specific pattern
                if len(data) > 2 and data[2] & 0x0F == 0x0A:
                    evidence_points += 4

                # Other Apple Find My patterns
                if data[0] == 0x10 or data[0] == 0x0F:
                    evidence_points += 2

        # Check name for AirTag indicators
        if self.name and any(
            identifier in self.name.lower() for identifier in AIRTAG_IDENTIFIERS
        ):
            evidence_points += 2

        # Check for Find My UUIDs
        for uuid in self.service_uuids:
            uuid_upper = uuid.upper()
            for find_my_id in FIND_MY_UUIDS:
                if find_my_id in uuid_upper:
                    evidence_points += 2
                    break

        # Check for Find My service data
        for service_uuid, _ in self.service_data.items():
            service_uuid_upper = service_uuid.upper()
            if any(find_my_id in service_uuid_upper for find_my_id in FIND_MY_UUIDS):
                evidence_points += 2
                break

        # Determine confidence level based on evidence points
        if evidence_points >= 7:
            return TRACKING_CONFIDENCE["CONFIRMED"]
        elif evidence_points >= 5:
            return TRACKING_CONFIDENCE["HIGH"]
        elif evidence_points >= 3:
            return TRACKING_CONFIDENCE["MEDIUM"]
        elif evidence_points >= 1:
            return TRACKING_CONFIDENCE["LOW"]
        else:
            return TRACKING_CONFIDENCE["UNLIKELY"]

    def get_tracker_type(self) -> str:
        """Identify the specific type of tracking device"""
        if not self.is_airtag:
            return "Not a tracker"

        # --- AirTag Identification (High Confidence) ---
        if self.manufacturer == "Apple":
            # Definitive AirTag signal from manufacturer data
            if 76 in self.manufacturer_data and len(self.manufacturer_data[76]) > 2:
                if (
                    len(self.manufacturer_data[76]) > 3
                    and self.manufacturer_data[76][2] & 0x0F == 0x0A
                ):
                    return "Apple AirTag"

            # Clear name match
            if self.name and "airtag" in self.name.lower():
                return "Apple AirTag"

            # Find My network protocol without specific AirTag identifier
            if 76 in self.manufacturer_data and len(self.manufacturer_data[76]) >= 2:
                if (
                    self.manufacturer_data[76][0] == 0x12
                    and self.manufacturer_data[76][1] == 0x19
                ):
                    # Find My protocol but not specifically AirTag
                    return "Apple Find My Device"

            # Check for Find My Network specific UUIDs
            for uuid in self.service_uuids:
                if any(
                    find_my_id in uuid.upper()
                    for find_my_id in ["7DFC9000", "7DFC9001", "0000FD44"]
                ):
                    return "Apple Find My Device"

            # Other Apple device that uses Find My network
            return "Apple Find My Device"

        # --- Samsung SmartTag Identification ---
        if self.manufacturer == "Samsung":
            if (
                "smarttag" in self.name.lower()
                or "smart tag" in self.name.lower()
                or "galaxy tag" in self.name.lower()
            ):
                return "Samsung SmartTag"

            # Check for Samsung SmartTag service UUID
            for uuid in self.service_uuids:
                if "FD5A" in uuid.upper():
                    return "Samsung SmartTag"

        # --- Tile Identification ---
        if self.manufacturer == "Tile" or any(
            "tile" == word for word in self.name.lower().split()
        ):
            return "Tile Tracker"

        # --- Chipolo Identification ---
        if "chipolo" in self.name.lower():
            for uuid in self.service_uuids:
                if any(
                    chipolo_uuid in uuid.upper() for chipolo_uuid in ["FEE1", "FEE0"]
                ):
                    return "Chipolo Tracker"

        # Generic tracker if we can't identify the specific type but it triggered our tracker detection
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
        """Calculate approximate distance with improved environment correction for long range"""
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
        elif "find my" in self.device_type.lower():
            # Find My devices may need a specific correction
            rssi_correction = -3

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
        # and long-distance correction factor

        # For very close devices (< 1m), use linear interpolation
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

            # Apply improved long-range correction factors for signals below -80 dBm
            if corrected_rssi < -80:
                # For weaker signals, calibrate distance differently
                signal_strength_factor = (
                    abs(corrected_rssi) / 80.0
                )  # Normalized factor (>1 for weak signals)

                # Apply non-linear correction to prevent unrealistic distances
                # This provides a more realistic curve for long-range distance estimation
                if signal_strength_factor > 1.1:
                    # Adjust distance with diminishing returns for very weak signals
                    # Prevents exponential growth for extremely weak signals
                    correction_factor = 1 + math.log(signal_strength_factor) * 0.5
                    distance = distance * correction_factor

                    # Apply maximum realistic range cap based on BLE physics
                    # Max theoretical range is ~100m in perfect conditions
                    distance = min(distance, 100.0)

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

    def update_proximity_trend(self) -> Tuple[str, float]:
        """Update and return the proximity trend (getting closer or further)

        Returns:
            Tuple containing the trend direction as a string and the rate of change
        """
        current_distance = self.distance
        current_time = time.time()
        trend_direction = "stable"
        change_rate = 0.0

        # Initialize previous distance and trend history if not set
        if not hasattr(self, "previous_distance") or self.previous_distance is None:
            self.previous_distance = current_distance
            self.last_trend_update = current_time
            if not hasattr(self, "distance_trend"):
                self.distance_trend = []
            return trend_direction, change_rate

        # Only update if enough time has passed (100ms minimum)
        if current_time - self.last_trend_update < 0.1:
            # Return the last trend if available
            if hasattr(self, "distance_trend") and self.distance_trend:
                _, _, last_trend, last_rate = self.distance_trend[-1]
                return last_trend, last_rate
            return trend_direction, change_rate

        # Calculate time since last update (minimum 0.1 second to avoid division by zero)
        time_diff = max(0.1, current_time - self.last_trend_update)

        # Calculate distance change
        distance_diff = current_distance - self.previous_distance

        # Calculate rate of change (meters per second)
        change_rate = distance_diff / time_diff

        # Apply smoothing to reduce fluctuations (exponential moving average)
        if hasattr(self, "distance_trend") and self.distance_trend:
            _, _, _, last_rate = self.distance_trend[-1]
            # Blend new and old rates (70% new, 30% old)
            change_rate = (0.7 * change_rate) + (0.3 * last_rate)

        # Determine trend direction with dampening to avoid small fluctuations
        if abs(change_rate) < 0.03:  # Less than 3cm per second is considered stable
            trend_direction = "stable"
        elif change_rate < 0:
            trend_direction = "closer"  # Getting closer (negative rate)
        else:
            trend_direction = "further"  # Getting further (positive rate)

        # Initialize distance_trend if not already done
        if not hasattr(self, "distance_trend"):
            self.distance_trend = []

        # Add to trend history (keep last 10 updates for better analysis)
        self.distance_trend.append(
            (current_time, current_distance, trend_direction, change_rate)
        )
        if len(self.distance_trend) > 10:
            self.distance_trend.pop(0)

        # Update previous values for next calculation
        self.previous_distance = current_distance
        self.last_trend_update = current_time

        return trend_direction, change_rate

    def get_trend_summary(self) -> str:
        """Get a human-readable summary of the proximity trend"""
        if not hasattr(self, "distance_trend") or not self.distance_trend:
            return "Monitoring proximity trend..."

        # Get the latest trend
        _, _, latest_trend, latest_rate = self.distance_trend[-1]

        # Count trends in history to determine consistency
        trend_counts = {"closer": 0, "further": 0, "stable": 0}
        for _, _, trend, _ in self.distance_trend:
            trend_counts[trend] += 1

        # Determine most common trend
        max_trend = max(trend_counts.items(), key=lambda x: x[1])
        consistent = max_trend[1] >= 3  # At least 3 of 5 readings show the same trend

        # Format the rate of change
        rate_abs = abs(latest_rate)
        if rate_abs < 0.01:
            rate_text = "very slowly"
        elif rate_abs < 0.05:
            rate_text = "slowly"
        elif rate_abs < 0.2:
            rate_text = "steadily"
        elif rate_abs < 0.5:
            rate_text = "quickly"
        else:
            rate_text = "very quickly"

        # Create the message
        if latest_trend == "stable":
            return "Distance is stable"
        elif latest_trend == "closer":
            confidence = "Consistently" if consistent else "Possibly"
            return f"{confidence} getting closer {rate_text} ({rate_abs:.2f}m/s)"
        else:  # further
            confidence = "Consistently" if consistent else "Possibly"
            return f"{confidence} moving away {rate_text} ({rate_abs:.2f}m/s)"

    def get_detailed_proximity_analysis(self) -> Dict:
        """Get detailed proximity analysis with prediction"""
        if (
            not hasattr(self, "distance_trend")
            or not self.distance_trend
            or len(self.distance_trend) < 2
        ):
            return {
                "status": "initializing",
                "message": "Initializing trend analysis...",
                "direction": "unknown",
                "rate": 0.0,
                "prediction": None,
                "confidence": 0.0,
                "data_points": (
                    len(self.distance_trend)
                    if hasattr(self, "distance_trend") and self.distance_trend
                    else 0
                ),
            }

        # Current and previous readings
        current_time, current_distance, current_trend, current_rate = (
            self.distance_trend[-1]
        )

        # Calculate average rate from last 3 readings if available
        rates = [rate for _, _, _, rate in self.distance_trend[-3:]]
        avg_rate = sum(rates) / len(rates)

        # Count direction occurrences for confidence calculation
        directions = [trend for _, _, trend, _ in self.distance_trend]
        direction_counts = {
            "closer": directions.count("closer"),
            "further": directions.count("further"),
            "stable": directions.count("stable"),
        }

        # Determine dominant direction
        dominant_direction = max(direction_counts, key=direction_counts.get)

        # Calculate confidence level (0.0 to 1.0)
        confidence = direction_counts[dominant_direction] / len(directions)

        # Make short-term prediction (where will distance be in 5 seconds)
        prediction_time = 5.0  # seconds
        predicted_distance = current_distance + (avg_rate * prediction_time)
        predicted_distance = max(0.1, predicted_distance)  # Ensure positive distance

        # Generate human-readable status message
        if dominant_direction == "closer":
            status = "approaching"
            verb = "reach" if predicted_distance < 0.5 else "be"
            time_to_target = (
                abs(current_distance / avg_rate) if avg_rate != 0 else float("inf")
            )

            if confidence > 0.8:
                confidence_text = "Definitely"
            elif confidence > 0.6:
                confidence_text = "Likely"
            else:
                confidence_text = "Possibly"

            if time_to_target < 30 and time_to_target > 0:
                eta = f"ETA: ~{time_to_target:.1f} seconds"
            else:
                eta = ""

            message = f"{confidence_text} getting closer. You'll {verb} ~{predicted_distance:.2f}m in 5s. {eta}"

        elif dominant_direction == "further":
            status = "moving_away"

            if confidence > 0.8:
                confidence_text = "Definitely"
            elif confidence > 0.6:
                confidence_text = "Likely"
            else:
                confidence_text = "Possibly"

            message = f"{confidence_text} moving away. Distance in 5s: ~{predicted_distance:.2f}m"

        else:  # stable
            status = "stable"
            message = f"Distance is stable at {current_distance:.2f}m"

        return {
            "status": status,
            "message": message,
            "direction": dominant_direction,
            "rate": avg_rate,
            "prediction": {"time": prediction_time, "distance": predicted_distance},
            "confidence": confidence,
            "current_distance": current_distance,
            "data_points": len(self.distance_trend),
        }

    def get_movement_guidance(self) -> str:
        """Generate guidance to help user locate the device"""
        # Get the detailed analysis first
        analysis = self.get_detailed_proximity_analysis()

        if analysis["status"] == "initializing":
            return "Move slowly in any direction to establish a baseline..."

        current_distance = analysis.get("current_distance", self.distance)
        direction = analysis.get("direction", "unknown")
        rate = analysis.get("rate", 0.0)
        confidence = analysis.get("confidence", 0.0)

        # Very close to device
        if current_distance < 0.5:
            return "VERY CLOSE! Look around carefully, you should be able to see the device."

        # Close range
        elif current_distance < 2.0:
            if direction == "closer":
                return "You're on the right track! Continue in this direction."
            elif direction == "further":
                return "Wrong way! Turn around and go in the opposite direction."
            else:
                return (
                    "You're at a steady distance. Try moving in different directions."
                )

        # Medium range
        elif current_distance < 5.0:
            if direction == "closer" and abs(rate) > 0.1:
                return "Good progress! Keep moving in this direction."
            elif direction == "closer" and abs(rate) <= 0.1:
                return "Correct direction but moving slowly. Try to speed up."
            elif direction == "further":
                return "Wrong direction! Try a different approach."
            else:
                return "You're maintaining distance. Try moving more deliberately in one direction."

        # Long range
        else:
            if confidence < 0.5:
                return "Signal is unstable at this distance. Move in larger steps to establish direction."
            elif direction == "closer":
                return "You're heading in the right direction. Keep going."
            elif direction == "further":
                return "You're moving away from the device. Change direction."
            else:
                return "You're moving parallel to the device. Try changing direction."

    def to_dict(self) -> Dict:
        """Convert device to dictionary for storage"""
        # Convert distance_trend to a serializable format
        serializable_trend = []
        for timestamp, distance, trend, rate in getattr(self, "distance_trend", []):
            serializable_trend.append(
                {
                    "timestamp": timestamp,
                    "distance": distance,
                    "trend": trend,
                    "rate": rate,
                }
            )

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
            "tracker_confidence": self.tracker_confidence,
            "is_new": getattr(self, "is_new", False),
            "distance": self.distance,
            "calibrated_n_value": self.calibrated_n_value,
            "calibrated_rssi_at_one_meter": self.calibrated_rssi_at_one_meter,
            "manufacturer": self.manufacturer,
            "device_type": self.device_type,
            "device_details": self.device_details,
            # Include proximity tracking data
            "previous_distance": getattr(self, "previous_distance", None),
            "distance_trend": serializable_trend,
            "last_trend_update": getattr(self, "last_trend_update", 0),
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
            is_new=data.get("is_new", False),
        )
        device.first_seen = data["first_seen"]
        device.last_seen = data["last_seen"]
        if "calibrated_n_value" in data:
            device.calibrated_n_value = data["calibrated_n_value"]
        if "calibrated_rssi_at_one_meter" in data:
            device.calibrated_rssi_at_one_meter = data["calibrated_rssi_at_one_meter"]
        if "tracker_confidence" in data:
            device.tracker_confidence = data["tracker_confidence"]

        # Restore proximity tracking data if available
        if "previous_distance" in data and data["previous_distance"] is not None:
            device.previous_distance = data["previous_distance"]

        if "last_trend_update" in data:
            device.last_trend_update = data["last_trend_update"]

        # Restore distance trend history
        if "distance_trend" in data and isinstance(data["distance_trend"], list):
            device.distance_trend = []
            for trend_data in data["distance_trend"]:
                if isinstance(trend_data, dict):
                    try:
                        device.distance_trend.append(
                            (
                                trend_data["timestamp"],
                                trend_data["distance"],
                                trend_data["trend"],
                                trend_data["rate"],
                            )
                        )
                    except (KeyError, TypeError):
                        # Skip malformed entries
                        continue

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

                    # Update is_new flag to respect the NEW_DEVICE_TIMEOUT
                    # This ensures devices in history don't perpetually show as NEW
                    if entry.get("is_new", False) and "first_seen" in entry:
                        # If the device has been known for longer than the timeout, reset the flag
                        if time.time() - entry["first_seen"] > NEW_DEVICE_TIMEOUT:
                            entry["is_new"] = False

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
            title="[bold]Bluetooth Devices[/] [dim](Sorted by: Last seen → Distance → Track probability)[/]",
            box=ROUNDED,
            highlight=True,
            style="bold cyan",
            border_style="blue",
            expand=True,  # Make table expand to fill available width
        )

        # Determine if we have a selected device - make some columns optional
        has_selected = (
            self.selected_device is not None and self.selected_device in self.devices
        )

        # Add columns with responsive width settings
        table.add_column("Name", style="cyan", ratio=3, no_wrap=False)
        table.add_column("Type", ratio=2, no_wrap=False)

        # Always show MAC address column
        table.add_column("MAC", ratio=1, no_wrap=False)

        # Add tracker probability column
        table.add_column("Track Prob", justify="center", ratio=1)

        # Only show manufacturer column if space permits or no device is selected
        if not has_selected or self.console.width > 100:
            table.add_column("Manufacturer", ratio=1, no_wrap=False)

        # Separate RSSI and Signal columns
        table.add_column("RSSI", justify="right", ratio=1)
        table.add_column("Signal", justify="right", ratio=1)  # Signal quality info
        table.add_column("Distance", justify="right", ratio=1)

        # Only show seen time column if no device is selected
        if not has_selected or self.console.width > 120:
            table.add_column("Last Seen", justify="right", ratio=1)

        # Always show details but adjust width based on available space
        if self.console.width > 140:
            table.add_column("Details", ratio=5, no_wrap=False)
        else:
            table.add_column("Details", ratio=4, no_wrap=False)

        # Create a sorting function that prioritizes:
        # 1. Last seen (most recent first)
        # 2. Distance (closest first)
        # 3. Tracker probability (highest confidence first)
        def multi_sort_key(device):
            # Negative last_seen puts most recent first
            last_seen_key = -device.last_seen

            # Distance (smaller values first)
            distance_key = device.distance if device.distance < 100 else 100

            # Tracker probability (convert confidence to numeric value, lower is higher confidence)
            if device.is_airtag:
                tracker_key = (
                    device.tracker_confidence
                )  # Lower values = higher confidence
            else:
                tracker_key = 999  # Non-trackers at bottom

            return (last_seen_key, distance_key, tracker_key)

        # Sort devices by our multi-sort key
        sorted_devices = sorted(devices.values(), key=multi_sort_key)

        # For AirTag only mode, filter to only include actual AirTags or Find My devices
        if self.airtag_only_mode:
            filtered_devices = []
            for device in sorted_devices:
                # Only include devices that are definitely AirTags or Find My devices
                if device.is_airtag:
                    # Get the specific tracker type
                    tracker_type = device.get_tracker_type()
                    # Only include if it's a known Apple tracker or Find My device
                    if "Apple" in tracker_type and (
                        "AirTag" in tracker_type or "Find My" in tracker_type
                    ):
                        filtered_devices.append(device)
            sorted_devices = filtered_devices

        # Store sorted list for tab-based selection
        self.sorted_device_list = sorted_devices

        # Reset device map for this display
        device_map = {}
        # Track visible devices for UI count
        visible_devices = 0

        for i, device in enumerate(sorted_devices):
            # Skip non-AirTags if in AirTag only mode - redundant now but keeping as safety check
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

            # Format last seen ago in a more human-readable way
            time_since_last_seen = time.time() - device.last_seen
            if time_since_last_seen < 10:
                seen_time = "Just now"
            elif time_since_last_seen < 60:
                seen_time = f"{time_since_last_seen:.0f}s ago"
            elif time_since_last_seen < 3600:
                seen_time = f"{time_since_last_seen/60:.1f}m ago"
            else:
                seen_time = f"{time_since_last_seen/3600:.1f}h ago"

            # Color code RSSI for signal strength
            rssi_str = str(int(device.smooth_rssi))
            if device.smooth_rssi > -60:
                rssi_color = "green"
            elif device.smooth_rssi > -80:
                rssi_color = "yellow"
            else:
                rssi_color = "red"

            # Color code for AirTags and Find My devices based on confidence
            tracker_type = (
                device.get_tracker_type() if device.is_airtag else "Not a tracker"
            )

            # Enhanced confidence-based color coding
            if device.is_airtag:
                if hasattr(device, "tracker_confidence"):
                    # Use confidence level for coloring
                    if device.tracker_confidence == TRACKING_CONFIDENCE["CONFIRMED"]:
                        name_color = "bright_red"  # Confirmed trackers in bright red
                    elif device.tracker_confidence == TRACKING_CONFIDENCE["HIGH"]:
                        name_color = "red"  # High confidence in regular red
                    elif device.tracker_confidence == TRACKING_CONFIDENCE["MEDIUM"]:
                        name_color = "yellow"  # Medium confidence in yellow
                    else:
                        name_color = "blue"  # Low confidence in blue
                else:
                    # Backward compatibility with older data
                    if "Apple AirTag" in tracker_type:
                        name_color = "bright_red"
                    elif "Find My" in tracker_type:
                        name_color = "yellow"
                    else:
                        name_color = "blue"
            else:
                name_color = "white"

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

                # Get signal quality as a percentage and stability
            stability = device.signal_stability

            # Format signal with both quality and stability information
            if stability < 2.0:
                stability_label = "Stable"
                stability_suffix = "+"
            elif stability < 5.0:
                stability_label = "Moderate"
                stability_suffix = "~"
            else:
                stability_label = "Unstable"
                stability_suffix = "-"

            signal_quality = f"{device.signal_quality:.0f}% {stability_suffix}"

            # Color code signal quality
            if device.signal_quality > 70:
                signal_color = "green"
            elif device.signal_quality > 40:
                signal_color = "yellow"
            else:
                signal_color = "red"

            # Create device name display with NEW indicator if needed (only within timeout period)
            if (
                getattr(device, "is_new", False)
                and time.time() - device.first_seen <= NEW_DEVICE_TIMEOUT
            ):
                name_display = Text()
                name_display.append(" NEW ", style="bold yellow on black")
                name_display.append(
                    f" {idx_display} {device.name}", style=f"{name_color} {style}"
                )
            else:
                name_display = Text(
                    f"{idx_display} {device.name}", style=f"{name_color} {style}"
                )

            # Add tracking indicator based on confidence
            if device.is_airtag and hasattr(device, "tracker_confidence"):
                if device.tracker_confidence == TRACKING_CONFIDENCE["CONFIRMED"]:
                    name_display.append(" ⚠️", style="bold bright_red")
                elif device.tracker_confidence == TRACKING_CONFIDENCE["HIGH"]:
                    name_display.append(" ⚠️", style="bold red")
                elif device.tracker_confidence == TRACKING_CONFIDENCE["MEDIUM"]:
                    name_display.append(" 🔍", style="bold yellow")
                elif device.tracker_confidence == TRACKING_CONFIDENCE["LOW"]:
                    name_display.append(" ?", style="bold blue")

            # Calculate tracker probability display
            tracker_prob_display = ""
            if device.is_airtag:
                if device.tracker_confidence == TRACKING_CONFIDENCE["CONFIRMED"]:
                    tracker_prob = "95-100%"
                    prob_color = "bright_red"
                elif device.tracker_confidence == TRACKING_CONFIDENCE["HIGH"]:
                    tracker_prob = "75-95%"
                    prob_color = "red"
                elif device.tracker_confidence == TRACKING_CONFIDENCE["MEDIUM"]:
                    tracker_prob = "50-75%"
                    prob_color = "yellow"
                elif device.tracker_confidence == TRACKING_CONFIDENCE["LOW"]:
                    tracker_prob = "25-50%"
                    prob_color = "blue"
                else:
                    tracker_prob = "< 25%"
                    prob_color = "blue"
                tracker_prob_display = Text(tracker_prob, style=f"bold {prob_color}")
            else:
                tracker_prob_display = Text("0%", style="dim")

            # Build row data based on which columns are enabled
            row_data = [
                name_display,
                device.device_type,
                mac_display,
                tracker_prob_display,  # Add tracker probability
            ]

            # Add manufacturer column if it exists
            if not has_selected or self.console.width > 100:
                row_data.append(device.manufacturer)

            # Always add RSSI, signal quality, and distance
            row_data.extend(
                [
                    Text(rssi_str, style=f"{rssi_color} {style}"),
                    Text(
                        f"{signal_quality}",  # Simplified signal display
                        style=f"{signal_color} {style}",
                    ),
                    distance,
                ]
            )

            # Add seen time if column exists, with color coding
            if not has_selected or self.console.width > 120:
                # Color code last seen times
                if time_since_last_seen < 30:
                    seen_style = "green"  # Very recent
                elif time_since_last_seen < 300:
                    seen_style = "yellow"  # Within last 5 minutes
                else:
                    seen_style = "red"  # Older

                row_data.append(Text(seen_time, style=f"{seen_style}"))

            # Always add details
            row_data.append(details)

            # Add the row with the correct data
            table.add_row(*row_data, style=style)

        if not sorted_devices or visible_devices == 0:
            # Create empty row data based on how many columns we have
            if self.airtag_only_mode:
                empty_message = "No Find My devices or AirTags found"
            else:
                empty_message = "No devices found"

            empty_row = [empty_message]
            empty_columns = (
                len(table.columns) - 1
            )  # -1 because we already added message

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
        # Get range mode from settings or use default
        range_mode = self.settings.get("range_mode", "Normal")
        range_color = "yellow"
        if range_mode == "Maximum":
            range_color = "green"
        elif range_mode == "Balanced":
            range_color = "blue"

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
                        " [bold blue]a[/] - Toggle Find My mode",
                        " [bold blue]d[/] - Toggle adaptive mode",
                        " [bold blue]c[/] - Toggle calibration mode",
                        " [bold blue]r[/] - Configure scan range",
                        " [bold blue]m[/] - Test max adapter range",
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
                        f"[bold]Find My mode:[/] {airtag_mode}",
                        f"[bold]Adaptive:[/] {adaptive_mode}",
                        f"[bold]Calibration:[/] {calibration_mode}",
                        f"[bold]Range mode:[/] [{range_color}]{range_mode}[/]",
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
                        " [bold blue]s[/] - Scan [bold blue]a[/] - Find My mode [bold blue]d[/] - Adaptive",
                        " [bold blue]c[/] - Calibration [bold blue]r[/] - Range [bold blue]m[/] - Max range test [bold blue]l[/] - Adapters [bold blue]z[/] - Analyze [bold blue]q[/] - Quit",
                        "",
                        f"[bold]Status:[/] [yellow]Idle[/] | Find My: {airtag_mode} | Adaptive: {adaptive_mode} | Calib: {calibration_mode}",
                        f"[bold]Range:[/] [{range_color}]{range_mode}[/] | [bold]Adapter:[/] {self.current_adapter or 'Default'}",
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

        # Show NEW badge if this is a newly discovered device AND within timeout period
        if getattr(device, "is_new", False) and (
            time.time() - device.first_seen <= NEW_DEVICE_TIMEOUT
        ):
            details_text.append("🆕 ", style="bold yellow")
            details_text.append("NEWLY DISCOVERED DEVICE", style="bold yellow")
            # Also show when it was first seen
            details_text.append("\n")
            time_ago = format_time_ago(time.time() - device.first_seen)
            details_text.append(f"First seen {time_ago} ago", style="yellow")
            details_text.append("\n")

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

            # Get confidence level if available
            confidence_level = "Unknown"
            confidence_style = "bold red"

            if hasattr(device, "tracker_confidence"):
                confidence_levels = {
                    TRACKING_CONFIDENCE["CONFIRMED"]: ("Confirmed", "bold bright_red"),
                    TRACKING_CONFIDENCE["HIGH"]: ("High Confidence", "bold red"),
                    TRACKING_CONFIDENCE["MEDIUM"]: ("Medium Confidence", "bold yellow"),
                    TRACKING_CONFIDENCE["LOW"]: ("Low Confidence", "bold blue"),
                    TRACKING_CONFIDENCE["UNLIKELY"]: ("Unlikely", "bold blue"),
                }
                confidence_level, confidence_style = confidence_levels.get(
                    device.tracker_confidence, ("Unknown", "bold red")
                )

            details_text.append(f"  Tracker Type: ", style="bold red")
            details_text.append(f"{tracker_type}\n", style="bold red")
            details_text.append(f"  Detection Confidence: ", style="bold")
            details_text.append(f"{confidence_level}\n", style=confidence_style)

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
        details_text.append("Distance & Proximity Tracking", style="bold yellow")
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

        # Add proximity tracking - start tracking if not already tracking
        if device.previous_distance is None:
            # Initialize tracking
            device.previous_distance = device.distance
            device.last_trend_update = time.time()
            details_text.append(f"  Proximity Trend: ", style="bold")
            details_text.append("Initializing tracking...\n", style="yellow")
        else:
            # Update trend and display it
            trend_direction, change_rate = device.update_proximity_trend()
            trend_summary = device.get_trend_summary()

            details_text.append(f"  Proximity Trend: ", style="bold")

            if trend_direction == "closer":
                trend_style = "green"
                trend_icon = "▼"  # Down arrow for getting closer
            elif trend_direction == "further":
                trend_style = "red"
                trend_icon = "▲"  # Up arrow for getting further
            else:
                trend_style = "yellow"
                trend_icon = "◆"  # Diamond for stable

            details_text.append(f"{trend_icon} {trend_summary}\n", style=trend_style)

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

        # Service UUIDs with improved Find My detection
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

        # Manufacturer Data with improved Find My detection
        if device.manufacturer_data:
            details_text.append(f"  Manufacturer Data: ", style="bold")
            mfg_data_entries = []
            for company_id, data in device.manufacturer_data.items():
                if company_id in COMPANY_IDENTIFIERS:
                    company_name = COMPANY_IDENTIFIERS[company_id]
                    # Highlight Apple data
                    if company_id == 0x004C:  # Apple
                        mfg_data_str = f"{company_name} (0x{company_id:04X}): "
                        # Check if this is Find My data
                        if len(data) > 1 and (data[0] == 0x12 and data[1] == 0x19):
                            mfg_data_str += f"[bold red]{data.hex()[:16]}[/bold red]"
                        else:
                            mfg_data_str += f"{data.hex()[:16]}"
                    else:
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

            # Categorize trackers by confidence
            confirmed_trackers = []
            possible_trackers = []

            for device in airtags:
                confidence = device.get(
                    "tracker_confidence", TRACKING_CONFIDENCE["MEDIUM"]
                )
                if confidence <= TRACKING_CONFIDENCE["HIGH"]:
                    confirmed_trackers.append(device)
                else:
                    possible_trackers.append(device)

            # List the confirmed tracking devices first
            if confirmed_trackers:
                summary_text.append(
                    f"  [bold red]Confirmed Trackers: {len(confirmed_trackers)}[/]"
                )
                for i, device in enumerate(confirmed_trackers[:3], 1):  # Show top 3
                    device_type = device.get("device_type", "Unknown Tracker")
                    last_seen_ago = now - device.get("last_seen", now)
                    summary_text.append(
                        f"  {i}. [bold red]{device.get('name', 'Unnamed')}[/] - "
                        f"{device_type} - Last seen {format_time_ago(last_seen_ago)} ago"
                    )
                if len(confirmed_trackers) > 3:
                    summary_text.append(
                        f"  ...and {len(confirmed_trackers) - 3} more confirmed trackers"
                    )

            # List possible tracking devices
            if possible_trackers:
                summary_text.append(
                    f"  [bold yellow]Possible Trackers: {len(possible_trackers)}[/]"
                )
                for i, device in enumerate(possible_trackers[:2], 1):  # Show top 2
                    device_type = device.get("device_type", "Unknown Tracker")
                    last_seen_ago = now - device.get("last_seen", now)
                    summary_text.append(
                        f"  {i}. [bold yellow]{device.get('name', 'Unnamed')}[/] - "
                        f"{device_type} - Last seen {format_time_ago(last_seen_ago)} ago"
                    )
                if len(possible_trackers) > 2:
                    summary_text.append(
                        f"  ...and {len(possible_trackers) - 2} more possible trackers"
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
            style="bold cyan",
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

        # Show a special header for new devices
        is_new = getattr(device, "is_new", False)
        is_within_timeout = time.time() - device.first_seen <= NEW_DEVICE_TIMEOUT

        if is_new and is_within_timeout:
            # Add a prominent header for new devices
            details_text.append("\n")
            details_text.append("█▓▒░ ", style="bold yellow")
            details_text.append("NEW DEVICE DETECTED", style="bold yellow")
            details_text.append(" ░▒▓█", style="bold yellow")
            details_text.append("\n")

            # Show when the device was first discovered
            time_since_discovery = time.time() - device.first_seen
            details_text.append(
                f"First discovered {format_time_ago(time_since_discovery)} ago",
                style="yellow",
            )
            details_text.append("\n\n")

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

        details_text.append(f"Detection Status: ", style="bold")
        if is_new:
            if is_within_timeout:
                details_text.append("NEWLY DISCOVERED", style="bold yellow")
            else:
                details_text.append("Previously discovered", style="blue")
        else:
            details_text.append("Previously known", style="blue")
        details_text.append("\n")

        # Add tracker identification if it's a tracking device
        if device.is_airtag:
            tracker_type = device.get_tracker_type()

            # Get confidence level if available
            confidence_level = "Unknown"
            alert_style = "bold white on red"

            if hasattr(device, "tracker_confidence"):
                confidence_levels = {
                    TRACKING_CONFIDENCE["CONFIRMED"]: (
                        "CONFIRMED",
                        "bold white on red",
                    ),
                    TRACKING_CONFIDENCE["HIGH"]: (
                        "HIGH CONFIDENCE",
                        "bold white on red",
                    ),
                    TRACKING_CONFIDENCE["MEDIUM"]: (
                        "MEDIUM CONFIDENCE",
                        "bold black on yellow",
                    ),
                    TRACKING_CONFIDENCE["LOW"]: (
                        "LOW CONFIDENCE",
                        "bold white on blue",
                    ),
                    TRACKING_CONFIDENCE["UNLIKELY"]: ("UNLIKELY", "bold white on blue"),
                }
                confidence_level, alert_style = confidence_levels.get(
                    device.tracker_confidence, ("Unknown", "bold white on red")
                )

            details_text.append("\n")
            if device.tracker_confidence <= TRACKING_CONFIDENCE["HIGH"]:
                details_text.append(
                    f"⚠️  TRACKING DEVICE DETECTED - {confidence_level}  ⚠️",
                    style=alert_style,
                )
            else:
                details_text.append(
                    f"🔍  POSSIBLE TRACKING DEVICE - {confidence_level}  🔍",
                    style=alert_style,
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
        # Check if this is a new device for this scanning session
        is_new_device = device.address not in self.devices

        # Check if this device is in the history more thoroughly
        known_addresses = set()
        known_device_in_history = False
        similar_name_in_history = False

        if self.history:
            # First, extract all known addresses from history
            for hist_device in self.history:
                if isinstance(hist_device, dict) and "address" in hist_device:
                    known_addresses.add(hist_device["address"])

                    # Check if this exact address is in history
                    if hist_device["address"] == device.address:
                        known_device_in_history = True

                    # For thoroughness, also check if a device with same name exists
                    # This helps with devices that might have randomly changing MAC addresses
                    if (
                        device.name
                        and "name" in hist_device
                        and device.name == hist_device["name"]
                    ):
                        similar_name_in_history = True

        # Device is truly new if:
        # 1. It's not in our current scanning session
        # 2. It's not in our history (by address)
        # 3. There's no device with the same name in our history (extra check)
        is_truly_new = (
            is_new_device
            and not known_device_in_history
            and not similar_name_in_history
        )

        # For unnamed devices, be very cautious about marking as new
        if is_truly_new and (not device.name or device.name == "Unknown"):
            # Don't mark unnamed devices as new
            is_truly_new = False

        # Check for Find My identifiers to keep weak signals from possible trackers
        might_be_tracker = False

        # Check manufacturer data for Apple ID or Find My patterns
        if 76 in advertisement_data.manufacturer_data:
            data = advertisement_data.manufacturer_data[76]
            # Look for Find My protocol signature
            if len(data) > 1:
                if (
                    (data[0] == 0x12 and data[1] == 0x19)
                    or data[0] == 0x10
                    or data[0] == 0x0F
                ):
                    might_be_tracker = True

        # Check for Find My UUIDs
        for uuid in advertisement_data.service_uuids:
            uuid_upper = uuid.upper()
            if any(find_my_id in uuid_upper for find_my_id in FIND_MY_UUIDS):
                might_be_tracker = True
                break

        # Check for service data with Find My signatures
        for service_uuid, _ in advertisement_data.service_data.items():
            service_uuid_upper = service_uuid.upper()
            if any(find_my_id in service_uuid_upper for find_my_id in FIND_MY_UUIDS):
                might_be_tracker = True
                break

        # Check if name contains tracker keywords
        if device.name and any(
            identifier in device.name.lower() for identifier in AIRTAG_IDENTIFIERS
        ):
            might_be_tracker = True

        # Always keep tracking devices, even with weak signals
        if advertisement_data.rssi < DETECTION_THRESHOLD and not might_be_tracker:
            # Only keep extremely weak signals if the device was previously seen
            # or if it has Find My identifiers worth tracking
            if not is_new_device:
                # Update existing very weak device only
                if device.address in self.devices:
                    self.devices[device.address].update(
                        rssi=advertisement_data.rssi,
                        manufacturer_data=advertisement_data.manufacturer_data,
                        service_data=advertisement_data.service_data,
                        service_uuids=advertisement_data.service_uuids,
                    )
            return

        # Apply signal amplification for weak but usable signals to improve detection
        enhanced_rssi = advertisement_data.rssi

        # Use the might_be_tracker flag to boost signals from potential tracking devices
        if might_be_tracker:
            # Apply an adaptive signal boost based on signal strength to improve detection
            if advertisement_data.rssi < -85 and advertisement_data.rssi > -95:
                # Moderate boost for moderately weak signals that might be trackers
                enhanced_rssi = advertisement_data.rssi + 6  # 6dBm boost
            elif advertisement_data.rssi <= -95:
                # Stronger boost for very weak signals that might be trackers
                enhanced_rssi = (
                    advertisement_data.rssi + 8
                )  # 8dBm boost to detect from further away
            else:
                # Slight boost even for stronger signals to prioritize tracker detection
                enhanced_rssi = advertisement_data.rssi + 3  # 3dBm boost

        if is_new_device:
            # Create new device instance
            self.devices[device.address] = Device(
                address=device.address,
                name=device.name,
                rssi=enhanced_rssi,  # Use enhanced RSSI
                manufacturer_data=advertisement_data.manufacturer_data,
                service_data=advertisement_data.service_data,
                service_uuids=advertisement_data.service_uuids,
                is_new=is_truly_new,  # Mark as new only if truly new after thorough checks
            )

            # Assign a persistent device ID if it doesn't have one yet
            if device.address not in self.device_ids:
                self.device_ids[device.address] = self.next_device_id
                self.next_device_id += 1
        else:
            # When updating an existing device, never set it back to new
            # Update existing device with new data
            self.devices[device.address].update(
                rssi=enhanced_rssi,  # Use enhanced RSSI
                manufacturer_data=advertisement_data.manufacturer_data,
                service_data=advertisement_data.service_data,
                service_uuids=advertisement_data.service_uuids,
                is_new=False,  # Ensure it's not marked as new when updating
            )

            # Apply adaptive calibration if enabled
            if self.adaptive_mode:
                # If signal is strong and we can assume it's close
                dev = self.devices[device.address]
                if dev.rssi > -55 and dev.signal_stability < 3.0:
                    # Device is probably around 1m, adjust RSSI@1m
                    dev.calibrated_rssi_at_one_meter = dev.smooth_rssi

        # For potential Find My devices, ensure we do deeper inspection by forcing a detailed data scan
        if (
            device.address in self.devices
            and not self.devices[device.address].is_airtag
        ):
            # Check if this might be a Find My device that wasn't detected yet
            is_potential_find_my = False

            # Check some basic indicators
            if 76 in advertisement_data.manufacturer_data:
                # This is an Apple device, so worth checking further
                is_potential_find_my = True

            # For potential Find My devices, force a re-check
            if is_potential_find_my:
                # Force recalculation of is_airtag flag with latest data
                self.devices[device.address].is_airtag = self.devices[
                    device.address
                ]._check_if_airtag()
                # Force update of device details to be sure
                self.devices[device.address].device_details = self.devices[
                    device.address
                ]._extract_detailed_info()

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

        # Create basic or_patterns for passive scanning - required for Linux
        # This is a basic pattern that will match any BLE advertisement
        or_patterns = [
            OrPattern(0, AdvertisementDataType.FLAGS, b"\x00"),  # Match any flags
            OrPattern(
                0, AdvertisementDataType.COMPLETE_LOCAL_NAME, b"\x00"
            ),  # Match any name
        ]

        # Display scanning parameters
        self.console.print(
            Panel(
                "\n".join(
                    [
                        "[bold green]Starting enhanced range scan with optimized parameters[/]",
                        f"[yellow]Scan interval: {SCAN_INTERVAL}s | Timeout: {scanner_kwargs['timeout']}s | Detection threshold: {DETECTION_THRESHOLD} dBm[/]",
                        f"[yellow]Scanning mode: {scanner_kwargs['scanning_mode']} | Multi-phase: {ADVANCED_SCAN_SETTINGS['extended_retries']} phases[/]",
                        f"[yellow]Adapter: {self.current_adapter or 'Default'}[/]",
                    ]
                ),
                title="[bold blue]Range-Optimized Scan[/]",
                border_style="blue",
                box=ROUNDED,
            )
        )

        # Set additional platform-specific parameters for maximum range
        if hasattr(bleak.backends, "bluezdbus") and sys.platform.startswith("linux"):
            # For Linux systems with BlueZ - can set more aggressive parameters
            scanner_kwargs["bluez"] = {
                "interval": scan_settings.get("interval", SCAN_PARAMETERS["interval"]),
                "window": scan_settings.get("window", SCAN_PARAMETERS["window"]),
                "passive": not scan_settings.get("active", SCAN_PARAMETERS["active"]),
            }

            # Add required or_patterns for passive scanning
            if scanner_kwargs["scanning_mode"] == "passive":
                scanner_kwargs["bluez"]["or_patterns"] = or_patterns

        elif hasattr(bleak.backends, "corebluetooth") and sys.platform == "darwin":
            # For macOS systems - can set some CoreBluetooth parameters
            # CoreBluetooth doesn't expose as many parameters as BlueZ
            # Always force active scanning mode on macOS as passive is not supported
            scanner_kwargs["scanning_mode"] = "active"
            scanner_kwargs["cb"] = {
                "use_bdaddr": True,  # Use Bluetooth address when available
                "duration": SCAN_DURATION,  # Duration in seconds for scan
            }

        try:
            # Implement multi-phase scanning for maximum range
            retry_count = ADVANCED_SCAN_SETTINGS["extended_retries"]

            # Determine range mode for proper scanning intensity
            range_mode = self.settings.get("range_mode", "Normal")

            # Create different scanning phases with different parameters based on range mode
            if sys.platform == "darwin":  # macOS doesn't support passive scanning
                if range_mode == "Maximum":
                    # Ultra-aggressive scanning for Maximum mode on macOS
                    scan_phases = [
                        {"mode": "active", "description": "Active scanning (standard)"},
                        {
                            "mode": "active",
                            "interval": 0x0010,  # Ultra-aggressive interval
                            "description": "Aggressive active scanning",
                        },
                        {
                            "mode": "active",
                            "interval": 0x0020,
                            "window": 0x0020,  # Full duty cycle
                            "description": "Maximum power active scanning",
                        },
                    ]
                else:
                    scan_phases = [
                        {"mode": "active", "description": "Active scanning (standard)"},
                        {
                            "mode": "active",
                            "interval": 0x0020,
                            "description": "Aggressive active scanning",
                        },
                    ]
            else:
                if range_mode == "Maximum":
                    # Ultra-aggressive scanning for Maximum mode on Linux
                    scan_phases = [
                        {"mode": "active", "description": "Active scanning (standard)"},
                        {
                            "mode": "passive",
                            "description": "Passive scanning (longer range)",
                            "passive": True,  # Critical for passive scanning on Linux
                        },
                        {
                            "mode": "active",
                            "interval": 0x0010,  # Ultra-aggressive interval
                            "window": 0x0010,  # Maximum window size
                            "description": "Ultra-aggressive active scanning",
                        },
                        {
                            "mode": "active",
                            "interval": 0x0020,
                            "window": 0x0020,  # Full duty cycle for maximum power
                            "description": "Maximum power active scanning",
                        },
                    ]
                else:
                    scan_phases = [
                        {"mode": "active", "description": "Active scanning (standard)"},
                        {
                            "mode": "passive",
                            "description": "Passive scanning (longer range)",
                            "passive": True,  # Critical for passive scanning on Linux
                        },
                        {
                            "mode": "active",
                            "interval": 0x0020,
                            "description": "Aggressive active scanning",
                        },
                    ]

            # Use Rich Live display for UI updates during all scanning phases
            # Increase refresh rate for more responsive real-time updates
            refresh_rate = 10  # Higher refresh rate (10 updates per second)
            with Live(self._update_ui(), refresh_per_second=refresh_rate) as live:
                # Main scan loop that continues indefinitely until user quits
                scan_start_time = time.time()

                # Keep track of scan cycles to prevent getting stuck
                scan_cycles = 0
                max_phase_duration = SCAN_DURATION * 1.5  # Add extra time for safety

                # Set watchdog timer to prevent scans from getting stuck
                watchdog_timer = time.time()

                while self.scanning:
                    try:
                        # First handle Linux BlueZ backend specifically to avoid InProgress errors
                        if sys.platform.startswith("linux"):
                            scanner = None
                            try:
                                # Perform multi-phase scanning on Linux
                                for phase_idx, phase in enumerate(scan_phases):
                                    # If user stopped scanning, exit
                                    if not self.scanning:
                                        break

                                    # Skip phases if user requested to quit
                                    if not self.scanning:
                                        break

                                    # Reset watchdog timer for each phase
                                    watchdog_timer = time.time()

                                    # Update scanner parameters for this phase
                                    scanner_kwargs["scanning_mode"] = phase["mode"]

                                    # Update Linux-specific bluez parameters when mode changes
                                    if "bluez" in scanner_kwargs:
                                        # Handle passive scanning mode for Linux
                                        if (
                                            "passive" in phase
                                            and phase["mode"] == "passive"
                                        ):
                                            scanner_kwargs["bluez"]["passive"] = True
                                            # Add required or_patterns for passive scanning
                                            scanner_kwargs["bluez"][
                                                "or_patterns"
                                            ] = or_patterns
                                        else:
                                            scanner_kwargs["bluez"]["passive"] = False

                                        # Update interval if specified
                                        if "interval" in phase:
                                            scanner_kwargs["bluez"]["interval"] = phase[
                                                "interval"
                                            ]

                                        # Update window if specified (for aggressive scanning)
                                        if "window" in phase:
                                            scanner_kwargs["bluez"]["window"] = phase[
                                                "window"
                                            ]

                                    self.console.print(
                                        f"[yellow]Phase {phase_idx+1}/{len(scan_phases)}: {phase['description']}[/]"
                                    )

                                    # Create scanner without starting it yet
                                    try:
                                        scanner = BleakScanner(**scanner_kwargs)
                                        # Start scanning explicitly
                                        await scanner.start()
                                        self.last_scan_refresh = time.time()
                                        phase_start_time = time.time()
                                    except Exception as e:
                                        self.console.print(
                                            f"[yellow]Warning: Scanner initialization error: {e}. Trying next phase.[/]"
                                        )
                                        await asyncio.sleep(1.0)
                                        continue

                                    # Scan for specified duration with watchdog
                                    scan_running = True
                                    while (
                                        self.scanning
                                        and scan_running
                                        and (
                                            time.time() - phase_start_time
                                            < max_phase_duration
                                        )
                                    ):
                                        # Update UI
                                        live.update(self._update_ui())

                                        # Handle input processing
                                        await self._process_input()

                                        # Periodically refresh the scan on Linux
                                        if (
                                            time.time() - self.last_scan_refresh
                                            > SCAN_DURATION / 3
                                        ):
                                            try:
                                                # Restart scanner carefully to avoid BlueZ errors
                                                await scanner.stop()
                                                await asyncio.sleep(
                                                    0.3
                                                )  # Allow BlueZ to settle
                                                await scanner.start()
                                                self.last_scan_refresh = time.time()
                                            except Exception as e:
                                                self.console.print(
                                                    f"[yellow]Scan refresh warning: {e}. Continuing.[/]",
                                                    end="\r",
                                                )
                                                self.last_scan_refresh = time.time()
                                                # If scanner error, break this phase
                                                if (
                                                    "not found" in str(e).lower()
                                                    or "error" in str(e).lower()
                                                ):
                                                    scan_running = False

                                        # Watchdog - check if we're stuck in this phase for too long
                                        if (
                                            time.time() - watchdog_timer
                                            > max_phase_duration * 1.5
                                        ):
                                            self.console.print(
                                                f"[yellow]Warning: Scan phase taking too long. Moving to next phase.[/]"
                                            )
                                            scan_running = False

                                        # Short sleep to avoid high CPU usage
                                        await asyncio.sleep(0.1)

                                    # Stop the scanner after each phase
                                    if scanner is not None:
                                        try:
                                            await scanner.stop()
                                        except Exception:
                                            pass
                            finally:
                                # Ensure scanner is properly closed
                                if scanner is not None:
                                    try:
                                        await scanner.stop()
                                    except Exception:
                                        pass
                        else:
                            # For non-Linux platforms, use multiple scanning phases
                            for phase_idx, phase in enumerate(scan_phases):
                                # If user stopped scanning, exit
                                if not self.scanning:
                                    break

                                # Reset watchdog timer for each phase
                                watchdog_timer = time.time()

                                # Update scanner parameters for this phase
                                scanner_kwargs["scanning_mode"] = phase["mode"]

                                # Update interval/window parameters if specified
                                if "cb" in scanner_kwargs:
                                    if "interval" in phase:
                                        scanner_kwargs["cb"]["interval"] = phase[
                                            "interval"
                                        ]
                                    if "window" in phase:
                                        scanner_kwargs["cb"]["window"] = phase["window"]

                                self.console.print(
                                    f"[yellow]Phase {phase_idx+1}/{len(scan_phases)}: {phase['description']}[/]"
                                )

                                # Start the scanner with the current phase parameters
                                try:
                                    async with BleakScanner(
                                        **scanner_kwargs
                                    ) as scanner:
                                        phase_start_time = time.time()

                                        # Scan for the specified duration with watchdog
                                        scan_running = True
                                        while (
                                            self.scanning
                                            and scan_running
                                            and (
                                                time.time() - phase_start_time
                                                < max_phase_duration
                                            )
                                        ):
                                            # Update UI
                                            live.update(self._update_ui())

                                            # Handle input processing
                                            await self._process_input()

                                            # Periodically refresh the scanner
                                            if hasattr(self, "last_scan_refresh"):
                                                time_since_refresh = (
                                                    time.time() - self.last_scan_refresh
                                                )
                                                if (
                                                    time_since_refresh
                                                    > SCAN_DURATION / 3
                                                ):
                                                    try:
                                                        # Restart scanner to prevent device cache issues
                                                        await scanner.stop()
                                                        await asyncio.sleep(0.3)
                                                        await scanner.start()
                                                        self.last_scan_refresh = (
                                                            time.time()
                                                        )
                                                    except Exception as e:
                                                        self.console.print(
                                                            f"[yellow]Scan refresh warning: {e}. Continuing.[/]",
                                                            end="\r",
                                                        )
                                                        self.last_scan_refresh = (
                                                            time.time()
                                                        )
                                                        # If scanner error, break this phase
                                                        if (
                                                            "not found"
                                                            in str(e).lower()
                                                            or "error" in str(e).lower()
                                                        ):
                                                            scan_running = False
                                            else:
                                                self.last_scan_refresh = time.time()

                                            # Watchdog - check if we're stuck
                                            if (
                                                time.time() - watchdog_timer
                                                > max_phase_duration * 1.5
                                            ):
                                                self.console.print(
                                                    f"[yellow]Warning: Scan phase taking too long. Moving to next phase.[/]"
                                                )
                                                scan_running = False

                                            # Short sleep to avoid high CPU usage
                                            await asyncio.sleep(0.1)
                                except Exception as e:
                                    self.console.print(
                                        f"[yellow]Warning: Scanner error in phase {phase_idx+1}: {e}. Continuing to next phase.[/]"
                                    )
                                    await asyncio.sleep(1.0)
                                    continue

                                # Short pause between phases
                                if self.scanning and phase_idx < len(scan_phases) - 1:
                                    self.console.print(
                                        "[yellow]Switching scan phase...[/]", end="\r"
                                    )
                                    await asyncio.sleep(0.5)

                        # Increment scan cycles count
                        scan_cycles += 1

                        # Short pause between full scan cycles
                        if self.scanning:
                            self.console.print(
                                f"[green]Scan cycle {scan_cycles} complete. Starting next cycle...[/]",
                                end="\r",
                            )
                            await asyncio.sleep(0.5)

                    except Exception as e:
                        # Catch any unexpected errors and continue scanning
                        self.console.print(
                            f"[bold yellow]Scan error: {e}. Restarting scan...[/]"
                        )
                        await asyncio.sleep(1.0)

                    # Update UI even if an error occurred
                    live.update(self._update_ui())

                    # Always process input to ensure user can exit
                    await self._process_input()

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

            # Get range mode
            range_mode = self.settings.get("range_mode", "Normal")
            range_color = "yellow"
            if range_mode == "Maximum":
                range_color = "green"
            elif range_mode == "Balanced":
                range_color = "blue"

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
            # Add proximity tracking info if there's a selected device
            proximity_info = ""
            if self.selected_device and self.selected_device in self.devices:
                selected_device = self.devices[self.selected_device]
                if (
                    hasattr(selected_device, "distance_trend")
                    and selected_device.distance_trend
                ):
                    _, _, trend, rate = selected_device.distance_trend[-1]
                    if trend == "closer":
                        proximity_info = (
                            f"\n[bold]Tracking:[/] [green]▼ Getting closer[/]"
                        )
                    elif trend == "further":
                        proximity_info = f"\n[bold]Tracking:[/] [red]▲ Moving away[/]"
                    else:
                        proximity_info = f"\n[bold]Tracking:[/] [yellow]◆ Stable[/]"

            settings_panel = Panel(
                "\n".join(
                    [
                        f"[bold]Status:[/] [green]Scanning...[/]",
                        f"[bold]Duration:[/] {scan_duration}",
                        f"[bold]Devices found:[/] {device_count}",
                        "",
                        f"[bold]Find My mode:[/] {airtag_mode}",
                        f"[bold]Adaptive:[/] {adaptive_mode}",
                        f"[bold]Calibration:[/] {calibration_mode}",
                        f"[bold]Range mode:[/] [{range_color}]{range_mode}[/]",
                        f"[bold]Adapter:[/] {self.current_adapter or 'Default'}",
                        "",
                        f"{selected_info.strip() if selected_info else ''}",
                        f"{proximity_info if proximity_info else ''}",
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
                # When a device is selected, show the dedicated proximity tracking view
                # Use the new proximity view for better real-time tracking
                selected_device = self.devices[self.selected_device]

                # Make sure proximity tracking is initialized
                if (
                    not hasattr(selected_device, "previous_distance")
                    or selected_device.previous_distance is None
                ):
                    selected_device.previous_distance = selected_device.distance
                    selected_device.last_trend_update = time.time()

                # Optimize updates for selected device - update more frequently for selected devices
                current_time = time.time()
                elapsed_time = current_time - getattr(
                    selected_device, "last_trend_update", 0
                )

                # Update interval is shorter for proximity tracking (100ms instead of normal interval)
                proximity_update_interval = 0.1  # 100ms for very responsive updates

                if elapsed_time >= proximity_update_interval:
                    # Force an update to smooth RSSI value
                    if len(selected_device.rssi_history) > 0:
                        # Update proximity trend with latest data for real-time feedback
                        selected_device.update_proximity_trend()
                        selected_device.last_trend_update = current_time

                # Return dedicated proximity tracking view
                return self.generate_proximity_view(selected_device)
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
                selected_device = self.devices[self.selected_device]

                # Make sure proximity tracking is initialized
                if (
                    not hasattr(selected_device, "previous_distance")
                    or selected_device.previous_distance is None
                ):
                    selected_device.previous_distance = selected_device.distance
                    selected_device.last_trend_update = time.time()

                # Optimize updates for selected device in non-scanning mode too
                current_time = time.time()
                elapsed_time = current_time - getattr(
                    selected_device, "last_trend_update", 0
                )

                # Same optimized update interval for proximity tracking
                proximity_update_interval = 0.1  # 100ms for very responsive updates

                if elapsed_time >= proximity_update_interval:
                    # Force update when enough time has passed
                    if len(selected_device.rssi_history) > 0:
                        # Update proximity trend with latest data for real-time feedback
                        selected_device.update_proximity_trend()
                        selected_device.last_trend_update = current_time

                # Use the new proximity view instead of details panel
                return self.generate_proximity_view(selected_device)
            else:
                self.layout["details"].visible = False

            return self.layout

    async def main(self):
        """Main application entry point"""
        # Clear terminal at startup
        self.console.clear()

        # Declare globals first
        global SCAN_DURATION, DETECTION_THRESHOLD, SCAN_PARAMETERS, ADVANCED_SCAN_SETTINGS

        self.console.print(
            Panel.fit("[bold cyan]TagFinder - Bluetooth Device Scanner[/]", box=ROUNDED)
        )

        # Initialize with settings
        if "adapter" in self.settings:
            self.current_adapter = self.settings["adapter"]

        # Apply custom calibration values if available
        if "distance_n_value" in self.settings:
            global DEFAULT_DISTANCE_N_VALUE
            DEFAULT_DISTANCE_N_VALUE = self.settings["distance_n_value"]
        if "rssi_at_one_meter" in self.settings:
            global DEFAULT_RSSI_AT_ONE_METER
            DEFAULT_RSSI_AT_ONE_METER = self.settings["rssi_at_one_meter"]

        # Apply range mode settings if available
        if "scan_duration" in self.settings:
            SCAN_DURATION = self.settings["scan_duration"]
        if "detection_threshold" in self.settings:
            DETECTION_THRESHOLD = self.settings["detection_threshold"]
        if "extended_retries" in self.settings:
            ADVANCED_SCAN_SETTINGS["extended_retries"] = self.settings.get(
                "extended_retries", 3
            )

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

                # Provide clear feedback on what the mode does
                if self.airtag_only_mode:
                    self.console.print(
                        Panel.fit(
                            "[bold green]Find My/AirTag Mode: ON[/]\n\n"
                            + "Only Apple AirTags and Find My enabled devices will be displayed.\n"
                            + "This mode applies strict detection criteria to avoid false positives.",
                            title="Mode Changed",
                            border_style="green",
                        )
                    )
                else:
                    self.console.print(
                        Panel.fit(
                            "[bold red]Find My/AirTag Mode: OFF[/]\n\n"
                            + "All Bluetooth devices will be displayed.",
                            title="Mode Changed",
                            border_style="yellow",
                        )
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
            elif cmd == "r":
                # Configure scan range
                self.configure_scan_range()
            elif cmd == "m":
                # Test maximum range of all adapters
                await self.test_adapter_range()
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
                    "[yellow]Unknown command. Use 's', 'a', 'd', 'c', 'r', 'm', 'l', 'z', or 'q'.[/]"
                )

        self.console.print("[green]Exiting TagFinder...[/]")

    def configure_scan_range(self):
        """Configure scan range optimization settings"""
        # Declare globals first
        global SCAN_DURATION, DETECTION_THRESHOLD, SCAN_PARAMETERS, ADVANCED_SCAN_SETTINGS

        # Clear terminal before showing range options
        self.console.clear()

        # Current range mode
        current_mode = self.settings.get("range_mode", "Normal")

        # Display explanation and options
        self.console.print(
            Panel(
                "\n".join(
                    [
                        "[bold]Configure Scanning Range[/]",
                        "",
                        "Choose a scanning range preset to optimize detection:",
                        "",
                        f"[yellow]1. Normal[/] - Standard scanning parameters",
                        "   • Balanced power consumption",
                        "   • Detects devices within ~10-15m range",
                        "   • Battery friendly for mobile devices",
                        "",
                        f"[blue]2. Balanced[/] - Enhanced scanning parameters",
                        "   • Moderately aggressive scanning",
                        "   • Increased range up to ~20-25m",
                        "   • Moderate battery impact",
                        "",
                        f"[green]3. Maximum[/] - Maximum range optimization",
                        "   • Multi-phase aggressive scanning",
                        "   • Maximum possible range (up to ~30-40m in good conditions)",
                        "   • Uses more battery power",
                        "   • May detect very weak signals",
                        "",
                        f"Current setting: [{current_mode}]",
                    ]
                ),
                title="[bold cyan]Range Configuration[/]",
                border_style="cyan",
                box=ROUNDED,
            )
        )

        # Get user choice
        choice = self.console.input("\n[bold blue]Select range mode (1-3): [/]").strip()

        # Process choice
        range_mode = current_mode
        extended_retries = ADVANCED_SCAN_SETTINGS["extended_retries"]
        detection_threshold = DETECTION_THRESHOLD
        scan_duration = SCAN_DURATION
        scan_timeout = SCAN_PARAMETERS["timeout"]

        if choice == "1":
            range_mode = "Normal"
            extended_retries = 1  # Just one standard scan phase
            detection_threshold = -85  # Standard threshold
            scan_duration = 10.0  # Normal duration
            scan_timeout = 5.0

            self.console.print("[yellow]Normal range mode selected[/]")

        elif choice == "2":
            range_mode = "Balanced"
            extended_retries = 2  # Two scan phases
            detection_threshold = -90  # Enhanced threshold
            scan_duration = 12.0  # Slightly longer duration
            scan_timeout = 8.0

            self.console.print("[blue]Balanced range mode selected[/]")

        elif choice == "3":
            range_mode = "Maximum"
            extended_retries = 4  # Increased for ultra-aggressive scanning
            detection_threshold = -100  # Ultra-sensitive threshold for maximum range
            scan_duration = 20.0  # Extended duration for thorough scanning
            scan_timeout = 15.0  # Longer timeout to allow weak signals to be processed

            # Update advanced scan settings for maximum aggressiveness
            ADVANCED_SCAN_SETTINGS["multi_adapter"] = (
                True  # Try to use all available adapters
            )
            ADVANCED_SCAN_SETTINGS["combine_results"] = True  # Combine all results
            ADVANCED_SCAN_SETTINGS["use_extended_features"] = (
                True  # Use all extended features
            )

            self.console.print(
                "[bold green]Maximum range mode selected - Ultra-aggressive scanning enabled[/]"
            )

        else:
            self.console.print("[yellow]Invalid choice. Keeping current settings.[/]")
            return

        # Update settings
        self.settings["range_mode"] = range_mode
        self.settings["scan_duration"] = scan_duration
        self.settings["detection_threshold"] = detection_threshold

        # Update global constants based on settings
        SCAN_DURATION = scan_duration
        DETECTION_THRESHOLD = detection_threshold
        SCAN_PARAMETERS["timeout"] = scan_timeout

        # Update advanced settings
        ADVANCED_SCAN_SETTINGS["extended_retries"] = extended_retries

        # Save settings
        self._save_settings()

        # Show success message
        self.console.print(
            f"[bold green]Scan range settings updated to {range_mode} mode[/]"
        )

        # Wait for user to press a key
        self.console.print("\n[bold]Press any key to continue...[/]")
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
                # Fallback if terminal handling fails
                input()

    async def test_adapter_range(self):
        """Test all range modes for each adapter to determine optimal settings"""
        # Clear terminal
        self.console.clear()

        # Declare globals to ensure we're using the latest settings
        global SCAN_DURATION, DETECTION_THRESHOLD, SCAN_PARAMETERS, ADVANCED_SCAN_SETTINGS

        # Store original adapter and settings to restore later
        original_adapter = self.current_adapter
        original_range_mode = self.settings.get("range_mode", "Normal")
        original_scan_duration = SCAN_DURATION
        original_detection_threshold = DETECTION_THRESHOLD
        original_scan_timeout = SCAN_PARAMETERS["timeout"]
        original_extended_retries = ADVANCED_SCAN_SETTINGS["extended_retries"]

        # Create basic or_patterns for passive scanning - required for Linux
        or_patterns = [
            OrPattern(0, AdvertisementDataType.FLAGS, b"\x00"),  # Match any flags
            OrPattern(
                0, AdvertisementDataType.COMPLETE_LOCAL_NAME, b"\x00"
            ),  # Match any name
        ]

        # Force maximum range settings for the test
        SCAN_DURATION = 20.0  # Extended duration for thorough testing
        DETECTION_THRESHOLD = -100  # Maximum sensitivity
        SCAN_PARAMETERS["timeout"] = 15.0
        ADVANCED_SCAN_SETTINGS["extended_retries"] = 3

        self.console.print(
            Panel(
                "[bold cyan]Comprehensive Adapter Range Test[/]\n\n"
                "This test will scan with each available Bluetooth adapter using ALL three range modes:\n"
                "  • Normal - Standard scanning parameters\n"
                "  • Balanced - Enhanced scanning parameters\n"
                "  • Maximum - Ultra-aggressive scanning parameters\n\n"
                "The test will determine which range mode works best for each adapter in your environment.\n\n"
                "[yellow]Note: This comprehensive test may take 10-15 minutes to complete.[/]",
                title="[bold green]Optimized Adapter Settings Test[/]",
                border_style="green",
                box=ROUNDED,
            )
        )

        # Define all range modes to test
        range_modes = ["Normal", "Balanced", "Maximum"]

        # Get list of available adapters
        available_adapters = await self._find_available_adapters()

        if not available_adapters:
            self.console.print(
                "[yellow]No Bluetooth adapters found. Using default adapter.[/]"
            )
            available_adapters = [{"address": None, "name": "Default Adapter"}]

        # Create table for results
        results_table = Table(
            title="[bold]Adapter Range Mode Optimization Results[/]",
            box=ROUNDED,
            border_style="blue",
        )

        results_table.add_column("Adapter", style="cyan")
        results_table.add_column("Range Mode", style="yellow")
        results_table.add_column("Devices Found", style="green", justify="right")
        results_table.add_column("Max Distance", style="yellow", justify="right")
        results_table.add_column("Avg RSSI", style="magenta", justify="right")
        results_table.add_column("Find My Devices", style="red", justify="right")
        results_table.add_column("Scan Time", style="blue", justify="right")

        # Create comprehensive results storage
        all_results = []

        # Test each adapter with each range mode
        for i, adapter in enumerate(available_adapters):
            adapter_name = adapter["name"]
            adapter_address = adapter["address"]

            adapter_results = []

            self.console.print(
                f"\n[bold cyan]Testing adapter {i+1}/{len(available_adapters)}: {adapter_name}[/]"
            )

            # Set current adapter
            self.current_adapter = adapter_address

            # Test each range mode
            for range_mode in range_modes:
                self.console.print(
                    f"\n[bold yellow]Testing {range_mode} mode on {adapter_name}...[/]"
                )

                # Apply range mode settings
                if range_mode == "Normal":
                    # Normal mode settings
                    SCAN_DURATION = 10.0
                    DETECTION_THRESHOLD = -85
                    SCAN_PARAMETERS["timeout"] = 5.0
                    ADVANCED_SCAN_SETTINGS["extended_retries"] = 1
                elif range_mode == "Balanced":
                    # Balanced mode settings
                    SCAN_DURATION = 12.0
                    DETECTION_THRESHOLD = -90
                    SCAN_PARAMETERS["timeout"] = 8.0
                    ADVANCED_SCAN_SETTINGS["extended_retries"] = 2
                elif range_mode == "Maximum":
                    # Maximum mode settings
                    SCAN_DURATION = 15.0  # Reduced for testing (full would be 20.0)
                    DETECTION_THRESHOLD = -100
                    SCAN_PARAMETERS["timeout"] = 10.0  # Reduced for testing
                    ADVANCED_SCAN_SETTINGS["extended_retries"] = (
                        3  # Reduced for testing
                    )
                    ADVANCED_SCAN_SETTINGS["multi_adapter"] = True
                    ADVANCED_SCAN_SETTINGS["combine_results"] = True
                    ADVANCED_SCAN_SETTINGS["use_extended_features"] = True

                # Clear devices from previous tests
                self.devices = {}

                # Perform the scan
                try:
                    self.console.print(
                        f"[yellow]Starting {range_mode} scan with {adapter_name}...[/]"
                    )

                    # Record start time
                    start_time = time.time()

                    # Start a new scan with configured settings
                    scanner_kwargs = {}
                    if adapter_address:
                        scanner_kwargs["adapter"] = adapter_address

                    # Configure scanner based on range mode
                    scanner_kwargs["scanning_mode"] = (
                        "active"  # Start with active scanning
                    )
                    scanner_kwargs["detection_callback"] = self.discovery_callback
                    scanner_kwargs["timeout"] = SCAN_PARAMETERS["timeout"]

                    # Use platform-specific optimizations
                    if hasattr(bleak.backends, "bluezdbus") and sys.platform.startswith(
                        "linux"
                    ):
                        # Configure BlueZ parameters - required for both active and passive scanning
                        scanner_kwargs["bluez"] = {
                            "interval": 0x0020,  # Aggressive scanning
                            "window": 0x0020,  # Maximize window
                            "passive": False,  # Start with active scanning
                        }
                    elif (
                        hasattr(bleak.backends, "corebluetooth")
                        and sys.platform == "darwin"
                    ):
                        # Always force active mode on macOS as passive is not supported
                        scanner_kwargs["scanning_mode"] = "active"
                        scanner_kwargs["cb"] = {
                            "use_bdaddr": True,
                            "duration": SCAN_DURATION,
                        }

                    # Multi-phase scanning for maximum coverage
                    if (
                        sys.platform == "darwin"
                    ):  # macOS doesn't support passive scanning
                        scan_phases = [
                            {"mode": "active", "description": "Active scanning"},
                            {
                                "mode": "active",
                                "description": "Aggressive active scanning",
                                "interval": 0x0020,
                            },
                        ]
                    else:
                        scan_phases = [
                            {"mode": "active", "description": "Active scanning"},
                            # For Linux, always include bluez passive parameter when using passive mode
                            {
                                "mode": "passive",
                                "description": "Passive scanning",
                                "passive": True,  # This is critical for passive scanning on Linux
                            },
                        ]

                    # Progress indicator
                    progress_chars = "⣾⣽⣻⢿⡿⣟⣯⣷"
                    progress_index = 0

                    # Scan with each phase
                    for phase_idx, phase in enumerate(scan_phases):
                        # Update scanning mode
                        scanner_kwargs["scanning_mode"] = phase["mode"]

                        # For Linux, update bluez parameters when mode changes
                        if hasattr(
                            bleak.backends, "bluezdbus"
                        ) and sys.platform.startswith("linux"):
                            if "passive" in phase and phase["mode"] == "passive":
                                # Ensure bluez parameter is set correctly for passive scanning
                                scanner_kwargs["bluez"]["passive"] = True
                                # Add required or_patterns for passive scanning
                                scanner_kwargs["bluez"]["or_patterns"] = or_patterns
                            else:
                                # Active scanning
                                scanner_kwargs["bluez"]["passive"] = False

                            # Update interval if specified in the phase
                            if "interval" in phase:
                                scanner_kwargs["bluez"]["interval"] = phase["interval"]

                        # Create and start scanner
                        scanner = BleakScanner(**scanner_kwargs)
                        await scanner.start()

                        # Scan for duration
                        start_time = time.time()
                        while time.time() - start_time < SCAN_DURATION:
                            # Show progress
                            progress_index = (progress_index + 1) % len(progress_chars)
                            self.console.print(
                                f"[bold cyan]{progress_chars[progress_index]} Scanning with {phase['description']} ({int(time.time() - start_time)}/{int(SCAN_DURATION)}s)[/]",
                                end="\r",
                            )
                            await asyncio.sleep(0.5)

                        # Stop scanner
                        await scanner.stop()

                        # Calculate scan time
                        scan_time = time.time() - start_time

                        # Collect results
                        device_count = len(self.devices)

                        # Calculate maximum distance and average RSSI
                        max_distance = 0
                        total_rssi = 0
                        find_my_count = 0

                        for device in self.devices.values():
                            total_rssi += device.rssi
                            if device.distance > max_distance:
                                max_distance = device.distance
                            if device.is_airtag:
                                find_my_count += 1

                        avg_rssi = total_rssi / device_count if device_count > 0 else 0

                        # Store results for this range mode
                        mode_result = {
                            "adapter": adapter_name,
                            "adapter_address": adapter_address,
                            "range_mode": range_mode,
                            "device_count": device_count,
                            "max_distance": max_distance,
                            "avg_rssi": avg_rssi,
                            "find_my_count": find_my_count,
                            "scan_time": scan_time,
                        }

                        adapter_results.append(mode_result)
                        all_results.append(mode_result)

                        # Add to results table
                        results_table.add_row(
                            adapter_name,
                            range_mode,
                            str(device_count),
                            f"{max_distance:.2f}m",
                            f"{avg_rssi:.1f} dBm",
                            str(find_my_count),
                            f"{scan_time:.1f}s",
                        )

                        self.console.print(
                            f"\n[green]Scan complete: Found {device_count} devices with {adapter_name} in {range_mode} mode[/]"
                        )

                except Exception as e:
                    self.console.print(
                        f"[bold red]Error testing adapter {adapter_name} in {range_mode} mode: {e}[/]"
                    )
                    results_table.add_row(
                        adapter_name, range_mode, "Error", "N/A", "N/A", "N/A", "N/A"
                    )

                # Short pause between range modes
                await asyncio.sleep(1)

            # Determine best range mode for this adapter
            if adapter_results:
                # Find the best mode based on various metrics
                # First prioritize Find My devices count
                best_find_my = max(adapter_results, key=lambda x: x["find_my_count"])

                # Then device count
                best_device_count = max(
                    adapter_results, key=lambda x: x["device_count"]
                )

                # Then max distance
                best_distance = max(adapter_results, key=lambda x: x["max_distance"])

                # Show best mode for this adapter
                self.console.print(f"\n[bold cyan]Best settings for {adapter_name}:[/]")

                if best_find_my["find_my_count"] > 0:
                    self.console.print(
                        f"[bold green]Best for finding trackers:[/] {best_find_my['range_mode']} mode "
                        f"({best_find_my['find_my_count']} tracking devices)"
                    )

                if best_device_count != best_find_my:
                    self.console.print(
                        f"[bold blue]Best for overall device count:[/] {best_device_count['range_mode']} mode "
                        f"({best_device_count['device_count']} devices)"
                    )

                if best_distance != best_find_my and best_distance != best_device_count:
                    self.console.print(
                        f"[bold yellow]Best for maximum distance:[/] {best_distance['range_mode']} mode "
                        f"({best_distance['max_distance']:.2f}m)"
                    )

            # Short pause between adapters
            await asyncio.sleep(2)

        # Restore original adapter and settings
        self.current_adapter = original_adapter
        self.settings["range_mode"] = original_range_mode
        SCAN_DURATION = original_scan_duration
        DETECTION_THRESHOLD = original_detection_threshold
        SCAN_PARAMETERS["timeout"] = original_scan_timeout
        ADVANCED_SCAN_SETTINGS["extended_retries"] = original_extended_retries

        # Display results
        self.console.clear()
        self.console.print(
            Panel(
                "[bold green]Comprehensive Adapter Range Test Complete[/]\n\n"
                "The following results show the performance of each adapter with different range modes.\n"
                "This helps you identify the optimal adapter AND range mode combination for your environment.",
                title="[bold cyan]Test Results[/]",
                border_style="cyan",
            )
        )

        self.console.print(results_table)

        # Analyze results for each adapter and range mode
        if all_results:
            # Find best results by different metrics
            best_overall = max(all_results, key=lambda x: x["device_count"])
            best_for_trackers = max(all_results, key=lambda x: x["find_my_count"])
            best_for_distance = max(all_results, key=lambda x: x["max_distance"])

            # Create a best performance summary
            summary_text = []

            summary_text.append(f"[bold green]Best Overall Performance:[/]")
            summary_text.append(f"  Adapter: {best_overall['adapter']}")
            summary_text.append(f"  Range Mode: {best_overall['range_mode']}")
            summary_text.append(f"  Devices Found: {best_overall['device_count']}")
            summary_text.append(
                f"  Maximum Distance: {best_overall['max_distance']:.2f}m"
            )
            summary_text.append(f"  Find My Devices: {best_overall['find_my_count']}")
            summary_text.append("")

            # Only show best for trackers if different from overall
            if best_for_trackers != best_overall:
                summary_text.append(f"[bold red]Best for Finding Trackers:[/]")
                summary_text.append(f"  Adapter: {best_for_trackers['adapter']}")
                summary_text.append(f"  Range Mode: {best_for_trackers['range_mode']}")
                summary_text.append(
                    f"  Find My Devices: {best_for_trackers['find_my_count']}"
                )
                summary_text.append(
                    f"  Devices Found: {best_for_trackers['device_count']}"
                )
                summary_text.append("")

            # Only show best for distance if different from the others
            if (
                best_for_distance != best_overall
                and best_for_distance != best_for_trackers
            ):
                summary_text.append(f"[bold yellow]Best for Maximum Distance:[/]")
                summary_text.append(f"  Adapter: {best_for_distance['adapter']}")
                summary_text.append(f"  Range Mode: {best_for_distance['range_mode']}")
                summary_text.append(
                    f"  Maximum Distance: {best_for_distance['max_distance']:.2f}m"
                )
                summary_text.append("")

            # Add recommendations based on user goals
            summary_text.append(f"[bold cyan]Recommendations:[/]")
            summary_text.append(
                f"  • For finding trackers, use: [bold]{best_for_trackers['adapter']}[/] with [bold]{best_for_trackers['range_mode']}[/] mode"
            )
            summary_text.append(
                f"  • For maximum device detection, use: [bold]{best_overall['adapter']}[/] with [bold]{best_overall['range_mode']}[/] mode"
            )
            summary_text.append(
                f"  • For best battery life with reasonable detection, use: [bold]Normal[/] mode"
            )

            # Create optimal settings panel
            self.console.print(
                Panel(
                    "\n".join(summary_text),
                    title="[bold green]Optimal Settings Analysis[/]",
                    border_style="green",
                    box=ROUNDED,
                )
            )

            # Ask if user wants to apply the recommended settings
            apply_settings = (
                self.console.input(
                    f"\n[bold blue]Would you like to apply the recommended settings for finding trackers? "
                    f"({best_for_trackers['adapter']} with {best_for_trackers['range_mode']} mode) (y/n): [/]"
                )
                .strip()
                .lower()
            )

            if apply_settings == "y":
                # Set adapter if needed
                if best_for_trackers["adapter"] != "Default Adapter":
                    # Find address for this adapter
                    best_address = None
                    for adapter in available_adapters:
                        if adapter["name"] == best_for_trackers["adapter"]:
                            best_address = adapter["address"]
                            break

                    if best_address:
                        self.current_adapter = best_address
                        self.settings["adapter"] = best_address

                # Set range mode
                self.settings["range_mode"] = best_for_trackers["range_mode"]

                # Save settings
                self._save_settings()
                self.console.print(
                    f"[green]Settings applied: Adapter = {best_for_trackers['adapter']}, Range Mode = {best_for_trackers['range_mode']}[/]"
                )

        # Wait for user to press a key before continuing
        self.console.print("\n[bold]Press any key to return to main menu...[/]")
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
                # Fallback if terminal handling fails
                input()

    async def _find_available_adapters(self):
        """Find all available Bluetooth adapters"""
        adapters = []

        # Different methods for different platforms
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

            elif sys.platform.startswith("linux"):
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
            self.console.print(f"[bold yellow]Error finding adapters: {e}[/]")

        return adapters

    def generate_proximity_view(self, device: Device) -> Layout:
        """Generate a focused proximity tracking view for the selected device"""
        # Create a layout for the proximity view
        layout = Layout()

        # Split the layout into sections
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main_content", ratio=1),
            Layout(name="footer", size=3),
        )

        # Split the main content area into sections
        layout["main_content"].split_row(
            Layout(name="device_info", ratio=1),
            Layout(name="proximity_data", ratio=2),
        )

        # Split the proximity data section into components
        layout["proximity_data"].split(
            Layout(name="distance_gauge", ratio=2),
            Layout(name="trend_analysis", ratio=2),
            Layout(name="guidance", ratio=1),
        )

        # Create header with device name and type with proper styling
        device_type_color = "red" if device.is_airtag else "cyan"
        header_text = Text()
        header_text.append(device.name, style="bold white")
        header_text.append(" (")
        header_text.append(device.device_type, style=device_type_color)
        header_text.append(")")

        header = Panel(
            header_text,
            title="Proximity Tracking",
            title_align="center",
            style="bold cyan",
            border_style="cyan",
            box=ROUNDED,
        )
        layout["header"].update(header)

        # Create device information panel with proper styling
        device_info_text = Text()
        device_info_text.append("\n◉ Device Details\n\n", style="bold cyan")

        device_info_text.append("Address: ", style="bold")
        device_info_text.append(f"{device.address}\n")

        device_info_text.append("Manufacturer: ", style="bold")
        device_info_text.append(f"{device.manufacturer}\n")

        # Add battery info if available
        if "Battery" in device.device_details:
            device_info_text.append(f"Battery: ", style="bold")
            battery_info = device.device_details.split("Battery: ")[1].split("%")[0]
            try:
                battery_level = int(battery_info)
                battery_color = (
                    "green"
                    if battery_level > 50
                    else "yellow" if battery_level > 20 else "red"
                )
                device_info_text.append(f"{battery_level}%\n", style=battery_color)
            except ValueError:
                device_info_text.append(f"{battery_info}%\n")

        # Add signal quality information
        device_info_text.append(f"Signal Quality: ", style="bold")
        quality = device.signal_quality
        quality_style = "green" if quality > 70 else "yellow" if quality > 40 else "red"
        device_info_text.append(f"{quality:.1f}%\n", style=quality_style)

        device_info_text.append(f"Signal Stability: ", style="bold")
        stability = device.signal_stability
        stability_style = (
            "green" if stability < 3 else "yellow" if stability < 6 else "red"
        )
        device_info_text.append(f"{stability:.1f}\n", style=stability_style)

        # Add first seen information
        device_info_text.append(f"First Seen: ", style="bold")
        first_seen_ago = time.time() - device.first_seen
        device_info_text.append(f"{format_time_ago(first_seen_ago)} ago\n")

        # Create tracker info if relevant
        if device.is_airtag:
            device_info_text.append("\n◉ Tracker Information\n\n", style="bold red")
            tracker_type = device.get_tracker_type()
            device_info_text.append("Type: ", style="bold")
            device_info_text.append(f"{tracker_type}\n", style="red")

            # Get confidence level
            if hasattr(device, "tracker_confidence"):
                confidence_levels = {
                    TRACKING_CONFIDENCE["CONFIRMED"]: ("Confirmed", "bright_red"),
                    TRACKING_CONFIDENCE["HIGH"]: ("High", "red"),
                    TRACKING_CONFIDENCE["MEDIUM"]: ("Medium", "yellow"),
                    TRACKING_CONFIDENCE["LOW"]: ("Low", "blue"),
                    TRACKING_CONFIDENCE["UNLIKELY"]: ("Unlikely", "blue"),
                }
                confidence_level, confidence_style = confidence_levels.get(
                    device.tracker_confidence, ("Unknown", "red")
                )
                device_info_text.append(f"Confidence: ", style="bold")
                device_info_text.append(f"{confidence_level}\n", style=confidence_style)

        device_info_panel = Panel(
            device_info_text,
            title="Device Info",
            style="bold cyan",
            border_style="cyan",
            box=ROUNDED,
        )
        layout["device_info"].update(device_info_panel)

        # Get detailed proximity analysis
        proximity_analysis = device.get_detailed_proximity_analysis()

        # Create distance gauge panel - a visual representation of distance
        distance = device.distance
        gauge_text = Text()

        # Create an enhanced visual distance gauge with more real-time information
        gauge_text.append("\n")
        gauge_text.append("Current Distance:", style="bold cyan")

        # Distance with units display
        if distance < 1:
            gauge_text.append(
                f" {distance:.2f}m ({distance*100:.0f}cm)\n\n", style="bold green"
            )
        elif distance < 3:
            gauge_text.append(f" {distance:.2f}m\n\n", style="bold yellow")
        else:
            gauge_text.append(f" {distance:.2f}m\n\n", style="bold red")

        # Visual gauge - different representation based on distance
        if distance <= 10:  # Only show gauge for distances under 10m
            gauge_width = 48  # Wider gauge for better visualization
            filled_chars = min(
                int((10 - min(distance, 10)) / 10 * gauge_width), gauge_width
            )
            empty_chars = gauge_width - filled_chars

            # Color coding based on distance
            if distance < 1:
                color = "green"
            elif distance < 3:
                color = "yellow"
            else:
                color = "red"

            gauge_text.append("0m ")
            gauge_text.append("█" * filled_chars, style=f"bold {color}")
            gauge_text.append("░" * empty_chars, style="dim")
            gauge_text.append(" 10m\n\n")

            # Add real-time signal information section
            gauge_text.append("Signal Information\n", style="bold cyan")

            # Current RSSI with timestamp
            rssi_time = time.strftime("%H:%M:%S.%f")[:-3]
            gauge_text.append(f"RSSI: ", style="bold")

            # Color-code RSSI
            rssi_style = (
                "green"
                if device.rssi > -70
                else "yellow" if device.rssi > -85 else "red"
            )
            gauge_text.append(f"{device.rssi} dBm", style=rssi_style)
            gauge_text.append(f" (at {rssi_time})\n")

            # Add smoothed RSSI
            gauge_text.append(f"Smoothed RSSI: ", style="bold")
            smooth_rssi_style = (
                "green"
                if device.smooth_rssi > -70
                else "yellow" if device.smooth_rssi > -85 else "red"
            )
            gauge_text.append(
                f"{device.smooth_rssi:.1f} dBm\n", style=smooth_rssi_style
            )

            # Add calibration parameters
            gauge_text.append(f"RSSI@1m: ", style="bold")
            gauge_text.append(f"{device.calibrated_rssi_at_one_meter} dBm\n")

            gauge_text.append(f"Env factor: ", style="bold")
            gauge_text.append(f"{device.calibrated_n_value:.2f}\n")

            # Signal quality
            gauge_text.append(f"Quality: ", style="bold")
            quality = device.signal_quality
            quality_style = (
                "green" if quality > 70 else "yellow" if quality > 40 else "red"
            )
            gauge_text.append(f"{quality:.1f}%\n\n", style=quality_style)

            # Show real-time distance changes with more detail
            gauge_text.append("Distance Trend\n", style="bold cyan")

            if (
                hasattr(device, "previous_distance")
                and device.previous_distance is not None
            ):
                delta = distance - device.previous_distance
                if abs(delta) >= 0.01:  # Only show meaningful changes
                    delta_text = f"{abs(delta):.2f}m"
                    delta_pct = abs(delta / max(device.previous_distance, 0.1)) * 100

                    if delta < 0:
                        gauge_text.append(f"Direction: ", style="bold")
                        gauge_text.append(f"▼ Closer ", style="bold green")
                        gauge_text.append(f"({delta_pct:.1f}% change)\n", style="green")

                        # Show rate of approach
                        time_diff = time.time() - device.last_trend_update
                        if time_diff > 0:
                            approach_rate = abs(delta) / time_diff
                            gauge_text.append(f"Speed: ", style="bold")
                            gauge_text.append(
                                f"{approach_rate:.2f} m/s\n", style="green"
                            )
                    else:
                        gauge_text.append(f"Direction: ", style="bold")
                        gauge_text.append(f"▲ Further ", style="bold red")
                        gauge_text.append(f"({delta_pct:.1f}% change)\n", style="red")

                        # Show rate of movement away
                        time_diff = time.time() - device.last_trend_update
                        if time_diff > 0:
                            away_rate = abs(delta) / time_diff
                            gauge_text.append(f"Speed: ", style="bold")
                            gauge_text.append(f"{away_rate:.2f} m/s\n", style="red")
                else:
                    gauge_text.append(f"Direction: ", style="bold")
                    gauge_text.append(f"◆ Stable\n", style="bold yellow")

                # Show historical distance changes if available
                if (
                    hasattr(device, "distance_trend")
                    and len(device.distance_trend) >= 3
                ):
                    # Get last few distance points
                    recent_distances = [d for _, d, _, _ in device.distance_trend[-3:]]
                    gauge_text.append(f"Recent values: ", style="bold")
                    gauge_text.append(
                        f"{', '.join([f'{d:.2f}m' for d in recent_distances])}\n"
                    )
        else:
            # For long distances, show simple text
            gauge_text.append("Distance too large for visual gauge\n", style="yellow")
            gauge_text.append(f"RSSI: ", style="bold")
            gauge_text.append(f"{device.rssi} dBm\n", style="red")

        distance_panel = Panel(
            gauge_text,
            title="Distance Gauge",
            style="bold green",
            border_style="green",
            box=ROUNDED,
        )
        layout["distance_gauge"].update(distance_panel)

        # Create enhanced trend analysis panel with more visuals
        trend_text = Text()
        trend_text.append("\n")

        status = proximity_analysis.get("status", "unknown")

        if status == "initializing":
            trend_text.append("Initializing trend analysis...\n", style="yellow")
            trend_text.append("\nMove around to establish tracking data.")
        else:
            # Show the direction trend visually with real-time timestamp
            direction = proximity_analysis.get("direction", "unknown")
            confidence = proximity_analysis.get("confidence", 0.0)
            current_time = time.strftime("%H:%M:%S.%f")[:-3]

            # Visual trend indicator
            trend_text.append("Movement Trend: ", style="bold cyan")
            if direction == "closer":
                trend_text.append("▼ GETTING CLOSER\n", style="bold green")
            elif direction == "further":
                trend_text.append("▲ MOVING AWAY\n", style="bold red")
            else:
                trend_text.append("◆ STABLE\n", style="bold yellow")
            trend_text.append(f"Updated at: {current_time}\n\n")

            # Add confidence meter with improved visualization
            trend_text.append("Confidence: ", style="bold cyan")
            confidence_bar = "█" * int(confidence * 10)
            empty_bar = "░" * (10 - int(confidence * 10))
            if confidence > 0.7:
                confidence_color = "green"
            elif confidence > 0.4:
                confidence_color = "yellow"
            else:
                confidence_color = "red"
            trend_text.append(f"{confidence_bar}", style=f"bold {confidence_color}")
            trend_text.append(f"{empty_bar}", style="dim")
            trend_text.append(f" {confidence*100:.0f}%\n\n")

            # Show detailed prediction with improved formatting
            trend_text.append("Analysis:\n", style="bold cyan")
            analysis_message = proximity_analysis.get("message", "")

            # Apply different styles based on message content
            if "getting closer" in analysis_message.lower():
                trend_text.append(f"{analysis_message}\n\n", style="green")
            elif "moving away" in analysis_message.lower():
                trend_text.append(f"{analysis_message}\n\n", style="red")
            else:
                trend_text.append(f"{analysis_message}\n\n")

            # Add prediction visualization
            prediction = proximity_analysis.get("prediction", {})
            if prediction and "distance" in prediction:
                predicted_distance = prediction["distance"]
                prediction_time = prediction.get("time", 5.0)

                trend_text.append("Prediction:\n", style="bold cyan")
                trend_text.append(f"In {prediction_time} seconds: ", style="bold")

                if predicted_distance < distance:
                    pred_style = "green"
                    pred_prefix = "▼ "
                elif predicted_distance > distance:
                    pred_style = "red"
                    pred_prefix = "▲ "
                else:
                    pred_style = "yellow"
                    pred_prefix = "◆ "

                trend_text.append(
                    f"{pred_prefix}{predicted_distance:.2f}m\n", style=pred_style
                )

                # Show distance change prediction
                distance_change = predicted_distance - distance
                pct_change = (distance_change / max(distance, 0.1)) * 100

                if abs(distance_change) > 0.01:
                    trend_text.append("Expected change: ", style="bold")
                    if distance_change < 0:
                        trend_text.append(
                            f"{distance_change:.2f}m ({pct_change:.1f}%)\n\n",
                            style="green",
                        )
                    else:
                        trend_text.append(
                            f"+{distance_change:.2f}m (+{pct_change:.1f}%)\n\n",
                            style="red",
                        )
                else:
                    trend_text.append("Expected change: ", style="bold")
                    trend_text.append("minimal\n\n", style="yellow")

            # Show technical details for advanced users with more information
            trend_text.append("Technical Details:\n", style="bold cyan")
            rate = proximity_analysis.get("rate", 0.0)
            rate_abs = abs(rate)

            # Rate of change with intuitive description
            trend_text.append("Rate of change: ", style="bold")
            if rate < 0:
                speed_desc = (
                    "very fast"
                    if rate_abs > 0.5
                    else (
                        "fast"
                        if rate_abs > 0.2
                        else "moderate" if rate_abs > 0.1 else "slow"
                    )
                )
                trend_text.append(
                    f"{rate:.2f} m/s (approaching {speed_desc})\n", style="green"
                )
            elif rate > 0:
                speed_desc = (
                    "very fast"
                    if rate_abs > 0.5
                    else (
                        "fast"
                        if rate_abs > 0.2
                        else "moderate" if rate_abs > 0.1 else "slow"
                    )
                )
                trend_text.append(
                    f"{rate:.2f} m/s (receding {speed_desc})\n", style="red"
                )
            else:
                trend_text.append(f"{rate:.2f} m/s (stable)\n", style="yellow")

            # Show current data points used for analysis
            data_points = proximity_analysis.get("data_points", 0)
            trend_text.append("Data points: ", style="bold")
            trend_text.append(f"{data_points}\n")

            # Calculate and show estimated time to reach device if approaching
            if direction == "closer" and rate_abs > 0.01:
                time_to_reach = device.distance / rate_abs
                if time_to_reach < 120:  # Only show if less than 2 minutes
                    trend_text.append("ETA: ", style="bold")
                    # Format time to reach in a more user-friendly way
                    if time_to_reach < 10:
                        trend_text.append(f"{time_to_reach:.1f}s\n", style="bold green")
                    elif time_to_reach < 30:
                        trend_text.append(f"{time_to_reach:.1f}s\n", style="green")
                    else:
                        trend_text.append(
                            f"{time_to_reach:.0f}s (~{time_to_reach/60:.1f}min)\n",
                            style="yellow",
                        )

        trend_panel = Panel(
            trend_text,
            title="Trend Analysis",
            style="bold magenta",
            border_style="magenta",
            box=ROUNDED,
        )
        layout["trend_analysis"].update(trend_panel)

        # Create enhanced guidance panel with more real-time actionable advice
        guidance_text = Text()
        guidance_text.append("\n")

        # Get guidance message
        guidance_message = device.get_movement_guidance()

        # Style based on distance
        if device.distance < 0.5:
            guidance_color = "bright_green"
        elif device.distance < 2.0:
            guidance_color = "green"
        elif device.distance < 5.0:
            guidance_color = "yellow"
        else:
            guidance_color = "red"

        guidance_text.append(guidance_message, style=f"bold {guidance_color}")
        guidance_text.append("\n\n")

        # Add dynamic suggestions based on current trend and environment
        trend_direction = ""
        if hasattr(device, "distance_trend") and device.distance_trend:
            _, _, direction, _ = device.distance_trend[-1]
            trend_direction = direction

        guidance_text.append("Current Suggestion:\n", style="bold cyan")

        # Get the detailed analysis to determine next step
        analysis = device.get_detailed_proximity_analysis()
        confidence = analysis.get("confidence", 0)

        if device.distance < 0.5:
            # Very close - focused search
            guidance_text.append(
                "• Look around carefully at eye level\n", style="bright_green"
            )
            guidance_text.append(
                "• Check pockets, bags, and nearby objects\n", style="bright_green"
            )
            guidance_text.append(
                "• Try making the device play a sound if available\n",
                style="bright_green",
            )
        elif trend_direction == "closer" and confidence > 0.5:
            # Getting closer with good confidence
            guidance_text.append("• Continue in the same direction\n", style="green")
            guidance_text.append(
                "• Increase movement speed for faster result\n", style="green"
            )
            guidance_text.append(
                f"• Keep watching the RSSI ({device.rssi} dBm) to confirm progress\n",
                style="green",
            )
        elif trend_direction == "further" and confidence > 0.5:
            # Moving away with good confidence
            guidance_text.append(
                "• Stop and reverse direction immediately\n", style="red"
            )
            guidance_text.append(
                "• Make larger movements to establish clear signal change\n",
                style="red",
            )
            guidance_text.append(
                "• Watch for signal strength improvement\n", style="red"
            )
        elif confidence < 0.4:
            # Low confidence - need to establish baseline
            guidance_text.append(
                "• Move in large, deliberate steps (1-2m at a time)\n", style="yellow"
            )
            guidance_text.append(
                "• Pause for 2-3 seconds after each movement\n", style="yellow"
            )
            guidance_text.append(
                "• Try moving in a grid pattern to find the best signal\n",
                style="yellow",
            )
        else:
            # General advice
            guidance_text.append(
                "• Move deliberately in one direction at a time\n", style="cyan"
            )
            guidance_text.append("• Pause briefly after each movement\n", style="cyan")
            guidance_text.append(
                "• Watch signal strength to determine direction\n", style="cyan"
            )

        # Add environment-specific advice
        guidance_text.append("\nEnvironment Tips:\n", style="bold cyan")

        # Signal stability-based tips for the current environment
        if device.signal_stability > 7:
            # Very unstable signal - likely indoors with obstacles
            guidance_text.append(
                "• Signal is unstable (indoor/obstacles detected)\n", style="yellow"
            )
            guidance_text.append(
                "• Move slowly and check multiple levels\n", style="yellow"
            )
            guidance_text.append(
                "• Be aware of walls and metal objects causing reflections\n",
                style="yellow",
            )
        elif device.signal_stability < 3:
            # Stable signal - likely outdoors or line-of-sight
            guidance_text.append(
                "• Signal is stable (likely outdoor/clear area)\n", style="green"
            )
            guidance_text.append(
                "• Trust the distance readings more precisely\n", style="green"
            )
            guidance_text.append(
                "• Make larger movements to save time\n", style="green"
            )

        # Add Apple-specific tips for AirTags
        if device.is_airtag and "Apple" in device.manufacturer:
            guidance_text.append("\nAirTag-Specific:\n", style="bold cyan")
            guidance_text.append(
                "• Try using Find My app with Precision Finding\n", style="green"
            )
            guidance_text.append(
                "• If available, use UWB direction finding\n", style="green"
            )
            guidance_text.append(
                "• Try making the AirTag play a sound through Find My\n", style="green"
            )

        guidance_panel = Panel(
            guidance_text,
            title="Movement Guidance",
            style="bold yellow",
            border_style="yellow",
            box=ROUNDED,
        )
        layout["guidance"].update(guidance_panel)

        # Create footer with key controls
        footer = Panel(
            "[bold cyan]Controls:[/] [bold blue]q[/] - Quit scanning | [bold blue]b[/] - Back to device list",
            border_style="blue",
            box=SIMPLE,
        )
        layout["footer"].update(footer)

        return layout


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
