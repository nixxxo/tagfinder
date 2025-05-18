#!/usr/bin/env python3

import asyncio
import copy
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

# Updated FindMy data patterns based on Adam Catley's research
FIND_MY_DATA_PATTERNS = [
    {"offset": 0, "value": 0x12, "mask": 0xFF},  # First byte 0x12
    {"offset": 1, "value": 0x19, "mask": 0xFF},  # Second byte 0x19
    {"offset": 0, "value": 0x10, "mask": 0xFF},  # First byte 0x10 (alternate pattern)
    {"offset": 0, "value": 0x0F, "mask": 0xFF},  # First byte 0x0F (Nearby interaction)
    {"offset": 0, "value": 0x07, "mask": 0xFF},  # AirPods pattern / Unregistered Airtag
    {"offset": 0, "value": 0x01, "mask": 0xFF},  # Another AirPods pattern
    {"offset": 0, "value": 0x0C, "mask": 0xFF},  # iPhone/iPad pattern
]

# Add specific AirTag status bits patterns for detection
AIRTAG_STATUS_BITS = {
    0x01: "Separated from owner",
    0x02: "Play Sound",
    0x04: "Lost Mode",
}

# Add AirTag status byte battery level indicators
AIRTAG_BATTERY_STATUS = {
    0x10: "Battery Full",  # Status byte 0x10 when battery is full
    0x50: "Battery Medium",  # Status byte 0x50 when battery is medium
    0x90: "Battery Low",  # Status byte 0x90 when battery is low
    0xD0: "Battery Very Low",  # Status byte 0xD0 when battery is very low
}

# AirTag advertisement format details
AIRTAG_ADV_FORMAT = {
    "adv_data_length": 0x1E,  # Advertising data length: 31 (maximum allowed)
    "adv_data_type": 0xFF,  # Advertising data type: Manufacturer Specific Data
    "company_id": 0x004C,  # Apple's company identifier (2 bytes: 0x004C)
    "registered_payload_type": 0x12,  # Apple payload type for FindMy network broadcast
    "unregistered_payload_type": 0x07,  # Apple payload type for unregistered device
    "payload_length": 0x19,  # Apple payload length (31 - 6 = 25 = 0x19)
    "status_byte_offset": 6,  # Status byte position in advertisement data
    "public_key_offset": 7,  # Start of EC P-224 public key
    "public_key_length": 23,  # Length of public key in advertisement
    "crypto_counter_offset": 31,  # Position of crypto counter (changes every 15min)
}

# Daily update timing for AirTag
AIRTAG_UPDATE_TIMES = {
    "public_key": "04:00am",  # Updates BLE address and public key once a day at 04:00am
    "advertisement_data": 15
    * 60,  # Updates last byte of advertisement data every 15 minutes
}

# AirTag sleep/wake timing
AIRTAG_TIMING = {
    "lost_mode_trigger": 3
    * 24
    * 60
    * 60,  # Goes into lost mode exactly 3 days after separation
    "sound_alert_interval": 6
    * 60
    * 60,  # Makes noise once every 6 hours in lost mode with movement
    "accelerometer_idle_sample": 10,  # Samples accelerometer every 10 seconds when waiting for movement
    "accelerometer_active_sample": 0.5,  # Samples accelerometer every 0.5 seconds after motion
    "accelerometer_active_duration": 20,  # Samples accelerometer for 20 seconds after motion detected
    "advertisement_interval": 2,  # Transmits BLE advertisement every 2 seconds when away from owner
    "unregistered_adv_interval": 0.033,  # Unregistered AirTag advertises every 33ms
    "connection_interval": 1,  # BLE connection interval of 1 second when near owner
}

# AirTag specific power profiles
AIRTAG_POWER = {
    "sleep_current": 2.3,  # µA (microamps)
    "min_voltage": 1.9,  # Volts (minimum to boot)
    "advertisement_current": 6.0,  # mA during advertisement
    "accelerometer_sample_current": 0.4,  # mA during accelerometer wakeup
}

# Add Apple-specific apple advertisement data structures
APPLE_ADV_TYPES = {
    0x01: "iBeacon",
    0x05: "AirDrop",
    0x07: "Unregistered AirTag/FindMy",
    0x09: "HomeKit",
    0x0A: "AirTag/Find My",
    0x0C: "Handoff",
    0x0F: "Nearby",
    0x10: "Nearby Action/Find My",
    0x12: "Find My",
}

# Add specific byte positions for AirTag status in manufacturer data
AIRTAG_BYTE_POSITIONS = {
    "status": 5,  # Status byte position in manufacturer data for AirTag status
    "type": 2,  # Type byte position (0x0A for AirTag)
    "protocol": [0, 1],  # Protocol identifier bytes (0x12, 0x19)
    "battery_status": 6,  # Position of status byte that contains battery level
    "public_key": [7, 29],  # Range of bytes for the public key (inclusive)
    "crypto_counter": 31,  # Crypto counter byte (changes every 15 minutes)
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
        # Store previous advertisement time for calculating interval
        # (Used for AirTag detection based on Adam Catley's research on 2s advertisement interval)
        self.previous_seen = getattr(self, "last_seen", time.time())

        # Store previous manufacturer data to detect changes
        if 76 in self.manufacturer_data:  # Apple's company identifier
            # Store previous data before updating
            if not hasattr(self, "prev_manufacturer_data"):
                self.prev_manufacturer_data = {}
            self.prev_manufacturer_data[76] = bytes(self.manufacturer_data[76])

        self.rssi = rssi
        self.rssi_history.append(rssi)

        # Check for manufacturer data changes (for detecting AirTag 15-minute update cycle)
        if manufacturer_data:
            # Check for changes in Apple's manufacturer data
            if (
                76 in manufacturer_data
                and hasattr(self, "prev_manufacturer_data")
                and 76 in self.prev_manufacturer_data
            ):
                # Compare data to detect changes in advertisement
                if bytes(manufacturer_data[76]) != self.prev_manufacturer_data[76]:
                    # Record time of change and update counter
                    current_time = time.time()
                    self.last_adv_change_time = current_time

                    # Calculate time since last change if available
                    if hasattr(self, "prev_adv_change_time"):
                        change_interval = current_time - self.prev_adv_change_time
                        # Check if this matches the 15-minute cycle from Adam's research
                        if 840 <= change_interval <= 960:  # 14-16 minutes in seconds
                            self.matches_airtag_timing = True
                        self.adv_change_interval = change_interval

                    # Update change history
                    self.prev_adv_change_time = current_time
                    self.adv_changes = getattr(self, "adv_changes", 0) + 1

            # Now update the actual data
            self.manufacturer_data = manufacturer_data

        if service_data:
            self.service_data = service_data
        if service_uuids:
            self.service_uuids = service_uuids
        if is_new is not None:
            self.is_new = is_new

        self.last_seen = time.time()

        # Calculate advertisement interval (Adam's research says AirTags use ~2s when separated)
        self.adv_interval = self.last_seen - self.previous_seen
        # Build up history of intervals to detect consistent patterns
        if not hasattr(self, "adv_interval_history"):
            self.adv_interval_history = deque(maxlen=10)
        self.adv_interval_history.append(self.adv_interval)

        # Analyze if device shows consistent ~2s advertisement interval like AirTags
        if len(self.adv_interval_history) >= 5:
            # Calculate average and standard deviation
            avg_interval = sum(self.adv_interval_history) / len(
                self.adv_interval_history
            )
            # Check if average is close to AirTag's expected 2s and relatively stable
            if 1.8 <= avg_interval <= 2.2:
                self.consistent_airtag_interval = True

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

            # Try to extract Apple model details based on Adam Catley's AirTag research
            if len(apple_data) > 5:
                try:
                    # AirTag protocol detection
                    # Registered AirTag/Find My protocol (0x12, 0x19)
                    if apple_data[0] == 0x12 and apple_data[1] == 0x19:
                        details.append("Find My Network")
                    # Unregistered AirTag detection (0x07, 0x19) per new research
                    elif apple_data[0] == 0x07 and apple_data[1] == 0x19:
                        details.append("Unregistered AirTag")

                        # Check for AirTag specific identifiers
                        if len(apple_data) > 3 and apple_data[2] & 0x0F == 0x0A:
                            details.append("AirTag")

                        # Track advertisement data changes - might indicate 15 minute update cycle
                        if hasattr(self, "last_advertisement_data"):
                            if (
                                self.manufacturer_data[76]
                                != self.last_advertisement_data
                            ):
                                self.advertisement_changed_at = time.time()
                                self.advertisement_changes = (
                                    getattr(self, "advertisement_changes", 0) + 1
                                )
                        # Store current data for next comparison
                        self.last_advertisement_data = bytes(self.manufacturer_data[76])

                        # Try to extract AirTag status bits if available (position 5 according to Adam's research)
                        if len(apple_data) >= 6:
                            status_byte = apple_data[5]
                            status_details = []

                            if status_byte & 0x01:
                                status_details.append("Separated")
                            if status_byte & 0x02:
                                status_details.append("Play Sound")
                            if status_byte & 0x04:
                                status_details.append("Lost Mode")

                            # Add status bits information
                            if status_details:
                                details.append(" | ".join(status_details))

                            # Add status byte for advanced users if non-zero
                            if status_byte > 0:
                                details.append(f"Status: 0x{status_byte:02X}")

                        # Check for battery status at position 6 (per new research)
                        if len(apple_data) >= 7:
                            battery_status_byte = apple_data[6]
                            battery_value = battery_status_byte & 0xF0

                            # Check against known battery status values from new research
                            if battery_value == 0x10:
                                details.append("Battery Full")
                            elif battery_value == 0x50:
                                details.append("Battery Medium")
                            elif battery_value == 0x90:
                                details.append("Battery Low")
                            elif battery_value == 0xD0:
                                details.append("Battery Very Low")

                        # Check for crypto counter (position 31) which changes every 15 minutes
                        if len(apple_data) >= 32:
                            # Store the crypto counter for change detection
                            if not hasattr(self, "crypto_counter"):
                                self.crypto_counter = apple_data[31]
                                self.crypto_counter_time = time.time()
                            elif self.crypto_counter != apple_data[31]:
                                # Calculate time since last change
                                time_diff = time.time() - self.crypto_counter_time
                                # Check if it's around 15 minutes (14-16 min range)
                                if 840 <= time_diff <= 960:
                                    details.append("15min Counter Change")
                                    self.crypto_counter_matches = True
                                # Update for next check
                                self.crypto_counter = apple_data[31]
                                self.crypto_counter_time = time.time()

                            # Show the crypto counter value (helpful for tracking changes)
                            details.append(f"Counter: 0x{apple_data[31]:02X}")

                        # Add timing information if we have it
                        if (
                            hasattr(self, "advertisement_changes")
                            and self.advertisement_changes > 0
                        ):
                            details.append(f"Adv Changes: {self.advertisement_changes}")

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
        """Check if device is potentially an AirTag or other tracking device with enhanced detection based on
        Adam Catley's research on AirTag reverse engineering"""
        # Store verification flags with confidence levels
        evidence = {
            "name_match": False,
            "apple_manufacturer": False,
            "find_my_pattern": False,
            "airtag_pattern": False,
            "known_uuid": False,
            "service_data": False,
            "nearby_interaction": False,
            "status_bits": False,
            "advertisement_interval": False,
            "daily_advertisement_update": False,
            "unregistered_airtag": False,  # New flag for unregistered AirTags
            "battery_status": False,  # New flag for battery status detection
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

                        # Also store the Apple advertisement type for further analysis
                        if offset == 0:
                            if data[0] in APPLE_ADV_TYPES:
                                self.apple_adv_type = APPLE_ADV_TYPES[data[0]]
                            else:
                                self.apple_adv_type = (
                                    f"Unknown Apple Type: {data[0]:02X}"
                                )
                        break

                # Exact Find My network pattern (highest confidence) - Registered AirTag
                if len(data) > 1 and data[0] == 0x12 and data[1] == 0x19:
                    evidence["find_my_pattern"] = True

                    # Exact AirTag identifier pattern - AirTag type is 0x0A
                    # According to Adam Catley's research, this is a definitive AirTag marker
                    if len(data) > 3 and data[2] & 0x0F == 0x0A:
                        evidence["airtag_pattern"] = True

                    # Check for AirTag status bits if we have enough data
                    # Adam's research shows status byte at position 5
                    if len(data) >= 6:
                        status_byte = data[5]
                        # Store the AirTag status bits for display and analysis
                        self.airtag_status = {}
                        for bit, meaning in AIRTAG_STATUS_BITS.items():
                            if status_byte & bit:
                                self.airtag_status[bit] = meaning
                                evidence["status_bits"] = True

                    # Check for battery status in status byte at position 6
                    if len(data) >= 7:
                        battery_byte = data[6] & 0xF0
                        if battery_byte in [0x10, 0x50, 0x90, 0xD0]:
                            evidence["battery_status"] = True
                            if battery_byte == 0x10:
                                self.battery_status = "Battery Full"
                            elif battery_byte == 0x50:
                                self.battery_status = "Battery Medium"
                            elif battery_byte == 0x90:
                                self.battery_status = "Battery Low"
                            elif battery_byte == 0xD0:
                                self.battery_status = "Battery Very Low"

                # Check for Unregistered AirTag pattern (type 0x07)
                # According to new research, unregistered AirTags use this pattern
                if len(data) > 1 and data[0] == 0x07 and data[1] == 0x19:
                    evidence["unregistered_airtag"] = True
                    # Store the information for later use
                    self.unregistered_airtag = True
                    # This is a stronger evidence than just a generic "find_my_pattern"
                    # as it specifically identifies an unregistered AirTag

                # Check for Nearby Interaction protocol (also used by Find My)
                if len(data) > 2 and data[0] == 0x0F:
                    evidence["nearby_interaction"] = True

        # Check for specific status update timing patterns
        # According to Adam's research, AirTags update advertisement data every 15 minutes
        # This is harder to detect in a single scan, but we can look for consistent advertisement
        # interval around 2 seconds as mentioned in Adam's research
        if hasattr(self, "last_seen") and getattr(self, "previous_seen", None):
            adv_interval = self.last_seen - self.previous_seen
            # Registered AirTags advertise approximately every 2 seconds when away from owner
            if 1.5 <= adv_interval <= 2.5:
                evidence["advertisement_interval"] = True
            # Unregistered AirTags advertise much more frequently (~33ms)
            elif 0.02 <= adv_interval <= 0.05:
                evidence["unregistered_airtag"] = True

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
                    # Store the matching Find My UUID for further analysis
                    self.find_my_uuid = uuid
                    break

        # Check for specific service data patterns related to Find My network
        for service_uuid, data in self.service_data.items():
            service_uuid_upper = service_uuid.upper()
            if any(find_my_id in service_uuid_upper for find_my_id in FIND_MY_UUIDS):
                evidence["service_data"] = True
                # Store the service data for further analysis
                self.find_my_service_data = data.hex() if data else ""
                break

        # Apply decision rules for classification based on Adam Catley's research:

        # Definite AirTag (extremely high confidence)
        if (
            # AirTag specific pattern mentioned in Adam's research - highest confidence
            (evidence["apple_manufacturer"] and evidence["airtag_pattern"])
            # Unregistered AirTag pattern
            or (evidence["apple_manufacturer"] and evidence["unregistered_airtag"])
            # Find My pattern with status bits is very high confidence
            or (
                evidence["apple_manufacturer"]
                and evidence["find_my_pattern"]
                and evidence["status_bits"]
            )
            # AirTag based on multiple high confidence indicators
            or (
                evidence["apple_manufacturer"]
                and evidence["find_my_pattern"]
                and evidence["known_uuid"]
            )
            # AirTag with battery status indicators
            or (
                evidence["apple_manufacturer"]
                and evidence["find_my_pattern"]
                and evidence["battery_status"]
            )
            # AirTag with correct advertisement interval timings per Adam's research
            or (
                evidence["apple_manufacturer"]
                and evidence["find_my_pattern"]
                and evidence["advertisement_interval"]
            )
            # Old but reliable pattern according to Adam's research
            or (
                evidence["apple_manufacturer"]
                and evidence["nearby_interaction"]
                and evidence["known_uuid"]
            )
        ):
            return True

        # High confidence Find My device (not necessarily an AirTag)
        if (
            (evidence["apple_manufacturer"] and evidence["find_my_pattern"])
            or (evidence["apple_manufacturer"] and evidence["known_uuid"])
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
        """Calculate confidence level for tracker detection (0 = confirmed, 4 = unlikely)
        based on Adam Catley's AirTag research"""
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
                # Classic Find My pattern from Adam Catley's research (0x12, 0x19)
                if data[0] == 0x12 and data[1] == 0x19:
                    evidence_points += 3

                # AirTag specific pattern (type byte is 0x0A) - strongest evidence according to research
                if len(data) > 2 and data[2] & 0x0F == 0x0A:
                    evidence_points += (
                        5  # Increased due to high confidence based on research
                    )

                # Check for status bits - strong evidence for AirTag
                if len(data) >= 6:
                    status_byte = data[5]
                    # If any status bits are set that match known AirTag states
                    if status_byte & 0x01:  # Separated from owner
                        evidence_points += 4
                    if status_byte & 0x02:  # Play Sound
                        evidence_points += 4
                    if status_byte & 0x04:  # Lost Mode
                        evidence_points += 4

                # Other Apple Find My patterns identified in Adam's research
                if data[0] == 0x10:  # Nearby Action/Find My
                    evidence_points += 3
                elif data[0] == 0x0F:  # Nearby Interaction
                    evidence_points += 2
                elif data[0] == 0x07 or data[0] == 0x01:  # AirPods patterns
                    evidence_points += (
                        1  # Lower points as these are not tracker-specific
                    )

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
                    # Higher points for more specific Find My UUIDs identified by Adam
                    if any(
                        specific_id in uuid_upper
                        for specific_id in ["7DFC9000", "7DFC9001"]
                    ):
                        evidence_points += (
                            3  # Higher confidence for specific AirTag UUIDs
                        )
                    else:
                        evidence_points += 2
                    break

        # Check for Find My service data
        for service_uuid, _ in self.service_data.items():
            service_uuid_upper = service_uuid.upper()
            if any(find_my_id in service_uuid_upper for find_my_id in FIND_MY_UUIDS):
                evidence_points += 2
                break

        # Check consistent advertisement timing if data available
        if hasattr(self, "last_seen") and getattr(self, "previous_seen", None):
            adv_interval = self.last_seen - self.previous_seen
            # According to Adam's research, AirTags advertise every ~2 seconds when separated
            if 1.8 <= adv_interval <= 2.2:
                evidence_points += 2

        # Check AirTag power states if data is available
        if hasattr(self, "rssi_history") and len(self.rssi_history) >= 5:
            # Look for patterns of consistent signal that match AirTag advertisement pattern
            # AirTags advertise every 2 seconds with relatively stable power
            rssi_diffs = [
                abs(self.rssi_history[i] - self.rssi_history[i - 1])
                for i in range(1, len(self.rssi_history))
            ]
            avg_diff = sum(rssi_diffs) / len(rssi_diffs)
            if (
                avg_diff < 5
            ):  # Stable RSSI indicates fixed location and consistent transmission
                evidence_points += 1

        # Determine confidence level based on evidence points - thresholds adjusted based on research
        if evidence_points >= 9:  # Increased for definitive identification
            return TRACKING_CONFIDENCE["CONFIRMED"]
        elif evidence_points >= 6:  # Adjusted for high confidence
            return TRACKING_CONFIDENCE["HIGH"]
        elif evidence_points >= 4:  # Adjusted for medium confidence
            return TRACKING_CONFIDENCE["MEDIUM"]
        elif evidence_points >= 1:
            return TRACKING_CONFIDENCE["LOW"]
        else:
            return TRACKING_CONFIDENCE["UNLIKELY"]

    def get_tracker_type(self) -> str:
        """Identify the specific type of tracking device based on Adam Catley's AirTag research"""
        if not self.is_airtag:
            return "Not a tracker"

        # --- AirTag Identification (High Confidence) ---
        if self.manufacturer == "Apple":
            # Definitive AirTag signal with type byte 0x0A as documented by Adam Catley
            if 76 in self.manufacturer_data and len(self.manufacturer_data[76]) > 2:
                data = self.manufacturer_data[76]

                # Check for specific AirTag type byte (0x0A)
                if len(data) > 3 and data[2] & 0x0F == 0x0A:
                    # Check if we've observed timing characteristics of AirTags
                    if (
                        hasattr(self, "consistent_airtag_interval")
                        and self.consistent_airtag_interval
                    ):
                        return "Apple AirTag (Verified)"
                    else:
                        return "Apple AirTag"

                # Check for exact FindMy protocol with status bits that match AirTag
                if (
                    len(data) > 5
                    and data[0] == 0x12
                    and data[1] == 0x19
                    and data[5] & 0x07
                ):  # Check if any status bits are set

                    # Check status byte for AirTag-specific bits identified by Adam
                    status_bits = []
                    if data[5] & 0x01:
                        status_bits.append("Separated")
                    if data[5] & 0x02:
                        status_bits.append("Play Sound")
                    if data[5] & 0x04:
                        status_bits.append("Lost Mode")

                    if status_bits:
                        return f"Apple AirTag ({', '.join(status_bits)})"

                # Unregistered AirTag pattern - type 0x07, 0x19 as per new research
                if data[0] == 0x07 and data[1] == 0x19:
                    return "Unregistered Apple AirTag"

                # Find My pattern but no specific AirTag identifier - type 0x12, 0x19
                if data[0] == 0x12 and data[1] == 0x19:
                    # Check for battery status indicator to improve confidence
                    if hasattr(self, "battery_status"):
                        return f"Apple AirTag ({self.battery_status})"

                    # Check timing characteristics unique to AirTags according to Adam
                    if (
                        hasattr(self, "consistent_airtag_interval")
                        and self.consistent_airtag_interval
                    ):
                        return "Likely Apple AirTag"
                    elif (
                        hasattr(self, "matches_airtag_timing")
                        and self.matches_airtag_timing
                    ):
                        return "Likely Apple AirTag"
                    elif (
                        hasattr(self, "crypto_counter_matches")
                        and self.crypto_counter_matches
                    ):
                        return "Likely Apple AirTag (15min cycle)"
                    else:
                        return "Apple Find My Device"

                # Nearby Interaction protocol (0x0F) with confident timing
                if data[0] == 0x0F and hasattr(self, "consistent_airtag_interval"):
                    return "Likely Apple AirTag"

            # Clear name match
            if self.name and "airtag" in self.name.lower():
                return "Apple AirTag"

            # Check for Find My Network specific UUIDs identified by Adam Catley
            for uuid in self.service_uuids:
                uuid_upper = uuid.upper()
                # More specific UUIDs that are strongly associated with AirTags
                if any(
                    find_my_id in uuid_upper for find_my_id in ["7DFC9000", "7DFC9001"]
                ):
                    return "Apple AirTag"
                # General Find My network UUIDs
                elif any(
                    find_my_id in uuid_upper for find_my_id in ["0000FD44", "74278BDA"]
                ):
                    return "Apple Find My Device"

            # Check for advertisement interval pattern (2s) specific to AirTags (Adam's research)
            if (
                hasattr(self, "adv_interval_history")
                and len(self.adv_interval_history) >= 5
            ):
                avg_interval = sum(self.adv_interval_history) / len(
                    self.adv_interval_history
                )
                if 1.8 <= avg_interval <= 2.2:
                    return "Likely Apple AirTag"

            # Check for 15-minute advertisement data update pattern described by Adam
            if hasattr(self, "matches_airtag_timing") and self.matches_airtag_timing:
                return "Likely Apple AirTag"

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
        """Convert device to dictionary for storage including AirTag detection properties"""
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

        # Convert advertisement interval history to serializable format
        adv_interval_history = list(getattr(self, "adv_interval_history", []))

        # Basic device data
        result = {
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
            # Include AirTag detection properties based on Adam Catley's research
            "previous_seen": getattr(self, "previous_seen", None),
            "adv_interval": getattr(self, "adv_interval", None),
            "adv_interval_history": adv_interval_history,
            "consistent_airtag_interval": getattr(
                self, "consistent_airtag_interval", False
            ),
            "adv_changes": getattr(self, "adv_changes", 0),
            "last_adv_change_time": getattr(self, "last_adv_change_time", None),
            "prev_adv_change_time": getattr(self, "prev_adv_change_time", None),
            "adv_change_interval": getattr(self, "adv_change_interval", None),
            "matches_airtag_timing": getattr(self, "matches_airtag_timing", False),
            "apple_adv_type": getattr(self, "apple_adv_type", None),
            "find_my_uuid": getattr(self, "find_my_uuid", None),
            "find_my_service_data": getattr(self, "find_my_service_data", None),
            "airtag_status": getattr(self, "airtag_status", {}),
            # New AirTag detection properties
            "unregistered_airtag": getattr(self, "unregistered_airtag", False),
            "battery_status": getattr(self, "battery_status", None),
            "crypto_counter": getattr(self, "crypto_counter", None),
            "crypto_counter_time": getattr(self, "crypto_counter_time", None),
            "crypto_counter_matches": getattr(self, "crypto_counter_matches", False),
        }

        # If we have stored the last advertisement data, convert it to a serializable format
        if hasattr(self, "last_advertisement_data"):
            result["last_advertisement_data"] = list(self.last_advertisement_data)

        # Convert previous manufacturer data to serializable format if available
        if hasattr(self, "prev_manufacturer_data"):
            result["prev_manufacturer_data"] = {
                str(k): list(v) for k, v in self.prev_manufacturer_data.items()
            }

        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "Device":
        """Create device from dictionary including AirTag detection properties"""
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

        # Restore AirTag detection properties from Adam Catley's research
        if "previous_seen" in data:
            device.previous_seen = data["previous_seen"]

        if "adv_interval" in data:
            device.adv_interval = data["adv_interval"]

        if "adv_interval_history" in data and isinstance(
            data["adv_interval_history"], list
        ):
            device.adv_interval_history = deque(data["adv_interval_history"], maxlen=10)

        if "consistent_airtag_interval" in data:
            device.consistent_airtag_interval = data["consistent_airtag_interval"]

        if "adv_changes" in data:
            device.adv_changes = data["adv_changes"]

        if "last_adv_change_time" in data:
            device.last_adv_change_time = data["last_adv_change_time"]

        if "prev_adv_change_time" in data:
            device.prev_adv_change_time = data["prev_adv_change_time"]

        if "adv_change_interval" in data:
            device.adv_change_interval = data["adv_change_interval"]

        if "matches_airtag_timing" in data:
            device.matches_airtag_timing = data["matches_airtag_timing"]

        if "apple_adv_type" in data:
            device.apple_adv_type = data["apple_adv_type"]

        if "find_my_uuid" in data:
            device.find_my_uuid = data["find_my_uuid"]

        if "find_my_service_data" in data:
            device.find_my_service_data = data["find_my_service_data"]

        if "airtag_status" in data and isinstance(data["airtag_status"], dict):
            device.airtag_status = data["airtag_status"]

        # Restore new AirTag detection properties
        if "unregistered_airtag" in data:
            device.unregistered_airtag = data["unregistered_airtag"]

        if "battery_status" in data:
            device.battery_status = data["battery_status"]

        if "crypto_counter" in data:
            device.crypto_counter = data["crypto_counter"]

        if "crypto_counter_time" in data:
            device.crypto_counter_time = data["crypto_counter_time"]

        if "crypto_counter_matches" in data:
            device.crypto_counter_matches = data["crypto_counter_matches"]

        # Restore last advertisement data if available
        if "last_advertisement_data" in data and isinstance(
            data["last_advertisement_data"], list
        ):
            device.last_advertisement_data = bytes(data["last_advertisement_data"])

        # Restore previous manufacturer data if available
        if "prev_manufacturer_data" in data and isinstance(
            data["prev_manufacturer_data"], dict
        ):
            device.prev_manufacturer_data = {
                int(k): bytes(v)
                for k, v in data.get("prev_manufacturer_data", {}).items()
            }

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

        # Column visibility settings
        self.visible_columns = self.settings.get(
            "visible_columns",
            {
                "name": True,
                "type": True,
                "mac": True,
                "track_prob": True,
                "manufacturer": True,
                "rssi": True,
                "signal": True,
                "distance": True,
                "last_seen": True,
                "details": True,
            },
        )

        # Sorting priority settings (default: track_prob → distance → last_seen)
        if "sort_priority" not in self.settings:
            self.settings["sort_priority"] = ["track_prob", "distance", "last_seen"]

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
        # Save column visibility settings
        self.settings["visible_columns"] = self.visible_columns
        with open(SETTINGS_FILE, "w") as f:
            json.dump(self.settings, f, indent=2)

    def _update_sort_priority(self, sort_key: str, position: int = 0):
        """Update the sort priority by moving a key to the specified position

        Args:
            sort_key: The key to prioritize
            position: The position to place the key (0 = first priority)
        """
        # Get current priority list or use default
        current_priority = self.settings.get(
            "sort_priority", ["track_prob", "distance", "last_seen"]
        )

        # Remove the key if it already exists in the list
        if sort_key in current_priority:
            current_priority.remove(sort_key)

        # Insert the key at the specified position
        current_priority.insert(position, sort_key)

        # Limit to 3 sort keys maximum to keep sorting reasonable
        self.settings["sort_priority"] = current_priority[:3]

        # Save settings
        self._save_settings()

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

        # Find available adapters
        adapters = await self._find_available_adapters()

        # If no adapters found, add a default one
        if not adapters:
            adapters.append({"address": "default", "name": "Default Bluetooth Adapter"})

        # Display adapters table
        table = Table(title="Available Bluetooth Adapters", box=box.ROUNDED)
        table.add_column("Index", style="cyan")
        table.add_column("Address", style="green")
        table.add_column("Name", style="magenta")

        # Only add status column for Linux which has this information
        if sys.platform.startswith("linux"):
            table.add_column("Status", style="yellow")
            table.add_column("ID", style="cyan")

        for i, adapter in enumerate(adapters):
            is_current = (
                "[bold green]⟹[/]" if adapter["address"] == self.current_adapter else ""
            )

            if sys.platform.startswith("linux"):
                status = adapter.get("status", "UNKNOWN")
                status_style = "[bold green]" if status == "UP" else "[bold red]"
                adapter_id = adapter.get("id", "Unknown")
                table.add_row(
                    str(i),
                    adapter["address"] or "Unknown",
                    f"{adapter['name']} {is_current}",
                    f"{status_style}{status}[/]",
                    adapter_id,
                )
            else:
                table.add_row(
                    str(i),
                    adapter["address"] or "Unknown",
                    f"{adapter['name']} {is_current}",
                )

        self.console.print(table)

        # If on Linux, suggest the first UP adapter
        default_choice = ""
        if sys.platform.startswith("linux"):
            # Find the first UP adapter
            up_adapters = [i for i, a in enumerate(adapters) if a.get("status") == "UP"]
            if up_adapters:
                default_choice = str(up_adapters[0])
                self.console.print(
                    f"[bold green]Suggested adapter: {adapters[up_adapters[0]]['name']} (UP)[/]"
                )

        choice = self.console.input(
            f"[bold blue]Select adapter index (or Enter {f'for suggested [{default_choice}]' if default_choice else 'to skip'}): [/]"
        )

        # Use default_choice if user just pressed Enter and a default was suggested
        if choice == "" and default_choice:
            choice = default_choice

        if choice.isdigit() and 0 <= int(choice) < len(adapters):
            selected_adapter = adapters[int(choice)]
            self.current_adapter = selected_adapter["address"]
            self.settings["adapter"] = self.current_adapter

            # For Linux, also store the adapter ID (hci0, hci1, etc.) which will be needed later
            if sys.platform.startswith("linux") and "id" in selected_adapter:
                self.settings["adapter_id"] = selected_adapter["id"]
                # Print info about the selected adapter
                status = selected_adapter.get("status", "UNKNOWN")
                self.console.print(
                    f"[bold {'green' if status == 'UP' else 'red'}]Adapter status: {status}[/]"
                )

            self._save_settings()
            self.console.print(
                f"[bold green]Selected adapter: {adapters[int(choice)]['name']}[/]"
            )

    def generate_device_table(self, devices: Dict[str, Device]) -> Table:
        """Generate a table of devices for display"""
        # Create a responsive table that adapts to available space

        # Get current sort priority
        sort_priority = self.settings.get(
            "sort_priority", ["track_prob", "distance", "last_seen"]
        )
        sort_names = {
            "track_prob": "Track probability",
            "distance": "Distance",
            "last_seen": "Last seen",
            "rssi": "Signal strength",
            "signal": "Signal quality",
        }

        # Format sort priority for display
        sort_display = " → ".join([sort_names.get(p, p) for p in sort_priority])

        table = Table(
            title=f"[bold]Bluetooth Devices[/] [dim](Sorted by: {sort_display})[/]",
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

        # Add columns with responsive width settings - respect visibility settings

        # Name column is always visible (required for selection)
        table.add_column("Name", style="cyan", ratio=3, no_wrap=False)

        # Type column
        if self.visible_columns.get("type", True):
            table.add_column("Type", ratio=2, no_wrap=False)

        # MAC address column
        if self.visible_columns.get("mac", True):
            table.add_column("MAC", ratio=1, no_wrap=False)

        # Tracker probability column
        if self.visible_columns.get("track_prob", True):
            table.add_column("Track Prob", justify="center", ratio=1)

        # Manufacturer column - respect both space constraints and visibility
        if self.visible_columns.get("manufacturer", True) and (
            not has_selected or self.console.width > 100
        ):
            table.add_column("Manufacturer", ratio=1, no_wrap=False)

        # RSSI column
        if self.visible_columns.get("rssi", True):
            table.add_column("RSSI", justify="right", ratio=1)

        # Signal column
        if self.visible_columns.get("signal", True):
            table.add_column("Signal", justify="right", ratio=1)  # Signal quality info

        # Distance column
        if self.visible_columns.get("distance", True):
            table.add_column("Distance", justify="right", ratio=1)

        # Last seen column - respect both space constraints and visibility
        if self.visible_columns.get("last_seen", True) and (
            not has_selected or self.console.width > 120
        ):
            table.add_column("Last Seen", justify="right", ratio=1)

        # Details column - respect both space constraints and visibility
        if self.visible_columns.get("details", True):
            if self.console.width > 140:
                table.add_column("Details", ratio=5, no_wrap=False)
            else:
                table.add_column("Details", ratio=4, no_wrap=False)

        # Create a sorting function based on current sort priority
        def multi_sort_key(device):
            # Get sort priority from settings or use default
            sort_priority = self.settings.get(
                "sort_priority", ["track_prob", "distance", "last_seen"]
            )

            # Initialize keys dictionary
            keys = {}

            # Tracker probability (convert confidence to numeric value, lower is higher confidence)
            if device.is_airtag:
                keys["track_prob"] = (
                    device.tracker_confidence
                )  # Lower values = higher confidence
            else:
                keys["track_prob"] = 999  # Non-trackers at bottom

            # Distance (smaller values first)
            keys["distance"] = device.distance if device.distance < 100 else 100

            # Last seen (negative value puts most recent first)
            keys["last_seen"] = -device.last_seen

            # RSSI (stronger signal first)
            keys["rssi"] = (
                -device.smooth_rssi
            )  # Negative RSSI value makes stronger signals first

            # Signal quality (higher quality first)
            keys["signal"] = (
                -device.signal_quality
            )  # Negative value makes higher quality first

            # Create a tuple of keys based on current sort priority
            return tuple(keys[k] for k in sort_priority if k in keys)

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
        # This sorted_device_list is used for tab navigation in selection mode
        # We need to make sure it's consistent with our frozen device list if we're in selection mode
        if (
            hasattr(self, "selection_mode")
            and self.selection_mode
            and hasattr(self, "frozen_devices")
        ):
            # When in selection mode, we should use the same sorting but on frozen devices
            # to ensure consistent tab navigation
            frozen_sorted = sorted(self.frozen_devices.values(), key=multi_sort_key)
            self.sorted_device_list = frozen_sorted
        else:
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
                # Also store the current cursor position's device for consistency
                if hasattr(self, "frozen_devices"):
                    # Ensure the cursor_device comes from frozen_devices in selection mode
                    frozen_devices_list = list(self.frozen_devices.values())
                    if 0 <= self.cursor_position < len(frozen_devices_list):
                        frozen_device = frozen_devices_list[self.cursor_position]
                        self.cursor_device = frozen_device.address

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

            # Build row data based on which columns are visible
            row_data = [name_display]  # Name is always visible

            # Type column
            if self.visible_columns.get("type", True):
                row_data.append(device.device_type)

            # MAC column
            if self.visible_columns.get("mac", True):
                row_data.append(mac_display)

            # Tracker probability column
            if self.visible_columns.get("track_prob", True):
                row_data.append(tracker_prob_display)

            # Manufacturer column - respect both space constraints and visibility
            if self.visible_columns.get("manufacturer", True) and (
                not has_selected or self.console.width > 100
            ):
                row_data.append(device.manufacturer)

            # RSSI column
            if self.visible_columns.get("rssi", True):
                row_data.append(Text(rssi_str, style=f"{rssi_color} {style}"))

            # Signal column
            if self.visible_columns.get("signal", True):
                row_data.append(
                    Text(f"{signal_quality}", style=f"{signal_color} {style}")
                )

            # Distance column
            if self.visible_columns.get("distance", True):
                row_data.append(distance)

            # Last seen column - respect both space constraints and visibility
            if self.visible_columns.get("last_seen", True) and (
                not has_selected or self.console.width > 120
            ):
                # Color code last seen times
                if time_since_last_seen < 30:
                    seen_style = "green"  # Very recent
                elif time_since_last_seen < 300:
                    seen_style = "yellow"  # Within last 5 minutes
                else:
                    seen_style = "red"  # Older

                row_data.append(Text(seen_time, style=f"{seen_style}"))

            # Details column
            if self.visible_columns.get("details", True):
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
        # Skip updates when in selection mode to prevent table movement
        if hasattr(self, "selection_mode") and self.selection_mode:
            return

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

            # Use the specific adapter ID that was selected (or default to hci0)
            adapter_id = self.settings.get("adapter_id", "hci0")
            scanner_kwargs["adapter"] = adapter_id

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
                            # For Linux, try to clean up any existing BLE scan operations first
                            try:
                                import subprocess

                                # Only attempt adapter reset if we're seeing issues
                                if (
                                    hasattr(self, "_last_scan_error")
                                    and "operation already in progress"
                                    in str(self._last_scan_error).lower()
                                ):
                                    # Use the stored adapter_id if available, default to hci0 otherwise
                                    adapter_id = self.settings.get("adapter_id", "hci0")

                                    # First check if adapter is UP
                                    try:
                                        check_result = subprocess.run(
                                            ["hciconfig", adapter_id],
                                            capture_output=True,
                                            text=True,
                                        )
                                        if "UP RUNNING" not in check_result.stdout:
                                            self.console.print(
                                                f"[bold red]Bluetooth adapter {adapter_id} is not UP. Cannot scan with this adapter.[/]"
                                            )
                                            # Try to bring the adapter up
                                            subprocess.run(
                                                ["sudo", "hciconfig", adapter_id, "up"],
                                                capture_output=True,
                                            )
                                    except Exception as e:
                                        self.console.print(
                                            f"[bold red]Error checking adapter status: {e}[/]"
                                        )

                                    self.console.print(
                                        f"[bold yellow]Resetting Bluetooth adapter {adapter_id} to clear stuck operations...[/]"
                                    )
                                    subprocess.run(
                                        ["hciconfig", adapter_id, "reset"],
                                        capture_output=True,
                                    )
                                    await asyncio.sleep(
                                        1.0
                                    )  # Let BlueZ settle after reset
                                    self._last_scan_error = None  # Clear the error
                            except Exception as e:
                                self.console.print(
                                    f"[yellow]Failed to reset adapter: {e}. Continuing...[/]",
                                    end="\r",
                                )

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
            # Clean up frozen devices when exiting selection mode
            if hasattr(self, "frozen_devices"):
                del self.frozen_devices
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
                # Clean up frozen devices when exiting selection mode
                if hasattr(self, "frozen_devices"):
                    del self.frozen_devices
        # Column visibility toggle keys
        elif key == "c":  # Toggle type column
            self.visible_columns["type"] = not self.visible_columns.get("type", True)
            self._save_settings()
        elif key == "m":  # Toggle MAC address column
            self.visible_columns["mac"] = not self.visible_columns.get("mac", True)
            self._save_settings()
        elif key == "p":  # Toggle tracker probability column
            self.visible_columns["track_prob"] = not self.visible_columns.get(
                "track_prob", True
            )
            self._save_settings()
        elif key == "f":  # Toggle manufacturer column
            self.visible_columns["manufacturer"] = not self.visible_columns.get(
                "manufacturer", True
            )
            self._save_settings()
        elif key == "r":  # Toggle RSSI column
            self.visible_columns["rssi"] = not self.visible_columns.get("rssi", True)
            self._save_settings()
        elif key == "s":  # Toggle signal column
            self.visible_columns["signal"] = not self.visible_columns.get(
                "signal", True
            )
            self._save_settings()
        elif key == "d":  # Toggle distance column
            self.visible_columns["distance"] = not self.visible_columns.get(
                "distance", True
            )
            self._save_settings()
        elif key == "l":  # Toggle last seen column
            self.visible_columns["last_seen"] = not self.visible_columns.get(
                "last_seen", True
            )
            self._save_settings()
        elif key == "i":  # Toggle details column
            self.visible_columns["details"] = not self.visible_columns.get(
                "details", True
            )
            self._save_settings()

        # Sort priority controls - using Shift+Number combination
        elif key == "!":  # Shift+1: Set track probability as first sort key
            self._update_sort_priority("track_prob", 0)
        elif key == "@":  # Shift+2: Set distance as first sort key
            self._update_sort_priority("distance", 0)
        elif key == "#":  # Shift+3: Set last seen as first sort key
            self._update_sort_priority("last_seen", 0)
        elif key == "$":  # Shift+4: Set signal strength (RSSI) as first sort key
            self._update_sort_priority("rssi", 0)
        elif key == "%":  # Shift+5: Set signal quality as first sort key
            self._update_sort_priority("signal", 0)
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
                    # Clean up frozen devices when exiting selection mode
                    if hasattr(self, "frozen_devices"):
                        del self.frozen_devices
            except ValueError:
                # Invalid buffer content
                pass

    def _update_ui(self) -> Layout:
        """Update the UI layout"""
        if self.scanning:
            # Create scanning-specific layout
            scanning_layout = Layout()

            # Store a snapshot of devices when entering selection mode
            if (
                hasattr(self, "selection_mode")
                and self.selection_mode
                and not hasattr(self, "frozen_devices")
            ):
                self.frozen_devices = copy.deepcopy(self.devices)
            # Clear frozen devices when exiting selection mode
            elif hasattr(self, "frozen_devices") and not (
                hasattr(self, "selection_mode") and self.selection_mode
            ):
                del self.frozen_devices

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
            # Use frozen devices for time calculations when in selection mode
            devices_to_use = (
                self.frozen_devices if hasattr(self, "frozen_devices") else self.devices
            )
            scan_time = time.time() - min(
                [d.first_seen for d in devices_to_use.values()], default=time.time()
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
                        "[bold cyan]Column Visibility Controls:[/]",
                        " [bold blue]c[/] - Toggle Type column",
                        " [bold blue]m[/] - Toggle MAC column",
                        " [bold blue]p[/] - Toggle Track Prob column",
                        " [bold blue]f[/] - Toggle Manufacturer column",
                        " [bold blue]r[/] - Toggle RSSI column",
                        " [bold blue]s[/] - Toggle Signal column",
                        " [bold blue]d[/] - Toggle Distance column",
                        " [bold blue]l[/] - Toggle Last Seen column",
                        " [bold blue]i[/] - Toggle Details column",
                        "",
                        "[bold cyan]Sorting Controls:[/]",
                        " [bold blue]Shift+1[/] - Sort by tracking probability",
                        " [bold blue]Shift+2[/] - Sort by distance",
                        " [bold blue]Shift+3[/] - Sort by last seen time",
                        " [bold blue]Shift+4[/] - Sort by signal strength",
                        " [bold blue]Shift+5[/] - Sort by signal quality",
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

            # Prepare column visibility status
            column_status = []
            column_names = {
                "type": "Type",
                "mac": "MAC",
                "track_prob": "Track Prob",
                "manufacturer": "Manufacturer",
                "rssi": "RSSI",
                "signal": "Signal",
                "distance": "Distance",
                "last_seen": "Last Seen",
                "details": "Details",
            }

            for key, display_name in column_names.items():
                is_visible = self.visible_columns.get(key, True)
                status = f"[green]✓[/]" if is_visible else f"[red]✗[/]"
                column_status.append(f"{display_name}: {status}")

                # Format column visibility status in a compact way
            # Check terminal width to determine how many columns to use
            if self.console.width > 100:
                # For wider terminals, use 3 columns
                vis_col1 = column_status[:3]
                vis_col2 = column_status[3:6]
                vis_col3 = column_status[6:]

                vis_status = []
                for i in range(max(len(vis_col1), len(vis_col2), len(vis_col3))):
                    row = []
                    if i < len(vis_col1):
                        row.append(vis_col1[i])
                    else:
                        row.append("")

                    if i < len(vis_col2):
                        row.append(vis_col2[i])
                    else:
                        row.append("")

                    if i < len(vis_col3):
                        row.append(vis_col3[i])
                    else:
                        row.append("")

                    vis_status.append(" | ".join([col for col in row if col]))
            else:
                # For narrower terminals, use 2 columns to fit better
                half = len(column_status) // 2 + len(column_status) % 2
                vis_col1 = column_status[:half]
                vis_col2 = column_status[half:]

                vis_status = []
                for i in range(max(len(vis_col1), len(vis_col2))):
                    row = []
                    if i < len(vis_col1):
                        row.append(vis_col1[i])
                    else:
                        row.append("")

                    if i < len(vis_col2):
                        row.append(vis_col2[i])
                    else:
                        row.append("")

                    vis_status.append(" | ".join([col for col in row if col]))

            # Format current sort order for display
            sort_priority = self.settings.get(
                "sort_priority", ["track_prob", "distance", "last_seen"]
            )
            sort_names = {
                "track_prob": "Track probability",
                "distance": "Distance",
                "last_seen": "Last seen",
                "rssi": "Signal strength",
                "signal": "Signal quality",
            }

            # Choose display format based on available width
            if self.console.width > 140:
                # For wide screens, use verbose format with priorities
                sort_display = []
                for i, key in enumerate(sort_priority[:3]):
                    priority = ["1st", "2nd", "3rd"][i]
                    sort_display.append(
                        f"{priority}: [cyan]{sort_names.get(key, key)}[/]"
                    )
            else:
                # For narrower screens, use a more compact format
                sort_display = [
                    f"1:[cyan]{sort_names.get(sort_priority[0], sort_priority[0])}[/]",
                    f"2:[cyan]{sort_names.get(sort_priority[1], sort_priority[1])}[/] 3:[cyan]{sort_names.get(sort_priority[2], sort_priority[2])}[/]",
                ]

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
                        "[bold cyan]Visible Columns:[/]",
                        *vis_status,
                        "",
                        "[bold cyan]Sort Priority:[/]",
                        *sort_display,
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

            # Calculate minimum required height for controls panel
            # Base size + column controls + sorting controls + device selection info
            controls_panel_height = 9 + 9 + 9 + (2 if input_status else 0)

            # Calculate minimum required height for settings panel
            # Basic settings + column visibility + sort priority + device details
            settings_panel_height = (
                9
                + len(vis_status)
                + len(sort_display)
                + (2 if selected_info else 0)
                + (2 if proximity_info else 0)
            )

            # Determine minimum required height for both panels
            min_panel_height = max(controls_panel_height, settings_panel_height)

            # Choose layout based on available width
            top_panel = Layout()

            if self.console.width > 120:
                # For wide screens, use side-by-side layout
                top_panel.split_row(
                    Layout(name="controls_panel", ratio=1),
                    Layout(name="settings_panel", ratio=1),
                )

                top_panel["controls_panel"].update(controls_panel)
                top_panel["settings_panel"].update(settings_panel)
            else:
                # For narrower screens, create a combined panel with all info
                combined_content = []

                # Core controls section
                combined_content.extend(
                    [
                        "[bold cyan]Controls:[/]",
                        " [bold blue]q[/] - Quit  [bold blue]0-9[/] - Select device  [bold blue]t[/] - Tab mode",
                        " [bold blue]Tab/Space[/] - Navigate  [bold blue]Enter[/] - Select  [bold blue]b[/] - Back",
                        "",
                    ]
                )

                # Column controls in compact format
                combined_content.extend(
                    [
                        "[bold cyan]Columns:[/] [dim](toggle with key)[/]",
                        " [bold blue]c[/]-Type [bold blue]m[/]-MAC [bold blue]p[/]-Track [bold blue]f[/]-Mfr [bold blue]r[/]-RSSI",
                        " [bold blue]s[/]-Signal [bold blue]d[/]-Dist [bold blue]l[/]-Seen [bold blue]i[/]-Details",
                        "",
                    ]
                )

                # Sorting controls
                combined_content.extend(
                    [
                        "[bold cyan]Sort:[/] [dim](Shift+number)[/]",
                        " [bold blue]1[/]-Track [bold blue]2[/]-Dist [bold blue]3[/]-Time [bold blue]4[/]-RSSI [bold blue]5[/]-Quality",
                        "",
                    ]
                )

                # Current settings
                combined_content.extend(
                    [
                        f"[bold]Status:[/] [green]Scanning...[/] ({scan_duration}) - {device_count} devices",
                        f"[bold]Find My:[/] {airtag_mode} [bold]Adaptive:[/] {adaptive_mode} [bold]Calib:[/] {calibration_mode}",
                        f"[bold]Range:[/] [{range_color}]{range_mode}[/] [bold]Adapter:[/] {self.current_adapter or 'Default'}",
                        "",
                    ]
                )

                # Add sort priority information in a compact way
                sort_info = []
                for i, key in enumerate(sort_priority[:3]):
                    priority = ["1st", "2nd", "3rd"][i]
                    sort_name = sort_names.get(key, key)
                    # Truncate long names
                    if len(sort_name) > 12:
                        sort_name = sort_name[:10] + ".."
                    sort_info.append(f"{key.split('_')[0]}")

                combined_content.extend(
                    [
                        f"[bold]Sort:[/] [cyan]1:{sort_info[0]}[/] → [cyan]2:{sort_info[1]}[/] → [cyan]3:{sort_info[2]}[/]",
                        "",
                    ]
                )

                # Device selection status
                if input_status:
                    combined_content.append(input_status.strip())

                if selected_info:
                    combined_content.append(selected_info.strip())

                if proximity_info:
                    combined_content.append(proximity_info.strip())

                # Create the compact panel
                # If we have a lot of content, use a scrollable panel
                total_content_height = len(combined_content)

                # Check if we need a scrollable panel (more than ~20 lines of content)
                if total_content_height > 20:
                    from rich.console import Group

                    # Create a scrollable group with all content
                    scrollable_content = Group(
                        *[Text(line) for line in combined_content]
                    )

                    compact_panel = Panel(
                        scrollable_content,
                        title="[bold blue]TagFinder Controls & Settings[/] [dim](Scrollable)[/]",
                        border_style="blue",
                        box=ROUNDED,
                        expand=True,
                    )
                else:
                    # Standard panel for normal content amount
                    compact_panel = Panel(
                        "\n".join(combined_content),
                        title="[bold blue]TagFinder Controls & Settings[/]",
                        border_style="blue",
                        box=ROUNDED,
                        expand=True,
                    )

                # Use a single layout with the compact panel
                top_panel.update(compact_panel)

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
                # Calculate the best panel height based on screen size and content
                if self.console.width > 120:
                    # For wider screens with side-by-side panels
                    min_height = max(
                        min_panel_height, 24
                    )  # At least 24 lines for side-by-side panels
                else:
                    # For narrower screens with compact layout
                    min_height = max(
                        16, min(22, len(combined_content) + 2)
                    )  # Content height + panel borders

                # Ensure the controls area doesn't take more than 40% of the screen height
                max_height = int(self.console.height * 0.5)
                panel_height = min(min_height, max_height)

                scanning_layout.split(
                    Layout(name="controls", size=panel_height),
                    Layout(name="devices", ratio=1),
                )

                scanning_layout["controls"].update(top_panel)
                # Use frozen devices in selection mode to keep table from moving
                devices_to_display = (
                    self.frozen_devices
                    if hasattr(self, "frozen_devices")
                    else self.devices
                )
                scanning_layout["devices"].update(
                    self.generate_device_table(devices_to_display)
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
            # Use frozen devices in selection mode to keep table from moving
            devices_to_display = (
                self.frozen_devices if hasattr(self, "frozen_devices") else self.devices
            )
            self.layout["devices"].update(
                self.generate_device_table(devices_to_display)
            )

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
                # Ask if user wants standard or advanced range testing
                self.console.clear()
                self.console.print(
                    Panel(
                        "\n".join(
                            [
                                "[bold cyan]Adapter Range Testing[/]",
                                "",
                                "[yellow]1. Standard Mode[/] - Test basic range modes (Normal, Balanced, Maximum)",
                                "   • Takes 10-15 minutes to complete",
                                "   • Tests standard configurations",
                                "   • Recommended for most users",
                                "",
                                "[green]2. Advanced Mode[/] - Test multiple parameter combinations",
                                "   • Takes 25-40 minutes to complete",
                                "   • Tests multiple configurations for each range mode",
                                "   • Provides more detailed optimization",
                                "   • For advanced users seeking maximum performance",
                            ]
                        ),
                        title="[bold]Select Testing Mode[/]",
                        border_style="blue",
                        box=ROUNDED,
                    )
                )

                # Get user choice
                test_choice = self.console.input(
                    "\n[bold]Select testing mode (1-2): [/]"
                ).strip()
                advanced_mode = test_choice == "2"

                # Run test with appropriate mode
                await self.test_adapter_range(advanced_mode=advanced_mode)
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

    async def test_adapter_range(self, advanced_mode=False):
        """
        Test all range modes and advanced settings for each adapter to determine optimal settings.

        Args:
            advanced_mode (bool): If True, tests additional parameters beyond the predefined modes
        """
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
        original_multi_adapter = ADVANCED_SCAN_SETTINGS.get("multi_adapter", False)
        original_combine_results = ADVANCED_SCAN_SETTINGS.get("combine_results", False)
        original_use_extended_features = ADVANCED_SCAN_SETTINGS.get(
            "use_extended_features", False
        )

        # For Linux, try to clean up any existing BLE scan operations
        if sys.platform.startswith("linux"):
            try:
                import subprocess

                self.console.print(
                    "[bold yellow]Cleaning up any existing BLE scan operations...[/]"
                )
                # Attempt to reset the Bluetooth adapter to clear any stuck operations
                # Use the stored adapter_id if available
                adapter_id = self.settings.get("adapter_id", "hci0")

                # First check if adapter is UP
                try:
                    check_result = subprocess.run(
                        ["hciconfig", adapter_id], capture_output=True, text=True
                    )
                    if "UP RUNNING" not in check_result.stdout:
                        self.console.print(
                            f"[bold red]Bluetooth adapter {adapter_id} is not UP. Attempting to bring it up...[/]"
                        )
                        # Try to bring the adapter up
                        subprocess.run(
                            ["sudo", "hciconfig", adapter_id, "up"], capture_output=True
                        )
                        await asyncio.sleep(1.0)  # Let adapter initialize
                except Exception as e:
                    self.console.print(
                        f"[bold red]Error checking adapter status: {e}[/]"
                    )

                process = subprocess.run(
                    ["hciconfig", adapter_id, "reset"], capture_output=True
                )
                await asyncio.sleep(1.0)  # Let BlueZ settle after reset
            except Exception as e:
                self.console.print(
                    f"[bold yellow]Failed to reset Bluetooth adapter: {e}[/]"
                )
                self.console.print(
                    f"[bold yellow]You may need to manually reset your Bluetooth adapter with 'sudo hciconfig {self.settings.get('adapter_id', 'hci0')} reset'[/]"
                )
                await asyncio.sleep(1.0)

        # Create basic or_patterns for passive scanning - required for Linux
        or_patterns = [
            OrPattern(0, AdvertisementDataType.FLAGS, b"\x00"),  # Match any flags
            OrPattern(
                0, AdvertisementDataType.COMPLETE_LOCAL_NAME, b"\x00"
            ),  # Match any name
        ]

        # Set up the test panel based on which mode we're in
        if advanced_mode:
            test_panel_content = (
                "[bold cyan]Advanced Adapter Range Test[/]\n\n"
                + "This test will scan with each available Bluetooth adapter using:\n"
                + "  • Every standard range mode (Normal, Balanced, Maximum)\n"
                + "  • Multiple scan durations within each mode\n"
                + "  • Various detection thresholds\n"
                + "  • Different timeout values\n"
                + "  • Different retry combinations\n\n"
                + "The test will determine specifically tuned optimal settings for your environment.\n\n"
                + "[yellow]Note: This comprehensive test will take 25-40 minutes to complete.[/]"
            )
            test_panel_title = "[bold green]Advanced Optimized Adapter Settings Test[/]"
        else:
            test_panel_content = (
                "[bold cyan]Comprehensive Adapter Range Test[/]\n\n"
                + "This test will scan with each available Bluetooth adapter using ALL three range modes:\n"
                + "  • Normal - Standard scanning parameters\n"
                + "  • Balanced - Enhanced scanning parameters\n"
                + "  • Maximum - Ultra-aggressive scanning parameters\n\n"
                + "The test will determine which range mode works best for each adapter in your environment.\n\n"
                + "[yellow]Note: This comprehensive test may take 10-15 minutes to complete.[/]"
            )
            test_panel_title = "[bold green]Optimized Adapter Settings Test[/]"

        self.console.print(
            Panel(
                test_panel_content,
                title=test_panel_title,
                border_style="green",
                box=ROUNDED,
            )
        )

        # Define test parameters based on mode
        if advanced_mode:
            # For advanced mode, we'll test a wider range of settings
            range_modes = {
                "Normal": [
                    {"duration": 8.0, "threshold": -80, "timeout": 4.0, "retries": 1},
                    {"duration": 10.0, "threshold": -85, "timeout": 5.0, "retries": 1},
                    {"duration": 12.0, "threshold": -85, "timeout": 6.0, "retries": 1},
                ],
                "Balanced": [
                    {"duration": 10.0, "threshold": -90, "timeout": 6.0, "retries": 2},
                    {"duration": 12.0, "threshold": -90, "timeout": 8.0, "retries": 2},
                    {"duration": 15.0, "threshold": -90, "timeout": 10.0, "retries": 2},
                ],
                "Maximum": [
                    {
                        "duration": 15.0,
                        "threshold": -95,
                        "timeout": 10.0,
                        "retries": 3,
                        "extended": True,
                    },
                    {
                        "duration": 20.0,
                        "threshold": -100,
                        "timeout": 15.0,
                        "retries": 3,
                        "extended": True,
                    },
                    {
                        "duration": 25.0,
                        "threshold": -100,
                        "timeout": 20.0,
                        "retries": 4,
                        "extended": True,
                    },
                ],
            }
        else:
            # For standard mode, just test the three predefined range modes
            range_modes = {
                "Normal": [
                    {"duration": 10.0, "threshold": -85, "timeout": 5.0, "retries": 1}
                ],
                "Balanced": [
                    {"duration": 12.0, "threshold": -90, "timeout": 8.0, "retries": 2}
                ],
                "Maximum": [
                    {
                        "duration": 15.0,
                        "threshold": -100,
                        "timeout": 10.0,
                        "retries": 3,
                        "extended": True,
                    }
                ],
            }

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
        results_table.add_column("Settings", style="cyan", justify="center")
        results_table.add_column("Devices Found", style="green", justify="right")
        results_table.add_column("Max Distance", style="yellow", justify="right")
        results_table.add_column("Avg RSSI", style="magenta", justify="right")
        results_table.add_column("Find My Devices", style="red", justify="right")
        results_table.add_column(
            "Performance Score", style="bold green", justify="right"
        )

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
            for range_mode, configs in range_modes.items():
                for config_idx, config in enumerate(configs):
                    # Extract configuration parameters
                    scan_duration = config["duration"]
                    detection_threshold = config["threshold"]
                    scan_timeout = config["timeout"]
                    extended_retries = config["retries"]
                    use_extended = config.get("extended", False)

                    # Format settings for display
                    settings_str = f"D:{scan_duration}s T:{detection_threshold}dB R:{extended_retries}"

                    self.console.print(
                        f"\n[bold yellow]Testing {range_mode} mode configuration {config_idx+1}/{len(configs)} on {adapter_name}...[/]"
                    )
                    self.console.print(
                        f"[blue]Settings: Duration={scan_duration}s, Threshold={detection_threshold}dB, Timeout={scan_timeout}s, Retries={extended_retries}[/]"
                    )

                    # Apply test configuration settings
                    SCAN_DURATION = scan_duration
                    DETECTION_THRESHOLD = detection_threshold
                    SCAN_PARAMETERS["timeout"] = scan_timeout
                    ADVANCED_SCAN_SETTINGS["extended_retries"] = extended_retries

                    # Apply extended settings for Maximum mode
                    if use_extended:
                        ADVANCED_SCAN_SETTINGS["multi_adapter"] = True
                        ADVANCED_SCAN_SETTINGS["combine_results"] = True
                        ADVANCED_SCAN_SETTINGS["use_extended_features"] = True
                    else:
                        ADVANCED_SCAN_SETTINGS["multi_adapter"] = False
                        ADVANCED_SCAN_SETTINGS["combine_results"] = False
                        ADVANCED_SCAN_SETTINGS["use_extended_features"] = False

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
                        if hasattr(
                            bleak.backends, "bluezdbus"
                        ) and sys.platform.startswith("linux"):
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

                        # Scan with phase 0 only to prevent operation-in-progress errors
                        if sys.platform.startswith("linux"):
                            # On Linux, only use the first phase to avoid BlueZ errors between phases
                            phase = scan_phases[0]  # Just use first phase

                            # Update scanning mode
                            scanner_kwargs["scanning_mode"] = phase["mode"]

                            # Update bluez parameters for passive/active scanning
                            if "passive" in phase and phase["mode"] == "passive":
                                scanner_kwargs["bluez"]["passive"] = True
                                scanner_kwargs["bluez"]["or_patterns"] = or_patterns
                            else:
                                scanner_kwargs["bluez"]["passive"] = False

                            # Create and start scanner
                            scanner = BleakScanner(**scanner_kwargs)
                            try:
                                await scanner.start()

                                # Scan for shorter duration to avoid timeouts
                                scan_duration = min(
                                    SCAN_DURATION, 8.0
                                )  # Limit to 8s max
                                start_time = time.time()

                                while time.time() - start_time < scan_duration:
                                    # Show progress
                                    progress_index = (progress_index + 1) % len(
                                        progress_chars
                                    )
                                    self.console.print(
                                        f"[bold cyan]{progress_chars[progress_index]} Scanning with {phase['description']} ({int(time.time() - start_time)}/{int(scan_duration)}s)[/]",
                                        end="\r",
                                    )
                                    await asyncio.sleep(0.5)

                                # Stop scanner and allow time to clean up
                                await scanner.stop()
                                await asyncio.sleep(1.0)  # Let BlueZ settle
                                scanner = None  # Force garbage collection

                            except Exception as e:
                                self.console.print(
                                    f"[bold red]Error during scanning: {e}[/]"
                                )
                                # Try to clean up
                                try:
                                    if scanner:
                                        await scanner.stop()
                                except:
                                    pass
                                scanner = None
                                await asyncio.sleep(2.0)  # Let BlueZ clean up resources
                        else:
                            # Non-Linux platforms - use normal multi-phase scanning
                            for phase_idx, phase in enumerate(scan_phases):
                                # Update scanning mode
                                scanner_kwargs["scanning_mode"] = phase["mode"]

                                # For Linux, update bluez parameters when mode changes
                                if hasattr(
                                    bleak.backends, "bluezdbus"
                                ) and sys.platform.startswith("linux"):
                                    if (
                                        "passive" in phase
                                        and phase["mode"] == "passive"
                                    ):
                                        # Ensure bluez parameter is set correctly for passive scanning
                                        scanner_kwargs["bluez"]["passive"] = True
                                        # Add required or_patterns for passive scanning
                                        scanner_kwargs["bluez"][
                                            "or_patterns"
                                        ] = or_patterns
                                    else:
                                        # Active scanning
                                        scanner_kwargs["bluez"]["passive"] = False

                                    # Update interval if specified in the phase
                                    if "interval" in phase:
                                        scanner_kwargs["bluez"]["interval"] = phase[
                                            "interval"
                                        ]

                                # Create and start scanner
                                scanner = BleakScanner(**scanner_kwargs)
                                await scanner.start()

                                # Scan for duration
                                start_time = time.time()

                                while time.time() - start_time < SCAN_DURATION:
                                    # Show progress
                                    progress_index = (progress_index + 1) % len(
                                        progress_chars
                                    )
                                    self.console.print(
                                        f"[bold cyan]{progress_chars[progress_index]} Scanning with {phase['description']} ({int(time.time() - start_time)}/{int(SCAN_DURATION)}s)[/]",
                                        end="\r",
                                    )
                                    await asyncio.sleep(0.5)

                                # Stop scanner
                                await scanner.stop()
                                await asyncio.sleep(0.5)  # Short pause between phases

                        # Calculate scan time
                        scan_time = time.time() - start_time

                        # Collect results
                        device_count = len(self.devices)

                        # If no devices found, skip this configuration
                        if device_count == 0:
                            self.console.print(
                                f"[yellow]No devices found with these settings. Skipping...[/]"
                            )
                            continue

                        # Calculate various metrics
                        max_distance = 0
                        total_rssi = 0
                        total_signal_quality = 0
                        max_signal_quality = 0
                        min_signal_quality = 100
                        find_my_count = 0
                        tracker_confidence_sum = 0
                        high_confidence_trackers = 0

                        for device in self.devices.values():
                            total_rssi += device.rssi

                            # Calculate signal quality
                            sq = device.signal_quality
                            total_signal_quality += sq
                            max_signal_quality = max(max_signal_quality, sq)
                            min_signal_quality = min(min_signal_quality, sq)

                            # Track maximum distance of any device
                            if device.distance > max_distance:
                                max_distance = device.distance

                            # Count trackers and high confidence trackers
                            if device.is_airtag or "Find My" in str(
                                device.service_data
                            ):
                                find_my_count += 1

                            # Analyze tracker confidence values
                            confidence = device._calculate_tracker_confidence()
                            tracker_confidence_sum += confidence
                            if confidence > 75:  # 75% is high confidence
                                high_confidence_trackers += 1

                        # Calculate averages
                        avg_rssi = total_rssi / device_count if device_count > 0 else 0
                        avg_signal_quality = (
                            total_signal_quality / device_count
                            if device_count > 0
                            else 0
                        )

                        # Calculate a performance score based on multiple factors
                        # This weights different aspects of scanning performance
                        performance_score = (
                            (device_count * 5)  # Basic device count (5 points each)
                            + (find_my_count * 15)  # Find My devices (15 points each)
                            + (
                                high_confidence_trackers * 10
                            )  # High confidence trackers (10 points each)
                            + (
                                max_distance * 2
                            )  # Maximum distance (2 points per meter)
                            + (
                                avg_signal_quality * 0.5
                            )  # Average signal quality (0.5 points per %)
                            + (100 + avg_rssi)  # RSSI boost (higher RSSI = more points)
                        )

                        # For advanced setups that use extended features
                        if use_extended:
                            # Bonus for finding devices at long distances with good signal
                            if max_distance > 10 and avg_signal_quality > 40:
                                performance_score += 50

                        # Normalize score from 0-100 for easier comparison
                        normalized_score = min(100, max(0, performance_score / 10))

                        # Store results for this configuration
                        mode_result = {
                            "adapter": adapter_name,
                            "adapter_address": adapter_address,
                            "range_mode": range_mode,
                            "settings": {
                                "duration": scan_duration,
                                "threshold": detection_threshold,
                                "timeout": scan_timeout,
                                "retries": extended_retries,
                                "extended": use_extended,
                            },
                            "device_count": device_count,
                            "max_distance": max_distance,
                            "avg_rssi": avg_rssi,
                            "avg_signal_quality": avg_signal_quality,
                            "find_my_count": find_my_count,
                            "high_confidence_trackers": high_confidence_trackers,
                            "scan_time": scan_time,
                            "performance_score": normalized_score,
                        }

                        adapter_results.append(mode_result)
                        all_results.append(mode_result)

                        # Add to results table
                        results_table.add_row(
                            adapter_name,
                            range_mode,
                            settings_str,
                            str(device_count),
                            f"{max_distance:.2f}m",
                            f"{avg_rssi:.1f} dBm",
                            str(find_my_count),
                            f"{normalized_score:.1f}",
                        )

                        self.console.print(
                            f"\n[green]Scan complete: Found {device_count} devices with {adapter_name} in {range_mode} mode with performance score: {normalized_score:.1f}[/]"
                        )

                    except Exception as e:
                        err_msg = str(e)
                        # Store the error for potential automatic recovery during next scan
                        self._last_scan_error = err_msg
                        self.console.print(
                            f"[bold red]Error testing adapter {adapter_name} in {range_mode} mode: {err_msg}[/]"
                        )
                        results_table.add_row(
                            adapter_name,
                            range_mode,
                            "Error",
                            "N/A",
                            "N/A",
                            "N/A",
                            "N/A",
                            "N/A",
                        )

                        # For Linux, check for 'operation already in progress'
                        if (
                            sys.platform.startswith("linux")
                            and "operation already in progress" in err_msg.lower()
                        ):
                            self.console.print(
                                "[yellow]BlueZ operation already in progress. Trying to reset adapter...[/]"
                            )
                            try:
                                import subprocess

                                adapter_id = self.settings.get("adapter_id", "hci0")
                                subprocess.run(
                                    ["hciconfig", adapter_id, "down"],
                                    capture_output=True,
                                )
                                await asyncio.sleep(0.5)
                                subprocess.run(
                                    ["hciconfig", adapter_id, "up"], capture_output=True
                                )
                                await asyncio.sleep(1.0)
                            except Exception as reset_error:
                                self.console.print(
                                    f"[yellow]Failed to reset Bluetooth adapter: {reset_error}[/]"
                                )
                                self.console.print(
                                    f"[bold yellow]You may need to manually reset your Bluetooth with 'sudo hciconfig {self.settings.get('adapter_id', 'hci0')} reset'[/]"
                                )

                    # Short pause between range modes
                    await asyncio.sleep(1)

                # Determine best settings for this adapter based on performance score
                if adapter_results:
                    # Find best overall setting by performance score
                    best_overall = max(
                        adapter_results, key=lambda x: x["performance_score"]
                    )

                    # Find best for trackers if any were found
                    tracker_results = [
                        r for r in adapter_results if r["find_my_count"] > 0
                    ]
                    best_for_trackers = (
                        max(tracker_results, key=lambda x: x["find_my_count"])
                        if tracker_results
                        else None
                    )

                    # Show best mode for this adapter
                    self.console.print(
                        f"\n[bold cyan]Best settings for {adapter_name}:[/]"
                    )

                    self.console.print(
                        f"[bold green]Best overall performance:[/] {best_overall['range_mode']} mode "
                        f"(Score: {best_overall['performance_score']:.1f}, {best_overall['device_count']} devices)"
                    )

                    # Show settings details
                    best_settings = best_overall["settings"]
                    self.console.print(
                        f"   Settings: Duration={best_settings['duration']}s, "
                        f"Threshold={best_settings['threshold']}dB, "
                        f"Timeout={best_settings['timeout']}s, "
                        f"Retries={best_settings['retries']}"
                    )

                    if best_for_trackers:
                        self.console.print(
                            f"[bold red]Best for tracking devices:[/] {best_for_trackers['range_mode']} mode "
                            f"({best_for_trackers['find_my_count']} trackers, Score: {best_for_trackers['performance_score']:.1f})"
                        )

                        # Show settings details for tracker optimization
                        tracker_settings = best_for_trackers["settings"]
                        self.console.print(
                            f"   Settings: Duration={tracker_settings['duration']}s, "
                            f"Threshold={tracker_settings['threshold']}dB, "
                            f"Timeout={tracker_settings['timeout']}s, "
                            f"Retries={tracker_settings['retries']}"
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
            ADVANCED_SCAN_SETTINGS["multi_adapter"] = original_multi_adapter
            ADVANCED_SCAN_SETTINGS["combine_results"] = original_combine_results
            ADVANCED_SCAN_SETTINGS["use_extended_features"] = (
                original_use_extended_features
            )

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
                # Find best results by different metrics and performance score
                best_overall = max(all_results, key=lambda x: x["performance_score"])

                # Find best for tracking devices
                tracker_results = [r for r in all_results if r["find_my_count"] > 0]
                best_for_trackers = (
                    max(tracker_results, key=lambda x: x["performance_score"])
                    if tracker_results
                    else best_overall
                )

                # Find best for distance (with good signal quality)
                distance_results = [r for r in all_results if r["max_distance"] > 0]
                best_for_distance = (
                    max(distance_results, key=lambda x: x["max_distance"])
                    if distance_results
                    else best_overall
                )

                # Create a best performance summary
                summary_text = []

                summary_text.append(f"[bold green]Best Overall Performance:[/]")
                summary_text.append(f"  Adapter: {best_overall['adapter']}")
                summary_text.append(f"  Range Mode: {best_overall['range_mode']}")
                summary_text.append(
                    f"  Performance Score: {best_overall['performance_score']:.1f}"
                )
                summary_text.append(f"  Devices Found: {best_overall['device_count']}")
                summary_text.append(
                    f"  Maximum Distance: {best_overall['max_distance']:.2f}m"
                )
                summary_text.append(
                    f"  Find My Devices: {best_overall['find_my_count']}"
                )

                # Show detailed settings
                best_settings = best_overall["settings"]
                summary_text.append(
                    f"  Settings: Duration={best_settings['duration']}s, Threshold={best_settings['threshold']}dB, Timeout={best_settings['timeout']}s, Retries={best_settings['retries']}"
                )
                summary_text.append("")

                # Only show best for trackers if different from overall and trackers were found
                if best_for_trackers != best_overall and tracker_results:
                    summary_text.append(f"[bold red]Best for Finding Trackers:[/]")
                    summary_text.append(f"  Adapter: {best_for_trackers['adapter']}")
                    summary_text.append(
                        f"  Range Mode: {best_for_trackers['range_mode']}"
                    )
                    summary_text.append(
                        f"  Performance Score: {best_for_trackers['performance_score']:.1f}"
                    )
                    summary_text.append(
                        f"  Find My Devices: {best_for_trackers['find_my_count']}"
                    )
                    summary_text.append(
                        f"  Devices Found: {best_for_trackers['device_count']}"
                    )

                    # Show detailed settings
                    tracker_settings = best_for_trackers["settings"]
                    summary_text.append(
                        f"  Settings: Duration={tracker_settings['duration']}s, Threshold={tracker_settings['threshold']}dB, Timeout={tracker_settings['timeout']}s, Retries={tracker_settings['retries']}"
                    )
                    summary_text.append("")

                # Only show best for distance if different from the others
                if (
                    best_for_distance != best_overall
                    and best_for_distance != best_for_trackers
                    and distance_results
                ):
                    summary_text.append(f"[bold yellow]Best for Maximum Distance:[/]")
                    summary_text.append(f"  Adapter: {best_for_distance['adapter']}")
                    summary_text.append(
                        f"  Range Mode: {best_for_distance['range_mode']}"
                    )
                    summary_text.append(
                        f"  Performance Score: {best_for_distance['performance_score']:.1f}"
                    )
                    summary_text.append(
                        f"  Maximum Distance: {best_for_distance['max_distance']:.2f}m"
                    )

                    # Show detailed settings
                    distance_settings = best_for_distance["settings"]
                    summary_text.append(
                        f"  Settings: Duration={distance_settings['duration']}s, Threshold={distance_settings['threshold']}dB, Timeout={distance_settings['timeout']}s, Retries={distance_settings['retries']}"
                    )
                    summary_text.append("")

                # Add recommendations based on user goals with detailed settings
                summary_text.append(f"[bold cyan]Recommendations:[/]")

                if tracker_results:
                    summary_text.append(
                        f"  • For finding trackers, use: [bold]{best_for_trackers['adapter']}[/] with [bold]{best_for_trackers['range_mode']}[/] mode"
                    )
                    tracker_settings = best_for_trackers["settings"]
                    summary_text.append(
                        f"    Duration={tracker_settings['duration']}s, Threshold={tracker_settings['threshold']}dB, Timeout={tracker_settings['timeout']}s, Retries={tracker_settings['retries']}"
                    )

                summary_text.append(
                    f"  • For maximum overall performance, use: [bold]{best_overall['adapter']}[/] with [bold]{best_overall['range_mode']}[/] mode"
                )
                best_settings = best_overall["settings"]
                summary_text.append(
                    f"    Duration={best_settings['duration']}s, Threshold={best_settings['threshold']}dB, Timeout={best_settings['timeout']}s, Retries={best_settings['retries']}"
                )

                summary_text.append(
                    f"  • For best battery life with reasonable detection, use: [bold]Normal[/] mode with minimal duration and retries"
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

                # Present options for applying settings
                self.console.print("\n[bold cyan]Available Settings to Apply:[/]")
                self.console.print("1. Apply best settings for finding trackers")
                self.console.print("2. Apply best overall performance settings")
                if (
                    best_for_distance != best_overall
                    and best_for_distance != best_for_trackers
                ):
                    self.console.print("3. Apply best settings for maximum distance")
                self.console.print("0. Don't apply any settings (keep current)")

                # Get user choice
                choice = self.console.input(
                    "\n[bold blue]Enter your choice (0-3): [/]"
                ).strip()

                # Determine which settings to apply
                settings_to_apply = None
                if choice == "1" and tracker_results:
                    settings_to_apply = best_for_trackers
                    settings_type = "tracking devices"
                elif choice == "2":
                    settings_to_apply = best_overall
                    settings_type = "overall performance"
                elif (
                    choice == "3"
                    and best_for_distance != best_overall
                    and best_for_distance != best_for_trackers
                ):
                    settings_to_apply = best_for_distance
                    settings_type = "maximum distance"

                # Apply the selected settings
                if settings_to_apply:
                    # Set adapter if needed
                    if settings_to_apply["adapter"] != "Default Adapter":
                        # Find address for this adapter
                        best_address = None
                        for adapter in available_adapters:
                            if adapter["name"] == settings_to_apply["adapter"]:
                                best_address = adapter["address"]
                                break

                        if best_address:
                            self.current_adapter = best_address
                            self.settings["adapter"] = best_address

                    # Set range mode and detailed settings
                    self.settings["range_mode"] = settings_to_apply["range_mode"]

                    # Save the detailed scan parameters
                    detailed_settings = settings_to_apply["settings"]
                    self.settings["scan_duration"] = detailed_settings["duration"]
                    self.settings["detection_threshold"] = detailed_settings[
                        "threshold"
                    ]
                    SCAN_PARAMETERS["timeout"] = detailed_settings["timeout"]
                    ADVANCED_SCAN_SETTINGS["extended_retries"] = detailed_settings[
                        "retries"
                    ]

                    # Apply extended features if specified
                    if detailed_settings.get("extended", False):
                        ADVANCED_SCAN_SETTINGS["multi_adapter"] = True
                        ADVANCED_SCAN_SETTINGS["combine_results"] = True
                        ADVANCED_SCAN_SETTINGS["use_extended_features"] = True
                    else:
                        ADVANCED_SCAN_SETTINGS["multi_adapter"] = False
                        ADVANCED_SCAN_SETTINGS["combine_results"] = False
                        ADVANCED_SCAN_SETTINGS["use_extended_features"] = False

                    # Save settings
                    self._save_settings()
                    self.console.print(
                        f"[green]Settings applied: Optimized for {settings_type}[/]\n"
                        f"Adapter = {settings_to_apply['adapter']}, Range Mode = {settings_to_apply['range_mode']}\n"
                        f"Duration = {detailed_settings['duration']}s, Threshold = {detailed_settings['threshold']}dB, "
                        f"Timeout = {detailed_settings['timeout']}s, Retries = {detailed_settings['retries']}"
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
                # On Linux, we can use hciconfig to get adapter status
                import subprocess

                # First get all adapters and their status
                result = subprocess.run(
                    ["hciconfig", "-a"], capture_output=True, text=True
                )
                output = result.stdout

                # Parse hciconfig output to get status information
                current_adapter = None
                current_address = None
                current_name = None
                current_status = "DOWN"

                for line in output.split("\n"):
                    line = line.strip()
                    if line.startswith("hci"):
                        # Save previous adapter if we have one
                        if current_adapter:
                            adapters.append(
                                {
                                    "address": current_address,
                                    "name": f"Bluetooth Adapter ({current_adapter})",
                                    "id": current_adapter,
                                    "status": current_status,
                                }
                            )

                        # Start new adapter
                        current_adapter = line.split(":")[0].strip()
                        current_address = None
                        current_name = None
                        current_status = "DOWN"

                    elif "BD Address:" in line:
                        current_address = (
                            line.split("BD Address:")[1].split()[0].strip()
                        )

                    elif "Name:" in line:
                        current_name = line.split("Name:")[1].split("'")[1].strip()

                    elif "UP RUNNING" in line:
                        current_status = "UP"

                # Add the last adapter
                if current_adapter:
                    adapters.append(
                        {
                            "address": current_address,
                            "name": f"{current_name or 'Bluetooth Adapter'} ({current_adapter})",
                            "id": current_adapter,
                            "status": current_status,
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
