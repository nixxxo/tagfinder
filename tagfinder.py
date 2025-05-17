import asyncio
import platform
import subprocess
import json
import sys
import time
import os
import datetime
from typing import Dict, Any, Optional, List
import select
import shutil  # For getting terminal size
import re

# Conditionally import platform-specific dependencies
if platform.system() != "Windows":
    import termios
    import tty
else:
    # Windows-specific imports
    import msvcrt

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

try:
    from bleak.exc import BleakError
except ImportError:
    from bleak.exceptions import BleakError

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from rich.live import Live  # Added for Live display

# Constants for AirTag filtering
APPLE_COMPANY_ID = 0x004C
# The Find My advertising type byte that signifies devices like AirTags, AirPods, etc.
# This byte is part of the manufacturer-specific data payload for Apple devices.
FINDMY_DEVICE_AD_TYPE = 0x12

# Typical TX power for AirTags/BLE beacons at 1 meter. This is an approximation.
# The actual value can vary based on the specific device and conditions.
DEFAULT_TX_POWER_AT_1M = -59  # dBm
# Path loss exponent (n). Varies from 2.0 (free space) to around 4.0 (in lossy environments like indoors).
DEFAULT_PATH_LOSS_EXPONENT = 2.5  # A general value for mixed environments

console = Console()

# Add additional configuration files
SETTINGS_FILE = "settings.json"
DEVICES_HISTORY_FILE = "devices_history.json"
SESSION_START_TIME = time.time()

# Update global state variables to include historical data and persistence
scan_running = False
should_exit = False
found_devices: List[Dict[str, Any]] = []
known_devices: Dict[str, Dict[str, Any]] = {}  # Persistent device storage by address
first_seen_timestamps: Dict[str, float] = {}  # When each device was first seen

current_settings = {
    "duration": 10,
    "airtags_only": False,  # Default to False to discover all devices
    "tx_power": DEFAULT_TX_POWER_AT_1M,
    "path_loss": DEFAULT_PATH_LOSS_EXPONENT,
    "scan_once": False,  # Default to continuous scan
    "show_manufacturer_data": True,  # Default to show manufacturer data
    "highlight_new_devices": True,  # Highlight devices seen for the first time
    "auto_save_devices": True,  # Automatically save discovered devices
    "selected_adapter": None,  # Selected Bluetooth adapter for scanning
    "target_airtag_serial": "HGFL6DDSP0GV",  # User's target AirTag serial
    "target_device_address": None,  # MAC address of the specifically targeted device by user
}

# Dictionary to store friendly names for devices
friendly_names = {}
# Data file to persist friendly names
FRIENDLY_NAMES_FILE = "friendly_names.json"

# File descriptors for terminal input handling
old_settings = None

# Add a new dictionary for Bluetooth company identifiers and known device signatures
COMPANY_IDENTIFIERS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x00D2: "Sony",
    0x0059: "Nordic",
    0x00F0: "Xiaomi",
    0x000F: "Broadcom",
    0x0157: "Bose",
    0x008A: "Toshiba",
    0x003D: "FitBit",
    0x0087: "Garmin",
    0x0157: "Bose",
    0x0440: "LG",
    0x00D7: "Beats",
    0x0030: "ST Micro",
    0x0590: "Huawei",
    0x0499: "Ruuvi",
    0x0131: "Logitech",
    0x0108: "Tile",
    0x0310: "Philips",
    0x010F: "Sonos",
    0x054C: "Sony",
    0x0210: "Acer",
    # Add more companies as needed
}

# Add device signature patterns
DEVICE_SIGNATURES = {
    # Apple devices
    "airpods": "AirPods",
    "airtag": "AirTag",
    "airpod": "AirPods",
    "watch": "Apple Watch",
    "iphone": "iPhone",
    "ipad": "iPad",
    "mac": "Mac",
    "homepod": "HomePod",
    # Other devices
    "tv": "TV",
    "remote": "Remote",
    "headphone": "Headphones",
    "speaker": "Speaker",
    "watch": "Smartwatch",
    "fitness": "Fitness Tracker",
    "tag": "Tracker",
    "sense": "Sensor",
    "therm": "Thermostat",
    "lock": "Smart Lock",
    "light": "Smart Light",
    "bulb": "Light Bulb",
    "hub": "Hub",
    "cam": "Camera",
    "door": "Door/Window Sensor",
    "motion": "Motion Sensor",
    "button": "Button/Switch",
    "scale": "Scale",
    "fridge": "Refrigerator",
    "oven": "Oven",
    "washer": "Washer/Dryer",
    "air": "Air Conditioner",
    "purifier": "Air Purifier",
    "vacuum": "Vacuum",
    "plug": "Smart Plug",
    "outlet": "Smart Outlet",
    "switch": "Smart Switch",
    "bridge": "Bridge",
    "gateway": "Gateway",
    "router": "Router",
    "beacon": "Beacon",
    "tile": "Tile Tracker",
    "tag": "Tracker Tag",
    "car": "Car",
    "key": "Key Finder",
    "pen": "Stylus Pen",
    "game": "Game Controller",
    "health": "Health Device",
    "medical": "Medical Device",
    "band": "Wristband",
}

# Improve TX power values based on device types for more accurate distance calculations
TX_POWER_BY_DEVICE_TYPE = {
    "AirTag": -62,
    "AirPods": -65,
    "iPhone": -59,
    "Apple Watch": -65,
    "Tile Tracker": -72,
    "Beacon": -59,
    "Light Bulb": -69,
    "Smart Speaker": -67,
    "Fitness Tracker": -70,
    "Headphones": -70,
    "TV": -58,
    "Speaker": -65,
    "Hub": -60,
    "Default": -67,  # General default for unknown devices
}


def setup_terminal():
    """Set up terminal for character-by-character input."""
    global old_settings
    if platform.system() != "Windows":  # Unix-like systems
        try:
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except Exception as e:
            console.print(f"[yellow]Warning: Could not set up terminal: {e}[/yellow]")
            console.print(
                "[yellow]Some keyboard input features may not work properly.[/yellow]"
            )


def restore_terminal():
    """Restore terminal to original settings."""
    if old_settings is not None and platform.system() != "Windows":
        try:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except Exception:
            pass  # If restore fails, we're exiting anyway


def is_key_pressed():
    """Check if a key has been pressed without blocking."""
    try:
        if platform.system() == "Windows":
            return msvcrt.kbhit()
        else:
            # Unix implementation
            r, _, _ = select.select([sys.stdin], [], [], 0)
            return r != []
    except Exception:
        # If key detection fails, return false
        return False


def get_key():
    """Get a single keypress from the terminal without blocking."""
    try:
        if is_key_pressed():
            if platform.system() == "Windows":
                try:
                    return msvcrt.getch().decode("utf-8").lower()
                except Exception:
                    return "q"  # Return a safe value on error
            else:
                return sys.stdin.read(1).lower()
    except Exception:
        # If key reading fails, return None to try again later
        pass
    return None


def get_linux_bluetooth_adapters() -> List[Dict[str, Any]]:
    """
    Retrieves Bluetooth adapter information on Linux using hciconfig.
    Returns a list of dictionaries with adapter information.
    """
    try:
        result = subprocess.run(
            ["hciconfig", "-a"],
            capture_output=True,
            text=True,
            check=False,  # Don't fail if return code is non-zero
        )

        if result.returncode != 0:
            # Try alternative bluetoothctl
            try:
                result = subprocess.run(
                    ["bluetoothctl", "list"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except:
                return []

        adapters = []
        if "hci" in result.stdout:
            # Parse hciconfig output
            current_adapter = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("hci"):
                    # New adapter
                    if current_adapter:
                        adapters.append(current_adapter)
                    current_adapter = {"name": line.split(":")[0]}

                if "BD Address:" in line:
                    current_adapter["address"] = line.split("BD Address:")[1].strip()
                if "Down" in line:
                    current_adapter["powered"] = "Off"
                if "UP" in line:
                    current_adapter["powered"] = "On"
                if "Manufacturer:" in line:
                    current_adapter["manufacturer"] = line.split("Manufacturer:")[
                        1
                    ].strip()
                if "HCI Version:" in line:
                    parts = line.split(",")
                    for part in parts:
                        if "HCI Version:" in part:
                            current_adapter["version"] = part.split("HCI Version:")[
                                1
                            ].strip()

            # Add the last adapter
            if current_adapter:
                adapters.append(current_adapter)

        return adapters
    except Exception as e:
        console.print(f"[yellow]Error getting Linux Bluetooth adapters: {e}[/yellow]")
        return []


def get_windows_bluetooth_adapters() -> List[Dict[str, Any]]:
    """
    Retrieves Bluetooth adapter information on Windows using PowerShell or WMI.
    Returns a list of dictionaries with adapter information.
    """
    adapters = []

    # First try PowerShell method
    try:
        script = "Get-PnpDevice -Class Bluetooth | ConvertTo-Json"
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0 and result.stdout and len(result.stdout.strip()) > 2:
            try:
                devices = json.loads(result.stdout)
                # If it's a single device, make it a list
                if isinstance(devices, dict):
                    devices = [devices]

                for device in devices:
                    if device.get("Status") == "OK":
                        adapter = {
                            "name": device.get("FriendlyName", "Unknown Adapter"),
                            "address": "N/A",  # Windows doesn't easily expose MAC in PowerShell
                            "powered": "On" if device.get("Status") == "OK" else "Off",
                            "manufacturer": device.get("Manufacturer", "N/A"),
                            "device_id": device.get("DeviceID", "N/A"),
                        }
                        adapters.append(adapter)

                if adapters:
                    return adapters
            except json.JSONDecodeError:
                # Fall through to next method if JSON parsing fails
                pass
    except Exception as e:
        # PowerShell might not be available
        console.print(f"[yellow]PowerShell method failed: {e}[/yellow]")

    # Try WMI method as fallback
    try:
        result = subprocess.run(
            [
                "wmic",
                "path",
                "Win32_PnPEntity",
                "where",
                "ClassGuid='{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'",
                "get",
                "Caption,DeviceID,Status",
                "/format:list",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0 and "Caption=" in result.stdout:
            current_adapter = {}

            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Caption="):
                    # Start a new adapter
                    if current_adapter:
                        adapters.append(current_adapter)
                    current_adapter = {"name": line.split("=")[1].strip()}
                elif line.startswith("DeviceID="):
                    current_adapter["device_id"] = line.split("=")[1].strip()
                elif line.startswith("Status="):
                    current_adapter["powered"] = (
                        "On" if line.split("=")[1].strip() == "OK" else "Off"
                    )

            # Add the last adapter
            if current_adapter:
                adapters.append(current_adapter)

            if adapters:
                return adapters
    except Exception as e:
        console.print(f"[yellow]WMI method failed: {e}[/yellow]")

    # Try registry method as a last resort
    try:
        # This is a simplified approach that just checks if Bluetooth devices exist
        result = subprocess.run(
            [
                "reg",
                "query",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0:
            adapter = {
                "name": "Bluetooth Adapter",
                "address": "Available",
                "powered": "On",
                "manufacturer": "N/A",
                "device_id": "N/A",
            }
            adapters.append(adapter)
    except Exception as e:
        # Registry query failed
        pass

    # Last fallback - check if any BLE scan works
    if not adapters:
        try:
            from bleak import BleakScanner

            adapter = {
                "name": "Bluetooth Adapter",
                "address": "N/A",
                "powered": "On",
                "manufacturer": "N/A",
                "device_id": "N/A",
                "note": "Detected via BleakScanner",
            }
            adapters.append(adapter)
        except Exception:
            pass

    return adapters


def get_macos_bluetooth_adapters() -> Optional[List[Dict[str, Any]]]:
    """
    Retrieves Bluetooth adapter information on macOS using system_profiler.
    Returns a list of dictionaries containing adapter information or an empty list on error.
    """
    try:
        # Use -json flag for structured output
        result = subprocess.run(
            ["system_profiler", "SPBluetoothDataType", "-json"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        bluetooth_data = data.get("SPBluetoothDataType", [])

        adapters = []

        for adapter_info_set in bluetooth_data:
            controller_properties = adapter_info_set.get("controller_properties", {})
            if controller_properties:
                name = controller_properties.get("local_device_title", {}).get(
                    "general_name", "N/A"
                )
                # Sometimes name is directly under controller_properties
                if name == "N/A":
                    name = controller_properties.get("controller_name", "N/A")

                adapter = {
                    "name": name,
                    "address": controller_properties.get("controller_address", "N/A"),
                    "manufacturer": controller_properties.get(
                        "controller_manufacturer", "N/A"
                    ),
                    "version": controller_properties.get(
                        "controller_firmware_version", "N/A"
                    ),
                    "powered": controller_properties.get(
                        "controller_power_state", "N/A"
                    ),
                }
                adapters.append(adapter)
            else:
                # Fallback if controller_properties is not found
                name = adapter_info_set.get("local_device_name", "Unknown Adapter")
                address = adapter_info_set.get("local_device_address", "N/A")
                adapter = {
                    "name": name,
                    "address": address,
                    "manufacturer": "N/A",
                    "version": "N/A",
                    "powered": "N/A",
                }
                adapters.append(adapter)

        return adapters
    except Exception as e:
        console.print(f"[yellow]Error getting macOS Bluetooth adapters: {e}[/yellow]")
        return []


def get_bluetooth_adapters() -> List[Dict[str, Any]]:
    """Get Bluetooth adapters for the current platform."""
    system = platform.system()

    if system == "Darwin":
        return get_macos_bluetooth_adapters()
    elif system == "Linux":
        return get_linux_bluetooth_adapters()
    elif system == "Windows":
        return get_windows_bluetooth_adapters()
    else:
        console.print(f"[yellow]Unsupported platform: {system}[/yellow]")
        return []


def display_bluetooth_adapters():
    """Display Bluetooth adapter information for the current platform."""
    clear_screen()
    console.print("\n[bold cyan]✓ Bluetooth Adapter Information[/bold cyan]\n")

    adapters = get_bluetooth_adapters()

    if not adapters:
        console.print(
            "[yellow]No Bluetooth adapters found or unable to detect adapters.[/yellow]"
        )
        console.print(
            "[dim]Note: You may need administrator/root privileges to see all adapter details.[/dim]"
        )
        console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        while not is_key_pressed():
            time.sleep(0.1)
        get_key()
        return

    # Create a table to display adapter information
    table = Table(title=f"Bluetooth Adapters ({platform.system()})", box=box.ROUNDED)
    table.add_column("#", style="cyan", no_wrap=True, width=3)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Manufacturer", style="green")
    table.add_column("Version/ID", style="yellow")
    table.add_column("Powered", style="blue")

    # Add each adapter to the table with an index
    for idx, adapter in enumerate(adapters):
        name = adapter.get("name", "N/A")
        address = adapter.get("address", "N/A")
        manufacturer = adapter.get("manufacturer", "N/A")
        version = adapter.get("version", adapter.get("device_id", "N/A"))
        power_state = adapter.get("powered", "N/A")

        # Format power state with color
        power_text = Text(power_state)
        if "On" in power_state or "OK" in power_state or "Yes" in power_state:
            power_text.stylize("bold green")
        elif "Off" in power_state or "No" in power_state or "Down" in power_state:
            power_text.stylize("bold red")

        # Mark currently selected adapter
        is_selected = (
            "[bright_green]✓[/bright_green] "
            if current_settings["selected_adapter"] == name
            else ""
        )
        display_index = f"{idx + 1}"
        table.add_row(
            display_index,
            f"{is_selected}{name}",
            address,
            manufacturer,
            version,
            power_text,
        )

    # Add an option for system default
    table.add_row("0", "[dim]Default (System Choice)[/dim]", "", "", "", "")

    if table.row_count > 0:
        console.print(table)
    else:
        console.print("[yellow]No adapter information could be displayed.[/yellow]")

    # Add platform-specific notes
    if platform.system() == "Windows":
        console.print(
            "\n[dim]Note: On Windows, some adapter details may be limited without admin privileges.[/dim]"
        )
    elif platform.system() == "Linux":
        console.print(
            "\n[dim]Note: On Linux, you may need to run with sudo to see all adapter details.[/dim]"
        )

    # Ask if user wants to select an adapter
    console.print("\nDo you want to select a Bluetooth adapter to use? (y/n): ", end="")
    choice = input().strip().lower()

    if choice == "y":
        console.print(
            "\nEnter the number of the adapter to use (0 for default): ", end=""
        )
        adapter_choice = input().strip()

        try:
            idx = int(adapter_choice)
            if idx == 0:
                # Use system default
                current_settings["selected_adapter"] = None
                console.print("[green]✓ Using system default adapter.[/green]")
            elif 1 <= idx <= len(adapters):
                # Use selected adapter
                selected = adapters[idx - 1]
                adapter_name = selected.get("name", "N/A")
                current_settings["selected_adapter"] = adapter_name
                console.print(f"[green]✓ Selected adapter: {adapter_name}[/green]")
            else:
                console.print("[red]Invalid adapter number.[/red]")

        except ValueError:
            console.print("[red]Please enter a valid number.[/red]")

        # Save settings
        save_settings()

        # Wait for acknowledgment
        console.print("\n[dim]Press any key to continue...[/dim]")
        while not is_key_pressed():
            time.sleep(0.1)
        get_key()
    else:
        console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        while not is_key_pressed():
            time.sleep(0.1)
        get_key()  # Consume the key


def calculate_distance(
    rssi: int,
    tx_power: int = DEFAULT_TX_POWER_AT_1M,
    n: float = DEFAULT_PATH_LOSS_EXPONENT,
    device_type: str = None,
    advertised_tx_power: Optional[int] = None,
) -> float:
    """
    Estimates distance to a BLE device based on RSSI and TX power.
    RSSI: Received Signal Strength Indicator (in dBm).
    tx_power: Signal strength at 1 meter (in dBm).
    n: Path loss exponent (typically 2.0-4.0).
    device_type: Type of device for more accurate TX power
    Returns estimated distance in meters.
    """
    if rssi == 0:
        return -1.0  # Cannot determine distance

    # Prioritize advertised TX power if available and valid
    if (
        advertised_tx_power is not None
        and advertised_tx_power != 0
        and advertised_tx_power != 127
    ):  # 127 can be a placeholder for N/A
        effective_tx_power = advertised_tx_power
    # Else, use device-specific TX power if available and not overridden by CLI args
    elif device_type and tx_power == DEFAULT_TX_POWER_AT_1M:
        effective_tx_power = TX_POWER_BY_DEVICE_TYPE.get(
            device_type, TX_POWER_BY_DEVICE_TYPE["Default"]
        )
    else:
        effective_tx_power = tx_power

    # Apply environmental correction
    # Indoor environments often need higher path loss values
    if rssi < -75:  # Weak signals often indicate obstacles
        n = max(n, 2.8)  # Use at least 2.8 for weak signals

    # Apply signal stability adjustment
    # Very strong signals are more reliable for distance calculation
    if rssi > -60:
        # For very close devices, reduce variance
        ratio = (effective_tx_power - rssi) / (10 * n)
        # Apply some bounds checking to avoid unrealistic values
        ratio = max(0.04, min(ratio, 4.0))  # Keep within reasonable bounds
        distance = 10**ratio
    else:
        # Standard calculation for normal-to-weak signals
        ratio = (effective_tx_power - rssi) / (10 * n)
        # Apply some bounds checking to avoid unrealistic values
        ratio = max(0.04, min(ratio, 4.0))  # Keep within reasonable bounds
        distance = 10**ratio

    return distance


def extract_device_info(device_name, manufacturer_data, address, service_uuids):
    """Extract meaningful device information from BLE data."""
    # Start with device name if available
    inferred_name = device_name if device_name and device_name != "N/A" else None
    device_type = None
    company_name = None

    # If we have a valid device name, use it and look for device type clues
    if inferred_name:
        # Look for known device types in the name
        for keyword, device in DEVICE_SIGNATURES.items():
            if keyword.lower() in inferred_name.lower():
                device_type = device
                break

    # Check manufacturer data for company info and device type
    if manufacturer_data:
        for company_id, data in manufacturer_data.items():
            if company_id in COMPANY_IDENTIFIERS:
                company_name = COMPANY_IDENTIFIERS[company_id]

                # If the device is from Apple, see if we can identify the type
                if company_id == APPLE_COMPANY_ID:
                    # Check for AirTag/Find My signatures
                    if data.startswith(bytes([FINDMY_DEVICE_AD_TYPE])):
                        # Some basic heuristics based on data patterns
                        data_hex = data.hex()

                        # Different Apple devices have different data patterns
                        if len(data) > 3 and data[2] == 0x05:  # Common AirTag pattern
                            device_type = "AirTag"
                        elif len(data) > 3 and data[2] == 0x07:  # Common for AirPods
                            device_type = "AirPods"
                        elif len(data) > 3 and data[2] == 0x09:  # Often Apple Watch
                            device_type = "Apple Watch"
                        elif len(data) > 3 and data[2] == 0x0B:  # Often iPhone
                            device_type = "iPhone"
                        else:
                            device_type = "Find My Device"

    # Check for known service UUIDs that might indicate device type
    if (
        service_uuids and not device_type
    ):  # Only check if we don't have a device type yet
        for uuid in service_uuids:
            uuid_lower = uuid.lower()
            # Audio devices often advertise A2DP, AVRCP, etc.
            if "110a" in uuid_lower or "110b" in uuid_lower:  # A2DP related
                device_type = "Audio Device"
                break
            # Heart rate, health services
            elif "180d" in uuid_lower:  # Heart rate service
                device_type = "Health Device"
                break
            # Battery service
            elif "180f" in uuid_lower:
                device_type = "Battery-powered Device"
                break
            # Philips Hue and similar
            elif "1802" in uuid_lower or "1801" in uuid_lower:
                device_type = "Smart Device"
                break

    # Look for common patterns in addresses if we still don't have company info
    if not company_name:
        # Some devices have manufacturer prefixes in MAC
        if address.startswith("C0:1A:DA"):  # Common Samsung prefix
            company_name = "Samsung"
        elif address.startswith("94:9F:3E") or address.startswith("00:1A:7D"):
            company_name = "Apple"
        elif address.startswith("84:10:95") or address.startswith("B0:C5:CA"):
            company_name = "Philips"

    # Build a meaningful name - prefer actual device name first
    if inferred_name:
        # We already have a proper device name, use it as the meaningful name
        meaningful_name = inferred_name
    elif company_name and device_type:
        # If no name but we have both company and device type
        meaningful_name = f"{company_name} {device_type}"
    elif company_name:
        # If only company name
        meaningful_name = f"{company_name} Device"
    elif device_type:
        # If only device type
        meaningful_name = device_type
    else:
        # Default to Unknown with address prefix
        prefix = address.split(":")[0] if ":" in address else address[:6]
        meaningful_name = f"Device {prefix}..."

    return {
        "name": device_name if device_name and device_name != "N/A" else "N/A",
        "device_type": device_type,
        "company": company_name,
        "meaningful_name": meaningful_name,
    }


def device_callback(
    device: BLEDevice,
    advertisement_data: AdvertisementData,
    airtags_only: bool,
    tx_power: int,
    path_loss: float,
):
    """
    Callback function invoked when a BLE device is discovered.
    Processes and stores device information.
    """
    global found_devices

    # device.address can be a UUID on macOS for anonymous devices
    device_id = device.address

    is_airtag_or_findmy = False
    manufacturer_data_dict = advertisement_data.manufacturer_data
    advertised_tx = advertisement_data.tx_power  # Get advertised TX power
    service_data_dict = advertisement_data.service_data  # Get service data

    # Prepare manufacturer data for processing
    mfg_data_str = ""
    if manufacturer_data_dict:
        for company_id, data_bytes in manufacturer_data_dict.items():
            mfg_data_str += f"ID 0x{company_id:04X}: {data_bytes.hex()}\n"
            # Check for Apple Find My devices
            if company_id == APPLE_COMPANY_ID:
                if data_bytes.startswith(bytes([FINDMY_DEVICE_AD_TYPE])):
                    is_airtag_or_findmy = True

    if airtags_only and not is_airtag_or_findmy:
        return  # Skip if filtering for AirTags and this is not one

    # Extract meaningful device information
    device_info_extract = extract_device_info(
        device.name or "N/A",
        manufacturer_data_dict,
        device.address,
        advertisement_data.service_uuids,
    )

    # Determine accurate device type for distance calculation
    device_type = device_info_extract.get("device_type")

    # Check if device already exists in our list
    exists = False
    for idx, dev in enumerate(found_devices):
        if dev["address"] == device_id:
            # Update the existing device
            exists = True
            # Only update if we have a non-zero RSSI (sometimes 0 means no update)
            if advertisement_data.rssi != 0:
                # Track signal trend (increasing or decreasing)
                old_rssi = dev["rssi"]  # This would be the previous average RSSI
                current_raw_rssi = advertisement_data.rssi

                # Update RSSI history
                dev["rssi_history"].append(current_raw_rssi)
                if len(dev["rssi_history"]) > 5:  # Keep last 5 readings
                    dev["rssi_history"].pop(0)

                # Calculate average RSSI
                avg_rssi = sum(dev["rssi_history"]) / len(dev["rssi_history"])
                dev["rssi"] = avg_rssi  # Store the new average RSSI

                # Calculate signal trend based on average RSSI changes
                if avg_rssi > old_rssi + 1.5:  # Adjusted threshold for averaged RSSI
                    trend = "increasing"
                elif avg_rssi < old_rssi - 1.5:  # Adjusted threshold for averaged RSSI
                    trend = "decreasing"
                else:  # Signal roughly the same
                    trend = dev.get("signal_trend", "stable")

                found_devices[idx]["rssi"] = avg_rssi  # Update with average RSSI
                found_devices[idx]["signal_trend"] = trend
                found_devices[idx]["distance"] = calculate_distance(
                    avg_rssi,  # Use average RSSI
                    tx_power=tx_power,
                    n=path_loss,
                    device_type=device_type,
                    advertised_tx_power=dev.get(
                        "advertised_tx_power"
                    ),  # Use stored advertised TX power
                )
                found_devices[idx]["last_seen"] = time.time()

                # Update device name if it wasn't available before but is now
                if (dev["name"] == "N/A" or not dev["name"]) and device.name:
                    found_devices[idx]["name"] = device.name
                    # Also update the meaningful name with the actual device name if available now
                    if device.name and device.name != "N/A":
                        found_devices[idx]["meaningful_name"] = device.name

                # Update device history
                update_device_history(found_devices[idx])
            break

    if not exists:
        # Add as new device
        initial_rssi = advertisement_data.rssi
        distance = calculate_distance(
            initial_rssi,  # Use initial RSSI for first calculation
            tx_power=tx_power,
            n=path_loss,
            device_type=device_type,
            advertised_tx_power=advertised_tx,  # Pass advertised TX power
        )

        # Prepare service UUIDs string
        service_uuids_str = (
            ", ".join(advertisement_data.service_uuids)
            if advertisement_data.service_uuids
            else ""
        )

        # Determine which name to use as friendly name (prioritize actual device name)
        if device.name and device.name != "N/A":
            # If device has a real name, use it instead of the generated meaningful name
            friendly_name = device.name
        else:
            # Otherwise use the existing friendly name or the inferred meaningful name
            friendly_name = friendly_names.get(
                device_id, device_info_extract["meaningful_name"]
            )

        # Create the device info
        device_info = {
            "name": device.name or "N/A",
            "meaningful_name": device_info_extract["meaningful_name"],
            "device_type": device_type,
            "company": device_info_extract["company"],
            "friendly_name": friendly_name,
            "address": device_id,
            "rssi": initial_rssi,  # Store initial RSSI, will be averaged later if device is seen again
            "rssi_history": [initial_rssi],  # Initialize RSSI history
            "signal_trend": "stable",  # Initial signal trend
            "distance": distance,
            "is_airtag": is_airtag_or_findmy,
            "advertised_tx_power": advertised_tx,  # Store advertised TX power
            "manufacturer_data": mfg_data_str.strip(),
            "service_uuids": service_uuids_str,
            "service_data": {
                str(uuid): data.hex()
                for uuid, data in service_data_dict.items()
                if data is not None
            },  # Store service data
            "last_seen": time.time(),
        }

        # Add to found devices
        found_devices.append(device_info)

        # Update device history
        update_device_history(device_info)


def clear_screen():
    """Clear the screen more effectively than console.clear()."""
    try:
        # Use platform-specific methods when possible
        if platform.system() == "Windows":
            os.system("cls")
        else:
            # ANSI escape sequence to clear screen and move cursor to home position
            print("\033c", end="", flush=True)
    except Exception:
        # Fallback to Rich's clear
        pass

    # Also use Rich's clear for good measure
    console.clear()


async def scan_once():
    """Perform a single scan for Bluetooth devices."""
    global scan_running, found_devices, should_exit

    # Clear the console and show a scanning message
    # clear_screen() # Moved to _run_scan before Live display starts

    # Get terminal dimensions for better layout - Not strictly needed for Live with screen=True
    # terminal_width, terminal_height = shutil.get_terminal_size()

    # Get adapter name for display
    adapter_name = "Default (System Choice)"
    if current_settings["selected_adapter"]:
        adapter_name = current_settings["selected_adapter"]

    # Create a nice looking scan screen - This will be handled by Live display in _run_scan
    # scan_mode = (
    #     "Continuous scan" if not current_settings["scan_once"] else "Single scan"
    # )
    # status_text = f\"\"\"[bold cyan]Scanning for Bluetooth devices...[/bold cyan]

    # {'Duration: ' + str(current_settings['duration']) + ' seconds' if current_settings["scan_once"] else 'Continuous scan mode'}
    # Mode: {scan_mode}
    # AirTag filter: {'ON' if current_settings['airtags_only'] else 'OFF'}
    # TX Power: {current_settings['tx_power']} dBm
    # Path Loss: {current_settings['path_loss']}
    # Using adapter: [cyan]{adapter_name}[/cyan]

    # [dim]Press 'q' to stop scanning and return to menu[/dim]
    # \"\"\"
    # console.print(Panel(status_text, border_style="green", padding=(1, 2)))

    # Clear found devices for a new scan
    found_devices = []
    scan_running = True  # Set scan_running before calling _run_scan

    # Determine adapter settings for different platforms
    adapter_kwargs = {}
    if platform.system() == "Linux" and current_settings["selected_adapter"]:
        # On Linux, the adapter parameter is the name like "hci0", "hci1", etc.
        adapter_kwargs = {"adapter": current_settings["selected_adapter"]}

    # Setup scanner with the callback function and adapter
    scanner = BleakScanner(
        detection_callback=lambda d, ad: device_callback(
            d,
            ad,
            current_settings["airtags_only"],
            current_settings["tx_power"],
            current_settings["path_loss"],
        ),
        **adapter_kwargs,
    )

    # _run_scan will now handle its own exceptions related to scanner.start/stop
    # and the Live display loop.
    # scan_once handles higher-level errors or results.
    try:
        await _run_scan(scanner)
    except BleakError as be:
        console.print(f"[red]Bluetooth error: {be}[/red]")
        console.print(
            "[yellow]This may indicate missing Bluetooth adapters or permissions issues.[/yellow]"
        )
        if platform.system() == "Linux":
            console.print(
                "[yellow]On Linux, you may need to run with sudo or add your user to the bluetooth group.[/yellow]"
            )
        console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        # await asyncio.sleep(3) # Give time to read the error - Handled by key press
        while not is_key_pressed():
            await asyncio.sleep(0.1)
        get_key()  # Consume the key
    except Exception as e:
        console.print(f"[red]Error during scan setup: {e}[/red]")
        console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        # await asyncio.sleep(3)
        while not is_key_pressed():
            await asyncio.sleep(0.1)
        get_key()  # Consume the key
    # finally:
    # scan_running = False # _run_scan's finally block should handle this


async def _run_scan(scanner: BleakScanner):
    """Run the Bluetooth scan with the provided scanner using Rich Live display."""
    global scan_running, found_devices, should_exit, current_settings

    clear_screen()  # Clear once before Live display

    adapter_name = "Default (System Choice)"
    if current_settings["selected_adapter"]:
        adapter_name = current_settings["selected_adapter"]

    def generate_current_scan_display(progress_info_str: str) -> Layout:
        scan_mode_str = (
            "Single scan" if current_settings["scan_once"] else "Continuous scan"
        )
        status_text_content = f"""[bold cyan]Scanning for Bluetooth devices...[/bold cyan]

{progress_info_str}
Mode: {scan_mode_str}
AirTag filter: {'ON' if current_settings['airtags_only'] else 'OFF'}
Devices found: {len(found_devices)}
Using adapter: [cyan]{adapter_name}[/cyan]

[bold green]Available commands while scanning:[/bold green]
q - {'Cancel' if current_settings["scan_once"] else 'Stop'} scan and return to menu
[dim]l - List adapters (use main menu)[/dim]
[dim]b - Change adapter (use main menu)[/dim]
"""
        status_panel = Panel(status_text_content, border_style="green", padding=(1, 2))

        devices_renderable = display_devices()  # Returns Table or Panel

        display_layout = Layout(name="root")
        display_layout.split_column(
            Layout(status_panel, name="status", minimum_size=10, ratio=1),
            Layout(devices_renderable, name="devices_list", ratio=3),
        )
        return display_layout

    try:
        await scanner.start()

        with Live(
            generate_current_scan_display("Initializing..."),
            refresh_per_second=4,  # Adjust for desired refresh rate
            screen=True,
            transient=False,  # Keeps display until Live block exits
        ) as live:

            scan_start_time = time.time()

            while scan_running:  # Primary loop condition
                current_time = time.time()
                elapsed_scan_time = current_time - scan_start_time
                progress_str = ""

                if current_settings["scan_once"]:
                    duration = current_settings["duration"]
                    if elapsed_scan_time >= duration:
                        scan_running = False  # Signal scan to stop
                        break
                    progress_str = (
                        f"Progress: {int(elapsed_scan_time) + 1}/{duration} seconds"
                    )
                else:  # Continuous scan
                    progress_str = f"Running time: {int(elapsed_scan_time)} seconds"

                live.update(generate_current_scan_display(progress_str))

                key = get_key()
                if key:
                    if key == "q":
                        scan_running = False  # Signal to stop
                        message = (
                            "[yellow]Scan cancelled.[/yellow]"
                            if current_settings["scan_once"]
                            else "[yellow]Scan stopped.[/yellow]"
                        )
                        # live.console.print(message, justify="center") # Print to live console
                        # await asyncio.sleep(0.5) # Let message show briefly
                        # No direct print needed here, scan_once handles post-scan messages
                        break
                    elif key in ("l", "b"):
                        # live.console.print("[yellow]To list/change adapters, please stop scan (q) and use main menu.[/yellow]", justify="center")
                        # await asyncio.sleep(1.5) # Show message
                        # The message is now part of the status panel
                        pass

                if not scan_running:  # Re-check if q was pressed or duration ended
                    break

                await asyncio.sleep(
                    0.1
                )  # Short sleep to yield control, check keys, allow BLE callbacks

    except BleakError as be:
        # This error is specific to scanner operations like start/stop
        console.print(f"[red]Bluetooth error during scanning operation: {be}[/red]")
        console.print(
            "[yellow]This may indicate missing Bluetooth adapters or permissions issues.[/yellow]"
        )
        if platform.system() == "Linux":
            console.print(
                "[yellow]On Linux, you may need to run with sudo or add your user to the bluetooth group.[/yellow]"
            )
        # console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        # await asyncio.sleep(3)
        # while not is_key_pressed(): # Let scan_once handle this interaction
        #     await asyncio.sleep(0.1)
        # get_key()
        scan_running = False  # Ensure scan stops
        raise  # Re-raise for scan_once to handle user interaction for returning to menu

    except Exception as e:
        # General errors during _run_scan (e.g., within Live loop if not caught there)
        console.print(f"[red]Error during scan execution: {e}[/red]")
        # console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        # await asyncio.sleep(3)
        # while not is_key_pressed():
        #     await asyncio.sleep(0.1)
        # get_key()
        scan_running = False  # Ensure scan stops
        raise  # Re-raise for scan_once

    finally:
        if (
            scanner.is_scanning
        ):  # is_scanning might not be available on all backends, or check via other means
            try:
                await scanner.stop()
            except BleakError as be_stop:
                console.print(
                    f"[yellow]Warning: Error stopping scanner: {be_stop}[/yellow]"
                )
            except Exception as e_stop:  # Catch any other error during stop
                console.print(
                    f"[yellow]Warning: Generic error stopping scanner: {e_stop}[/yellow]"
                )
        scan_running = False  # Ensure this is always set

    # Post-scan messages for 'scan_once' are handled by the caller (scan_once function)
    # after _run_scan completes or raises an exception.
    # If _run_scan completes normally (scan_running becomes False due to duration or 'q'),
    # control returns to scan_once.


# Original _run_scan parts that are now integrated or handled by Live or scan_once:
# - Initial status panel printing (done by Live)
# - Loop with display_devices() and clear_screen() (done by Live update)
# - Key handling for l and b (simplified for now)
# - Final "Scan complete" and device display for scan_once (handled in scan_once after _run_scan)
# - BleakError and Exception handling (now more structured)


async def display_adapters_during_scan():
    """Display Bluetooth adapters. For use when scan is NOT live or Live is paused."""
    # Keep scan running but pause display updates temporarily
    clear_screen()
    console.print("\n[bold cyan]Available Bluetooth Adapters[/bold cyan]\n")

    adapters = get_bluetooth_adapters()

    if not adapters:
        console.print("[yellow]No Bluetooth adapters found.[/yellow]")
        console.print("\n[dim]Press any key to return to scanning...[/dim]")
        await asyncio.sleep(0.5)
        while not is_key_pressed():
            await asyncio.sleep(0.1)
        get_key()
        return

    # Create a table to display adapter information
    table = Table(title=f"Bluetooth Adapters ({platform.system()})", box=box.ROUNDED)
    table.add_column("#", style="cyan", no_wrap=True, width=3)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Manufacturer", style="green")
    table.add_column("Powered", style="blue")

    for idx, adapter in enumerate(adapters):
        name = adapter.get("name", "N/A")
        address = adapter.get("address", "N/A")
        manufacturer = adapter.get("manufacturer", "N/A")
        power_state = adapter.get("powered", "N/A")

        # Format power state with color
        power_text = Text(power_state)
        if "On" in power_state or "OK" in power_state or "Yes" in power_state:
            power_text.stylize("bold green")
        elif "Off" in power_state or "No" in power_state or "Down" in power_state:
            power_text.stylize("bold red")

        # Mark current adapter
        is_selected = (
            "[bright_green]✓[/bright_green] "
            if current_settings["selected_adapter"] == name
            else ""
        )
        display_index = f"{idx + 1}"
        table.add_row(
            display_index, f"{is_selected}{name}", address, manufacturer, power_text
        )

    console.print(table)
    console.print("\n[dim]Press any key to return to scanning...[/dim]")

    # Wait for key press
    await asyncio.sleep(0.5)
    while not is_key_pressed():
        await asyncio.sleep(0.1)
    get_key()


async def change_adapter_during_scan(current_scanner):
    """Allow changing the Bluetooth adapter during an active scan."""
    global current_settings

    # Pause the current scanner
    await current_scanner.stop()

    clear_screen()
    console.print("\n[bold cyan]Change Bluetooth Adapter[/bold cyan]\n")

    adapters = get_bluetooth_adapters()

    if not adapters:
        console.print("[yellow]No Bluetooth adapters found.[/yellow]")
        console.print("\n[dim]Press any key to return to scanning...[/dim]")
        await asyncio.sleep(0.5)
        while not is_key_pressed():
            await asyncio.sleep(0.1)
        get_key()

        # Restart the scanner with the same adapter
        await current_scanner.start()
        return

    # Create a table to display adapter information
    table = Table(title=f"Bluetooth Adapters ({platform.system()})", box=box.ROUNDED)
    table.add_column("#", style="cyan", no_wrap=True, width=3)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Status", style="blue")

    for idx, adapter in enumerate(adapters):
        name = adapter.get("name", "N/A")
        address = adapter.get("address", "N/A")
        power_state = adapter.get("powered", "N/A")

        # Format power state with color
        status = (
            "Active" if current_settings["selected_adapter"] == name else power_state
        )
        status_text = Text(status)
        if status == "Active":
            status_text.stylize("bold green")
        elif "On" in power_state or "OK" in power_state:
            status_text.stylize("green")
        else:
            status_text.stylize("red")

        table.add_row(f"{idx + 1}", name, address, status_text)

    # Add default option
    default_status = (
        "Active" if current_settings["selected_adapter"] is None else "Available"
    )
    default_text = Text(default_status)
    default_text.stylize("bold green" if default_status == "Active" else "green")
    table.add_row("0", "Default (System Choice)", "", default_text)

    console.print(table)
    console.print(
        "\nEnter adapter number to use (0 for default), or press Enter to cancel: ",
        end="",
    )

    # Get adapter selection
    choice = input().strip()

    restart_with_new_adapter = False

    if choice:
        try:
            idx = int(choice)
            if idx == 0:
                if current_settings["selected_adapter"] is not None:
                    current_settings["selected_adapter"] = None
                    console.print("[green]✓ Switching to default adapter[/green]")
                    restart_with_new_adapter = True
                else:
                    console.print("[yellow]Already using default adapter[/yellow]")
            elif 1 <= idx <= len(adapters):
                selected = adapters[idx - 1]
                adapter_name = selected.get("name", "N/A")

                if current_settings["selected_adapter"] != adapter_name:
                    current_settings["selected_adapter"] = adapter_name
                    console.print(
                        f"[green]✓ Switching to adapter: {adapter_name}[/green]"
                    )
                    restart_with_new_adapter = True
                else:
                    console.print(
                        f"[yellow]Already using adapter: {adapter_name}[/yellow]"
                    )
            else:
                console.print("[red]Invalid adapter number[/red]")

        except ValueError:
            console.print("[red]Invalid input[/red]")

    # Allow time to see the message
    await asyncio.sleep(1)

    if restart_with_new_adapter:
        # Save the settings
        save_settings()

        # We need to create a new scanner with the selected adapter
        adapter_kwargs = {}
        if platform.system() == "Linux" and current_settings["selected_adapter"]:
            adapter_kwargs = {"adapter": current_settings["selected_adapter"]}

        # Create new scanner with updated adapter
        new_scanner = BleakScanner(
            detection_callback=lambda d, ad: device_callback(
                d,
                ad,
                current_settings["airtags_only"],
                current_settings["tx_power"],
                current_settings["path_loss"],
            ),
            **adapter_kwargs,
        )

        # Replace the reference to the scanner
        current_scanner.__dict__.update(new_scanner.__dict__)

    # Restart the scanner (whether changed or not)
    await current_scanner.start()


def display_help():
    """Display help information for the interactive mode."""
    clear_screen()

    # Create a more visually organized help display
    layout = Layout()
    layout.split(
        Layout(
            Panel("[bold cyan]TagFinder Help & Usage Guide[/bold cyan]", style="cyan"),
            size=3,
        ),
        Layout(name="content"),
    )

    # Split content area into columns
    content_layout = layout["content"]
    content_layout.split_row(
        Layout(name="commands"),
        Layout(name="help"),
    )

    # Get adapter display name
    adapter_display = "Default (System Choice)"
    if current_settings["selected_adapter"]:
        adapter_display = current_settings["selected_adapter"]

    # Commands section
    commands_table = Table.grid(padding=1)
    commands_table.add_column(style="green bold", justify="center")
    commands_table.add_column(style="white")

    commands_table.add_row("s", "Start scanning for Bluetooth devices")
    commands_table.add_row(
        "a",
        f"Toggle AirTags-only filter ({['OFF', 'ON'][current_settings['airtags_only']]})",
    )
    commands_table.add_row("d", f"Set scan duration ({current_settings['duration']} s)")
    commands_table.add_row("n", "Set friendly names for devices")
    commands_table.add_row("t", f"Set TX power ({current_settings['tx_power']} dBm)")
    commands_table.add_row(
        "p", f"Set path loss exponent ({current_settings['path_loss']})"
    )
    commands_table.add_row(
        "m",
        f"Toggle scan mode ({'SINGLE' if current_settings['scan_once'] else 'CONTINUOUS'})",
    )
    commands_table.add_row("l", "List Bluetooth adapters")
    commands_table.add_row(
        "b", f"Select Bluetooth adapter (Current: {adapter_display})"
    )
    commands_table.add_row("c", "Clear device list")
    commands_table.add_row("h", "Show this help")
    commands_table.add_row("q", "Quit the application")

    content_layout["commands"].update(
        Panel(
            commands_table,
            title="Commands",
            border_style="green",
            padding=(1, 2),
        )
    )

    # Help content
    help_content = """
[bold cyan]Scan Modes:[/bold cyan]
• Single: Scans for the set duration and stops
• Continuous: Scans indefinitely until stopped with 'q'

[bold cyan]Direction Finding:[/bold cyan]
The [bold]Signal[/bold] column shows relative signal changes:
• [bold green]↑[/bold green] - Getting stronger (moving closer)
• [bold red]↓[/bold red] - Getting weaker (moving away)
• [yellow]•[/yellow] - Stable (not moving relative to device)

To locate a device, move slowly and watch for signal 
strength changes. The strongest signal (least negative 
RSSI value) indicates you're closest to the device.

[bold cyan]Distance Calculation:[/bold cyan]
For accurate distance, set appropriate TX power:
• AirTags: -59 to -65 dBm
• Standard BLE: -59 to -70 dBm

Path loss exponent varies by environment:
• 2.0: Free space / outdoors
• 2.5: Mixed environment (default)
• 3.0-4.0: Indoor with obstacles

[bold cyan]Bluetooth Adapters:[/bold cyan]
• If your system has multiple Bluetooth adapters, you can
  select which one to use for scanning.
• Linux users can specify adapters like "hci0", "hci1", etc.
• The default option uses the system's primary adapter.
• During continuous scanning, you can press 'l' to list adapters
  or 'b' to switch between available adapters without stopping
  the scan.
"""

    content_layout["help"].update(
        Panel(
            help_content,
            title="Usage Tips",
            border_style="blue",
            padding=(1, 2),
        )
    )

    console.print(layout)

    console.print("\n[dim]Press any key to return to the main menu...[/dim]")
    # Wait for a keypress
    while not is_key_pressed():
        time.sleep(0.1)
    get_key()  # Consume the key


def display_devices():
    """Display the list of found devices in a nicely formatted table.
    Returns a Rich Table object or a Rich Panel if no devices are found.
    """
    if not found_devices:
        # console.print("[yellow]No devices found.[/yellow]")
        return Panel(
            "[yellow]Scanning... No devices found yet.[/yellow]",
            border_style="dim",
            padding=(1, 2),
            title="Devices",
        )

    # Sort devices by RSSI (strongest signal first)
    sorted_devices = sorted(found_devices, key=lambda x: x["rssi"], reverse=True)

    try:
        # Create a comprehensive table with all information columns
        table = Table(
            title=f"Bluetooth Devices ({len(sorted_devices)})",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold cyan",
            row_styles=["", "dim"],  # Alternating row styles
            border_style="bright_black",
            min_width=95,  # Wider for more columns
        )

        # Add all available columns
        table.add_column("Name/Alias", style="cyan", no_wrap=True, width=20)
        table.add_column("RSSI", justify="right", width=5)
        table.add_column("Sig", width=4, justify="center")
        table.add_column("Dist", style="blue", width=6, justify="right")
        table.add_column("Type", style="green", width=12)
        table.add_column("Company", style="yellow", width=10)
        table.add_column("First Seen", style="magenta", width=12)
        table.add_column("ID", style="dim", width=18, overflow="fold")

        # Add device data
        for i, device in enumerate(sorted_devices):
            # Safety check for required fields
            if "address" not in device or "rssi" not in device:
                continue  # Skip incomplete device entries

            # Prioritize actual device name if available
            actual_name = device.get("name", "N/A")
            if (
                actual_name != "N/A"
                and actual_name is not None
                and actual_name.strip() != ""
            ):
                display_name = actual_name
            else:
                # Fall back to other options if no actual device name
                display_name = device.get(
                    "friendly_name", device.get("meaningful_name", "Unknown")
                )

            if display_name is None or display_name == "N/A":
                display_name = "Unknown"

            addr = device.get("address", "")
            # Truncate long addresses
            if addr and len(addr) > 18:
                addr = addr[:15] + "..."

            rssi = device.get("rssi", 0)
            distance = device.get("distance", -1)
            distance_str = f"{distance:.1f}m" if distance > 0 else "N/A"

            # Get signal trend
            trend = device.get("signal_trend", "stable")
            if trend == "increasing":
                trend_icon = (
                    "^"  # Signal getting stronger (moving closer) - using ASCII
                )
                trend_style = "bold green"
            elif trend == "decreasing":
                trend_icon = "v"  # Signal getting weaker (moving away) - using ASCII
                trend_style = "bold red"
            else:
                trend_icon = "."  # Signal stable - using ASCII
                trend_style = "yellow"

            try:
                trend_text = Text(trend_icon, style=trend_style)
            except Exception:
                # Fallback if Text creation fails
                trend_text = trend_icon

            # Colorize RSSI based on signal strength
            try:
                rssi_text = Text(f"{rssi}")
                if rssi > -70:
                    rssi_text.stylize("green")
                elif rssi > -85:
                    rssi_text.stylize("yellow")
                else:
                    rssi_text.stylize("red")
            except Exception:
                # Fallback if Text styling fails
                rssi_text = f"{rssi}"

            # Get device type information - use the enhanced info
            device_type = device.get("device_type", "BLE Device")
            if device_type is None:
                device_type = "BLE Device"

            is_airtag = device.get("is_airtag", False)

            try:
                if is_airtag:
                    type_text = Text(device_type, style="bold green")
                else:
                    type_text = Text(device_type, style="white")
            except Exception:
                # Fallback if Text creation fails
                type_text = device_type

            # Check if this is a new device in current session
            is_new_device = device.get("new_device", False)

            # Add "NEW" indicator for new devices if enabled
            if is_new_device and current_settings["highlight_new_devices"]:
                if display_name != "N/A" and display_name != "Unknown":
                    display_name = (
                        f"[bold bright_green]NEW[/bold bright_green] {display_name}"
                    )
                else:
                    display_name = f"[bold bright_green]NEW DEVICE[/bold bright_green]"

            # Format first seen time
            first_seen_time = device.get("first_seen", time.time())
            try:
                first_seen_str = datetime.datetime.fromtimestamp(
                    first_seen_time
                ).strftime("%H:%M:%S")
                # If from a previous day, include date
                if (
                    datetime.datetime.fromtimestamp(first_seen_time).date()
                    < datetime.datetime.today().date()
                ):
                    first_seen_str = datetime.datetime.fromtimestamp(
                        first_seen_time
                    ).strftime("%m-%d %H:%M")
            except Exception:
                first_seen_str = "Unknown"

            # Add company info if available
            company = device.get("company", "")

            # Show manufacturer data if enabled in settings
            if current_settings["show_manufacturer_data"] and device.get(
                "manufacturer_data"
            ):
                try:
                    mfg_data = device.get("manufacturer_data", "").split("\n")[
                        0
                    ]  # Just take first line
                    if mfg_data:
                        display_name += f"\n[dim]{mfg_data}[/dim]"
                except Exception:
                    pass  # Ignore errors with manufacturer data

            # Determine row styling based on target settings
            row_style = ""
            is_target_by_address = (
                current_settings.get("target_device_address")
                and device.get("address") == current_settings["target_device_address"]
            )
            is_potential_target_airtag = device.get(
                "is_airtag", False
            ) and current_settings.get("target_airtag_serial")

            if is_target_by_address:
                row_style = (
                    "on bright_cyan"  # Most prominent highlight for specific target
                )
                display_name = f"🎯 TARGET 🎯\n{display_name}"
            elif is_potential_target_airtag:
                row_style = "on dark_magenta"  # Highlight for all AirTags if a serial is being looked for
                display_name = f"⚠️ AirTag ⚠️\n{display_name}"

            # Add row to table
            try:
                table.add_row(
                    display_name,
                    rssi_text,
                    trend_text,
                    distance_str,
                    type_text,
                    company,
                    first_seen_str,
                    addr,
                    style=row_style,  # Apply the determined style to the row
                )
            except Exception as row_err:
                # If adding a specific row fails, log it but continue with other rows
                print(
                    f"Error adding device row: {row_err}"
                )  # This print will go to original stdout
                continue

        # Print the table with error handling
        # console.print(table) # Removed: will return table object
        return table
    except Exception as e:
        # Fallback to a simple display if the rich table fails
        # console.print(f"[red]Error displaying device table: {e}[/red]")
        # console.print(f"[yellow]Found {len(sorted_devices)} devices[/yellow]")
        # Print a simpler version of the data
        # for i, device in enumerate(sorted_devices[:10]):  # Limit to first 10 devices
        #     name = device.get("name", device.get("friendly_name", "Unknown"))
        #     rssi = device.get("rssi", 0)
        #     console.print(f"{i+1}. {name} (RSSI: {rssi})")
        # if len(sorted_devices) > 10:
        #     console.print(f"... and {len(sorted_devices) - 10} more devices")
        return Panel(
            f"[red]Error displaying device table: {e}[/red]\n[yellow]Found {len(sorted_devices)} devices[/yellow]",
            border_style="red",
            title="Device Display Error",
        )


def display_menu():
    """Display the main menu with current settings."""
    clear_screen()

    # Create a more compact layout
    layout = Layout()

    # Header section with app title and stats - Use text instead of emoji to avoid encoding issues
    # Replace the emoji with a safe ASCII alternative
    header_text = "[bold cyan]TagFinder[/bold cyan] - Bluetooth Device Scanner"

    # Stats about found devices
    num_devices = len(found_devices)
    num_airtags = sum(1 for d in found_devices if d.get("is_airtag", False))
    num_new = sum(1 for d in found_devices if d.get("new_device", False))

    if num_devices > 0:
        header_text += f" • [green]{num_devices} devices[/green]"
        if num_airtags > 0:
            header_text += f" • [cyan]{num_airtags} Apple Find My[/cyan]"
        if num_new > 0:
            header_text += f" • [bright_green]{num_new} new[/bright_green]"

    # Create a compact settings and commands layout
    menu_grid = Table.grid(padding=(0, 1))
    menu_grid.add_column(style="green", justify="right")
    menu_grid.add_column(style="white")
    menu_grid.add_column(style="dim", justify="right")
    menu_grid.add_column(style="cyan")

    # Format adapter name for display
    adapter_display = "Default (System Choice)"
    if current_settings["selected_adapter"]:
        adapter_display = current_settings["selected_adapter"]

    target_serial_display = current_settings.get("target_airtag_serial", "None")
    target_address_display = current_settings.get("target_device_address", "None")

    # Add a row for each command with settings on the right
    menu_grid.add_row(
        "s",
        "Start Scan",
        "AirTags Filter:",
        "ON" if current_settings["airtags_only"] else "OFF",
    )
    menu_grid.add_row(
        "a",
        "Toggle AirTags Filter",
        "Scan Duration:",
        f"{current_settings['duration']} seconds",
    )
    menu_grid.add_row(
        "d", "Set Duration", "TX Power:", f"{current_settings['tx_power']} dBm"
    )
    menu_grid.add_row(
        "n", "Set Friendly Name", "Path Loss Exp:", f"{current_settings['path_loss']}"
    )
    menu_grid.add_row(
        "t",
        "Set TX Power",
        "Scan Mode:",
        "SINGLE" if current_settings["scan_once"] else "CONTINUOUS",
    )
    menu_grid.add_row(
        "p",
        "Set Path Loss",
        "Highlight New:",
        "ON" if current_settings["highlight_new_devices"] else "OFF",
    )
    menu_grid.add_row(
        "m",
        "Toggle Scan Mode",
        "Auto Save:",
        "ON" if current_settings["auto_save_devices"] else "OFF",
    )
    menu_grid.add_row(
        "l",
        "List Adapters",
        "Show Mfg Data:",
        "ON" if current_settings["show_manufacturer_data"] else "OFF",
    )
    menu_grid.add_row(
        "b",
        "Select Adapter",
        "BT Adapter:",
        adapter_display,
    )
    menu_grid.add_row(  # New option for setting target MAC
        "k", "Set Target MAC", "Target Serial:", f"{target_serial_display}"
    )
    menu_grid.add_row(
        "c",
        "Clear Devices",
        "Target MAC:",
        f"{target_address_display}",
    )
    # Add new toggles with letter keys
    menu_grid.add_row(
        "u",  # Was '1'
        "Toggle Auto Save",
        "Auto Save:",
        "ON" if current_settings["auto_save_devices"] else "OFF",
    )
    menu_grid.add_row(
        "i",  # Was '2'
        "Toggle Highlight New",
        "Highlight New:",
        "ON" if current_settings["highlight_new_devices"] else "OFF",
    )
    menu_grid.add_row(
        "o",  # Was '3'
        "Toggle Show Mfg Data",
        "Show Mfg Data:",
        "ON" if current_settings["show_manufacturer_data"] else "OFF",
    )
    menu_grid.add_row("h", "Help", "", "")
    menu_grid.add_row("q", "Quit", "", "")

    commands_panel = Panel(
        menu_grid, title="Commands & Settings", border_style="green", padding=(1, 1)
    )

    # Set up main layout
    layout.split(
        Layout(Panel(header_text, style="cyan"), size=3),
        Layout(commands_panel, size=12),
    )

    # Error-safe rendering
    try:
        console.print(layout)
    except Exception as e:
        # Fallback to a simpler display if rich layout fails
        console.print("[bold cyan]TagFinder - Bluetooth Device Scanner[/bold cyan]")
        console.print("\n[bold]Commands & Settings:[/bold]")
        console.print(menu_grid)
        # Log the error but don't crash
        print(f"Display warning: {e}")

    # Show total devices in history
    if known_devices:
        total_known = len(known_devices)
        total_seen_today = sum(
            1
            for addr, info in known_devices.items()
            if datetime.datetime.fromtimestamp(info.get("last_seen", 0)).date()
            == datetime.datetime.today().date()
        )

        console.print(
            f"[dim]Device History: {total_known} total devices, {total_seen_today} seen today[/dim]"
        )

    # If we have devices, display them
    if num_devices > 0:
        console.print("\n[bold]Devices Found:[/bold]")
        try:
            display_devices()
        except Exception as e:
            console.print(f"[red]Error displaying devices: {e}[/red]")
            console.print(f"[yellow]Found {num_devices} devices[/yellow]")
    else:
        console.print(
            "\n[yellow]No devices found yet. Press 's' to start scanning.[/yellow]"
        )

    console.print("\nPress a key to select an action...", end="", highlight=False)
    # The actual input is handled in the main loop


def get_numeric_input(prompt, default_value, value_type=int):
    """Get numeric input from the user with validation."""
    console.clear()
    console.print(f"\n[bold]{prompt}[/bold]")
    console.print(f"Current value: {default_value}\n")

    while True:
        console.print(f"Enter new value [default: {default_value}]: ", end="")
        value = input()

        if not value:  # User pressed Enter, use default
            return default_value

        try:
            if value_type == int:
                return int(value)
            elif value_type == float:
                return float(value)
        except ValueError:
            console.print(
                f"[red]Invalid input. Please enter a valid {value_type.__name__}.[/red]"
            )


def load_friendly_names():
    """Load friendly names from file if it exists."""
    global friendly_names
    try:
        if os.path.exists(FRIENDLY_NAMES_FILE):
            with open(FRIENDLY_NAMES_FILE, "r") as f:
                friendly_names = json.load(f)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load friendly names: {e}[/yellow]")
        friendly_names = {}


def save_friendly_names():
    """Save friendly names to file."""
    try:
        with open(FRIENDLY_NAMES_FILE, "w") as f:
            json.dump(friendly_names, f)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save friendly names: {e}[/yellow]")


def set_friendly_name():
    """Set a friendly name for a device."""
    global friendly_names

    if not found_devices:
        console.print("[yellow]No devices found yet. Run a scan first.[/yellow]")
        console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        while not is_key_pressed():
            time.sleep(0.1)
        get_key()
        return

    # Clear screen and show device list with indices
    clear_screen()
    console.print("\n[bold cyan]Set Friendly Name for Device[/bold cyan]\n")

    # Show a list of devices with indices - more compact table
    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("#", style="dim", width=3)
    table.add_column("Auto-detected Name", style="cyan")
    table.add_column("Type", style="green", width=12)
    table.add_column("RSSI", style="magenta", width=6)
    table.add_column("Friendly Name", style="yellow")

    for i, device in enumerate(found_devices):
        friendly = friendly_names.get(device["address"], "Not set")
        device_type = device.get("device_type", "Unknown")
        if device["is_airtag"]:
            device_type = device.get("device_type", "Apple Find My")

        auto_name = device.get("meaningful_name", device["name"])

        table.add_row(
            str(i + 1),
            auto_name,
            device_type,
            str(device["rssi"]),
            friendly,
        )

    console.print(table)
    console.print(
        "\nEnter the number of the device to rename (or press Enter to cancel): ",
        end="",
    )

    choice = input().strip()
    if not choice:
        return

    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(found_devices):
            console.print("[red]Invalid device number.[/red]")
            return

        device = found_devices[idx]
        addr = device["address"]
        auto_name = device.get("meaningful_name", device["name"])
        current_name = friendly_names.get(addr, auto_name)

        console.print(f"\nAuto-detected name: [cyan]{auto_name}[/cyan]")
        console.print(f"Current friendly name: [cyan]{current_name}[/cyan]")
        console.print(f"Enter new friendly name for device: ", end="")

        new_name = input().strip()
        if new_name:
            friendly_names[addr] = new_name
            # Update friendly name in the device info
            for d in found_devices:
                if d["address"] == addr:
                    d["friendly_name"] = new_name

            save_friendly_names()
            console.print(f"[green]✓ Device renamed to: {new_name}[/green]")
        else:
            console.print("[yellow]Name unchanged.[/yellow]")

    except ValueError:
        console.print("[red]Please enter a valid number.[/red]")

    console.print("\n[dim]Press any key to return to the main menu...[/dim]")
    while not is_key_pressed():
        time.sleep(0.1)
    get_key()


def load_settings():
    """Load user settings from file."""
    global current_settings
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                loaded_settings = json.load(f)
                # Update existing settings with loaded ones, keeping defaults for any missing
                current_settings.update(loaded_settings)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load settings: {e}[/yellow]")


def save_settings():
    """Save current settings to file."""
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(current_settings, f, indent=2)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save settings: {e}[/yellow]")


def load_device_history():
    """Load device history from file."""
    global known_devices, first_seen_timestamps
    try:
        if os.path.exists(DEVICES_HISTORY_FILE):
            with open(DEVICES_HISTORY_FILE, "r") as f:
                data = json.load(f)
                known_devices = data.get("devices", {})
                first_seen_timestamps = data.get("first_seen", {})
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load device history: {e}[/yellow]")
        known_devices = {}
        first_seen_timestamps = {}


def save_device_history():
    """Save device history to file."""
    try:
        # Prepare the data structure
        data = {
            "devices": known_devices,
            "first_seen": first_seen_timestamps,
            "last_updated": time.time(),
        }
        with open(DEVICES_HISTORY_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save device history: {e}[/yellow]")


def update_device_history(device: Dict[str, Any]):
    """Update the device history with new information."""
    global known_devices, first_seen_timestamps

    address = device["address"]

    # Check if this is a new device
    if address not in known_devices:
        first_seen_timestamps[address] = time.time()
        device["first_seen"] = time.time()
        device["new_device"] = True
    else:
        device["first_seen"] = first_seen_timestamps.get(address, time.time())
        device["new_device"] = False

    # Update the known devices database
    known_devices[address] = {
        "name": device.get("name", "N/A"),
        "friendly_name": device.get("friendly_name", ""),
        "meaningful_name": device.get("meaningful_name", ""),
        "device_type": device.get("device_type", ""),
        "company": device.get("company", ""),
        "is_airtag": device.get("is_airtag", False),
        "last_seen": time.time(),
        "last_rssi": device.get("rssi", 0),
        "first_seen": first_seen_timestamps.get(address, time.time()),
    }

    # Auto-save if enabled
    if current_settings["auto_save_devices"]:
        save_device_history()


def set_target_device_address():
    """Allow the user to set or clear the target device MAC address."""
    global current_settings
    clear_screen()
    console.print("[bold cyan]Set Target Device MAC Address[/bold cyan]")

    current_target_address = current_settings.get("target_device_address", "Not set")
    console.print(
        f"\nCurrent target MAC address: [yellow]{current_target_address}[/yellow]"
    )
    console.print(
        "Enter the MAC address of the device you want to specifically target."
    )
    console.print("Leave blank and press Enter to clear the current target address.")
    console.print("\nEnter MAC address: ", end="")

    mac_address = input().strip()

    if not mac_address:  # User wants to clear
        current_settings["target_device_address"] = None
        console.print("[green]✓ Target device MAC address cleared.[/green]")
    else:
        # Basic validation for MAC address format (e.g., XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX)
        # This is a simple check, can be made more robust if needed
        if re.match(
            r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address
        ) or re.match(
            r"^[0-9A-Fa-f]{12}$", mac_address.replace(":", "").replace("-", "")
        ):
            current_settings["target_device_address"] = mac_address.upper()
            console.print(
                f"[green]✓ Target device MAC address set to: {current_settings['target_device_address']}[/green]"
            )
        else:
            console.print(
                "[red]Invalid MAC address format. Please use XX:XX:XX:XX:XX:XX or similar.[/red]"
            )

    save_settings()
    console.print("\n[dim]Press any key to return to the main menu...[/dim]")
    while not is_key_pressed():
        time.sleep(0.1)
    get_key()


def toggle_setting(setting_name: str):
    """Toggle a boolean setting and save settings."""
    if setting_name in current_settings and isinstance(
        current_settings[setting_name], bool
    ):
        current_settings[setting_name] = not current_settings[setting_name]
        save_settings()
        setting_state = "ON" if current_settings[setting_name] else "OFF"
        console.print(
            f"[green]✓ {setting_name.replace('_', ' ').title()} is now {setting_state}[/green]"
        )
    else:
        console.print(
            f"[red]Error: {setting_name} is not a valid boolean setting.[/red]"
        )


async def main_interactive():
    """Main function for the interactive mode."""
    global should_exit, scan_running

    try:
        # Main application loop
        while not should_exit:
            try:
                # Display the main menu
                display_menu()

                # Wait for a keypress
                key = None
                while key is None:
                    await asyncio.sleep(0.1)
                    try:
                        key = get_key()
                    except Exception:
                        # If key capture fails, just wait and try again
                        await asyncio.sleep(0.5)
                        continue

                # Process the keypress
                if key == "q":  # Quit
                    should_exit = True
                    # Save all data before quitting
                    try:
                        save_friendly_names()
                        save_settings()
                        save_device_history()
                    except Exception as e:
                        console.print(
                            f"[yellow]Warning: Error saving data: {e}[/yellow]"
                        )
                    break

                elif key == "h":  # Help
                    display_help()

                elif key == "s":  # Start scan
                    # await scan_once() # scan_once now sets scan_running
                    # clear_screen() is handled by scan_once/_run_scan

                    # Need to ensure scan_running is True before calling scan_once
                    # scan_running = True # scan_once sets this.
                    await scan_once()
                    # After scan_once returns, display_menu will be called again, clearing the screen.
                    # This is fine. No explicit clear_screen() needed here.

                elif key == "a":  # Toggle AirTags only
                    current_settings["airtags_only"] = not current_settings[
                        "airtags_only"
                    ]
                    save_settings()

                elif key == "d":  # Set duration
                    current_settings["duration"] = get_numeric_input(
                        "Set Scan Duration (seconds)", current_settings["duration"]
                    )
                    save_settings()

                elif key == "n":  # Set friendly name
                    set_friendly_name()

                elif key == "t":  # Set TX power
                    current_settings["tx_power"] = get_numeric_input(
                        "Set TX Power (dBm)", current_settings["tx_power"]
                    )
                    save_settings()

                elif key == "p":  # Set path loss exponent
                    current_settings["path_loss"] = get_numeric_input(
                        "Set Path Loss Exponent (2.0-4.0)",
                        current_settings["path_loss"],
                        float,
                    )
                    save_settings()

                elif key == "m":  # Toggle scan mode
                    current_settings["scan_once"] = not current_settings["scan_once"]
                    save_settings()

                elif key == "l":  # List adapters
                    display_bluetooth_adapters()

                elif key == "b":  # Select Bluetooth adapter
                    select_bluetooth_adapter()

                elif key == "k":  # Set target device MAC address (new key)
                    set_target_device_address()

                elif key == "c":  # Clear devices
                    found_devices.clear()

                # Add new key handlers for the new settings
                elif key == "u":  # Toggle auto save (was '1')
                    toggle_setting("auto_save_devices")

                elif key == "i":  # Toggle highlight new (was '2')
                    toggle_setting("highlight_new_devices")

                elif key == "o":  # Toggle show manufacturer data (was '3')
                    toggle_setting("show_manufacturer_data")

                # Save settings after any change
                try:
                    save_settings()
                except Exception as e:
                    console.print(
                        f"[yellow]Warning: Error saving settings: {e}[/yellow]"
                    )

            except Exception as loop_err:
                console.print(f"\n[bold red]Error in menu loop: {loop_err}[/bold red]")
                console.print("[yellow]Press any key to continue...[/yellow]")
                await asyncio.sleep(2)  # Brief pause to show the error

    except Exception as e:
        console.print(f"\n[bold red]Error in main loop: {e}[/bold red]")
        # Give user time to see the error before continuing
        console.print("[yellow]Press any key to exit...[/yellow]")
        await asyncio.sleep(3)


def initialize_app():
    """Initialize the application, checking for required packages."""
    global console

    # Show startup banner
    console.print("[bold cyan]TagFinder - Bluetooth Device Scanner[/bold cyan]")
    console.print("[dim]Initializing application...[/dim]")

    # Check for required packages and try to guide the user if any are missing
    try:
        import bleak
        import rich
    except ImportError as e:
        module_name = str(e).split("'")[1] if "'" in str(e) else str(e)
        console.print(
            f"[bold red]Error: Required package '{module_name}' is missing.[/bold red]"
        )
        console.print("\nPlease install the required packages using:")
        console.print("[green]pip install -r requirements.txt[/green]")
        console.print("\nOr manually install the missing package:")
        console.print(f"[green]pip install {module_name}[/green]")

        # Create requirements.txt if it doesn't exist
        if not os.path.exists("requirements.txt"):
            with open("requirements.txt", "w") as f:
                f.write("bleak>=0.20.0\nrich>=12.0.0\n")
            console.print(
                "\n[green]Created requirements.txt with necessary dependencies.[/green]"
            )

        sys.exit(1)

    # Load saved data
    try:
        load_friendly_names()
        load_settings()
        load_device_history()
    except Exception as e:
        console.print(f"[yellow]Warning: Error loading saved data: {e}[/yellow]")

    # Check if Bluetooth is available
    adapters = get_bluetooth_adapters()
    if not adapters:
        console.print("[yellow]Warning: No Bluetooth adapters detected.[/yellow]")

        if platform.system() == "Linux":
            console.print(
                "[yellow]On Linux, ensure Bluetooth is installed and you have permission to use it:[/yellow]"
            )
            console.print(
                "[green]sudo apt-get install bluetooth bluez libbluetooth-dev[/green]"
            )
            console.print(
                "[green]sudo setcap 'cap_net_raw,cap_net_admin+eip' $(which python3)[/green]"
            )
        elif platform.system() == "Windows":
            console.print(
                "[yellow]On Windows, ensure your Bluetooth adapter is enabled in Device Manager.[/yellow]"
            )
        elif platform.system() == "Darwin":  # macOS
            console.print(
                "[yellow]On macOS, ensure Bluetooth is enabled in System Preferences.[/yellow]"
            )
    else:
        console.print(f"[green]Detected {len(adapters)} Bluetooth adapter(s).[/green]")

    # Clear screen before showing the menu
    time.sleep(1.5)
    clear_screen()


def select_bluetooth_adapter():
    """Allow the user to select a Bluetooth adapter from the available ones."""
    global current_settings

    clear_screen()
    console.print("\n[bold cyan]Select Bluetooth Adapter[/bold cyan]\n")

    adapters = get_bluetooth_adapters()

    if not adapters:
        console.print(
            "[yellow]No Bluetooth adapters found or unable to detect adapters.[/yellow]"
        )
        console.print(
            "[dim]Note: You may need administrator/root privileges to see all adapter details.[/dim]"
        )
        console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        while not is_key_pressed():
            time.sleep(0.1)
        get_key()
        return

    # Create a table to display adapter information
    table = Table(
        title=f"Available Bluetooth Adapters ({platform.system()})", box=box.ROUNDED
    )
    table.add_column("#", style="cyan", no_wrap=True, width=3)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Manufacturer", style="green")
    table.add_column("Version/ID", style="yellow")
    table.add_column("Powered", style="blue")

    # Add each adapter to the table with an index
    for idx, adapter in enumerate(adapters):
        name = adapter.get("name", "N/A")
        address = adapter.get("address", "N/A")
        manufacturer = adapter.get("manufacturer", "N/A")
        version = adapter.get("version", adapter.get("device_id", "N/A"))
        power_state = adapter.get("powered", "N/A")

        # Format power state with color
        power_text = Text(power_state)
        if "On" in power_state or "OK" in power_state or "Yes" in power_state:
            power_text.stylize("bold green")
        elif "Off" in power_state or "No" in power_state or "Down" in power_state:
            power_text.stylize("bold red")

        # Mark currently selected adapter
        is_selected = (
            "[bright_green]✓[/bright_green] "
            if current_settings["selected_adapter"] == name
            else ""
        )
        display_index = f"{idx + 1}"
        table.add_row(
            display_index,
            f"{is_selected}{name}",
            address,
            manufacturer,
            version,
            power_text,
        )

    # Add an option for system default
    table.add_row("0", "[dim]Default (System Choice)[/dim]", "", "", "", "")

    if table.row_count > 0:
        console.print(table)
    else:
        console.print("[yellow]No adapter information could be displayed.[/yellow]")

    # Add platform-specific notes
    if platform.system() == "Windows":
        console.print(
            "\n[dim]Note: On Windows, some adapter details may be limited without admin privileges.[/dim]"
        )
    elif platform.system() == "Linux":
        console.print(
            "\n[dim]Note: On Linux, you may need to run with sudo to see all adapter details.[/dim]"
        )

    # Ask if user wants to select an adapter
    console.print("\nDo you want to select a Bluetooth adapter to use? (y/n): ", end="")
    choice = input().strip().lower()

    if choice == "y":
        console.print(
            "\nEnter the number of the adapter to use (0 for default): ", end=""
        )
        adapter_choice = input().strip()

        try:
            idx = int(adapter_choice)
            if idx == 0:
                # Use system default
                current_settings["selected_adapter"] = None
                console.print("[green]✓ Using system default adapter.[/green]")
            elif 1 <= idx <= len(adapters):
                # Use selected adapter
                selected = adapters[idx - 1]
                adapter_name = selected.get("name", "N/A")
                current_settings["selected_adapter"] = adapter_name
                console.print(f"[green]✓ Selected adapter: {adapter_name}[/green]")
            else:
                console.print("[red]Invalid adapter number.[/red]")

        except ValueError:
            console.print("[red]Please enter a valid number.[/red]")

        # Save settings
        save_settings()

        # Wait for acknowledgment
        console.print("\n[dim]Press any key to continue...[/dim]")
        while not is_key_pressed():
            time.sleep(0.1)
        get_key()
    else:
        console.print("\n[dim]Press any key to return to the main menu...[/dim]")
        while not is_key_pressed():
            time.sleep(0.1)
        get_key()  # Consume the key


if __name__ == "__main__":
    try:
        # Initialize the application
        initialize_app()
        setup_terminal()  # Make sure terminal is set up for interactive mode

        # Run in interactive mode
        asyncio.run(main_interactive())

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Application interrupted by user.[/bold yellow]")

    except Exception as e:
        console.print(f"[bold red]Unhandled error in script execution: {e}[/bold red]")
        import traceback

        console.print(f"[dim]{traceback.format_exc()}[/dim]")

    finally:
        # Restore terminal settings
        restore_terminal()
        console.print("[bold cyan]Exiting TagFinder. Goodbye![/bold cyan]")
