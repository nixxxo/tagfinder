#!/usr/bin/env python3

import asyncio
import json
import math
import os
import sys
import time
from typing import Dict, List, Optional, Set, Tuple
from collections import deque

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

# Constants
SETTINGS_FILE = "settings.json"
HISTORY_FILE = "devices_history.json"
AIRTAG_IDENTIFIERS = ["apple", "airtag", "find"]  # Identifiers to detect AirTags
SCAN_INTERVAL = 1.0  # Scan interval in seconds
DEFAULT_RSSI_AT_ONE_METER = -59  # Default RSSI at 1 meter for Bluetooth LE
DEFAULT_DISTANCE_N_VALUE = 2.0  # Default environmental factor for distance calculation
RSSI_HISTORY_SIZE = 10  # Number of RSSI readings to keep for smoothing


class Device:
    def __init__(
        self,
        address: str,
        name: str,
        rssi: int,
        manufacturer_data: Optional[Dict] = None,
    ):
        self.address = address
        self.name = name or "Unknown"
        self.rssi = rssi
        self.rssi_history = deque([rssi], maxlen=RSSI_HISTORY_SIZE)
        self.manufacturer_data = manufacturer_data or {}
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.is_airtag = self._check_if_airtag()
        self.calibrated_n_value = DEFAULT_DISTANCE_N_VALUE
        self.calibrated_rssi_at_one_meter = DEFAULT_RSSI_AT_ONE_METER

    def update(self, rssi: int, manufacturer_data: Optional[Dict] = None):
        self.rssi = rssi
        self.rssi_history.append(rssi)
        if manufacturer_data:
            self.manufacturer_data = manufacturer_data
        self.last_seen = time.time()

    def _check_if_airtag(self) -> bool:
        """Check if device is potentially an AirTag or Find My device"""
        if self.name and any(
            identifier in self.name.lower() for identifier in AIRTAG_IDENTIFIERS
        ):
            return True
        # Check manufacturer data for Apple identifiers
        for key, value in self.manufacturer_data.items():
            # Apple's company identifier is 0x004C
            if key == 76:  # 0x004C in decimal
                return True
        return False

    @property
    def smooth_rssi(self) -> float:
        """Get smoothed RSSI value by averaging recent readings"""
        if not self.rssi_history:
            return self.rssi
        return sum(self.rssi_history) / len(self.rssi_history)

    @property
    def distance(self) -> float:
        """Calculate approximate distance based on smoothed RSSI"""
        if self.smooth_rssi == 0:
            return float("inf")
        return 10 ** (
            (self.calibrated_rssi_at_one_meter - self.smooth_rssi)
            / (10 * self.calibrated_n_value)
        )

    def calibrate_distance(self, known_distance: float):
        """Calibrate distance calculation for this device at a known distance"""
        if self.smooth_rssi != 0 and known_distance > 0:
            # Calculate N factor based on known distance
            self.calibrated_n_value = abs(
                (self.calibrated_rssi_at_one_meter - self.smooth_rssi)
                / (10 * math.log10(known_distance))
            )
            return True
        return False

    def calibrate_rssi_at_one_meter(self, rssi_at_one_meter: int):
        """Set the RSSI value at one meter for this device"""
        self.calibrated_rssi_at_one_meter = rssi_at_one_meter
        return True

    @property
    def signal_stability(self) -> float:
        """Calculate signal stability as standard deviation of RSSI history"""
        if len(self.rssi_history) < 2:
            return 0.0
        mean = sum(self.rssi_history) / len(self.rssi_history)
        variance = sum((x - mean) ** 2 for x in self.rssi_history) / len(
            self.rssi_history
        )
        return math.sqrt(variance)

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
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_airtag": self.is_airtag,
            "distance": self.distance,
            "calibrated_n_value": self.calibrated_n_value,
            "calibrated_rssi_at_one_meter": self.calibrated_rssi_at_one_meter,
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
        self.calibration_mode = False
        self.layout = self._create_layout()

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
                    return json.load(f)
            except json.JSONDecodeError:
                pass
        return []

    def _save_history(self):
        """Save device history to JSON file"""
        # Convert current devices to dict and add to history
        for device in self.devices.values():
            self.history.append(device.to_dict())
        # Save to file
        with open(HISTORY_FILE, "w") as f:
            json.dump(self.history, f, indent=2)

    async def list_adapters(self):
        """List all available Bluetooth adapters"""
        adapters = await BleakScanner.get_bluetooth_adapters()

        table = Table(title="Available Bluetooth Adapters", box=box.ROUNDED)
        table.add_column("Index", style="cyan")
        table.add_column("Address", style="green")
        table.add_column("Name", style="magenta")

        for i, adapter in enumerate(adapters):
            is_current = (
                "[bold green]⟹[/]" if adapter.address == self.current_adapter else ""
            )
            table.add_row(str(i), adapter.address, f"{adapter.name} {is_current}")

        self.console.print(table)

        choice = self.console.input(
            "[bold blue]Select adapter index (or Enter to skip): [/]"
        )
        if choice.isdigit() and 0 <= int(choice) < len(adapters):
            self.current_adapter = adapters[int(choice)].address
            self.settings["adapter"] = self.current_adapter
            self._save_settings()
            self.console.print(
                f"[bold green]Selected adapter: {adapters[int(choice)].name}[/]"
            )

    def generate_device_table(self, devices: Dict[str, Device]) -> Table:
        """Generate a table of devices for display"""
        table = Table(
            title="[bold]Bluetooth Devices[/]",
            box=ROUNDED,
            highlight=True,
            title_style="bold cyan",
            border_style="blue",
        )
        table.add_column("Name", style="cyan")
        table.add_column("Address", style="dim blue")
        table.add_column("RSSI (dBm)", justify="right")
        table.add_column("Distance (m)", justify="right")
        table.add_column("Stability", justify="right")
        table.add_column("Type")
        table.add_column("Seen (s)", justify="right")

        # Sort devices by RSSI (closest first)
        sorted_devices = sorted(devices.values(), key=lambda d: d.rssi, reverse=True)

        for device in sorted_devices:
            # Skip non-AirTags if in AirTag only mode
            if self.airtag_only_mode and not device.is_airtag:
                continue

            device_type = "AirTag/Find My" if device.is_airtag else "Standard BLE"
            distance = f"{device.distance:.2f}" if device.distance < 100 else "Unknown"
            duration = f"{device.seen_duration:.1f}"
            stability = f"{device.signal_stability:.1f}"

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

            table.add_row(
                Text(device.name, style=f"{name_color} {style}"),
                device.address,
                Text(rssi_str, style=f"{rssi_color} {style}"),
                distance,
                stability,
                device_type,
                duration,
                style=style,
            )

        if not sorted_devices:
            table.add_row("No devices found", "", "", "", "", "", "")

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

        return Panel(
            "\n".join(
                [
                    "[bold cyan]Controls:[/]",
                    " [bold blue]s[/] - Start/Stop scanning",
                    " [bold blue]a[/] - Toggle AirTag only mode",
                    " [bold blue]d[/] - Toggle adaptive distance mode",
                    " [bold blue]c[/] - Calibrate selected device",
                    " [bold blue]l[/] - List Bluetooth adapters",
                    " [bold blue]z[/] - Summarize findings",
                    " [bold blue]q[/] - Quit",
                    "",
                    f"[bold]Status:[/] {'[green]Scanning[/]' if self.scanning else '[yellow]Idle[/]'}",
                    f"[bold]AirTag only mode:[/] {airtag_mode}",
                    f"[bold]Adaptive distance:[/] {adaptive_mode}",
                    f"[bold]Calibration mode:[/] {calibration_mode}",
                    f"[bold]Adapter:[/] {self.current_adapter or 'Default'}",
                ]
            ),
            title="[bold blue]TagFinder Controls[/]",
            border_style="blue",
            box=ROUNDED,
        )

    def generate_device_details(self, device: Device) -> Panel:
        """Generate detailed panel for selected device"""
        if not device:
            return Panel("No device selected", title="Device Details")

        mfg_data = ""
        for key, value in device.manufacturer_data.items():
            mfg_data += f"\n  {key}: {value.hex()}"

        return Panel(
            "\n".join(
                [
                    f"[bold]Name:[/] {device.name}",
                    f"[bold]Address:[/] {device.address}",
                    f"[bold]RSSI:[/] {device.smooth_rssi:.1f} dBm",
                    f"[bold]Raw RSSI:[/] {device.rssi} dBm",
                    f"[bold]Distance:[/] {device.distance:.2f} meters",
                    f"[bold]Signal Stability:[/] {device.signal_stability:.2f}",
                    f"[bold]First seen:[/] {time.strftime('%H:%M:%S', time.localtime(device.first_seen))}",
                    f"[bold]Last seen:[/] {time.strftime('%H:%M:%S', time.localtime(device.last_seen))}",
                    f"[bold]Duration:[/] {device.seen_duration:.1f} seconds",
                    f"[bold]AirTag/Find My:[/] {'Yes' if device.is_airtag else 'No'}",
                    f"[bold]N-Value:[/] {device.calibrated_n_value:.2f}",
                    f"[bold]RSSI@1m:[/] {device.calibrated_rssi_at_one_meter} dBm",
                    f"[bold]Manufacturer Data:[/] {mfg_data if mfg_data else 'None'}",
                ]
            ),
            title=f"[bold cyan]Device Details: {device.name}[/]",
            border_style="cyan",
            box=ROUNDED,
        )

    def summarize_findings(self):
        """Summarize findings from history or current scan"""
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

        # Display summary
        summary = Panel(
            "\n".join(
                [
                    f"[bold]Total unique devices:[/] {total_devices}",
                    f"[bold]AirTags/Find My devices:[/] {len(airtags)}",
                    f"[bold]Closest device:[/] {closest_device.get('name', 'Unknown')} ({closest_device['address']})",
                    f"[bold]Closest signal strength:[/] {strongest_signal} dBm",
                    f"[bold]Estimated distance:[/] {10 ** ((DEFAULT_RSSI_AT_ONE_METER - strongest_signal) / (10 * DEFAULT_DISTANCE_N_VALUE)):.2f} meters",
                    "",
                    f"[bold]Average distance:[/] {avg_distance:.2f} meters",
                    f"[bold]Min distance:[/] {min_distance:.2f} meters",
                    f"[bold]Max distance:[/] {max_distance:.2f} meters",
                    "",
                    f"[bold]Scan duration:[/] {time.time() - min(d.get('first_seen', time.time()) for d in unique_devices.values()):.1f} seconds",
                ]
            ),
            title="[bold green]Scan Summary[/]",
            border_style="green",
            box=ROUNDED,
        )

        self.console.print(summary)

    async def discovery_callback(self, device, advertisement_data):
        """Callback for BleakScanner when a device is discovered"""
        if device.address not in self.devices:
            self.devices[device.address] = Device(
                address=device.address,
                name=device.name,
                rssi=advertisement_data.rssi,
                manufacturer_data=advertisement_data.manufacturer_data,
            )
        else:
            self.devices[device.address].update(
                rssi=advertisement_data.rssi,
                manufacturer_data=advertisement_data.manufacturer_data,
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
        self.console.clear()
        self.console.print(f"[bold green]Calibrating device: {device.name}[/]")
        self.console.print(
            "\nPlace the device at a known distance and enter the distance in meters:"
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

            # Wait for scanner to collect some readings
            for _ in range(5):
                self.console.print(f"Current RSSI: {device.rssi} dBm")
                await asyncio.sleep(1)

            if device.calibrate_distance(distance):
                self.console.print(f"[bold green]Calibration successful:[/]")
                self.console.print(f"  N-Value: {device.calibrated_n_value:.2f}")
                self.console.print(f"  RSSI@1m: {device.calibrated_rssi_at_one_meter}")
                self.settings["distance_n_value"] = device.calibrated_n_value
                self.settings["rssi_at_one_meter"] = device.calibrated_rssi_at_one_meter
                self._save_settings()
            else:
                self.console.print("[bold red]Calibration failed[/]")
        except ValueError:
            self.console.print("[bold red]Invalid distance value[/]")

    async def start_scan(self):
        """Start BLE scanning"""
        self.devices = {}
        self.scanning = True
        self.selected_device = None

        # Set up scanner with selected adapter if specified
        scanner_kwargs = {}
        if self.current_adapter:
            scanner_kwargs["adapter"] = self.current_adapter

        async with BleakScanner(
            detection_callback=self.discovery_callback, **scanner_kwargs
        ) as scanner:
            with Live(self._update_ui(), refresh_per_second=4) as live:
                while self.scanning:
                    live.update(self._update_ui())
                    await asyncio.sleep(SCAN_INTERVAL)

                    # Process any pending keyboard input
                    await self._process_keyboard_input()

        # Save scan results to history
        self._save_history()

    def _update_ui(self) -> Layout:
        """Update the UI layout"""
        self.layout["header"].update(self.generate_header())
        self.layout["devices"].update(self.generate_device_table(self.devices))
        self.layout["footer"].update(self.generate_status_panel())

        # Update device details if a device is selected
        if self.selected_device and self.selected_device in self.devices:
            self.layout["details"].visible = True
            self.layout["details"].update(
                self.generate_device_details(self.devices[self.selected_device])
            )
        else:
            self.layout["details"].visible = False

        return self.layout

    async def _process_keyboard_input(self):
        """Process keyboard input during scanning"""
        # Check for keyboard input
        if sys.stdin in asyncio.get_event_loop()._ready:
            cmd = sys.stdin.readline().strip().lower()
            if cmd == "q":
                self.scanning = False
            elif cmd == "a":
                self.airtag_only_mode = not self.airtag_only_mode
                self.settings["airtag_only_mode"] = self.airtag_only_mode
                self._save_settings()
            elif cmd == "d":
                self.adaptive_mode = not self.adaptive_mode
                self.settings["adaptive_mode"] = self.adaptive_mode
                self._save_settings()
            elif cmd == "c" and self.selected_device:
                # Enter calibration mode
                self.calibration_mode = True
                await self.calibrate_device(self.devices[self.selected_device])
                self.calibration_mode = False
            elif cmd.isdigit() and 0 <= int(cmd) < len(self.devices):
                # Select device by index
                device_addresses = list(self.devices.keys())
                if int(cmd) < len(device_addresses):
                    self.selected_device = device_addresses[int(cmd)]

    async def main(self):
        """Main application entry point"""
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
                break
            elif cmd == "s":
                self.console.print("[green]Starting scan... Press 'q' to stop.[/]")
                await self.start_scan()
            elif cmd == "a":
                self.airtag_only_mode = not self.airtag_only_mode
                self.settings["airtag_only_mode"] = self.airtag_only_mode
                self._save_settings()
                self.console.print(
                    f"[bold]AirTag only mode: {'[green]ON[/]' if self.airtag_only_mode else '[red]OFF[/]'}"
                )
            elif cmd == "d":
                self.adaptive_mode = not self.adaptive_mode
                self.settings["adaptive_mode"] = self.adaptive_mode
                self._save_settings()
                self.console.print(
                    f"[bold]Adaptive distance: {'[green]ON[/]' if self.adaptive_mode else '[red]OFF[/]'}"
                )
            elif cmd == "l":
                await self.list_adapters()
            elif cmd == "z":
                self.summarize_findings()
            else:
                self.console.print(
                    "[yellow]Unknown command. Use 's', 'a', 'd', 'l', 'z', or 'q'.[/]"
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
