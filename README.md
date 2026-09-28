# TagFinder

A terminal Bluetooth LE scanner for spotting unwanted trackers: it identifies Apple AirTags and other Find My accessories from their advertisements, decodes their status and battery bits, and estimates distance and movement.

Built on published reverse-engineering of the Find My protocol ([Adam Catley's AirTag research](https://adamcatley.com/AirTag.html)).

> Shared as a reference. Not actively maintained for external contributions.

## What it does

| Area | Details |
|---|---|
| Tracker identification | Find My advertisement patterns, a tracker-probability score per device, unregistered AirTags (advertisement type `0x07`) |
| AirTag state | status bits for Separated, Play Sound and Lost Mode; battery level (Full, Medium, Low, Very Low) |
| Behaviour over time | the roughly 2 s advertising interval, the 15-minute key rotation, proximity trend and movement history |
| Distance | log-distance path-loss estimate from RSSI (defaults: −59 dBm at 1 m, n = 2.0), with a calibration mode |
| Device details | manufacturer (company ID), advertisement data, services, first and last seen |
| Adapters | list and switch Bluetooth adapters, adaptive scanning, a maximum-range test |

Everything runs locally. Nothing is sent over the network, and the tool never connects to or modifies the devices it sees.

## Quickstart

Requires Python 3.8+ and a Bluetooth adapter with BLE.

```bash
git clone https://github.com/nixxxo/tagfinder.git
cd tagfinder
python3 -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tagfinder.py
```

Platform notes:

- **macOS**: allow your terminal under System Settings → Privacy & Security → Bluetooth.
- **Linux**: `sudo apt install bluetooth bluez`, then either add your user to the `bluetooth` group or grant the interpreter raw-socket access: `sudo setcap 'cap_net_raw,cap_net_admin+eip' "$(readlink -f "$(which python3)")"`.
- **Windows**: Bluetooth on, current drivers; run as administrator if scanning is denied.

### Controls

| Key | Action |
|---|---|
| `s` | start or stop scanning |
| `a` | Find My mode (AirTags and Find My devices only) |
| `d` | adaptive mode |
| `c` | calibration mode (place a device at exactly 1 m) |
| `r` | scan range |
| `m` | maximum adapter range test |
| `l` | list and select adapters |
| `z` | analyse and summarise findings |
| `t` | select a device (freezes the list while selecting) |
| `b` | back: clear the selection |
| `p` / `f` / `i` | toggle the tracker-probability / manufacturer / details column |
| `q` | quit |

## Architecture

A single script, `tagfinder.py`, on top of [bleak](https://github.com/hbldh/bleak) (cross-platform BLE) and [rich](https://github.com/Textualize/rich) (terminal UI).

| Component | Responsibility |
|---|---|
| `Device` | per-device state: RSSI history, advertisement parsing, Find My and AirTag decoding, distance and movement |
| `TagFinder` | scanner lifecycle, adapter handling, settings, keyboard input and the live multi-pane display |

On Linux, passive scanning uses BlueZ advertisement monitors; macOS and Windows use their native backends through bleak.

## Configuration

Settings are saved to `settings.json` in the working directory: AirTag-only filter, sort priority, visible columns, scan range and parameters, and the selected adapter. Device history goes to `devices_history.json`. Both are gitignored.

## License

MIT: see [LICENSE](LICENSE).
