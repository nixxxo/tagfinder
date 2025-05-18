# TagFinder

A Bluetooth device scanner with enhanced detection for Apple AirTags and other tracking devices.

## Features

-   Scan for Bluetooth LE devices in your vicinity
-   Identify Apple AirTags and other tracking devices
-   Estimate distance to detected devices
-   Track device movements with proximity trend analysis
-   Analyze and summarize findings
-   Monitor for unwanted tracking devices

## Enhanced AirTag Detection

TagFinder now includes advanced detection techniques for AirTags based on Adam Catley's reverse engineering research:

-   Detection of Apple's Find My protocol patterns
-   Identification of AirTag status bits (Separated, Play Sound, Lost Mode)
-   Monitoring of 2-second advertisement intervals for AirTags
-   Detection of 15-minute advertisement data update cycles
-   Enhanced confidence scoring for more accurate detection
-   Detailed status information from AirTag advertisement data

### Latest Improvements

The latest version includes these additional detection capabilities:

-   **Unregistered AirTag detection** - Identify AirTags that are not paired (advertising with 0x07 type)
-   **Battery level detection** - Determine AirTag battery level (Full, Medium, Low, Very Low)
-   **Crypto counter tracking** - Monitor the 15-minute advertisement data changes in real-time
-   **Advanced classification** - Improved identification of both registered and unregistered AirTags
-   **Full advertisement format analysis** - Complete decoding of AirTag advertisement data format

## Setup

### 1. Clone the repository

```bash
git clone <repository-url>
cd tagfinder
```

### 2. Create a virtual environment

#### Windows

```bash
python -m venv venv
```

#### macOS/Linux

```bash
python3 -m venv venv
```

### 3. Activate the virtual environment

#### Windows

Command Prompt:

```cmd
venv\Scripts\activate.bat
```

PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

If you get a PowerShell execution policy error, you may need to run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### macOS/Linux

```bash
source venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

Run the scanner:

```
python tagfinder.py
```

### Controls

-   `s` - Start/Stop scanning
-   `a` - Toggle Find My mode (focus on AirTags and Find My devices)
-   `d` - Toggle adaptive mode
-   `c` - Toggle calibration mode
-   `r` - Configure scan range
-   `m` - Test maximum adapter range
-   `l` - List Bluetooth adapters
-   `z` - Analyze & Summarize findings
-   `q` - Quit

## Platform-Specific Notes

### Linux

On Linux, you may need to run with sudo or add your user to the bluetooth group:

```bash
sudo apt-get install bluetooth bluez libbluetooth-dev
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(which python3)
```

### Windows

Ensure Bluetooth is enabled in Windows Settings and Device Manager.

### macOS

Ensure Bluetooth is enabled in System Preferences.

## References

1. [Adam Catley's AirTag Reverse Engineering](https://adamcatley.com/AirTag.html)
