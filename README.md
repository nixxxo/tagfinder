# TagFinder

A cross-platform Bluetooth scanner for detecting and tracking BLE devices, with special support for AirTags and other Apple Find My devices.

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

Run the application in interactive mode:

```bash
python tagfinder.py
```

Or use command-line arguments:

```bash
# List all adapters
python tagfinder.py --list-adapters

# Scan for devices
python tagfinder.py --scan

# Scan for AirTags only
python tagfinder.py --scan --airtags-only
```

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