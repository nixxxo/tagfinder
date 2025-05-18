# TagFinder

![License](https://img.shields.io/badge/license-MIT-blue.svg)

A powerful Bluetooth scanner with specialized capabilities for detecting and analyzing tracking devices, particularly Apple AirTags and other Find My network accessories.

## 📋 Overview

TagFinder is a terminal-based interactive application that provides enhanced detection and analysis of Bluetooth Low Energy (BLE) devices, with a particular focus on identifying potentially unwanted tracking devices. The application uses advanced techniques to detect, analyze, and monitor BLE devices in your vicinity, providing detailed information about each detected device.

## 🔍 Key Features

-   **Advanced Tracking Device Detection**: Specialized algorithms to identify Apple AirTags, Find My accessories, and other Bluetooth trackers
-   **Real-time Distance Estimation**: Calculate approximate distance to detected devices with calibration capabilities
-   **Movement Analysis**: Track device movements with proximity trend analysis and movement history
-   **Comprehensive Device Information**: Detailed breakdown of device attributes, advertisement data, and manufacturer information
-   **Multi-adapter Support**: Use and test multiple Bluetooth adapters for increased range and detection capabilities
-   **Interactive Interface**: Rich terminal UI with filtering, sorting, and device inspection capabilities
-   **Cross-platform Support**: Works on macOS, Linux, and Windows

## 🎯 Special AirTag Detection Capabilities

TagFinder implements detection techniques based on reverse engineering research of the Apple Find My protocol:

-   **Protocol Pattern Detection**: Identifies characteristic Find My advertisement patterns
-   **Status Bit Analysis**: Reads AirTag status bits to determine if devices are in Separated, Play Sound, or Lost Mode
-   **Interval Monitoring**: Tracks the characteristic 2-second advertisement intervals of AirTags
-   **Crypto Counter Tracking**: Monitors the 15-minute advertisement data update cycles
-   **Battery Level Detection**: Determines AirTag battery level (Full, Medium, Low, Very Low)
-   **Registration Status**: Identifies unregistered AirTags (advertising with 0x07 type)
-   **Confidence Scoring**: Calculates a probability score for tracker identification

## 🚀 Installation

### Prerequisites

-   Python 3.7 or higher
-   Bluetooth adapter with BLE support
-   Administrator/sudo privileges (for certain Bluetooth operations)

### Setup Steps

1. **Clone the repository**

```bash
git clone https://github.com/nixxxo/tagfinder.git
cd tagfinder
```

2. **Create a virtual environment**

```bash
# On Windows
python -m venv venv

# On macOS/Linux
python3 -m venv venv
```

3. **Activate the virtual environment**

```bash
# On Windows (Command Prompt)
venv\Scripts\activate.bat

# On Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# On macOS/Linux
source venv/bin/activate
```

4. **Install dependencies**

```bash
pip install -r requirements.txt
```

## 💻 Usage

### Starting the Application

```bash
# With virtual environment activated
python tagfinder.py
```

### Keyboard Controls

| Key | Function                                                   |
| --- | ---------------------------------------------------------- |
| `s` | Start/Stop scanning                                        |
| `a` | Toggle Find My mode (focus on AirTags and Find My devices) |
| `d` | Toggle adaptive mode                                       |
| `c` | Toggle calibration mode                                    |
| `r` | Configure scan range                                       |
| `m` | Test maximum adapter range                                 |
| `l` | List Bluetooth adapters                                    |
| `z` | Analyze & Summarize findings                               |
| `q` | Quit                                                       |

### Interface Sections

The application has a multi-pane interface with:

-   **Header**: Application title and status information
-   **Device List**: Table of detected Bluetooth devices with sortable columns
-   **Details Panel**: Comprehensive information about the selected device
-   **Status Bar**: Current scanning status and application mode indicators
-   **Control Panel**: Available keyboard commands

## ⚙️ Platform-Specific Setup

### Linux

Linux requires additional permissions to access Bluetooth hardware:

```bash
# Install required packages
sudo apt-get install bluetooth bluez libbluetooth-dev

# Grant Python permission to access raw Bluetooth sockets
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(which python3)

# Alternative: Add your user to the bluetooth group
sudo usermod -a -G bluetooth $USER
```

### Windows

-   Ensure Bluetooth is enabled in Windows Settings
-   Run the application with administrator privileges if having permission issues
-   Latest Bluetooth drivers should be installed for optimal performance

### macOS

-   Ensure Bluetooth is enabled in System Preferences
-   The application may require permission to access Bluetooth when first run
-   For full functionality, authorize the terminal application in System Preferences > Security & Privacy > Privacy > Bluetooth

## 🔧 Configuration

TagFinder stores its configuration in `settings.json`, which includes:

-   Filter preferences (AirTag-only mode)
-   Sort priority for device listing
-   Visible columns in the device table
-   Scanning parameters (range mode, duration, detection threshold)
-   Selected Bluetooth adapter

## 🔒 Privacy & Security

TagFinder is designed as a security tool to help users detect unwanted tracking devices. When using this tool:

-   All data is processed locally on your device
-   No device information is transmitted to remote servers
-   Device history is stored in a local file (`devices_history.json`)
-   The application does not modify any detected Bluetooth devices

## 🔄 Advanced Usage

### Calibration Mode

For more accurate distance estimation, you can calibrate the application:

1. Place a known Bluetooth device at exactly 1 meter from your device
2. Enter calibration mode with the `c` key
3. Select the device and follow the calibration prompts

### Range Testing

Test the maximum range of your Bluetooth adapter:

1. Press `m` to enter range testing mode
2. Position a Bluetooth device at increasing distances
3. The application will report signal strength at each distance

### Adapter Selection

If you have multiple Bluetooth adapters:

1. Press `l` to list available adapters
2. Select the adapter you wish to use
3. The application will restart using the selected adapter

## 📚 References

This project builds upon research in Bluetooth tracking device protocols:

1. [Adam Catley's AirTag Reverse Engineering](https://adamcatley.com/AirTag.html)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
