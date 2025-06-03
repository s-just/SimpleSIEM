# SimpleSIEM

A basic/ongoing homelab Security Information and Event Management (SIEM) tool built with Python and PyQt5 for educational pruposes. Currently listens for syslog messages, parses them, has real-time filtering and display, and saves logs to daily files. This is

**⚠️ Disclaimer: Not for Professional Use ⚠️**

This project is a personal learning exercise and is **not in anyway a professional-grade SIEM solution**. It is intended for peronal-use: educational and experimental purposes only.

## Current Features

* Receives syslog messages over UDP (default port 5140, feel free to change, but stay above values 1024 if logging from windows. Port values below 1024 are considered privileged ports when logging from Windows).
* Parses standard RFC 3164 style syslog messages.
* Realtime updating log display in a filterable table format.
* GUI with PyQt5, dark theme included.
* Filtering based on log severity level (Critical, Error, Warning, Info, etc.) but is WIP.
* Text-based filtering of realtime display using a simple custom query language (`process=sshd && message("failed login")`).
* Settings for log directory, logging status, and monitoring level.
* Option to save received logs to daily JSON files in a specified directory.

## Current Status

The project is a **Work In Progress**. Core functionalities are in place, but I'm still working on further improvements to learn more and handle different log sources.

## Log Sources

This SIEM is currently designed to primarily capture and read syslog messages.

* **Linux/Unix (via rsyslog, syslog-ng, etc.):**
    * Works well for standard RFC 3164 syslog messages. The SIEM can parse common fields like timestamp, hostname, process, PID, and message using regex.

* **Windows (via NXLog or similar agents):**
    * You can forward Windows Event Logs to this SIEM using an agent like NXLog, configured to output in a syslog-compatible format.
    * The SIEM can typically parse the standard syslog header information (timestamp, hostname, severity, facility) from these messages.
    * **Important:** Full parsing of the *Windows-specific message content* (which often contains detailed event data, sometimes tab-separated or in another structured format within the main syslog message) is **currently limited and is a Work In Progress**.
    * This means that while Windows logs can be received and displayed currently, in testing, the information extracted is not fully formatted in terms of the message content.

## Requirements

* Python 3.x
* PyQt5

## Getting Started

1.  **Prerequisites:**
    * Ensure Python 3 is installed on your system.
    * Install PyQt5: `pip install PyQt5`

2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/s-just/SimpleSIEM.git](https://github.com/s-just/SimpleSIEM.git)
    cd SimpleSIEM
    ```

3.  **Run the GUI:**
    Execute the main GUI application file. (You might need to update the filename here if it's different).
    ```bash
    python main_gui.py
    ```

4.  **Configure Log Forwarding:**
    * Configure your devices (Linux servers, Windows machines with NXLog, etc.) to send syslog messages via **UDP** to the IP address of the machine running SimpleSIEM, on port `5140`, or whatever port you prefer.
## Key Files

* `main_gui.py` (or your main application file): The main entry point and GUI for the application.
* `siem_core.py`: Core logic for listening to and parsing syslog messages.
* `filter_logic.py`: Handles the custom text-based filtering.
* `priority_helper.py`: Contains utility functions for syslog facility and severity codes.
* `theme.py`: Defines the dark theme stylesheet for the GUI.

## Future Work (To-Do)

* Improved parsing for Windows Event Logs forwarded through applications/services such as NXLog.
* More varied interface filters and controls.
* Support for more log formats or input methods.
* Basic alerting
* Improve thread handling
