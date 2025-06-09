"""
SIEM Core - UDP Syslog Listener and Parser (Backend Logic)

Handles:
1. Listening for syslog messages on UDP port 5140
2. Parsing syslog messages according to RFC 3164 format
3. Converting raw syslog data into Syslog objects
4. Running in a separate thread to avoid blocking the GUI thread

Major Classes:
- Syslog: Represents and parses a single syslog message
- SysLogListener: UDP socket listener that runs in background thread
"""

import json
import os
import socket
import re
import time
from PyQt5.QtCore import QObject, pyqtSignal
from priority_helper import convert_facility, convert_severity, categorize_priority_value

# CONSTANTS
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 5140  # UDP port to listen for syslog data packets
DEFAULT_LOGS_DIRECTORY = "syslog_data"  # Dir to save log files

# RFC 3164 Syslog Format: <priority>timestamp hostname process[pid]: message
# Example: "<34>Oct 31 22:14:15 machine-name su: 'su root' failed for lonvick on /dev/pts/8"
SYSLOG_PATTERN = re.compile(
    r"<(\d+)>"  # Group 1: Priority (facility*8 + severity)
    r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # Group 2: Timestamp (Oct 31 22:14:15)
    r"\s+"  # Whitespace separator
    r"(\S+)"  # Group 3: Hostname (no spaces)
    r"\s+"  # Whitespace
    r"([^\[\s:]+)"  # Group 4: Process name (no brackets/spaces/colons)
    r"(?:\[(\d+)\])?"  # Group 5: PID in brackets [1234]
    r":?\s+"  # colon and whitespace
    r"(.*)"  # Group 6: Message (everything else)
)

class Syslog:
    """
    Represents a single syslog message through basic parsing.

    - Handles both successful parsing and errors
    - Extracts facility and severity from priority
    - Stores both parsed data and original raw data
    """

    def __init__(self, data, addr):
        """
        Initialize a new Syslog object from raw UDP data.

        Args:
            data (bytes): Raw bytes received from the UDP socket
            addr (tuple): (IP address, port) of sender
        """
        # === Raw Data Storage ===
        self.data_raw = data  # Keep original bytes for debugging
        self.addr = addr  # Source IP and port tuple

        # === Parsed Syslog Fields ===
        self.priority = None  # Combined facility/severity number
        self.timestamp = None  # Original timestamp from message
        self.hostname = None  # Source hostname
        self.process_name = None  # Name of process that generated log
        self.pid = None  # Process ID
        self.message = None  # Actual log message

        # === Extracted Priority Components ===
        self.facility = None  # Facility code (0-23, what type of program)
        self.severity = None  # Severity level (0-7, how important, lower values being more important)

        # === Human-Readable Info (tuples of name + description) ===
        self.facility_info = ("unknown", "not yet parsed")
        self.severity_info = ("unknown", "not yet parsed")

        # === Monitoring Level (used fto filter) ===
        self.log_monitor_level = 3  # Default to lowest

        # === System Time Recvd ===
        self.receive_time = time.strftime('%Y-%m-%d %H:%M:%S')  # Store when we received it

        # === Parse the raw data ===
        self.parsed = self.parse_data()  # True if parsing succeeded

    def parse_data(self):
        """
        Parse raw syslog data using regex pattern.

        - Uses regex to extract structured data from syslog string
        - Stores any error info

        Returns:
            bool: True if parsing succeeded, False otherwise
        """
        try:
            # === Convert bytes to string ===
            log_message = self.data_raw.decode('utf-8', errors='replace')

            # === Apply regex pattern ===
            match = SYSLOG_PATTERN.match(log_message)

            if match:
                # === Extract matched groups ===
                self.priority = int(match.group(1))  # <34> becomes 34
                self.timestamp = match.group(2)  # "Oct 11 22:14:15"
                self.hostname = match.group(3)  # "mymachine"
                self.process_name = match.group(4)  # "su"
                self.pid = match.group(5)  # "1234" or None
                self.message = match.group(6)  # "'su root' failed..."

                # === Calculate facility and severity from priority ===
                # RFC 3164: priority = facility * 8 + severity
                self.facility = int(self.priority // 8)  # Integer division
                self.severity = int(self.priority % 8)  # Modulo operation

                # === Get human-readable information ===
                self.facility_info = convert_facility(self.facility)
                self.severity_info = convert_severity(self.severity)

                # === Determine the monitoring level for GUI filtering ===
                self.log_monitor_level = categorize_priority_value(self.priority)

                return True

            else:
                # === PARSING FAILED: Store message and source IP anyway ===
                self.message = f"UNPARSEABLE: {log_message[:200]}..."
                self.hostname = self.addr[0]  # Use source IP as fallback hostname
                print(f"!!!Failed to parse message from {self.addr}: {log_message[:100]}...")
                return False

        except Exception as e:
            # === EXCEPTION DURING PARSING: Store error info through raw data then ===
            print(f"Failed to parse message from {self.addr}: {e}")
            self.message = f"PARSING_ERROR: {e} | Data: {self.data_raw[:100]}..."
            self.hostname = self.addr[0]  # Source IP as fallback
            return False

    def to_dict(self):
        """
        Convert Syslog object to dictionary for JSON serialization.

        This is used when saving logs to files.
        Includes both parsed fields and raw data for debugging.
        """
        return {
            "received_at": self.receive_time,
            "source_ip": self.addr[0] if self.addr else "N/A",
            "parsed": self.parsed,
            "priority": self.priority,
            "monitor_level": self.log_monitor_level,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "severity": self.severity_info[0] if self.severity_info else "unknown",
            "facility": self.facility_info[0] if self.facility_info else "unknown",
            "process": self.process_name,
            "pid": self.pid,
            "message": self.message,

            # Raw data for debugging (makes files larger, comment out if needed)
            "raw_data": self.data_raw.decode('utf-8', errors='replace') if self.data_raw else None
        }

    def to_string(self):
        """
        Create human-readable strings of the log entry.

        This formats the log for display in the GUI table.
        Handles both parsed and unparsed messages.
        """
        if not self.parsed and not self.message:
            # Complete parsing failure
            return f"Unparsable data/msg from [{self.addr[0]}]"
        elif not self.parsed and self.message:
            # Partial parsing - we have error message
            return f"Unparsable data from [{self.addr[0]}] : {self.message}"
        else:
            # Successful parsing - format nicely
            sev_name = self.severity_info[0] if self.severity_info else "N/A"
            return (f"[{self.timestamp or self.receive_time} | {self.hostname or self.addr[0]} | {sev_name}] "
                    f"{self.process_name or ''}{f'[{self.pid}]' if self.pid else ''}: "
                    f"{self.message or ''}")

class SysLogListener(QObject):
    """
    UDP socket listener that runs in a separate thread to avoid locking up the GUI.

    - Inherits from QObject to use PyQt signals
    - Uses UDP socket
    - Emits signals for sending data back to GUI thread
    """

    # === PyQt Signals ===
    log_received = pyqtSignal(object)  # Emits Syslog objects to main thread
    status_update = pyqtSignal(str)  # Emits status messages for GUI status bar

    def __init__(self, host=HOST, port=PORT, parent=None):
        """
        Initialize the listener with network configuration.

        Args:
            host (str): IP address to bind to ('0.0.0.0' = all interfaces)
            port (int): UDP port to listen on (5140 = standard/default)
            parent: PyQt parent object (inherits for signals...)
        """
        super().__init__(parent)
        self._host = host
        self._port = port
        self._running = False  # Control flag for the listener loop
        self._sock = None  # UDP socket object

    def run(self):
        """
        Main listener loop - runs in a separate thread.

        - Creates UDP socket and binds to specified port
        - Continuous loop receiving data with timeout
        - Creates Syslog objects from received data
        - Uses signals to communicate back to main thread
        """
        self._running = True
        socket_bound = False

        # === Create and bind UDP socket ===
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # SO_REUSEADDR allows restarting the app without "Address already in use" error
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self._host, self._port))
            socket_bound = True

            # Notify main thread
            self.status_update.emit(f"Listening on UDP | {self._host}:{self._port}")
            print(f"Listening on UDP | {self._host}:{self._port}")

        except Exception as e:
            # Socket binding failed -> notify main thread and exit
            error_msg = f"Failed to bind socket {self._host}:{self._port} : {e}"
            self.status_update.emit(error_msg)
            print(error_msg)
            self._running = False

        # === Main listening loop (only if socket bound successfully) ===
        if socket_bound:
            while self._running:
                # Safety check -> ensure socket still exists
                if not self._sock:
                    print("Listener Error: Socket missing.")
                    self._running = False
                    break

                try:
                    # === Set timeout to allow program termination ===
                    # 1 second timeout gives time to check running flag
                    self._sock.settimeout(1.0)

                    try:
                        # === Receive UDP data ===
                        # Buffer size: 4096 bytes (2048*2) handles most syslog messages
                        data, addr = self._sock.recvfrom(2048 * 2)

                    except socket.timeout:
                        # Normal timeout -> continue loop to check running flag
                        continue

                    except socket.error as recv_err:
                        # Socket error -> log but don't crash
                        print(f"Listener socket error: {recv_err}")
                        self.status_update.emit(f"Listener socket error: {recv_err}")
                        time.sleep(1)  # Prevent error loops
                        continue

                    # === Process received data ===
                    if data:
                        print(f"Raw data received from {addr}: {data!r}")
                        # Create Syslog object (parsing happens in constructor)
                        new_syslog = Syslog(data, addr)
                        # Send to main thread using signal
                        self.log_received.emit(new_syslog)

                except Exception as e:
                    # Unexpected error in listener loop
                    print(f"Listener loop error: {e}")
                    self.status_update.emit(f"Listener loop error: {e}")
                    time.sleep(1)  # Prevent inf looping

        # === Cleanup when loop exits ===
        print("Listener: Cleaning up...")
        if self._sock:
            try:
                self._sock.close()
                print("Listener socket closed.")
                self.status_update.emit("Listener Stopped")
            except Exception as close_e:
                print(f"Listener: Error closing socket: {close_e}")
            finally:
                self._sock = None  # Ensure socket reference is cleared
        print("Listener: Run method finished.")

    def stop(self):
        """
        Request listener to stop.

        Called from main thread when application closes.
        Sets the flag that causes the listener loop to exit properly.
        """
        print("Listener stop requested.")
        self._running = False