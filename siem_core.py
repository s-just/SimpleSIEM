import json
import os
import socket
import re
import time
from PyQt5.QtCore import QObject, pyqtSignal
from priority_helper import convert_facility, convert_severity, categorize_priority_value

# CONSTANTS
HOST = '0.0.0.0'
PORT = 5140
SYSLOG_PATTERN = re.compile(
    r"<(\d+)>"                                  # 1: Priority
    r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})" # 2: Timestamp (RFC 3164)
    r"\s+"
    r"(\S+)"                                    # 3: Hostname
    r"\s+"
    r"([^\[\s:]+)"                              # 4: Process Name
    r"(?:\[(\d+)\])?"                           # 5: Optional PID
    r":?\s+"
    r"(.*)"                                     # 6: Message
)
DEFAULT_LOGS_DIRECTORY = "syslog_data"

class Syslog:
    def __init__(self, data, addr):
        self.data_raw = data # Keep raw bytes if needed
        self.addr = addr
        self.priority = None
        self.timestamp = None
        self.hostname = None
        self.process_name = None
        self.pid = None
        self.message = None
        self.facility = None
        self.severity = None
        self.facility_info = ("unknown", "parsing pending")
        self.severity_info = ("unknown", "parsing pending")
        self.log_monitor_level = 3
        self.parsed = self.parse_data()
        self.receive_time = time.strftime('%Y-%m-%d %H:%M:%S')


    def parse_data(self):
        try:
            # Decode with error handling
            log_message = self.data_raw.decode('utf-8', errors='replace')
            match = SYSLOG_PATTERN.match(log_message)
            if match:
                self.priority = int(match.group(1))
                self.timestamp = match.group(2)
                self.hostname = match.group(3)
                self.process_name = match.group(4)
                self.pid = match.group(5)
                self.message = match.group(6)
                self.facility = int(self.priority // 8)
                self.severity = int(self.priority % 8)
                self.facility_info = convert_facility(self.facility)
                self.severity_info = convert_severity(self.severity)
                self.log_monitor_level = categorize_priority_value(self.priority)
                return True
            else:
                # Store the unparseable message for logging
                self.message = f"UNPARSEABLE: {log_message[:200]}..."
                self.hostname = self.addr[0] # Use source IP as hostname
                print(f"!!!Failed to parse message from {self.addr}: {log_message[:100]}...")
                return False
        except Exception as e:
            print(f"Failed to parse message from {self.addr}: {e}")
            self.message = f"PARSING_ERROR: {e} | Data: {self.data_raw[:100]}..."
            self.hostname = self.addr[0]
            return False

    def to_dict(self):
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

            # Makes logs larger but easier to debug, feel free to comment out
            "raw_data": self.data_raw.decode('utf-8', errors='replace') if self.data_raw else None
        }

    def to_string(self):
        if not self.parsed and not self.message:
            return f"Unparsable data/msg from [{self.addr[0]}]"
        elif not self.parsed and self.message:
            return f"Unparsable data from [{self.addr[0]}] : {self.message}"
        else:
            sev_name = self.severity_info[0] if self.severity_info else "N/A"
            return (f"[{self.timestamp or self.receive_time} | {self.hostname or self.addr[0]} | {sev_name}] "
                    f"{self.process_name or ''}{f'[{self.pid}]' if self.pid else ''}: "
                    f"{self.message or ''}")

class SysLogListener(QObject):
    log_received = pyqtSignal(object)
    status_update = pyqtSignal(str)

    def __init__(self, host=HOST, port=PORT, parent=None):
        super().__init__(parent)
        self._host = host
        self._port = port
        self._running = False
        self._sock = None

    def run(self):
        self._running = True
        socket_bound = False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self._host, self._port))
            socket_bound = True
            self.status_update.emit(f"Listening on UDP | {self._host}:{self._port}")
            print(f"Listening on UDP | {self._host}:{self._port}")
        except Exception as e:
            error_msg = f"Failed to bind socket {self._host}:{self._port} : {e}"
            self.status_update.emit(error_msg)
            print(error_msg)
            self._running = False

        if socket_bound:
            while self._running:
                if not self._sock:
                    print("Listener Error: Socket missing.")
                    self._running = False
                    break
                try:
                    self._sock.settimeout(1.0)
                    try:
                        data, addr = self._sock.recvfrom(2048*2)
                    except socket.timeout:
                        continue
                    except socket.error as recv_err:
                        print(f"Listener socket error: {recv_err}")
                        self.status_update.emit(f"Listener socket error: {recv_err}")
                        time.sleep(1) # Avoid looping
                        continue

                    if data:
                        print(f"Raw data received from {addr}: {data!r}")
                        new_syslog = Syslog(data, addr)
                        self.log_received.emit(new_syslog)

                except Exception as e:
                    print(f"Listener loop error: {e}")
                    self.status_update.emit(f"Listener loop error: {e}")
                    time.sleep(1) # Prevent looping on error

        print("Listener: Cleaning up...")
        if self._sock:
            try:
                self._sock.close()
                print("Listener socket closed.")
                self.status_update.emit("Listener Stopped")
            except Exception as close_e:
                print(f"Listener: Error closing socket: {close_e}")
            finally:
                self._sock = None
        print("Listener: Run method finished.")

    def stop(self):
        print("Listener stop requested.")
        self._running = False