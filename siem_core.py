import json
import os
import socket
import re
import time
from PyQt5.QtCore import QObject, pyqtSignal
from priority_helper import convert_facility, convert_severity, categorize_priority_value

# CONSTANTS
HOST = '0.0.0.0'  # listen on all available network interfaces
PORT = 514  # syslog port
# syslog structure: <PRIORITY>TIMESTAMP HOSTNAME PROCESS: MESSAGE
# regex pattern needed to match log data
SYSLOG_PATTERN = re.compile(r"<(\d+)>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:?\s+(.*)")
LOG_FILE_NAME_BASE = "syslog.log"
LOGS_DIRECTORY = "logs"


session_logs = []
monitoring_level = 3

class Syslog:
    """
    Class to instantiate, parse, and hold data for syslogs
    """
    def __init__(self, data, addr):
        self.data_raw = data
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

    def parse_data(self):
        try:
            log_message = self.data_raw.decode('utf-8')
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
                #print("Log parsed successfully")
                #print("-" * 5)
                return True
            else:
                print(f"!!!Failed to parse message from {self.addr}: {log_message[:100]}...")
                return False
        except Exception as e:
            print(f"Failed to parse message from {self.addr}: {e}")
            self.message = f"Failed to parse message from {self.addr}: {e}"
            return False

    def to_string(self):
        if not self.parsed and not self.message:
            return f"Unparsable data/msg from [{self.addr[0]}]"
        elif not self.parsed and self.message:
            return f"Unparsable data from [{self.addr[0]}] : {self.message}"
        else:
            return (f"[{self.timestamp} | {self.hostname} | {self.severity_info[0]}] "
                    f"{self.process_name or ''}{f'[{self.pid}]' if self.pid else ''}: "
                    f"{self.message}")

class SysLogListener(QObject):
    """
    Listens on given host/port for syslog data and creates object data for the incoming logs.
    Designed to be run on a separate QThread, and inherits from QObject for signals and slots.
    """

    # Log received Signal (takes in an object, which we can pass our previously defined syslog obj)
    log_received = pyqtSignal(object)
    # Status/Error Signal
    status_update = pyqtSignal(str)

    def __init__(self, host=HOST, port=PORT, parent=None):
        super().__init__(parent)
        self._host = host
        self._port = port
        self._running = False
        self._sock = None
        # Skip for now, implement later...
        # self._monitoring_level = 3

    # Method called by QThread for starting work, continues to loop while the listener is running.
    def run(self):
        self._running = True
        socket_bound = False  # Flag for debugging and tracking success
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self._host, self._port))
            socket_bound = True

            # Output to status update and console
            self.status_update.emit(f"Listening on UDP|{self._host}:{self._port}")
            print(f"Listening on UDP|{self._host}:{self._port}")

        except Exception as e:
            self.status_update.emit(f"Failed to listen on UDP|{self._host}:{self._port}: {e} | Cannot bind socket")
            print(f"Failed to listen on UDP|{self._host}:{self._port} | Cannot bind socket - {e}")
            self._running = False  # Critical error, cannot run

        # Main logic loop
        if socket_bound:  # Ensure we didn't have a socket issue...
            while self._running:
                if not self._sock: # Check socket validity at the start of each loop
                    print("Listener Error: Socket object missing? Exiting main loop instead...")
                    self._running = False  # Ensure loop stops
                    break

                try:
                    self._sock.settimeout(1.0)  # Set timeout for recvfrom
                    try:
                        data, addr = self._sock.recvfrom(1024)  # 1024 bytes
                    except socket.timeout:
                        continue  # Normal timeout, just loop and check _running again
                    except socket.error as recv_err:
                        print(f"Listener socket.error: {recv_err}")
                        self.status_update.emit(f"Listener socket.error: {recv_err}")
                        time.sleep(1)
                        continue  # Go to next loop iteration check

                    # If everything was successful
                    new_syslog = Syslog(data, addr)
                    self.log_received.emit(new_syslog)

                except Exception as e:
                    print(f"Error listening on UDP|{self._host}:{self._port}: Failed to set socket timeout: {repr(e)}")

        print("Listener: Cleaning up...")
        if self._sock:
            try:
                self._sock.close()
                print("Listener Closed")
                self.status_update.emit(f"Listener Closed")
            except Exception as close_e:
                print(f"Listener: Error closing socket: {close_e}")
            finally:
                self._sock = None
        else:
            # if bind failed or socket was already None
            print("Listener: No socket to close (was None or bind failed).")

        print("Listener: Run method finished.")

    def stop(self):
        print("Listener stop requested.")
        self._running = False

