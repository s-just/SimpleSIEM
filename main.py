import json
import os
import socket
import re
import sys
from datetime import datetime

from priority_helper import convert_facility, convert_severity, categorize_priority_value

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
    data = None
    addr = None

    priority = None
    timestamp = None
    hostname = None
    process_name = None
    pid = None
    message = None

    parsed = False

    log_monitor_level = -1

    save_logs = True

    # Facility = priority % 8
    facility = -1
    facility_info = ()
    # Severity = priority // 8
    severity = -1
    severity_info = ()

    def __init__(self, data, addr):
        self.data = data
        self.addr = addr
        self.parsed = self.parse_data()

    def parse_data(self):
        log_message = data.decode('utf-8')
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
            print("Log parsed successfully")
            print("-" * 5)
            return True
        print(f"!!! Failed to parse message from {addr}: {log_message}")
        print("-" * 5)
        return False

    def print_info(self):
        if not self.parsed and self.log_monitor_level >= 0:
            print(f"! Failed to print syslog information, no data was parsed previously or the data of this log failed to parse")
            print("-" * 5)
            return
        if self.log_monitor_level <= monitoring_level:
            print(f"::syslog parsed from {addr}")
            if (self.priority != None):
                print(f"  PRIORITY: {self.priority} | facility: {self.facility_info[0]} - {self.facility_info[1]} | severity: {self.severity_info[0]} - {self.severity_info[1]} | log_monitor_level: {self.log_monitor_level}")
            print(f"  TIMESTAMP: {self.timestamp}")
            print(f"  HOSTNAME: {self.hostname}")
            print(f"  PROCESS_NAME: {self.process_name}")
            print(f"  PID: {self.pid if self.pid else 'N/A'}")
            print(f"  MESSAGE: {self.message}")
            print("-" * 5)

    def to_dict(self):
        return {
            "priority": self.priority,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "process_name": self.process_name,
            "pid": self.pid,
            "message": self.message,
            "facility": self.facility,
            "facility_name": self.facility_info[0],
            "facility_description": self.facility_info[1],
            "severity": self.severity,
            "severity_name": self.severity_info[0],
            "severity_description": self.severity_info[1]
        }

try:
    # create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # bind the socket to the host and port
    sock.bind((HOST, PORT))
    print(f"Listening for Syslog messages on {HOST}:{PORT}...")

    while True:
        data, addr = sock.recvfrom(1024)  # receive up to 1024 bytes of data
        new_syslog = Syslog(data, addr)
        if new_syslog.parsed:
            sanitized_timestamp = new_syslog.timestamp.replace(" ", "_").replace(":", "-")
            log_file_path = os.path.join(LOGS_DIRECTORY, LOG_FILE_NAME_BASE + sanitized_timestamp + ".log")
            try:
                with open(log_file_path, 'a') as log_file:
                    log_entry = new_syslog.to_dict()
                    log_entry['received_at'] = datetime.now().isoformat()
                    json.dump(log_entry, log_file)
                    log_file.write('\n')
            except Exception as e:
                print(f"Failed to write log to file: {e}")
        new_syslog.print_info()


except Exception as e:
    print(f"ERROR: {e}")
finally:
    if 'sock' in locals():
        sock.close()