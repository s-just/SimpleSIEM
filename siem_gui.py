import sys
import socket
import time
import os
import json
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QStatusBar, QHeaderView,
    QLineEdit, QPushButton, QAction, QFileDialog, QLabel,
    QComboBox
)
from PyQt5.QtCore import pyqtSlot, QThread, Qt, QSettings

from siem_core import SysLogListener, Syslog, DEFAULT_LOGS_DIRECTORY
from filter_logic import LogFilter
import theme

SETTINGS_LOG_DIR = "logging/logDirectory"
SETTINGS_LOG_ENABLED = "logging/logEnabled"
SETTINGS_MONITOR_LEVEL = "filtering/monitorLevel"

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.settings = QSettings("SJust", "Simple SIEM")

        self.setWindowTitle("Simple SIEM")
        self.setGeometry(100, 100, 1100, 750)

        self.log_directory = self.settings.value(SETTINGS_LOG_DIR, DEFAULT_LOGS_DIRECTORY)
        log_enabled_setting = self.settings.value(SETTINGS_LOG_ENABLED, False)
        self.logging_enabled = log_enabled_setting == 'true' if isinstance(log_enabled_setting, str) else bool(log_enabled_setting)
        monitor_level_setting = self.settings.value(SETTINGS_MONITOR_LEVEL, -1)
        try:
            self.current_monitor_level = int(monitor_level_setting)
        except ValueError:
            self.current_monitor_level = -1

        self.current_filter = LogFilter()

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self._create_menu_bar()

        level_layout = QHBoxLayout()
        level_layout.addWidget(QLabel("Monitoring Level:"))

        self.level_combo = QComboBox()
        self.level_combo.addItem("All Levels", -1)
        self.level_combo.addItem("Critical / Alert / Emergency (0)", 0)
        self.level_combo.addItem("Error (1)", 1)
        self.level_combo.addItem("Warning / Notice (2)", 2)
        self.level_combo.addItem("Informational / Debug (3)", 3)

        level_index = self.level_combo.findData(self.current_monitor_level)
        if level_index != -1:
            self.level_combo.setCurrentIndex(level_index)

        self.level_combo.currentIndexChanged.connect(self._update_monitor_level)
        level_layout.addWidget(self.level_combo)
        level_layout.addStretch()

        main_layout.addLayout(level_layout)

        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter text filter (process=sshd && message(\"failed\"))")
        self.filter_input.returnPressed.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input)

        self.apply_button = QPushButton("Apply Filter")
        self.apply_button.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.apply_button)

        self.reset_button = QPushButton("Reset Filter")
        self.reset_button.clicked.connect(self.reset_filter)
        filter_layout.addWidget(self.reset_button)

        main_layout.addLayout(filter_layout)

        self.log_display = QTableWidget()
        self.log_display.setReadOnly = True
        self.log_display.setAlternatingRowColors(True)
        self.log_display.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_display.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_display.setSortingEnabled(False)

        self.column_headers = ["Timestamp", "Hostname", "Severity", "Facility", "Process", "PID", "Message"]
        self.log_display.setColumnCount(len(self.column_headers))
        self.log_display.setHorizontalHeaderLabels(self.column_headers)

        header = self.log_display.horizontalHeader()
        header.setSectionResizeMode(6, QHeaderView.Stretch) # Message column
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) # Timestamp
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents) # Hostname
        for i in range(2, 6):
             header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
             # header.setSectionResizeMode(i, QHeaderView.Interactive)

        main_layout.addWidget(self.log_display)

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready.", 3000)

        self.listener_thread = None
        self.listener = None
        self.setup_listener_thread()

        self.apply_filter(is_initial=True)

    def _create_menu_bar(self):
        """ Creates the main application menu bar and actions. """
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")

        # Enable/Disable Logging Action
        self.log_action = QAction("Enable Logging", self, checkable=True)
        self.log_action.setChecked(self.logging_enabled)
        self.log_action.toggled.connect(self._toggle_logging)
        file_menu.addAction(self.log_action)

        # Set Log Directory Action
        set_dir_action = QAction("Set Log Directory...", self)
        set_dir_action.triggered.connect(self._set_log_directory)
        file_menu.addAction(set_dir_action)

        file_menu.addSeparator()

        # Clear Display Action
        clear_action = QAction("Clear Display", self)
        clear_action.triggered.connect(self.clear_table)
        file_menu.addAction(clear_action)

        file_menu.addSeparator()

        # Exit Action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def setup_listener_thread(self):
        self.listener_thread = QThread(self)
        self.listener = SysLogListener()
        self.listener.moveToThread(self.listener_thread)
        self.listener_thread.started.connect(self.listener.run)
        self.listener.log_received.connect(self._handle_new_log)
        self.listener.status_update.connect(self.status_bar.showMessage)
        self.listener_thread.finished.connect(self.listener.deleteLater)
        self.listener_thread.finished.connect(self.listener_thread.deleteLater)
        self.listener_thread.finished.connect(lambda: self.status_bar.showMessage("Listener Thread Finished", 3000))
        self.listener_thread.start()
        self.status_bar.showMessage("Listener Thread Started", 3000)

    @pyqtSlot(object)
    def _handle_new_log(self, syslog_obj):
        """ Handles incoming logs, writes to file if enabled, checks filters, adds to table. """
        # 1. Log to file
        if self.logging_enabled:
            self._write_log_to_file(syslog_obj)

        # 2. Check filters
        if not isinstance(syslog_obj, Syslog):
             print(f"Received non-Syslog object: {type(syslog_obj)}")
             # Show errors regardless of filters? Maybe add an "error" row type
             # For now,no added non-syslog objects to the display
             return

        # Check Level Filter
        level_match = (self.current_monitor_level == -1 or
                       (syslog_obj.log_monitor_level is not None and
                        syslog_obj.log_monitor_level <= self.current_monitor_level))

        if not level_match:
            return

        # Check Text Filter (only if level matches)
        # Note: current_filter might not be updated instantly if user types fast
        # generally okay, relies on apply_filter being called
        if self.current_filter.matches(syslog_obj):
            if not syslog_obj.parsed:
                print(f"Adding unparsed Syslog object that matched filters: {syslog_obj.to_string()}")
                self._add_table_row(["", "", "", "", "", "", syslog_obj.to_string()], None)
            else:
                 self._add_syslog_to_table(syslog_obj)


    def _write_log_to_file(self, syslog_obj):
        """ Appends a Syslog object (as JSON) to the daily log file. """
        try:
            # Ensure log directory exists
            os.makedirs(self.log_directory, exist_ok=True)

            # Generate filename (syslog_2025-04-12.json.log)
            today_date = time.strftime('%Y-%m-%d')
            filename = f"syslog_{today_date}.json.log"
            filepath = os.path.join(self.log_directory, filename)

            # Convert Syslog object to dictionary
            log_dict = syslog_obj.to_dict()

            # Append JSON object as a new line
            with open(filepath, 'a', encoding='utf-8') as f:
                json.dump(log_dict, f)
                f.write('\n')

        except IOError as e:
            print(f"Error writing to log file {filepath}: {e}")
            self.status_bar.showMessage(f"Log Write Error: {e}", 5000)
            # Disable logging automatically on error?
            # self.logging_enabled = False
            # self.log_action.setChecked(False)
            # self.settings.setValue(SETTINGS_LOG_ENABLED, False)
        except Exception as e:
             print(f"Unexpected error during log writing: {e}")
             self.status_bar.showMessage(f"Log Write Error: {e}", 5000)


    def _add_syslog_to_table(self, syslog_obj: Syslog):
        row_data = [
            syslog_obj.timestamp or "N/A",
            syslog_obj.hostname or "N/A",
            syslog_obj.severity_info[0] if syslog_obj.severity_info else "N/A",
            syslog_obj.facility_info[0] if syslog_obj.facility_info else "N/A",
            syslog_obj.process_name or "",
            syslog_obj.pid or "",
            syslog_obj.message or "N/A"
        ]
        self._add_table_row(row_data, syslog_obj)

    def _add_table_row(self, row_data, syslog_obj=None):
        try:
            row_position = self.log_display.rowCount()
            self.log_display.insertRow(row_position)
            for col_index, data in enumerate(row_data):
                item = QTableWidgetItem(str(data))
                if col_index == 6 and syslog_obj and syslog_obj.message:
                     item.setToolTip(str(syslog_obj.message))
                self.log_display.setItem(row_position, col_index, item)
                if col_index == 0 and syslog_obj:
                    item.setData(Qt.UserRole, syslog_obj)
            # Only scroll if the vertical scrollbar is near the bottom
            scrollbar = self.log_display.verticalScrollBar()
            if scrollbar.value() >= scrollbar.maximum() - 15:
                 self.log_display.scrollToBottom()
        except Exception as e:
            print(f"Error adding row to table: {e}")
            self.status_bar.showMessage(f"Error displaying log: {e}", 5000)

    @pyqtSlot(int) # Slot receives the index from the combobox signal
    def _update_monitor_level(self, index):
        """ Updates the monitoring level based on combobox selection and reapplies filters. """
        new_level = self.level_combo.itemData(index) # Get stored level (-1, 0, 1, 2, 3)
        if new_level != self.current_monitor_level:
            self.current_monitor_level = new_level
            self.settings.setValue(SETTINGS_MONITOR_LEVEL, self.current_monitor_level)
            level_text = self.level_combo.itemText(index)
            self.status_bar.showMessage(f"Monitor level set to: {level_text}", 3000)
            print(f"Monitor level changed to: {self.current_monitor_level}")
            self.apply_filter() # Re-apply all filters

    @pyqtSlot()
    def apply_filter(self, is_initial=False): # flag for initial call
        """ Parses text filter, then applies BOTH level and text filters to table rows. """
        filter_text = self.filter_input.text()

        if not is_initial: # Avoid the status message spam on startup
            if filter_text:
                self.status_bar.showMessage(f"Applying filters...", 2000)
            else:
                self.status_bar.showMessage("Applying level filter...", 2000)

        # Parse the text filter first
        try:
            self.current_filter = LogFilter(filter_text)
            if self.current_filter.error:
                 self.status_bar.showMessage(f"Text Filter Error: {self.current_filter.error}", 5000)
                 # Let's stop.
                 return
        except Exception as e:
             self.status_bar.showMessage(f"Unexpected Text Filter Error: {e}", 5000)
             self.current_filter = LogFilter() # Reset to prevent issues
             return

        # Iterate through rows and apply BOTH filters
        self.log_display.setUpdatesEnabled(False)
        rows_shown = 0
        for row in range(self.log_display.rowCount()):
            should_be_visible = False
            item = self.log_display.item(row, 0)
            if not item: continue

            syslog_obj = item.data(Qt.UserRole)
            if isinstance(syslog_obj, Syslog):
                # 1. Check Level Filter
                level_match = (self.current_monitor_level == -1 or
                               (syslog_obj.log_monitor_level is not None and
                                syslog_obj.log_monitor_level <= self.current_monitor_level))

                # 2. Check Text Filter (only if level matches)
                if level_match:
                    text_match = self.current_filter.matches(syslog_obj)
                    if text_match:
                        should_be_visible = True
            else:
                 # Handle non-syslog rows (old errors) - show if no filters active?
                 if self.current_monitor_level == -1 and not self.current_filter.filter_string:
                      should_be_visible = True

            self.log_display.setRowHidden(row, not should_be_visible)
            if should_be_visible:
                 rows_shown += 1

        self.log_display.setUpdatesEnabled(True)
        if not is_initial:
             self.status_bar.showMessage(f"Filters applied. Showing {rows_shown} rows.", 3000)

    @pyqtSlot()
    def reset_filter(self):
        """ Clears the text filter input and applies filters. """
        self.filter_input.clear()
        self.apply_filter()

    @pyqtSlot()
    def clear_table(self):
        """ Removes all rows from the log display table. """
        self.log_display.setRowCount(0)
        self.status_bar.showMessage("Display cleared.", 3000)
        print("Log display table cleared.")

    @pyqtSlot(bool)
    def _toggle_logging(self, checked):
        """ Handles the Enable Logging menu action. """
        self.logging_enabled = checked
        self.settings.setValue(SETTINGS_LOG_ENABLED, self.logging_enabled)
        if checked:
            self.status_bar.showMessage(f"Logging enabled. Saving to: {self.log_directory}", 4000)
            print(f"Logging enabled. Directory: {self.log_directory}")
        else:
            self.status_bar.showMessage("Logging disabled.", 4000)
            print("Logging disabled.")

    @pyqtSlot()
    def _set_log_directory(self):
        """ Opens dialog to choose log directory and updates setting. """
        new_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Log Output Directory",
            self.log_directory # Start in the current log directory
        )
        if new_dir and new_dir != self.log_directory: # Check if a directory was selected and it's different
            self.log_directory = new_dir
            self.settings.setValue(SETTINGS_LOG_DIR, self.log_directory)
            self.status_bar.showMessage(f"Log directory set to: {self.log_directory}", 4000)
            print(f"Log directory set to: {self.log_directory}")
            # Update status if logging is already enabled
            if self.logging_enabled:
                 self.status_bar.showMessage(f"Logging enabled. Saving to: {self.log_directory}", 4000)

    def closeEvent(self, event):
        """ Handles window close; stops listener, saves settings. """
        self.status_bar.showMessage("Closing application...")
        print("Saving settings...")
        # Ensure latest values are saved ( safe)
        self.settings.setValue(SETTINGS_LOG_DIR, self.log_directory)
        self.settings.setValue(SETTINGS_LOG_ENABLED, self.logging_enabled)
        self.settings.setValue(SETTINGS_MONITOR_LEVEL, self.current_monitor_level)
        self.settings.sync()

        if self.listener_thread and self.listener_thread.isRunning():
            print("Stopping listener thread...")
            if self.listener:
                self.listener.stop()
            if not self.listener_thread.wait(2000):
                print("Warning: Listener thread did not finish gracefully. Terminating...")
                self.listener_thread.terminate()
                self.listener_thread.wait()
            else:
                print("Listener thread stopped successfully.")
        else:
            print("Listener thread not running or already stopped.")
        print("Exiting application.")
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setOrganizationName("SJust")
    app.setApplicationName("SIEM Log Monitor")

    try:
        app.setStyleSheet(theme.DARK_STYLE)
    except Exception as e: # Catch broader errors
        print(f"Warning: Could not load theme.DARK_STYLE: {e}. Using default style.")

    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())