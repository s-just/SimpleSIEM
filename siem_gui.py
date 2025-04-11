import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QTextEdit, QStatusBar
)
from PyQt5.QtCore import pyqtSlot, QThread, Qt

# Import listener and syslog
from siem_core import SysLogListener, Syslog

class MainWindow(QMainWindow):
    def __init__(self, parent = None):
        super().__init__(parent)

        # Window parameters
        self.setWindowTitle("SIEM")
        self.setGeometry(100, 100, 800, 600)

        # GUI Elements
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)

        # Threading
        self.listener_thread = None
        self.listener = None
        self.setup_listener_thread()

    def setup_listener_thread(self):
        self.listener_thread = QThread(self)
        self.listener = SysLogListener()

        self.listener.moveToThread(self.listener_thread)

        # Connect signals and slots
        self.listener_thread.started.connect(self.listener.run)

        self.listener.log_received.connect(self._update_log_display)
        self.listener.status_update.connect(self.status_bar.showMessage)

        # Clean up after thread is finished executing
        self.listener_thread.finished.connect(self.listener.deleteLater)
        self.listener_thread.finished.connect(self.listener_thread.deleteLater)
        self.listener_thread.finished.connect(lambda: self.status_bar.showMessage("Thread Finished", 3000))

        # Start the thread
        self.listener_thread.start()
        self.status_bar.showMessage("Thread Started", 3000)

    @pyqtSlot(object)
    def _update_log_display(self, syslog_obj):
        if isinstance(syslog_obj, Syslog):
            log_line = syslog_obj.to_string()
            self.log_display.append(log_line)
        else:
            self.log_display.append(f"Received non-Syslog object: {type(syslog_obj)}")

    def closeEvent(self, event):
        self.status_bar.showMessage("Closing...")
        if self.listener_thread and self.listener_thread.isRunning():
            print("Stopping listener thread")
            if self.listener:
                self.listener.stop()

            # Wait for thread to finish and exit
            if not self.listener_thread.wait(1500):
                print("Thread not finished properly, attempting to terminate listener thread")
                self.listener_thread.terminate()
                self.listener_thread.wait()
            else:
                print("Listener thread stopped")
        else:
            print("Listener thread not started or already stopped previously")

        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
