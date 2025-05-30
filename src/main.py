from PyQt5.QtWidgets import QApplication
import sys
from core.monitor import FileMonitor
from core.detection import DetectionEngine
from core.policy import PolicyEngine
from core.database import Database
from gui.dashboard import Dashboard
from utils.logger import Logger
from utils.config import Config
# Add these imports
from core.clipboard_monitor import ClipboardMonitor
from core.screen_monitor import ScreenMonitor
from core.email_monitor import EmailMonitor
from core.usb_monitor import USBMonitor
from core.behavior_monitor import BehaviorMonitor

class SecureVault:
    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.db = Database()
        self.policy_engine = PolicyEngine(self.db)
        self.detection_engine = DetectionEngine(self.policy_engine)
        
        # Initialize all monitors
        self.file_monitor = FileMonitor(self.detection_engine)
        self.clipboard_monitor = ClipboardMonitor(self.detection_engine)
        self.screen_monitor = ScreenMonitor(self.detection_engine)
        self.email_monitor = EmailMonitor(self.detection_engine)
        self.usb_monitor = USBMonitor(self.detection_engine)
        self.behavior_monitor = BehaviorMonitor(self.detection_engine)
        
        self.app = QApplication(sys.argv)
        self.dashboard = Dashboard(self.policy_engine, self.detection_engine)

    def start(self):
        try:
            self.logger.info("Starting SecureVault DLP System...")
            self.file_monitor.start()
            self.dashboard.run()
            sys.exit(self.app.exec_())  # Start Qt event loop
        except Exception as e:
            self.logger.error(f"Error starting SecureVault: {str(e)}")
            raise

if __name__ == "__main__":
    vault = SecureVault()
    vault.start()