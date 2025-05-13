from utils.logger import Logger
import win32file
import win32con
import threading
import time

class USBMonitor:
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.logger = Logger()
        self.running = False
        self.monitor_thread = None
        self.known_drives = set()

    def start(self):
        try:
            self.running = True
            self._init_known_drives()
            self.monitor_thread = threading.Thread(target=self._monitor_usb)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.logger.info("USB monitoring started")
        except Exception as e:
            self.logger.error(f"Error starting USB monitor: {str(e)}")
            raise

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def _init_known_drives(self):
        drives = win32file.GetLogicalDrives()
        for i in range(26):
            if drives & (1 << i):
                drive = f"{chr(65 + i)}:\\"
                self.known_drives.add(drive)

    def _monitor_usb(self):
        while self.running:
            try:
                self._check_new_drives()
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Error in USB monitoring: {str(e)}")

    def _check_new_drives(self):
        drives = win32file.GetLogicalDrives()
        for i in range(26):
            if drives & (1 << i):
                drive = f"{chr(65 + i)}:\\"
                if drive not in self.known_drives:
                    self._handle_new_drive(drive)
                    self.known_drives.add(drive)

    def _handle_new_drive(self, drive):
        try:
            drive_type = win32file.GetDriveType(drive)
            if drive_type == win32file.DRIVE_REMOVABLE:
                self.logger.warning(f"New USB drive detected: {drive}")
                self._apply_protection(drive)
        except Exception as e:
            self.logger.error(f"Error handling new drive {drive}: {str(e)}")

    def _apply_protection(self, drive):
        # Apply write protection and monitoring
        results = {
            'event_type': 'usb_connected',
            'drive': drive,
            'timestamp': time.time()
        }
        self.detection_engine.policy_engine.apply_policy(results)