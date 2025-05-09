from PIL import ImageGrab
import threading
import time
from typing import Dict
from utils.logger import Logger
import pytesseract
import numpy as np

class ScreenMonitor:
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.logger = Logger()
        self.running = False
        self.monitor_thread = None
        self.screenshot_interval = 5  # seconds

    def start(self):
        try:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_screen)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.logger.info("Screen monitoring started")
        except Exception as e:
            self.logger.error(f"Error starting screen monitor: {str(e)}")
            raise

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_screen(self):
        while self.running:
            try:
                screenshot = self._capture_screen()
                if screenshot:
                    self._analyze_screenshot(screenshot)
                time.sleep(self.screenshot_interval)
            except Exception as e:
                self.logger.error(f"Screen monitoring error: {str(e)}")
                time.sleep(5)  # Wait before retrying

    def _capture_screen(self) -> Dict:
        try:
            screenshot = ImageGrab.grab()
            return {
                'image': screenshot,
                'timestamp': time.time(),
                'resolution': screenshot.size
            }
        except Exception as e:
            self.logger.error(f"Error capturing screen: {str(e)}")
            return None

    def _analyze_screenshot(self, screenshot_data: Dict):
        try:
            # Convert image to text
            image = screenshot_data['image']
            text = pytesseract.image_to_string(image)

            # Create analysis data structure
            screen_data = {
                'content': text,
                'source': 'screen',
                'timestamp': screenshot_data['timestamp'],
                'metadata': {
                    'resolution': screenshot_data['resolution']
                }
            }

            # Analyze the extracted text
            results = self.detection_engine.analyze_content(screen_data)

            if results.get('pattern_matches') or \
               results.get('ml_classification', {}).get('sensitivity_level') == 'sensitive':
                self._handle_sensitive_screen(results, screenshot_data)

        except Exception as e:
            self.logger.error(f"Error analyzing screenshot: {str(e)}")

    def _handle_sensitive_screen(self, results: Dict, screenshot_data: Dict):
        try:
            # Save incident details
            incident_data = {
                **results,
                'source': 'screen_capture',
                'timestamp': screenshot_data['timestamp'],
                'resolution': screenshot_data['resolution']
            }

            # Apply policy actions
            self.detection_engine.policy_engine.apply_policy(incident_data)

            # Log the incident
            self.logger.warning("Sensitive content detected on screen")

        except Exception as e:
            self.logger.error(f"Error handling sensitive screen content: {str(e)}")