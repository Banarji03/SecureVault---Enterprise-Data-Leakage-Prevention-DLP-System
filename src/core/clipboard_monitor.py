import win32clipboard
import time
import threading
from typing import Dict
from utils.logger import Logger

class ClipboardMonitor:
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.logger = Logger()
        self.running = False
        self.monitor_thread = None
        self.last_content = None

    def start(self):
        try:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_clipboard)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.logger.info("Clipboard monitoring started")
        except Exception as e:
            self.logger.error(f"Error starting clipboard monitor: {str(e)}")
            raise

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_clipboard(self):
        while self.running:
            try:
                content = self._get_clipboard_content()
                if content and content != self.last_content:
                    self._analyze_clipboard_content(content)
                    self.last_content = content
                time.sleep(1)  # Check every second
            except Exception as e:
                self.logger.error(f"Clipboard monitoring error: {str(e)}")
                time.sleep(5)  # Wait before retrying

    def _get_clipboard_content(self) -> Dict:
        try:
            win32clipboard.OpenClipboard()
            content = {
                'text': None,
                'format': None
            }

            # Check for text content
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                content['text'] = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT).decode('utf-8')
                content['format'] = 'text'
            # Add support for other formats as needed

            win32clipboard.CloseClipboard()
            return content
        except Exception as e:
            self.logger.error(f"Error accessing clipboard: {str(e)}")
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
            return None

    def _analyze_clipboard_content(self, content: Dict):
        if not content or not content['text']:
            return

        try:
            # Create a temporary file-like structure for the detection engine
            clipboard_data = {
                'content': content['text'],
                'source': 'clipboard',
                'format': content['format']
            }
            
            # Use the detection engine to analyze the content
            results = self.detection_engine.analyze_content(clipboard_data)
            
            if results.get('pattern_matches') or \
               results.get('ml_classification', {}).get('sensitivity_level') == 'sensitive':
                self._handle_sensitive_content(results)
        except Exception as e:
            self.logger.error(f"Error analyzing clipboard content: {str(e)}")

    def _handle_sensitive_content(self, results: Dict):
        try:
            # Clear clipboard if sensitive content is detected
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
            
            # Log the incident
            self.logger.warning("Sensitive content detected in clipboard")
            # Trigger policy actions
            self.detection_engine.policy_engine.apply_policy(results)
        except Exception as e:
            self.logger.error(f"Error handling sensitive clipboard content: {str(e)}")