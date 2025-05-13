import logging
import time
import win32clipboard
import win32con
from threading import Thread, Event

from src.ml.classifiers.data_classifier import DataClassifier
from src.policy.engine import PolicyEngine
from src.utils.encryption import encrypt_data

logger = logging.getLogger(__name__)

class ClipboardMonitor:
    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.classifier = DataClassifier()
        self.stop_event = Event()
        self.monitor_thread = None
        self.last_content = None
        self.encryption_enabled = True

    def _get_clipboard_text(self) -> str:
        """Safely retrieve text content from clipboard"""
        try:
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32con.CF_TEXT):
                    return win32clipboard.GetClipboardData(win32con.CF_TEXT).decode('utf-8')
                elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                    return win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
            finally:
                win32clipboard.CloseClipboard()
        except Exception as e:
            logger.error(f"Error accessing clipboard: {e}")
        return None

    def _set_clipboard_text(self, text: str):
        """Safely set text content to clipboard"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text, win32con.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
        except Exception as e:
            logger.error(f"Error setting clipboard: {e}")

    def _clear_clipboard(self):
        """Clear the clipboard content"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
        except Exception as e:
            logger.error(f"Error clearing clipboard: {e}")

    def _handle_sensitive_data(self, content: str):
        """Handle detected sensitive data based on policy"""
        if self.policy_engine.should_block_clipboard():
            self._clear_clipboard()
            logger.info("Cleared sensitive data from clipboard")
        elif self.encryption_enabled:
            encrypted_content = encrypt_data(content)
            self._set_clipboard_text(encrypted_content)
            logger.info("Encrypted sensitive data in clipboard")

        # Log the violation
        self.policy_engine.log_clipboard_violation(content)

    def _monitor_clipboard(self):
        """Monitor clipboard for sensitive data"""
        while not self.stop_event.is_set():
            try:
                current_content = self._get_clipboard_text()
                
                if current_content and current_content != self.last_content:
                    self.last_content = current_content
                    
                    # Check if content contains sensitive data
                    sensitivity_score = self.classifier.analyze_sensitivity(current_content)
                    if sensitivity_score > self.policy_engine.get_sensitivity_threshold():
                        logger.warning(f"Sensitive data detected in clipboard (score: {sensitivity_score})")
                        self._handle_sensitive_data(current_content)

            except Exception as e:
                logger.error(f"Error in clipboard monitoring: {e}")

            # Sleep briefly to prevent high CPU usage
            time.sleep(0.5)

    def start(self):
        """Start clipboard monitoring"""
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.stop_event.clear()
            self.monitor_thread = Thread(target=self._monitor_clipboard, daemon=True)
            self.monitor_thread.start()
            logger.info("Clipboard monitoring started")

    def stop(self):
        """Stop clipboard monitoring"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.stop_event.set()
            self.monitor_thread.join(timeout=2.0)
            logger.info("Clipboard monitoring stopped")

    def set_encryption_enabled(self, enabled: bool):
        """Enable or disable encryption of sensitive data"""
        self.encryption_enabled = enabled
        logger.info(f"Clipboard encryption {'enabled' if enabled else 'disabled'}")