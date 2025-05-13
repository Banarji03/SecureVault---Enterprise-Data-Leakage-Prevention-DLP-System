import logging
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class PolicyEngine:
    def __init__(self):
        self.config_path = Path('config/policies.yaml')
        self.policies = self._load_default_policies()
        self.violation_log = []
        self.sensitivity_threshold = 0.7  # Default threshold

    def _load_default_policies(self) -> Dict[str, Any]:
        """Load default security policies"""
        default_policies = {
            'clipboard': {
                'block_sensitive': True,
                'encrypt_sensitive': True,
                'max_size': 1024 * 1024  # 1MB
            },
            'file_system': {
                'watched_extensions': ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx'],
                'blocked_paths': ['C:/Windows', 'C:/Program Files'],
                'encrypt_sensitive': True
            },
            'email': {
                'scan_attachments': True,
                'block_sensitive': True,
                'allowed_domains': ['company.com']
            },
            'external_devices': {
                'block_write': False,
                'encrypt_transfers': True,
                'allowed_devices': []
            }
        }

        # Create config directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        # Save default policies if config doesn't exist
        if not self.config_path.exists():
            with open(self.config_path, 'w') as f:
                yaml.dump(default_policies, f)
            logger.info("Created default policy configuration")

        return default_policies

    def load_policies(self):
        """Load policies from configuration file"""
        try:
            with open(self.config_path, 'r') as f:
                self.policies = yaml.safe_load(f)
            logger.info("Loaded policy configuration")
        except Exception as e:
            logger.error(f"Error loading policies: {e}")

    def save_policies(self):
        """Save current policies to configuration file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.policies, f)
            logger.info("Saved policy configuration")
        except Exception as e:
            logger.error(f"Error saving policies: {e}")

    def should_block_clipboard(self) -> bool:
        """Check if clipboard content should be blocked"""
        return self.policies['clipboard'].get('block_sensitive', True)

    def should_encrypt_clipboard(self) -> bool:
        """Check if clipboard content should be encrypted"""
        return self.policies['clipboard'].get('encrypt_sensitive', True)

    def get_sensitivity_threshold(self) -> float:
        """Get the sensitivity threshold for classification"""
        return self.sensitivity_threshold

    def set_sensitivity_threshold(self, threshold: float):
        """Set the sensitivity threshold for classification"""
        if 0 <= threshold <= 1:
            self.sensitivity_threshold = threshold
            logger.info(f"Updated sensitivity threshold to {threshold}")
        else:
            logger.error("Threshold must be between 0 and 1")

    def is_path_allowed(self, path: str) -> bool:
        """Check if a file path is allowed"""
        blocked_paths = self.policies['file_system'].get('blocked_paths', [])
        return not any(path.startswith(blocked) for blocked in blocked_paths)

    def is_device_allowed(self, device_id: str) -> bool:
        """Check if an external device is allowed"""
        allowed_devices = self.policies['external_devices'].get('allowed_devices', [])
        return device_id in allowed_devices

    def log_clipboard_violation(self, content: Optional[str] = None):
        """Log a clipboard security violation"""
        violation = {
            'timestamp': datetime.now().isoformat(),
            'type': 'clipboard',
            'content_length': len(content) if content else 0
        }
        self.violation_log.append(violation)
        logger.warning("Clipboard security violation detected")

    def log_file_violation(self, file_path: str, event_type: str,
                          sensitivity_score: float, src_path: Optional[str] = None):
        """Log a file system security violation"""
        violation = {
            'timestamp': datetime.now().isoformat(),
            'type': 'file_system',
            'file_path': file_path,
            'event_type': event_type,
            'sensitivity_score': sensitivity_score,
            'src_path': src_path
        }
        self.violation_log.append(violation)
        logger.warning(f"File system security violation detected: {file_path}")

    def get_violation_log(self, limit: int = None) -> list:
        """Get recent security violations"""
        if limit:
            return self.violation_log[-limit:]
        return self.violation_log

    def clear_violation_log(self):
        """Clear the violation log"""
        self.violation_log = []
        logger.info("Cleared violation log")