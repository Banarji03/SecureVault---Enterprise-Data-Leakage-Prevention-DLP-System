import yaml
import os
from typing import Dict, Any

class Config:
    def __init__(self):
        self.config_file = 'config.yaml'
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        default_config = {
            'monitoring': {
                'file_patterns': ['*.doc', '*.docx', '*.pdf', '*.txt'],
                'screenshot_interval': 5,
                'clipboard_check_interval': 1
            },
            'detection': {
                'sensitivity_threshold': 0.8,
                'ml_model_path': 'models/classifier.pkl'
            },
            'database': {
                'path': 'securevault.db'
            },
            'logging': {
                'level': 'INFO',
                'file_path': 'logs/securevault.log'
            }
        }

        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                return self._merge_configs(default_config, user_config)
        else:
            self._save_config(default_config)
            return default_config

    def _save_config(self, config: Dict):
        with open(self.config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)

    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        merged = default.copy()
        for key, value in user.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        return merged

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default

    def set(self, key: str, value: Any):
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value
        self._save_config(self.config)