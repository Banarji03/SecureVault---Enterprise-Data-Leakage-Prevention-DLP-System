from typing import Dict
from utils.logger import Logger

class PolicyEngine:
    def __init__(self, db):
        self.db = db
        self.logger = Logger()
        self.policies = self._load_policies()
        self.roles = self._load_roles()
        self.user_roles = self._load_user_roles()

    def _load_roles(self):
        # In production, load from database
        return {
            'admin': {
                'allowed_actions': ['read', 'write', 'delete', 'configure'],
                'allowed_paths': ['*'],
                'sensitivity_access': 'all'
            },
            'manager': {
                'allowed_actions': ['read', 'write'],
                'allowed_paths': ['/department/*', '/shared/*'],
                'sensitivity_access': 'medium'
            },
            'employee': {
                'allowed_actions': ['read'],
                'allowed_paths': ['/department/employee/*', '/shared/public/*'],
                'sensitivity_access': 'low'
            }
        }

    def _load_user_roles(self):
        # In production, load from database
        return {
            'user1': 'admin',
            'user2': 'manager',
            'user3': 'employee'
        }

    def apply_policy(self, detection_results):
        try:
            user_id = detection_results.get('user_id', 'default')
            user_role = self.user_roles.get(user_id, 'employee')
            role_policies = self.roles.get(user_role, {})
            
            # Combine role policies with general policies
            policy = self._get_applicable_policy(detection_results)
            policy.update(role_policies)
            
            self._execute_policy_actions(policy, detection_results)
        except Exception as e:
            self.logger.error(f"Error applying policy: {str(e)}")

    def _load_policies(self) -> Dict:
        return {
            'default': {
                'actions': ['log', 'alert'],
                'sensitivity_threshold': 0.8,
                'blocked_patterns': [
                    'credit_card', 'ssn', 'aadhar', 'pan',
                    'api_key', 'jwt_token', 'medical_id', 'routing_number'
                ],
                'allowed_destinations': ['internal_network'],
                'quarantine_enabled': True,
                'language_support': ['en', 'hi', 'ar', 'fr']
            }
        }

    def _get_applicable_policy(self, detection_results: Dict) -> Dict:
        # In production, implement logic to select appropriate policy
        # based on user, department, file type, etc.
        return self.policies['default']

    def _execute_policy_actions(self, policy: Dict, detection_results: Dict):
        if 'log' in policy['actions']:
            self._log_incident(detection_results)

        if 'alert' in policy['actions']:
            self._send_alert(detection_results)

        if 'quarantine' in policy['actions'] and policy['quarantine_enabled']:
            self._quarantine_file(detection_results['file_path'])

    def _log_incident(self, detection_results: Dict):
        self.db.log_incident(detection_results)

    def _send_alert(self, detection_results: Dict):
        # Implement alert mechanism (email, webhook, etc.)
        self.logger.warning(f"Security alert for file: {detection_results['file_path']}")

    def _quarantine_file(self, file_path: str):
        try:
            # Implement file quarantine logic
            self.logger.info(f"Quarantining file: {file_path}")
        except Exception as e:
            self.logger.error(f"Error quarantining file {file_path}: {str(e)}")

    def add_policy(self, policy_data: Dict):
        try:
            policy_name = policy_data.get('name')
            if not policy_name:
                raise ValueError("Policy name is required")
                
            self.policies[policy_name] = {
                'actions': policy_data.get('actions', ['log']),
                'sensitivity_threshold': policy_data.get('sensitivity_threshold', 0.8),
                'blocked_patterns': policy_data.get('blocked_patterns', []),
                'allowed_destinations': policy_data.get('allowed_destinations', []),
                'quarantine_enabled': policy_data.get('quarantine_enabled', True)
            }
            self.logger.info(f"Added new policy: {policy_name}")
            return True
        except Exception as e:
            self.logger.error(f"Error adding policy: {str(e)}")
            return False

    def get_policies(self) -> Dict:
        """Return all configured policies"""
        return self.policies