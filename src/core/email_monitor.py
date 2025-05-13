import logging
from src.policy.engine import PolicyEngine
from src.ml.classifier import DataClassifier

logger = logging.getLogger(__name__)

class EmailMonitor:
    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.classifier = DataClassifier()
        
    def start(self):
        """Start email monitoring"""
        logger.info("Email monitoring started")
        
    def stop(self):
        """Stop email monitoring"""
        logger.info("Email monitoring stopped")