import logging
from src.policy.engine import PolicyEngine
from src.ml.classifier import DataClassifier

logger = logging.getLogger(__name__)

class DriveMonitor:
    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.classifier = DataClassifier()
        
    def start(self):
        """Start drive monitoring"""
        logger.info("Drive monitoring started")
        
    def stop(self):
        """Stop drive monitoring"""
        logger.info("Drive monitoring stopped")