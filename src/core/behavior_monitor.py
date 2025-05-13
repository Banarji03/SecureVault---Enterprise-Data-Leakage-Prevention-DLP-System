from utils.logger import Logger
from collections import defaultdict
import threading
import time

class BehaviorMonitor:
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.logger = Logger()
        self.running = False
        self.monitor_thread = None
        self.user_activities = defaultdict(list)
        self.thresholds = self._load_thresholds()

    def _load_thresholds(self):
        return {
            'file_access_rate': 10,  # files per minute
            'sensitive_access_rate': 5,  # sensitive files per minute
            'after_hours_threshold': 0.8,  # activity score threshold
            'data_transfer_limit': 100  # MB per hour
        }

    def start(self):
        try:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._analyze_behavior)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.logger.info("Behavior monitoring started")
        except Exception as e:
            self.logger.error(f"Error starting behavior monitor: {str(e)}")
            raise

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def record_activity(self, user_id, activity_type, details):
        timestamp = time.time()
        self.user_activities[user_id].append({
            'timestamp': timestamp,
            'type': activity_type,
            'details': details
        })

    def _analyze_behavior(self):
        while self.running:
            try:
                self._check_anomalies()
                self._cleanup_old_activities()
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Error in behavior analysis: {str(e)}")

    def _check_anomalies(self):
        for user_id, activities in self.user_activities.items():
            if self._detect_rapid_access(activities):
                self._report_anomaly(user_id, 'rapid_access')
            if self._detect_after_hours_activity(activities):
                self._report_anomaly(user_id, 'after_hours')
            if self._detect_unusual_transfer(activities):
                self._report_anomaly(user_id, 'unusual_transfer')

    def _report_anomaly(self, user_id, anomaly_type):
        results = {
            'event_type': 'behavior_anomaly',
            'user_id': user_id,
            'anomaly_type': anomaly_type,
            'timestamp': time.time()
        }
        self.detection_engine.policy_engine.apply_policy(results)