from typing import Dict, List
import sqlite3
from datetime import datetime
from utils.logger import Logger

class Database:
    def __init__(self):
        self.logger = Logger()
        self.db_path = 'securevault.db'
        self._initialize_database()

    def _initialize_database(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create incidents table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    file_path TEXT,
                    incident_type TEXT NOT NULL,
                    details TEXT,
                    severity TEXT,
                    status TEXT DEFAULT 'open'
                )''')

                # Create policies table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    actions TEXT NOT NULL,
                    sensitivity_threshold REAL,
                    blocked_patterns TEXT,
                    allowed_destinations TEXT,
                    quarantine_enabled INTEGER DEFAULT 1
                )''')

                conn.commit()
        except Exception as e:
            self.logger.error(f"Database initialization error: {str(e)}")
            raise

    def log_incident(self, detection_results: Dict):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO incidents (timestamp, file_path, incident_type, details, severity)
                VALUES (?, ?, ?, ?, ?)''',
                (datetime.now().isoformat(),
                 detection_results.get('file_path'),
                 self._determine_incident_type(detection_results),
                 str(detection_results),
                 self._determine_severity(detection_results)))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error logging incident: {str(e)}")

    def get_incidents(self, filters: Dict = None) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = "SELECT * FROM incidents"
                params = []

                if filters:
                    conditions = []
                    if 'status' in filters:
                        conditions.append("status = ?")
                        params.append(filters['status'])
                    if 'severity' in filters:
                        conditions.append("severity = ?")
                        params.append(filters['severity'])
                    if conditions:
                        query += " WHERE " + " AND ".join(conditions)

                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error retrieving incidents: {str(e)}")
            return []

    def _determine_incident_type(self, detection_results: Dict) -> str:
        if detection_results.get('pattern_matches'):
            return 'pattern_match'
        elif detection_results.get('ml_classification', {}).get('sensitivity_level') == 'sensitive':
            return 'ml_detection'
        elif detection_results.get('fingerprint_match', {}).get('matched'):
            return 'fingerprint_match'
        return 'unknown'

    def _determine_severity(self, detection_results: Dict) -> str:
        # Implement severity determination logic
        return 'high' if detection_results.get('pattern_matches') else 'medium'