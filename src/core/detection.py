from typing import List, Dict
import re
import hashlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from utils.logger import Logger
from datetime import datetime

class DetectionEngine:
    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self.logger = Logger()  # Add this line
        self.sensitive_patterns = {
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'aadhar': r'\d{4}[\s-]?\d{4}[\s-]?\d{4}',
            'pan': r'[A-Z]{5}\d{4}[A-Z]',
            'api_key': r'api[_\s]?key[=:]?\s*\w+',
            'jwt_token': r'[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
            'medical_id': r'\b[A-Z]\d{2}\.\d{1,2}\b',
            'routing_number': r'\b\d{9}\b'
        }
        self.ml_model = self._initialize_ml_model()
        self.document_fingerprints = {}

    def _initialize_ml_model(self) -> RandomForestClassifier:
        try:
            from joblib import load
            model = load('dlp_model_pipeline.joblib')
            self.logger.info("Successfully loaded pre-trained DLP model")
            return model
        except Exception as e:
            self.logger.error(f"Error loading pre-trained model: {str(e)}")
            # Fallback to pattern-based detection only
            return None  # Return None instead of untrained model
        model = RandomForestClassifier(n_estimators=100)
        # In production, load pre-trained model here
        return model

    # In the DetectionEngine class, modify the analyze_file method
    
    def analyze_file(self, file_path: str) -> Dict:
        try:
            content = self._read_file_content(file_path)
            results = {
                'pattern_matches': self._check_patterns(content),
                'ml_classification': self._classify_content(content),
                'fingerprint_match': self._check_fingerprint(content),
                'file_path': file_path
            }

            # Determine if content is sensitive
            is_sensitive = bool(
                results['pattern_matches'] or
                results.get('ml_classification', {}).get('sensitivity_level') == 'sensitive' or
                results.get('fingerprint_match', {}).get('matched')
            )

            self._handle_detection_results(results)
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {'error': str(e)}

    def _read_file_content(self, file_path: str) -> str:
        try:
            # Skip binary files and system files
            if file_path.endswith(('.db', '.db-journal', '.lock', '.git')) or '/.git/' in file_path or '\.git\\' in file_path:
                return ''
                
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {str(e)}")
            return ''

    def _check_patterns(self, content: str) -> Dict[str, List[str]]:
        matches = {}
        for pattern_name, pattern in self.sensitive_patterns.items():
            found = re.findall(pattern, content)
            if found:
                matches[pattern_name] = found
        return matches

    def _classify_content(self, content: str) -> Dict:
        try:
            if not content or not self.ml_model:
                return {'sensitivity_level': 'unknown', 'confidence': 0.0}
                
            features = TfidfVectorizer().fit_transform([content])
            prediction = self.ml_model.predict(features)
            return {
                'sensitivity_level': prediction[0],
                'confidence': max(self.ml_model.predict_proba(features)[0])
            }
        except Exception as e:
            self.logger.error(f"Error in ML classification: {str(e)}")
            return {'sensitivity_level': 'unknown', 'confidence': 0.0}

    def _check_fingerprint(self, content: str) -> Dict:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        return {
            'hash': content_hash,
            'matched': content_hash in self.document_fingerprints
        }

    def _handle_detection_results(self, results: Dict):
        if results.get('pattern_matches') or \
           results.get('ml_classification', {}).get('sensitivity_level') == 'sensitive' or \
           results.get('fingerprint_match', {}).get('matched'):
            self.policy_engine.apply_policy(results)

    def get_pattern_stats(self, start_date, end_date) -> Dict:
        try:
            # Get incidents from database within date range
            incidents = self.policy_engine.db.get_incidents()
            filtered_incidents = [i for i in incidents 
                                if start_date <= datetime.fromisoformat(i['timestamp']).date() <= end_date]
            
            # Initialize pattern stats
            stats = {pattern: 0 for pattern in self.sensitive_patterns.keys()}
            
            # Count occurrences of each pattern
            for incident in filtered_incidents:
                if 'pattern_matches' in incident:
                    for pattern in incident['pattern_matches'].keys():
                        stats[pattern] += 1
            
            return stats
        except Exception as e:
            self.logger.error(f"Error getting pattern stats: {str(e)}")
            return {}

    def get_model_performance(self, start_date, end_date) -> Dict:
        try:
            # Get incidents from database within date range
            incidents = self.policy_engine.db.get_incidents()
            filtered_incidents = [i for i in incidents 
                                if start_date <= datetime.fromisoformat(i['timestamp']).date() <= end_date]
            
            # Initialize performance metrics
            total_predictions = len(filtered_incidents)
            if total_predictions == 0:
                return {
                    'total_predictions': 0,
                    'avg_confidence': 0.0,
                    'sensitivity_distribution': {}
                }
            
            # Calculate metrics
            confidence_sum = 0
            sensitivity_counts = {}
            
            for incident in filtered_incidents:
                if 'ml_classification' in incident:
                    ml_result = incident['ml_classification']
                    confidence_sum += ml_result.get('confidence', 0)
                    
                    sensitivity = ml_result.get('sensitivity_level', 'unknown')
                    sensitivity_counts[sensitivity] = sensitivity_counts.get(sensitivity, 0) + 1
            
            return {
                'total_predictions': total_predictions,
                'avg_confidence': confidence_sum / total_predictions if total_predictions > 0 else 0.0,
                'sensitivity_distribution': sensitivity_counts
            }
        except Exception as e:
            self.logger.error(f"Error getting model performance: {str(e)}")
            return {
                'total_predictions': 0,
                'avg_confidence': 0.0,
                'sensitivity_distribution': {}
            }