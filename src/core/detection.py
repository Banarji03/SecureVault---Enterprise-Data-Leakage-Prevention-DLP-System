from typing import List, Dict
import re
import hashlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from utils.logger import Logger

class DetectionEngine:
    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self.logger = Logger()
        self.sensitive_patterns = {
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        self.ml_model = self._initialize_ml_model()
        self.document_fingerprints = {}

    def _initialize_ml_model(self) -> RandomForestClassifier:
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
                'file_path': file_path,
                'content': content  # Add content for training
            }
    
            # Determine if content is sensitive
            is_sensitive = bool(
                results['pattern_matches'] or
                results.get('ml_classification', {}).get('sensitivity_level') == 'sensitive' or
                results.get('fingerprint_match', {}).get('matched')
            )
    
            # Add to training dataset
            self.policy_engine.securevault.realtime_trainer.add_training_sample(
                results,
                is_sensitive
            )
    
            self._handle_detection_results(results)
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {'error': str(e)}

    def _read_file_content(self, file_path: str) -> str:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {str(e)}")
            raise

    def _check_patterns(self, content: str) -> Dict[str, List[str]]:
        matches = {}
        for pattern_name, pattern in self.sensitive_patterns.items():
            found = re.findall(pattern, content)
            if found:
                matches[pattern_name] = found
        return matches

    def _classify_content(self, content: str) -> Dict:
        try:
            # In production, use the actual trained model
            features = TfidfVectorizer().fit_transform([content])
            prediction = self.ml_model.predict(features)
            return {
                'sensitivity_level': prediction[0],
                'confidence': max(self.ml_model.predict_proba(features)[0])
            }
        except Exception as e:
            self.logger.error(f"Error in ML classification: {str(e)}")
            return {'error': str(e)}

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