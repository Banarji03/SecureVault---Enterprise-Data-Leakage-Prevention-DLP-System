import logging
import re
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np

logger = logging.getLogger(__name__)

class DataClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.classifier = RandomForestClassifier(n_estimators=100)
        self.patterns = self._compile_patterns()
        self.is_trained = False

    def _compile_patterns(self) -> Dict[str, Any]:
        """Compile regex patterns for sensitive data detection"""
        return {
            'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b'),
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            'password': re.compile(r'\b(password|passwd|pwd)\s*[=:]\s*\S+\b', re.I)
        }

    def train(self, training_data: List[str], labels: List[int]):
        """Train the classifier with labeled data"""
        try:
            X = self.vectorizer.fit_transform(training_data)
            X_train, X_test, y_train, y_test = train_test_split(
                X, labels, test_size=0.2, random_state=42
            )

            self.classifier.fit(X_train, y_train)
            score = self.classifier.score(X_test, y_test)
            self.is_trained = True
            logger.info(f"Classifier trained successfully. Accuracy: {score:.2f}")

        except Exception as e:
            logger.error(f"Error training classifier: {e}")
            self.is_trained = False

    def _pattern_match_score(self, text: str) -> float:
        """Calculate sensitivity score based on regex pattern matches"""
        matches = 0
        total_patterns = len(self.patterns)

        for pattern_name, pattern in self.patterns.items():
            if pattern.search(text):
                matches += 1
                logger.debug(f"Found {pattern_name} pattern in text")

        return matches / total_patterns if total_patterns > 0 else 0.0

    def _ml_classification_score(self, text: str) -> float:
        """Calculate sensitivity score using ML classification"""
        if not self.is_trained:
            return 0.0

        try:
            X = self.vectorizer.transform([text])
            probabilities = self.classifier.predict_proba(X)
            return probabilities[0][1]  # Probability of being sensitive

        except Exception as e:
            logger.error(f"Error in ML classification: {e}")
            return 0.0

    def analyze_sensitivity(self, text: str) -> float:
        """Analyze text for sensitive information
        
        Returns:
            float: Sensitivity score between 0 and 1
        """
        if not text:
            return 0.0

        # Combine pattern matching and ML classification scores
        pattern_score = self._pattern_match_score(text)
        ml_score = self._ml_classification_score(text)

        # Weight the scores (pattern matching has higher weight if ML is not trained)
        if self.is_trained:
            final_score = 0.4 * pattern_score + 0.6 * ml_score
        else:
            final_score = pattern_score

        logger.debug(f"Sensitivity analysis - Pattern: {pattern_score:.2f}, ML: {ml_score:.2f}, Final: {final_score:.2f}")
        return final_score

    def is_sensitive(self, text: str, threshold: float = 0.7) -> bool:
        """Check if text contains sensitive information"""
        return self.analyze_sensitivity(text) > threshold

    def get_sensitive_patterns(self) -> List[str]:
        """Get list of sensitive patterns being checked"""
        return list(self.patterns.keys())

    def add_pattern(self, name: str, pattern: str):
        """Add a new pattern for sensitive data detection"""
        try:
            self.patterns[name] = re.compile(pattern)
            logger.info(f"Added new pattern: {name}")
        except re.error as e:
            logger.error(f"Invalid regex pattern: {e}")

    def remove_pattern(self, name: str):
        """Remove a pattern from sensitive data detection"""
        if name in self.patterns:
            del self.patterns[name]
            logger.info(f"Removed pattern: {name}")