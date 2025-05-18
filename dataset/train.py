import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GridSearchCV
import joblib
import re

# Clean text function
def preprocess_text(text):
    # Keep more special characters for international formats
    text = re.sub(r"[^\w\s@.:/\-\[\]_\\₹।,]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

# Load dataset
print("Loading dataset...")
df = pd.read_csv("dataset_full.csv")

# Clean and prepare the text data
print("Preprocessing text data...")
df['clean_content'] = df['content'].apply(preprocess_text)

# Prepare features and target
X = df['clean_content']
y = df['label']

# Update pattern features with international support
def extract_pattern_features(text):
    text_lower = text.lower()
    patterns = {
        'has_password': bool(re.search(r'p[a@]ssw[o0]rd|pwd', text_lower)),
        'has_key': bool(re.search(r'key|t[o0]ken|secret|[a@]pi|[a@]uth', text_lower)),
        'has_ssn': bool(re.search(r'\d{3}-\d{2}-\d{4}|ssn|social security', text_lower)),
        'has_email': bool(re.search(r'[a@]|em[a@]il|e-m[a@]il', text_lower)),
        'has_account_number': bool(re.search(r'\d{4}[-\s]?\d{4}[-\s]?\d{4}|account.*?\d+|card.*?\d+', text_lower)),
        'has_routing_number': bool(re.search(r'\b\d{9}\b', text_lower)),
        'has_investment_data': bool(re.search(r'portfolio|stocks|yield|investment|ira', text_lower)),
        'has_money': bool(re.search(r'\$|\d+k|\d+m|₹|lpa|revenue|forecast|financial|\d+[,.]\d{2}', text_lower)),
        'has_international_id': bool(re.search(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}|[A-Z]{5}\d{4}[A-Z]|आधार|पैन|بطاقة', text_lower)),
        'has_medical_data': bool(re.search(r'patient|diagnosis|prescription|insurance|medical|doctor|hospital|treatment|code[:\s]+[A-Z]\d+', text_lower)),
        'has_hr_data': bool(re.search(r'candidate|ctc|background|verification|recruitment|employee', text_lower)),
        'has_confidential': bool(re.search(r'confidential|sensitive|private|internal|restricted|nda', text_lower)),
        'is_form_related': bool(re.search(r'form|field|input|login|signup|register|ui|interface', text_lower)),
        'is_documentation': bool(re.search(r'doc|documentation|manual|guide|readme|instruction|example|template', text_lower)),
        'is_public_context': bool(re.search(r'public|external|help|support|docs', text_lower))
    }
    return patterns

# Improve context-aware prediction with confidence thresholds
# Update prediction rules
def predict_with_context(model, text):
    patterns = extract_pattern_features(text)
    text_lower = text.lower()
    
    # Get base prediction
    pred = model.predict([text])[0]
    prob = max(model.predict_proba([text])[0])
    
    # Strong sensitive indicators
    if any([
        patterns['has_account_number'],
        patterns['has_international_id'],
        patterns['has_medical_data'],
        patterns['has_confidential'] and (patterns['has_money'] or patterns['has_key'])
    ]):
        return 'sensitive', 0.95
    
    return pred, prob
        # Financial data
    if patterns['has_account_number'] or patterns['has_routing_number'] or patterns['has_investment_data']:
        return 'sensitive', 0.95
    
    # API and Credentials
    if patterns['has_api_key'] or patterns['has_jwt']:
        return 'sensitive', 0.95
    
    # International IDs
    if patterns['has_aadhar'] or patterns['has_pan'] or patterns['has_international_id']:
        return 'sensitive', 0.95
    
    # Healthcare and HR
    if patterns['has_medical_data'] or patterns['has_hr_data']:
        if not patterns['is_public_context']:
            return 'sensitive', 0.90
    
    # High confidence rules (95%)
    if any([
        patterns['has_international_id'],
        patterns['has_medical_data'],
        re.search(r'api[_\s]?key[=:]?\s*\w+|token[=:]?\s*[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', text_lower)
    ]):
        return 'sensitive', 0.95
    
    # Medium confidence rules (90%)
    if any([
        patterns['has_hr_data'] and not patterns['is_public_context'],
        patterns['has_money'] and patterns['has_confidential']
    ]):
        return 'sensitive', 0.90
    
    # Lower confidence rules (80%)
    if patterns['is_documentation'] and patterns['is_public_context']:
        return 'safe', 0.80
        
    return pred, prob

# Modify the RandomForestClassifier parameters
# Modify the pipeline parameters
# Update pipeline parameters
# Update pipeline parameters
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        max_features=1500,
        ngram_range=(1, 3),    # Capture longer phrases
        min_df=3,              # Allow rarer terms
        max_df=0.85,
        analyzer='char_wb'      # Better for international text
    )),
    ('classifier', RandomForestClassifier(
        n_estimators=200,      # More trees
        max_depth=8,           # Slightly deeper
        min_samples_split=8,
        min_samples_leaf=3,
        class_weight='balanced',
        random_state=42
    ))
])

# Expand parameter grid
param_grid = {
    'tfidf__max_features': [3000, 5000],
    'tfidf__ngram_range': [(1, 2), (1, 3), (2, 4)],
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [15, 20, None],
    'classifier__min_samples_split': [5, 10],
    'classifier__min_samples_leaf': [2, 4]
}

# Remove these lines as they're causing the error
# Add noisy samples to the dataframe
# noisy_df = pd.DataFrame(noisy_samples)
# df = pd.concat([df, noisy_df], ignore_index=True)

# Prepare features and target
X = df['clean_content']
y = df['label']

# Add validation set
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

# Use validation set in GridSearchCV
grid_search = GridSearchCV(
    pipeline,
    param_grid,
    cv=5,
    n_jobs=-1,
    verbose=1,
    scoring=['accuracy', 'precision', 'recall', 'f1'],
    refit='f1'  # Optimize for F1-score instead of accuracy
)

# Grid search with cross-validation
print("🔍 Performing grid search...")
grid_search = GridSearchCV(pipeline, param_grid, cv=5, n_jobs=-1, verbose=1)
grid_search.fit(X_train, y_train)

print("\n📊 Best parameters:")
print(grid_search.best_params_)

# Evaluate on test set
print("\n📝 Model Evaluation:")
y_pred = grid_search.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
print("\nConfusion Matrix:")
print(cm)

# Save model
print("\n💾 Saving model...")
joblib.dump(grid_search.best_estimator_, "dlp_model_pipeline.joblib")
print("✅ Model pipeline saved successfully.")

# Test with challenging examples
# Add pattern-based features
# Update pattern features with more context
def extract_pattern_features(text):
    text_lower = text.lower()
    patterns = {
        'has_password': bool(re.search(r'password|pwd', text_lower)),
        'has_key': bool(re.search(r'key|t[o0]ken|secret|[a@]pi|[a@]uth', text_lower)),
        'has_ssn': bool(re.search(r'\d{3}-\d{2}-\d{4}|ssn|social security', text_lower)),
        'has_email': bool(re.search(r'@|email|e-mail', text_lower)),
        'has_money': bool(re.search(r'\$|\d+k|\d+m|revenue|forecast|financial', text_lower)),
        'has_confidential': bool(re.search(r'confidential|sensitive|private|internal|restricted', text_lower)),
        'is_form_related': bool(re.search(r'form|field|input|login|signup|register', text_lower)),
        'is_documentation': bool(re.search(r'doc|documentation|manual|guide|readme|instruction', text_lower)),
        'is_public_context': bool(re.search(r'public|external|help|support', text_lower))
    }
    return patterns

# Improve context-aware prediction
def predict_with_context(model, text):
    # Extract features
    patterns = extract_pattern_features(text)
    text_lower = text.lower()
    
    # Get model prediction and probability
    pred = model.predict([text])[0]
    prob = max(model.predict_proba([text])[0])
    
    # Clear sensitive data rules
    if patterns['has_ssn']:
        return 'sensitive', 0.95
    
    # API and Key handling
    if patterns['has_key']:
        if patterns['is_documentation'] and patterns['is_public_context']:
            return 'safe', 0.8
        if re.search(r'sk_live_|api_key|secret_key', text_lower):
            return 'sensitive', 0.95
    
    # Documentation and form context
    if patterns['is_form_related'] and patterns['is_documentation']:
        if not any([re.search(r'sk_live_|api_key|secret_key', text_lower),
                    patterns['has_ssn'],
                    patterns['has_confidential']]):
            return 'safe', 0.8
    
    # Financial context
    if patterns['has_money']:
        if patterns['has_confidential']:
            return 'sensitive', 0.9
        if patterns['is_public_context'] or 'report' in text_lower:
            return 'safe', 0.8
    
    # Confidential content
    if patterns['has_confidential']:
        if any([patterns['has_money'], patterns['has_key'], patterns['has_email']]):
            return 'sensitive', 0.9
    
    # Password field handling
    if patterns['has_password'] and patterns['is_form_related']:
        if not patterns['has_confidential']:
            return 'safe', 0.8
    
    return pred, prob

# Create custom transformer for pattern features
from sklearn.base import BaseEstimator, TransformerMixin

class PatternTransformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        features = [extract_pattern_features(text) for text in X]
        return pd.DataFrame(features)

# Create pipeline with both TF-IDF and pattern features
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import FunctionTransformer

# Suggested modifications to prevent overfitting
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        max_features=1500,    # Reduced features
        ngram_range=(1, 2),    # Simpler n-grams
        min_df=5,             # More restrictive
        max_df=0.85           # More restrictive
    )),
    ('classifier', RandomForestClassifier(
        n_estimators=100,
        max_depth=6,          # Reduced depth
        min_samples_split=15,  # Increased
        min_samples_leaf=5,    # Increased
        bootstrap=True,
        oob_score=True        # Enable out-of-bag scoring
    ))
])

# Add context-aware prediction function
def predict_with_context(model, text):
    # Extract features
    patterns = extract_pattern_features(text)
    
    # Get model prediction and probability
    pred = model.predict([text])[0]
    prob = max(model.predict_proba([text])[0])
    
    # Apply business rules
    if patterns['has_ssn'] or patterns['has_key']:
        return 'sensitive', max(prob, 0.95)  # High confidence for clear sensitive data
    
    if patterns['has_money'] and not patterns['has_confidential']:
        if 'forecast' in text.lower() or 'report' in text.lower():
            return 'safe', 0.8  # Public financial terms
    
    if patterns['has_password'] and ('form' in text.lower() or 'field' in text.lower()):
        return 'safe', 0.8  # UI-related terms
    
    return pred, prob

# Update the testing section
print("\n🔍 Testing model with challenging examples...")
example_texts = [
    "Meeting scheduled for next week",
    "Password: admin123, API Key: sk_live_12345",
    "Meeting about password security",
    "The password field in the form",
    "SSN: 123-45-6789",
    "Revenue forecast: $500k for Q2",
    "CONFIDENTIAL: Q3 Revenue Projections $1.2M",
    "Please update your password in the login form",
    "API Documentation: password field is required"
]

print("\nPredictions for example texts:")
for text in example_texts:
    pred, conf = predict_with_context(grid_search.best_estimator_, text)
    print(f"Text: {text}")
    print(f"Prediction: {pred}")
    print(f"Confidence: {conf:.3f}\n")

# Update train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=0.2,
    stratify=y,          # Ensure balanced split
    random_state=42
)

# Add after model creation - Fix the cross-validation code
scores = cross_val_score(grid_search.best_estimator_, X_train, y_train, cv=5)
print(f"Cross-validation scores: {scores.mean():.2f} (+/- {scores.std() * 2:.2f})")

example_texts.extend([
    "Statement Period: 01 Jan 2024 - 31 Jan 2024\nAccount Number: 1234-5678-9876",
    "API_KEY=AIzaSyDc_49uhF8gkFDPqR77a5kMvfxbL-0Ot1w",
    "मेरा आधार संख्या 5674 2321 8877 है।",
    "Patient Name: Sarah Holmes\nDiagnosis Code: E11.9",
    "Candidate: Rahul Mehra\nPAN: BNGPM8262K\nExpected CTC: ₹9.5 LPA",
    "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "रقم البطاقة هو 1234-5678-9876"
])

print("\nPredictions for example texts:")
for text in example_texts:
    pred, conf = predict_with_context(grid_search.best_estimator_, text)
    print(f"Text: {text}")
    print(f"Prediction: {pred}")
    print(f"Confidence: {conf:.3f}\n")
