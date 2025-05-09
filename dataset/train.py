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

# Load dataset
print("📊 Loading dataset...")
df = pd.read_csv("dataset_full.csv")

# Clean text function
def preprocess_text(text):
    if pd.isna(text):
        return ""
    text = str(text)
    text = text.lower()
    # Keep more special characters to maintain pattern complexity
    text = re.sub(r"[^\w\s@.:/\-\[\]_\\]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

# Apply preprocessing
print("🔄 Preprocessing text...")
df["clean_content"] = df["content"].apply(preprocess_text)

# Add noise to training data
def add_noise(text):
    words = text.split()
    if len(words) > 3:
        # Randomly drop or duplicate some words
        if np.random.rand() > 0.7:
            words = words[1:] if np.random.rand() > 0.5 else words[:-1]
    return " ".join(words)

# Add noisy samples
print("🔀 Augmenting dataset with variations...")
noisy_samples = []
for _, row in df.iterrows():
    if np.random.rand() > 0.7:  # Add noise to 30% of samples
        noisy_samples.append({
            'clean_content': add_noise(row['clean_content']),
            'label': row['label']
        })

df_noisy = pd.DataFrame(noisy_samples)
df = pd.concat([df, df_noisy], ignore_index=True)

# Features & labels
X = df["clean_content"]
y = df["label"]

# Create pipeline with RandomForest
print("🛠️ Creating model pipeline...")
# Add more data augmentation techniques
def augment_text(text, label):
    augmented = []
    words = text.split()
    
    # Word dropout with varying rates
    if len(words) > 4:
        for rate in [0.1, 0.2]:
            dropped = words.copy()
            n_drops = max(1, int(len(words) * rate))
            indices = np.random.choice(len(words), n_drops, replace=False)
            for i in sorted(indices, reverse=True):
                dropped.pop(i)
            augmented.append((' '.join(dropped), label))
    
    # Character noise
    if label == 'sensitive':
        for char in [':', '@', '_', '-']:
            noisy = text.replace(char, f' {char} ')
            augmented.append((noisy, label))
        
        # Add common obfuscation patterns
        if any(p in text.lower() for p in ['password', 'key', 'token']):
            obfuscated = text.replace('a', '@').replace('o', '0').replace('i', '1')
            augmented.append((obfuscated, label))
    
    return augmented

# Update pattern features
def extract_pattern_features(text):
    text_lower = text.lower()
    patterns = {
        'has_password': bool(re.search(r'p[a@]ssw[o0]rd|pwd', text_lower)),
        'has_key': bool(re.search(r'key|t[o0]ken|secret|[a@]pi|[a@]uth', text_lower)),
        'has_ssn': bool(re.search(r'\d{3}-\d{2}-\d{4}|ssn|social security', text_lower)),
        'has_email': bool(re.search(r'[a@]|em[a@]il|e-m[a@]il', text_lower)),
        'has_money': bool(re.search(r'\$|\d+k|\d+m|revenue|forecast|financial|budget', text_lower)),
        'has_confidential': bool(re.search(r'confidential|sensitive|private|internal|restricted|nda', text_lower)),
        'is_form_related': bool(re.search(r'form|field|input|login|signup|register|ui|interface', text_lower)),
        'is_documentation': bool(re.search(r'doc|documentation|manual|guide|readme|instruction|example|template', text_lower)),
        'is_public_context': bool(re.search(r'public|external|help|support|docs', text_lower))
    }
    return patterns

# Improve context-aware prediction
def predict_with_context(model, text):
    patterns = extract_pattern_features(text)
    text_lower = text.lower()
    
    pred = model.predict([text])[0]
    prob = max(model.predict_proba([text])[0])
    
    # Clear sensitive data patterns
    if patterns['has_ssn'] or re.search(r'\d{3}-\d{2}-\d{4}', text_lower):
        return 'sensitive', 0.95
    
    # API and Key handling
    if patterns['has_key']:
        if re.search(r'sk_live_|api_key|secret_key|private_key', text_lower):
            return 'sensitive', 0.95
        if patterns['is_documentation'] and patterns['is_public_context']:
            return 'safe', 0.8
    
    # Password handling
    if patterns['has_password']:
        if re.search(r'password[\s]*:[\s]*\S+', text_lower):
            return 'sensitive', 0.95
        if patterns['is_form_related'] and not patterns['has_confidential']:
            return 'safe', 0.8
    
    # Confidential content
    if patterns['has_confidential']:
        if any([patterns['has_money'], patterns['has_key'], patterns['has_email']]):
            return 'sensitive', 0.90
        return 'sensitive', 0.85
    
    # Financial data
    if patterns['has_money']:
        if patterns['has_confidential']:
            return 'sensitive', 0.90
        if patterns['is_public_context']:
            return 'safe', 0.80
    
    return pred, prob

# Modify the pipeline parameters
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 3),
        min_df=2,
        max_df=0.95,
        analyzer='char_wb',  # Use character n-grams for better pattern recognition
        strip_accents='unicode'
    )),
    ('classifier', RandomForestClassifier(
        n_estimators=200,
        max_depth=20,  # Limit tree depth to prevent overfitting
        min_samples_split=10,
        min_samples_leaf=4,
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
        'has_key': bool(re.search(r'key|token|secret|api|auth', text_lower)),
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

pipeline = Pipeline([
    ('features', ColumnTransformer([
        ('tfidf', TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.95
        ), 'clean_content'),
        ('patterns', PatternTransformer(), 'clean_content')
    ])),
    ('classifier', RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42
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
