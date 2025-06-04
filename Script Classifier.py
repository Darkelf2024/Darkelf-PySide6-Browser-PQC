#train_js_classifier_hardened.py

Hardened Local-Only JS Classifier Training Script
- NO telemetry, NO external connections
- Designed for secure environments and PQ-encrypted workflows (e.g., ML-KEM-1024)
- Outputs are local only (classifier, scaler, metadata, hash)
"""

import joblib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime
import hashlib
import warnings
import json
import os

# === Privacy Notice ===
# This script DOES NOT use telemetry, does not transmit any data, and logs ONLY to local disk.

warnings.filterwarnings("ignore")

feature_names = [
    "length", "cookie_access", "localStorage_access", "canvas_access",
    "font_fingerprinting", "network_calls", "entropy", "obfuscation_ratio"
]

# === Synthetic Dataset (expand as needed)
X = np.array([
    [200, 2, 1, 1, 1, 3, 4.2, 0.65],  # Malicious
    [150, 0, 0, 0, 0, 0, 2.8, 0.85],  # Safe
    [300, 3, 2, 1, 2, 4, 5.1, 0.60],  # Malicious
    [100, 0, 0, 0, 0, 1, 3.0, 0.88],  # Safe
    [500, 5, 4, 3, 4, 7, 6.2, 0.55],  # Malicious
    [120, 1, 0, 0, 1, 0, 2.5, 0.82],  # Safe
    [800, 6, 3, 2, 5, 10, 6.9, 0.50], # Malicious
    [80, 0, 0, 0, 0, 0, 2.3, 0.90],   # Safe
    [600, 4, 2, 2, 3, 5, 6.0, 0.57],  # Ad Script
    [90, 0, 0, 0, 0, 1, 2.9, 0.86],   # Safe
    [700, 3, 1, 2, 4, 6, 6.5, 0.52],  # Ad Script
    [130, 0, 0, 0, 0, 0, 2.4, 0.87],  # Safe
    [750, 4, 2, 2, 3, 5, 6.1, 0.54],  # Ad Script
    [140, 0, 0, 0, 0, 0, 2.5, 0.89],  # Safe
    [720, 5, 3, 2, 4, 7, 6.3, 0.53],  # Ad Script
])

y = np.array([1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2])  # 0=Safe, 1=Malicious, 2=Ad

# === Training Setup ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
model.fit(X_train_scaled, y_train)

cv = StratifiedKFold(n_splits=3)
cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=cv)

print(f"CV Scores: {cv_scores}")
print(f"Mean CV Accuracy: {cv_scores.mean():.4f}")

# === Evaluation
y_pred = model.predict(X_test_scaled)
print("\nTest Accuracy: {:.2f}%".format(np.mean(y_pred == y_test) * 100))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# === Output to Local Files ONLY
joblib.dump(model, "ml_script_classifier.pkl")
joblib.dump(scaler, "ml_script_scaler.pkl")

metadata = {
    "model_version": "2.0-hardened",
    "created": datetime.utcnow().isoformat(),
    "features": feature_names,
    "cv_accuracy": float(cv_scores.mean()),
    "test_accuracy": float(np.mean(y_pred == y_test))
}
joblib.dump(metadata, "ml_classifier_metadata.pkl")

# === Hash Integrity File (SHA256)
hash_value = hashlib.sha256(Path("ml_script_classifier.pkl").read_bytes()).hexdigest()
with open(".ml_script_classifier.sha256", "w") as f:
    f.write(hash_value)

print("\nâ All artifacts saved securely â no telemetry, all local.")