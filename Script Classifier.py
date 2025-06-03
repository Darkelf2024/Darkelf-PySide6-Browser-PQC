import joblib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import warnings

# Suppress any irrelevant warnings
warnings.filterwarnings("ignore")

# === Feature Labels (for ML threat/ad detection) ===
feature_names = [
    "length",
    "cookie_access",
    "localStorage_access",
    "canvas_access",
    "font_fingerprinting",
    "network_calls",
    "entropy",
    "obfuscation_ratio"
]

# === Sample Feature Matrix (expand for real-world usage) ===
X = np.array([
    [200, 2, 1, 1, 1, 3, 4.2, 0.65],
    [150, 0, 0, 0, 0, 0, 2.8, 0.85],
    [300, 3, 2, 1, 2, 4, 5.1, 0.60],
    [100, 0, 0, 0, 0, 1, 3.0, 0.88],
    [500, 5, 4, 3, 4, 7, 6.2, 0.55],
    [120, 1, 0, 0, 1, 0, 2.5, 0.82],
    [800, 6, 3, 2, 5, 10, 6.9, 0.50],
    [80, 0, 0, 0, 0, 0, 2.3, 0.90],
    [600, 4, 2, 2, 3, 5, 6.0, 0.57],
    [90, 0, 0, 0, 0, 1, 2.9, 0.86],
])

y = np.array([1, 0, 1, 0, 1, 0, 1, 0, 1, 0])  # 1 = Malicious/Tracker, 0 = Safe

# === Split into Train/Test Sets ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# === Normalize Features ===
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# === Train Model ===
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)

# === Evaluate Model via Cross-Validation ===
cv = StratifiedKFold(n_splits=3)
cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=cv)
print(f"Stratified CV Scores: {cv_scores}")
print(f"Mean CV Accuracy: {cv_scores.mean():.4f}")

# === Final Test Accuracy ===
y_pred = model.predict(X_test_scaled)
test_accuracy = np.mean(y_pred == y_test)
print(f"Test Set Accuracy: {test_accuracy * 100:.2f}%")

# === Save Model and Related Artifacts ===
joblib.dump(model, "ml_script_classifier.pkl")
joblib.dump(scaler, "ml_script_scaler.pkl")

metadata = {
    "model_version": "1.1",
    "date_created": datetime.utcnow().isoformat(),
    "features": feature_names,
    "cv_accuracy": float(cv_scores.mean()),
    "test_accuracy": float(test_accuracy)
}
joblib.dump(metadata, "ml_classifier_metadata.pkl")

print("\n✅ Model, scaler, and metadata saved as version 1.1")

# === Visualize Feature Importances ===
importances = model.feature_importances_
plt.barh(feature_names, importances)
plt.title("Feature Importances")
plt.xlabel("Importance")
plt.tight_layout()
plt.show()

# === WebEngineScript Injection (optional bundling) ===
from PySide6.QtWebEngineCore import QWebEngineScript

def inject_crypto_prng_script(self):
    script_code = """
        (function() {
            async function getRandomBytes(length) {
                return window.crypto.getRandomValues(new Uint8Array(length));
            }
            window.cryptoPRNG = {
                getRandomBytes
            };
        })();
    """

    prng_script = QWebEngineScript()
    prng_script.setName("CryptoPRNG")
    prng_script.setSourceCode(script_code)
    prng_script.setInjectionPoint(QWebEngineScript.DocumentCreation)
    prng_script.setRunsOnSubFrames(True)
    prng_script.setWorldId(QWebEngineScript.MainWorld)
    self.profile().scripts().insert(prng_script)

def inject_all_scripts(self):
    self.inject_crypto_prng_script()
    if hasattr(self, 'inject_ad_removal_js'):
        self.inject_ad_removal_js()
