import ember
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# --- CONFIGURATION ---
EMBER_DATA_DIR =r"C:\Users\kshit\Desktop\malwareml\data\ember2018\ember2018"
MODEL_OUT = "model_with_extractor_from_jsonl.pkl"
FEATURE_VERSION = 1

# --- Helper: load all train chunk files (0–5) ---
def load_all_train_chunks(base_path):
    X_all, y_all = [], []
    for i in range(6):
        chunk_path = f"{base_path}\train_features_{i}.jsonl"
        print(f"Loading {chunk_path}...")
        X, y = ember.read_vectorized_features(chunk_path)
        X_all.append(X)
        y_all.append(y)
    return np.vstack(X_all), np.concatenate(y_all)

# --- Load vectorized EMBER features ---
X_train, y_train = load_all_train_chunks(EMBER_DATA_DIR)
X_test, y_test = ember.read_vectorized_features(f"{EMBER_DATA_DIR}\test_features.jsonl")

print(f"\n[✔] Training samples: {len(y_train)}   |   Test samples: {len(y_test)}")
print(f"[ℹ] Feature vector size: {X_train.shape[1]}")

# --- Train classifier ---
clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
print("\nTraining RandomForest model…")
clf.fit(X_train, y_train)

# --- Evaluate ---
print("\n[Evaluation on test set]")
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# --- Bundle PE extractor (v1) for live scanning + model ---
extractor = ember.PEFeatureExtractor(version=FEATURE_VERSION)
joblib.dump((extractor, clf), MODEL_OUT)
print(f"\n Saved model + extractor to: {MODEL_OUT}")