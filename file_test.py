import joblib
import pefile
import ember
import os
import sys
import ember 
# --- Configuration ---
MODEL_PATH = "model.pkl"  # Replace with your actual path
EMBER_FEATURE_VERSION = 2

# --- Load model and vectorizer ---
print(" Loading model...")
model = joblib.load(MODEL_PATH)
vectorizer = ember.FeatureHasher(feature_version=EMBER_FEATURE_VERSION)

# --- Feature extraction ---
def extract_features(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        raw_features = ember.extract_raw_features(pe, EMBER_FEATURE_VERSION)
        feature_vector = vectorizer.vectorize(raw_features)
        return feature_vector
    except Exception as e:
        print(f" Failed to extract features: {e}")
        return None

# --- Predict function ---
def predict(file_path):
    print(f"\n Scanning: {file_path}")
    if not os.path.exists(file_path):
        print(" File does not exist.")
        return

    features = extract_features(file_path)
    if features is None:
        print(" Unable to extract features from file.")
        return

    prediction = model.predict([features])[0]
    confidence = model.predict_proba([features])[0][prediction]

    label = " Malicious" if prediction == 1 else " Benign"
    print(f" Prediction: {label} (Confidence: {confidence:.2f})")

# --- Entry Point ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict_file.py <path_to_file>")
    else:
        predict(sys.argv[1])