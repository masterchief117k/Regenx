# predict_gui.py
import os
import joblib
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ── Monkey‐patch lief so Ember 0.1.0 doesn’t blow up ──
import lief
if not hasattr(lief, "bad_format"):
    if hasattr(lief, "BadFormat"):
        lief.bad_format = lief.BadFormat
    else:
        class bad_format(Exception):
            pass
        lief.bad_format = bad_format

import ember  # now safe to import

# --- Configuration for Ember 0.1.0 ---
MODEL_PATH = "malware_model.pkl"
EMBER_FEATURE_VERSION = 1  # must be 1 for Ember 0.1.0

# --- Initialization ---
try:
    model     = joblib.load(MODEL_PATH)
    extractor = ember.PEFeatureExtractor(EMBER_FEATURE_VERSION)
    print(f"[INIT] Loaded model and Ember feature-version {EMBER_FEATURE_VERSION}")
except Exception as e:
    tk.Tk().withdraw()
    messagebox.showerror("Init Error", str(e))
    raise

# --- Feature Extraction ---
def extract_features(path):
    try:
        raw   = open(path, "rb").read()
        feats = extractor.feature_vector(raw)
        print(f"[DEBUG] {path} → {len(feats)} features")
        return feats
    except Exception as e:
        print(f"[ERROR] Extracting {path}: {e}")
        messagebox.showerror("Feature Extraction Error", str(e))
        return None

# --- Prediction ---
def predict_file(path):
    if not os.path.exists(path):
        return "File not found."
    feats = extract_features(path)
    if feats is None:
        return "Extraction failed."
    try:
        X    = np.array(feats, dtype=float).reshape(1, -1)
        pred = model.predict(X)[0]
        prob = model.predict_proba(X)[0][pred]
        label = "Malicious" if pred == 1 else "Benign"
        return f"{label} (Confidence: {prob:.2%})"
    except Exception as e:
        print(f"[ERROR] Predicting {path}: {e}")
        messagebox.showerror("Prediction Error", str(e))
        return "Prediction failed."

# --- GUI ---
root = tk.Tk()
root.title("Malware Scanner")
root.geometry("540x260")

tk.Label(root, text="Select PE File to Scan", font=("Arial", 14)).pack(pady=12)

row = tk.Frame(root); row.pack(padx=10)
path_entry = tk.Entry(row, width=50); path_entry.pack(side=tk.LEFT)

def browse():
    p = filedialog.askopenfilename(
        filetypes=[("PE files", "*.exe;*.dll"), ("All files", "*.*")]
    )
    if p:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, p)

tk.Button(row, text="Browse", command=browse).pack(side=tk.LEFT, padx=5)

progress = ttk.Progressbar(root, mode="indeterminate")
progress.pack(fill="x", padx=10, pady=8)

result_label = tk.Label(root, text="", font=("Arial",12))
result_label.pack(pady=4)

def on_scan():
    p = path_entry.get().strip()
    if not p:
        messagebox.showwarning("No File", "Choose a file first.")
        return
    scan_btn.config(state="disabled")
    progress.start(); root.update_idletasks()

    res = predict_file(p)

    progress.stop()
    scan_btn.config(state="normal")
    result_label.config(text=res)

scan_btn = tk.Button(
    root, text="Scan File", command=on_scan,
    bg="#4CAF50", fg="white", font=("Arial",12)
)
scan_btn.pack(pady=6)

root.mainloop()