# Regenx — Polymorphic Malware Detector

Machine-learning malware detection for Windows executables, built during research at **IIITM Gwalior**.
Regenx reads a `.exe` or `.dll` **without running it**, turns its structure into 2,381 numeric features,
and a gradient-boosted model estimates how likely it is to be malicious.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![LightGBM](https://img.shields.io/badge/LightGBM-2C7BB6?style=flat-square)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)
![LIEF](https://img.shields.io/badge/LIEF-PE%20parsing-555555?style=flat-square)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-4CAF50?style=flat-square)

---

## Why this matters

Polymorphic malware rewrites its own bytes with every copy, so hash- and signature-based scanners
miss each new variant until it has been catalogued. Regenx instead learns from **how a file is built**
(its headers, sections, imports, strings and byte statistics), which stays informative even when the
exact bytes change. That lets it score samples that no antivirus database has seen yet.

## How it works

```
 .exe / .dll ──► LIEF parser ──► EMBER feature extractor ──► LightGBM model ──► P(malicious)
                                  (2,381 features)            (100 trees)        Benign / Malicious
```

| Stage | What happens |
| :-- | :-- |
| **Parse** | [LIEF](https://lief.re) reads the Portable Executable format: headers, sections, imports and exports. |
| **Featurise** | The [EMBER](https://github.com/elastic/ember) v2 extractor builds a 2,381-value vector: byte and byte-entropy histograms, printable-string statistics, COFF/optional-header fields, per-section size and entropy, hashed import/export tables and data directories. |
| **Classify** | A LightGBM gradient-boosted tree ensemble (100 trees, 31 leaves each) outputs the probability that the file is malicious. |
| **Decide** | Scores at or above `0.5` are reported as **Malicious**, below as **Benign**, with the confidence shown. |

## Training data

The model is trained on the **EMBER 2018** benchmark from Elastic, about **1 million** labelled Windows
executables split into training and held-out test sets. Only pre-computed features are used, so no live
malware is needed to train or evaluate.

## Repository layout

| File | Purpose |
| :-- | :-- |
| `predict_gui.py` | Desktop scanner: pick a file, get a Benign / Malicious verdict with confidence |
| `malware_model.pkl` | Trained LightGBM model used by the scanner |
| `malware_detector.txt` | The same model in LightGBM's readable text format |
| `test.py` | Trains the LightGBM model on EMBER 2018 and saves both files above |
| `modelv2.py` | Alternative Random Forest model, with a full classification report on the test set |
| `file_test.py` | Command-line scanner for a single file |
| `extractor.py` | Safely unpacks the EMBER dataset archive |
| `build/lib/ember/` | Bundled copy of the EMBER feature-extraction library |

## Quick start

> EMBER dates from 2018 and relies on older library behaviour. Use **Python 3.10** (what the model was
> trained with) and keep **NumPy below 1.24**, which `requirements.txt` enforces. LIEF 0.9.0 reproduces
> EMBER's features exactly but only installs on older Python; newer LIEF works through the scanner's
> compatibility shim, and EMBER prints a warning that features may differ slightly.

```bash
git clone https://github.com/masterchief117k/Regenx.git
cd Regenx
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Scan a file with the desktop app**

```bash
python predict_gui.py
```

Click **Browse**, choose a `.exe` or `.dll`, then **Scan File**.

**Retrain the model**

1. Download the EMBER 2018 dataset from the [EMBER repository](https://github.com/elastic/ember) and unpack it with `python extractor.py`.
2. Point the data path in `test.py` at the unpacked folder.
3. The first time only, uncomment the `ember.create_vectorized_features(...)` line in `test.py`. It converts the raw feature files into the arrays training reads.
4. Run `python test.py`. This writes `malware_detector.txt` and `malware_model.pkl`.

For the Random Forest comparison and its precision/recall report, set the path in `modelv2.py` and run it.

## Limitations

- **Static analysis only.** Behaviour that appears only at runtime, such as downloaded payloads, isn't seen.
- **Dataset age.** EMBER 2018 reflects malware of that period; retraining on newer samples would improve coverage.
- **Fixed threshold.** `0.5` balances both error types; security teams often raise it to cut false alarms.

## Safety

Only scan files on a machine you're comfortable using for analysis. Regenx never executes the file it
scans, but you should still handle suspected malware inside a virtual machine.
