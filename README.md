<p align="center"> <em>a single-file machine learning pipeline that detects phishing URLs using stacking ensembles, conformal prediction, and SHAP-style explanations — my machine learning exam project</em> </p><p align="center"> <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blueviolet?style=for-the-badge&logo=python"> <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge"> <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-ensemble%20%2B%20conformal-ff69b4?style=for-the-badge&logo=scikitlearn"> <img alt="Status" src="https://img.shields.io/badge/exam%20project-%E2%9C%94%20submitted-success?style=for-the-badge"> </p>

## this is my machine learning exam project and i honestly can't believe it actually works as well, it's called AI Phishing URL Detector and it's a single Python file that:

* **generates a synthetic phishing dataset on the fly (no downloads, no leaks)**
* **extracts 50 lexical/structural features from URLs**
* **trains a stacking ensemble (RandomForest + ExtraTrees + HistGradientBoosting → logistic meta-learner)**
* **calibrates the probabilities (sigmoid or isotonic)**
* **picks a decision threshold using cost-aware scanning**
* **wraps everything in conformal prediction with an ABSTAIN band**
* **explains every prediction with SHAP-style tree contributions and heuristic reasons**
* **runs a GUI (tkinter), a CLI, an HTTP API, and a file-watcher mode**
* **and it fits in one file because my professor said "one file, no exceptions lol."**

## what it actually does
### the machine learning
* **50 engineered features: url length, dot/hyphen/percent counts, entropy, subdomain depth, punycode, homoglyphs, brand distance (Levenshtein + Jaro-Winkler), suspicious TLDs, brand-in-subdomain, hex encoding, double extensions, redirect params, and more**
* **Stacked ensemble over RF + ExtraTrees + HGB with a logistic meta-learner trained on out-of-fold predictions**
* **Calibrated probabilities via CalibratedClassifierCV (sigmoid or isotonic)**
* **Multi-criteria threshold tuning: pick the threshold maximising F1, minimising expected cost, Youden-J, balanced accuracy, or MCC**
* **Bootstrap confidence intervals for every metric**
* **Split-conformal prediction at 1-α coverage → when both classes are included, the model ABSTAINS**
* **Hashed char n-grams (char_wb 2–4) as a lexical side-channel**
* **Adversarial probing — mutates phishing URLs (homoglyphs, TLD swaps, subdomain injection, path noise, percent-encoding, case flips) and measures recall drop**
* **Online learning from user feedback via SGDClassifier.partial_fit**
* **Active learning queue — keeps the most uncertain URLs for labelling**
* **Drift monitoring with PSI (Population Stability Index)**

### the interfaces
* **Tkinter GUI with tabs for analysis, batch scanning, metrics, dataset preview, drift, and settings**
* **CLI with train, scan, serve, repl, watch subcommands**
* **HTTP API with /predict, /health, /metrics endpoints**
* **STIX 2.1 export for sharing indicators with threat intel platforms**
* **SQLite audit log of every prediction + feedback**
* **Model registry with versioning**
* **Webhook firing when risk ≥ 80**
* **Dark and light themes**

## installation
#### you'll need Python 3.10+ and:
``` bash
pip install numpy pandas scikit-learn joblib
```
#### tkinter is usually bundled with Python; if you're on Linux and it's missing:
```
sudo apt install python3-tk    # debian/ubuntu
sudo dnf install python3-tkinter  # fedora
```
## clone & run
```
git clone https://github.com/aqeu/phishing-detector.git
cd phishing-detector
python main.py
```

## limitations (please read)
#### i put this in the model card too, but it deserves to be here:
* **trained on synthetic data — real-world performance is unmeasured**
* **lexical only — no DNS, WHOIS, page content, or TLS certificate analysis**
* **adversarial probing samples mutations, doesn't search them exhaustively**
* **no reputation feeds — it can't know a brand-new phishing domain is brand-new**
* **the online model is linear — it's a gentle nudge, not a replacement**
* **not a security product — don't wire it into a production filter without a lot of validation**
#### it's a solid exam project. it's not a commercial phishing detector. please don't treat it like one.
