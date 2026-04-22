# 🛡️ Phishing Detector — Improved v2.0

## What was fixed

| Component | Old Problem | Fix Applied |
|---|---|---|
| `features.py` | Only 9 weak features | 22 strong features incl. entropy, brand spoofing, abuse TLDs |
| `app.py` | Bad score smoothing, always biased safe | Proper ML + rule-based hybrid, trusted domain shortcut |
| `train_model.py` | Wrong class upsampling, basic config | Correct balancing, char n-grams, tuned XGBoost |
| `background.js` | Alert on score≤5, blocked chrome:// pages | Smart skip logic, badge icons, confirm-or-go-back dialog |
| `popup.js/html` | No loading state, plain display | Spinner, color-coded card, domain age + confidence shown |
| `intelligence.py` | Could hang Flask request | Timeout protection with SIGALRM |

---

## Setup

### 1. Install Python dependencies
```bash
pip install flask flask-cors xgboost scikit-learn joblib numpy scipy python-whois
```

### 2. Retrain the model (recommended after code changes)
```bash
python train_model.py
```
This will regenerate `model.pkl` and `vectorizer.pkl`.

### 3. Start the Flask backend
```bash
python app.py
```
Server runs at `http://127.0.0.1:5000`

### 4. Load the extension in Chrome
1. Go to `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `extention/` folder

---

## How it works

```
Browser tab loads URL
        │
        ▼
background.js  ──────►  Skip chrome:// / internal pages
        │
        ▼
Flask /analyze endpoint
        │
        ├── ML model (TF-IDF char n-grams + 22 URL features → XGBoost)
        ├── Rule-based checks (IP host, @, abuse TLD, brand spoofing, etc.)
        └── Domain age (WHOIS with 4s timeout)
        │
        ▼
Weighted hybrid score (1–10)
        │
        ├── ≥8  →  Safe   (green badge ✓)
        ├── 5–7 →  Suspicious (orange badge ?)
        └── ≤4  →  Phishing (red badge ! + confirm dialog)
```

---

## API

`GET http://127.0.0.1:5000/analyze?url=<encoded_url>`

Response:
```json
{
  "url": "https://example.com",
  "score": 9,
  "status": "Safe",
  "ml_confidence": 4.2,
  "domain_age_days": 9832
}
```
