# 🛡️ Community-Driven Phishing Detection System (Version 1)

## 📌 Overview

The **Community-Driven Phishing Detection System** is a real-time cybersecurity solution that detects phishing websites using a hybrid approach combining **Machine Learning** and **User-Generated Intelligence**.

Unlike traditional systems that rely only on static blacklists or pre-trained models, this project allows users to actively contribute by reporting suspicious websites, making detection more adaptive and responsive to new threats.

---

## 🚀 Key Features

* 🔍 **Real-Time URL Analysis** using Machine Learning
* 👥 **User Reporting System** for suspicious websites
* 📊 **Dynamic Trust Score** based on multiple factors
* 🌐 **Browser Extension Integration**
* ⚡ **Fast and Lightweight Backend (Flask API)**
* 🧠 **Hybrid Detection (ML + Rule-Based System)**

---

## 🧠 How It Works

```
User visits a website
        │
        ▼
Browser Extension captures URL
        │
        ▼
Flask Backend (/analyze API)
        │
        ├── ML Model (URL features + TF-IDF)
        ├── Rule-based checks
        ├── Domain age (WHOIS)
        │
        ▼
Trust Score Generated (1–10)
        │
        ├── 8–10 → Safe ✅
        ├── 5–7 → Suspicious ⚠️
        └── 1–4 → Phishing ❌
```

---

## 🏗️ Project Structure

```
Community-Driven-Phishing-Detection/
│
├── Phishing-Detection-Extension/
│   ├── app.py
│   ├── train_model.py
│   ├── features.py
│   ├── intelligence.py
│   ├── db.py
│   ├── model.pkl
│   ├── vectorizer.pkl
│   ├── extention/
│
├── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repository

```
git clone https://github.com/tejasreekaranp/Community-Driven-Phishing-Detection.git
cd Community-Driven-Phishing-Detection
```

---

### 2. Create Virtual Environment

```
python -m venv venv
```

Activate:

```
venv\Scripts\activate
```

---

### 3. Install Dependencies

```
python -m pip install flask flask-cors flask-sqlalchemy xgboost scikit-learn joblib numpy scipy python-whois
```

---

### 4. Train Model (Optional if model.pkl exists)

```
cd Phishing-Detection-Extension
python train_model.py
```

---

### 5. Run Backend

```
python app.py
```

Server runs at:

```
http://127.0.0.1:5000
```

---

### 6. Load Chrome Extension

1. Open Chrome
2. Go to:

```
chrome://extensions/
```

3. Enable **Developer Mode**
4. Click **Load Unpacked**
5. Select:

```
extention/
```

---

## 📡 API Endpoint

**GET /analyze**

Example:

```
http://127.0.0.1:5000/analyze?url=https://example.com
```

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

---

## 🆕 Innovation

* Combines **Machine Learning + Community Intelligence**
* Introduces **Trust Score Mechanism**
* Enables **User Participation in Cybersecurity**
* Detects **Zero-Day Phishing Attacks**

---

## ⚠️ Limitations

* Requires user participation for better accuracy
* Initial dataset may be limited
* Possible false reporting

---

## 🔮 Future Scope

* Mobile application support
* Email phishing detection
* AI-based behavioral analysis
* Blockchain-based secure reporting

---

## 👨‍💻 Authors

* Teja Sri Karan
* Team Members

---

## 📜 License

This project is for academic and educational purposes.

---

## ⭐ Version

**Version 1.0**
