import pandas as pd
import numpy as np
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.utils import resample

from xgboost import XGBClassifier
from scipy.sparse import hstack, csr_matrix

import joblib
from features import extract_features

print("📦 Loading data...")

# ── Load & merge datasets ─────────────────────────────────────────────────────
df_main = pd.read_csv("url.csv")

# Normalize column names
df_main.columns = df_main.columns.str.strip().str.lower()
if "url" in df_main.columns and "URL" not in df_main.columns:
    df_main.rename(columns={"url": "URL"}, inplace=True)

# Map labels
label_map = {
    "benign": 0, "legitimate": 0, "safe": 0, "good": 0, "0": 0, 0: 0,
    "phishing": 1, "malicious": 1, "bad": 1, "1": 1, 1: 1
}
df_main["label"] = df_main["label"].map(label_map)
df_main = df_main.dropna(subset=["label"])
df_main["label"] = df_main["label"].astype(int)

print(f"✅ Loaded {len(df_main)} rows | Safe: {(df_main.label==0).sum()} | Phishing: {(df_main.label==1).sum()}")

# ── Balance classes ───────────────────────────────────────────────────────────
df_safe = df_main[df_main.label == 0]
df_phish = df_main[df_main.label == 1]

# Upsample the MINORITY class to match the majority
target_size = max(len(df_safe), len(df_phish))

df_safe_bal = resample(df_safe, replace=True, n_samples=target_size, random_state=42)
df_phish_bal = resample(df_phish, replace=True, n_samples=target_size, random_state=42)

df = pd.concat([df_safe_bal, df_phish_bal]).sample(frac=1, random_state=42).reset_index(drop=True)

print(f"🔄 Balanced dataset: {len(df)} rows ({target_size} each class)")

# ── Domain extraction ─────────────────────────────────────────────────────────
def get_domain(url):
    try:
        return urlparse(str(url)).netloc.lower()
    except:
        return ""

df["domain"] = df["URL"].apply(get_domain)

# ── Text features (TF-IDF on domain) ─────────────────────────────────────────
print("🔤 Extracting TF-IDF features...")
vectorizer = TfidfVectorizer(
    analyzer="char_wb",   # character n-grams — better for detecting obfuscated domains
    ngram_range=(2, 4),
    max_features=5000,
    sublinear_tf=True
)
X_text = vectorizer.fit_transform(df["domain"])

# ── Structured features ───────────────────────────────────────────────────────
print("🌐 Extracting structured URL features...")
extra_feats = np.array([extract_features(u) for u in df["URL"]])
extra_sparse = csr_matrix(extra_feats)

# ── Combine ───────────────────────────────────────────────────────────────────
X_final = hstack([X_text, extra_sparse])
y = df["label"].values

# ── Train/test split ──────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_final, y, test_size=0.2, random_state=42, stratify=y
)

# ── Model ─────────────────────────────────────────────────────────────────────
print("🏋️ Training XGBoost model...")
model = XGBClassifier(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.08,
    subsample=0.85,
    colsample_bytree=0.85,
    min_child_weight=3,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.5,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=False
)

# ── Evaluation ────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("\n📊 MODEL PERFORMANCE:")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
print(f"🎯 ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")

# ── Save ──────────────────────────────────────────────────────────────────────
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("\n✅ MODEL TRAINED & SAVED — model.pkl, vectorizer.pkl")
