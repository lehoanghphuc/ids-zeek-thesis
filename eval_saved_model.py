#!/usr/bin/env python3
"""In lai accuracy/F1 tu model da luu (khong train lai), tai su dung dung
train/test split cu (random_state=42 giong het luc train)."""
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report

DATA = "~/cicids2017_reduced.csv"
MODEL = "rf_zeek_multiclass_ids.pkl"
LE = "label_encoder_zeek_multiclass.pkl"
COLS = "feature_columns_zeek_multiclass.pkl"

clf = joblib.load(MODEL)
le = joblib.load(LE)
cols = joblib.load(COLS)

df = pd.read_csv(DATA, low_memory=False)
df.columns = [c.strip() for c in df.columns]

X = df[cols].replace([np.inf, -np.inf], np.nan)
y_raw = df["Attack Type"].astype(str).str.strip()
mask = X.notna().all(axis=1) & y_raw.notna()
X, y_raw = X[mask], y_raw[mask]
y = le.transform(y_raw)

_, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

y_pred = clf.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"F1-macro: {f1_score(y_test, y_pred, average='macro'):.4f}")
print(f"F1-weighted: {f1_score(y_test, y_pred, average='weighted'):.4f}")
print(classification_report(y_test, y_pred, target_names=le.classes_))