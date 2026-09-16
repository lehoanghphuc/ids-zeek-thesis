#!/usr/bin/env python3
"""
retrain_reduced_model.py (v2 - dung dung 8 feature + cot nhan "Attack Type")

Train RandomForest va XGBoost tren CICIDS2017 cleaned, nhung CHI dung 8 feature
ma extract_conn_features.py trich duoc tu Zeek conn.log:

    Destination Port
    Flow Duration
    Total Fwd Packets
    Total Length of Fwd Packets
    Flow Bytes/s
    Flow Packets/s
    Fwd Packets/s
    Bwd Packets/s

Cot nhan trong dataset la "Attack Type" (KHONG phai "Label").

KHONG ghi de model 52-feature cu (xgb_multiclass_ids.pkl, rf_multiclass_ids.pkl,
label_encoder_ids.pkl) - model cu giu nguyen lam benchmark doi chieu.

Cach dung:
    # xem truoc ten cot that trong file de doi chieu (chay 1 lan dau tien)
    python3 retrain_reduced_model.py --data cicids2017_cleaned.csv --check-columns

    # train multiclass (7 lop: Normal/DoS/DDoS/Port Scanning/Brute Force/Bots/Web Attacks)
    python3 retrain_reduced_model.py --data cicids2017_cleaned.csv --task multiclass --model both

    # train binary (Normal vs Attack)
    python3 retrain_reduced_model.py --data cicids2017_cleaned.csv --task binary --model rf
"""

import argparse
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, classification_report

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
]

LABEL_CANDIDATES = ["Attack Type", "attack type", " Attack Type", "Label", "label"]


def load_data(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    return df


def find_label_col(df):
    for c in LABEL_CANDIDATES:
        if c.strip() in df.columns:
            return c.strip()
    raise ValueError(
        f"Khong tim thay cot nhan. 10 cot dau trong file: {list(df.columns)[:10]}\n"
        "Sua LABEL_CANDIDATES o dau file cho khop ten cot that."
    )


def build_xy(df, task):
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Thieu {len(missing)} cot so voi FEATURE_COLUMNS: {missing}\n"
            "Chay lai voi --check-columns de xem ten cot that."
        )
    label_col = find_label_col(df)

    X = df[FEATURE_COLUMNS].copy()
    X = X.replace([np.inf, -np.inf], np.nan)

    y_raw = df[label_col].astype(str).str.strip()

    # bo cac dong bi NaN o feature hoac nhan (giu dung phuong phap cleaning
    # nhu luc train model 52-feature goc: replace inf -> nan roi dropna)
    valid_mask = X.notna().all(axis=1) & y_raw.notna()
    X = X[valid_mask]
    y_raw = y_raw[valid_mask]

    if task == "binary":
        y_raw = y_raw.apply(lambda v: "BENIGN" if v.upper() in ("BENIGN", "NORMAL") else "ATTACK")

    return X, y_raw


def train_one(model_name, X_train, y_train):
    if model_name == "rf":
        clf = RandomForestClassifier(
            n_estimators=100, max_depth=25, random_state=42, n_jobs=-1, class_weight="balanced"
        )
    elif model_name == "xgb":
        from xgboost import XGBClassifier
        clf = XGBClassifier(
            n_estimators=100, max_depth=8, learning_rate=0.1, random_state=42, n_jobs=-1,
            objective="multi:softmax" if len(set(y_train)) > 2 else "binary:logistic",
            num_class=len(set(y_train)) if len(set(y_train)) > 2 else None,
            eval_metric="mlogloss" if len(set(y_train)) > 2 else "logloss",
        )
    else:
        raise ValueError(model_name)
    clf.fit(X_train, y_train)
    return clf


def evaluate(clf, X_test, y_test, le):
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    print(f"Accuracy: {acc:.4f} | F1-macro: {f1_macro:.4f} | F1-weighted: {f1_weighted:.4f}")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    return acc, f1_macro, f1_weighted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--task", choices=["binary", "multiclass"], default="multiclass")
    ap.add_argument("--model", choices=["rf", "xgb", "both"], default="both")
    ap.add_argument("--check-columns", action="store_true")
    ap.add_argument("--out-prefix", default="zeek", help="tien to ten file model (mac dinh: zeek -> rf_zeek_..., xgb_zeek_...)")
    args = ap.parse_args()

    df = load_data(args.data)

    if args.check_columns:
        print("Cac cot co trong file:")
        for c in df.columns:
            print(" -", c)
        return

    X, y_raw = build_xy(df, args.task)
    print(f"Sau khi loc NaN/inf: {len(X)} dong dung duoc / {len(df)} dong goc")

    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    print("Cac lop:", list(le.classes_))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models_to_run = ["rf", "xgb"] if args.model == "both" else [args.model]

    for m in models_to_run:
        print(f"\n=== Training {m.upper()} ({args.task}, {len(FEATURE_COLUMNS)} features) ===")
        try:
            clf = train_one(m, X_train, y_train)
        except ImportError:
            print(f"[bo qua {m}] chua cai xgboost - chay: pip3 install xgboost")
            continue
        evaluate(clf, X_test, y_test, le)

        model_path = f"{m}_{args.out_prefix}_{args.task}_ids.pkl"
        joblib.dump(clf, model_path)
        print(f"Da luu model: {model_path}")

    le_path = f"label_encoder_{args.out_prefix}_{args.task}.pkl"
    cols_path = f"feature_columns_{args.out_prefix}_{args.task}.pkl"
    joblib.dump(le, le_path)
    joblib.dump(FEATURE_COLUMNS, cols_path)
    print(f"Da luu: {le_path}, {cols_path}")


if __name__ == "__main__":
    main()