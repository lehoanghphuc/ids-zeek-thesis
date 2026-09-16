import argparse
import pandas as pd
import numpy as np
import joblib
 
 
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True, help="CSV tu extract_conn_features.py")
    ap.add_argument("--model", required=True)
    ap.add_argument("--label-encoder", required=True)
    ap.add_argument("--out", default="predictions.csv")
    args = ap.parse_args()
 
    clf = joblib.load(args.model)
    le = joblib.load(args.label_encoder)
    feature_columns = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Length of Fwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Fwd Packets/s",
        "Bwd Packets/s",
    ]
 
    df = pd.read_csv(args.features)
 
    meta_cols = [c for c in df.columns if c.startswith("_")]
    missing = [c for c in feature_columns if c not in df.columns]
    if missing:
        raise ValueError(f"File features thieu cot: {missing}")
 
    X = df[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0)
 
    preds = clf.predict(X)
    labels = le.inverse_transform(preds)
 
    df_out = df[meta_cols].copy() if meta_cols else pd.DataFrame(index=df.index)
    df_out["predicted_label"] = labels
 
    # neu model ho tro predict_proba, them cot do tin cay
    if hasattr(clf, "predict_proba"):
        proba = clf.predict_proba(X)
        df_out["confidence"] = proba.max(axis=1)
 
    df_out.to_csv(args.out, index=False)
    print(f"Da du doan {len(df_out)} connection -> {args.out}\n")
 
    print("Thong ke ket qua:")
    print(df_out["predicted_label"].value_counts())
 
    # in vai dong canh bao (khong phai BENIGN/Normal) de demo nhanh
    alert_mask = ~df_out["predicted_label"].str.upper().isin(["BENIGN", "NORMAL"])
    alerts = df_out[alert_mask]
    if len(alerts):
        print(f"\n>>> {len(alerts)} connection bi gan nhan bat thuong, vi du:")
        print(alerts.head(10).to_string(index=False))
    else:
        print("\nKhong phat hien connection bat thuong nao trong file nay.")
 
 
if __name__ == "__main__":
    main()
