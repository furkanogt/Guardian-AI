import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle

print("[*] Zenginleştirilmiş dataset yükleniyor...")
df = pd.read_csv("/home/furkan/guardian-ai/data/dataset_v2_enriched.csv")

print(f"[*] Toplam satır: {len(df)}")
print(f"[*] Normal: {len(df[df['label']=='normal'])}")
print(f"[*] Attack: {len(df[df['label']=='attack'])}")

# Yeni özellikler dahil
features = [
    "protocol", "packet_size", "src_port", "dst_port",
    "tcp_flags", "ttl", "pkts_per_sec", "unique_dst_ports",
    "avg_packet_size", "std_packet_size"
]

X = df[features]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"\n[*] Eğitim seti: {len(X_train)} satır")
print(f"[*] Test seti: {len(X_test)} satır")

print("\n[*] Model eğitiliyor...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42
)
model.fit(X_train, y_train)
print("[+] Model eğitimi tamamlandı!")

y_pred = model.predict(X_test)

print("\n=== SONUÇLAR ===")
print(classification_report(y_test, y_pred))

print("=== CONFUSION MATRIX ===")
cm = confusion_matrix(y_test, y_pred)
print(cm)
print(f"Doğru tahmin : {cm[0][0] + cm[1][1]}")
print(f"Yanlış tahmin: {cm[0][1] + cm[1][0]}")

print("\n=== ÖZELLİK ÖNEMLERİ ===")
for feature, importance in zip(features, model.feature_importances_):
    print(f"{feature:20} → %{importance*100:.1f}")

with open("/home/furkan/guardian-ai/ml/model_v2.pkl", "wb") as f:
    pickle.dump(model, f)
print("\n[+] Model kaydedildi → ml/model_v2.pkl")
