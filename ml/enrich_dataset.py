import pandas as pd
import numpy as np

print("[*] Dataset yükleniyor...")
df = pd.read_csv("/home/furkan/guardian-ai/data/dataset_v2.csv")
df = df.sort_values("timestamp").reset_index(drop=True)

print("[*] Zaman penceresi özellikleri hesaplanıyor...")

# Her satır için son 1 saniyedeki istatistikleri hesapla
results = []

for i, row in df.iterrows():
    t = row["timestamp"]
    src = row["src_ip"]

    # Son 1 saniyede aynı src_ip'den gelen paketler
    window = df[
        (df["timestamp"] >= t - 1) &
        (df["timestamp"] <= t) &
        (df["src_ip"] == src)
    ]

    results.append({
        "protocol": row["protocol"],
        "packet_size": row["packet_size"],
        "src_port": row["src_port"],
        "dst_port": row["dst_port"],
        "tcp_flags": row["tcp_flags"],
        "ttl": row["ttl"],
        # YENİ ÖZELLİKLER
        "pkts_per_sec": len(window),
        "unique_dst_ports": window["dst_port"].nunique(),
        "avg_packet_size": window["packet_size"].mean(),
        "std_packet_size": window["packet_size"].std() or 0,
        "label": row["label"]
    })

    if i % 500 == 0:
        print(f"  {i}/{len(df)} satır işlendi...")

enriched = pd.DataFrame(results)
enriched.to_csv("/home/furkan/guardian-ai/data/dataset_v2_enriched.csv", index=False)
print(f"[+] Zenginleştirilmiş dataset kaydedildi → {len(enriched)} satır")
