import pickle
import pandas as pd
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

print("[*] Model yükleniyor...")
with open("/home/furkan/guardian-ai/ml/model_v2.pkl", "rb") as f:
    model = pickle.load(f)
print("[+] Model hazır!")

ip_window = defaultdict(list)

# Whitelist — bu IP'ler asla saldırgan sayılmaz
WHITELIST = ["127.0.0.1", "192.168.100.1"]

# Risk eşiği — bu değerin altındaki tahminler görmezden gelinir
RISK_THRESHOLD = 50

def analyze(packet):
    if IP not in packet:
        return

    now = time.time()
    src = packet[IP].src

    if src in WHITELIST:
        return

    ip_window[src].append({
        "time": now,
        "size": len(packet),
        "dst_port": packet[TCP].dport if TCP in packet else
                    packet[UDP].dport if UDP in packet else 0,
        "src_port": packet[TCP].sport if TCP in packet else
                    packet[UDP].sport if UDP in packet else 0,
        "flags": int(packet[TCP].flags) if TCP in packet else 0
    })

    window = [p for p in ip_window[src] if now - p["time"] <= 1]
    ip_window[src] = window

    sizes = [p["size"] for p in window]
    row = {
        "protocol": packet[IP].proto,
        "packet_size": len(packet),
        "src_port": window[-1]["src_port"],
        "dst_port": window[-1]["dst_port"],
        "tcp_flags": window[-1]["flags"],
        "ttl": packet[IP].ttl,
        "pkts_per_sec": len(window),
        "unique_dst_ports": len(set(p["dst_port"] for p in window)),
        "avg_packet_size": sum(sizes) / len(sizes),
        "std_packet_size": pd.Series(sizes).std() or 0
    }

    df = pd.DataFrame([row])
    pred = model.predict(df)[0]
    prob = model.predict_proba(df)[0]
    score = int(max(prob) * 100)

    if pred == "attack" and score >= RISK_THRESHOLD:
        print(f"[!] SALDIRI | {src} | Risk: %{score} | {len(window)} paket/sn")
    elif pred == "normal" and len(window) % 30 == 0:
        print(f"[+] Normal  | {src} | %{score}")

print("[*] Canlı tespit başlatılıyor...")
print(f"[*] Arayüz: br-69df7f24270c | Eşik: %{RISK_THRESHOLD}")
print("[*] CTRL+C ile durdur\n")

# Sadece Docker ağını dinle
sniff(
    iface="br-69df7f24270c",
    filter="ip",
    prn=analyze,
    store=False
)
