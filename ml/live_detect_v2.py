import pickle
import pandas as pd
import time
import subprocess
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

print("[*] Model yükleniyor...")
with open("/home/furkan/guardian-ai/ml/model_v2.pkl", "rb") as f:
    model = pickle.load(f)
print("[+] Model hazır!")

ip_window = defaultdict(list)
banned_ips = set()
ban_time = {}

WHITELIST = ["127.0.0.1", "192.168.100.2"]
RISK_THRESHOLD = 50
BAN_DURATION = 60  # saniye

def ban_ip(ip):
    if ip in banned_ips:
        return
    banned_ips.add(ip)
    ban_time[ip] = time.time()
    subprocess.run([
        "iptables", "-A", "INPUT",
        "-s", ip, "-j", "DROP"
    ])
    print(f"[X] IP BANLANDI → {ip}")

def unban_ip(ip):
    banned_ips.discard(ip)
    subprocess.run([
        "iptables", "-D", "INPUT",
        "-s", ip, "-j", "DROP"
    ])
    print(f"[✓] Ban kaldırıldı → {ip}")

def check_bans():
    now = time.time()
    expired = [ip for ip, t in ban_time.items()
               if now - t > BAN_DURATION and ip in banned_ips]
    for ip in expired:
        unban_ip(ip)

def analyze(packet):
    if IP not in packet:
        return

    check_bans()

    now = time.time()
    src = packet[IP].src

    if src in WHITELIST or src in banned_ips:
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
        ban_ip(src)
    elif pred == "normal" and len(window) % 30 == 0:
        print(f"[+] Normal  | {src} | %{score}")

print("[*] Guardian-AI v2 başlatılıyor...")
print(f"[*] Arayüz: br-69df7f24270c | Eşik: %{RISK_THRESHOLD} | Ban: {BAN_DURATION}sn")
print("[*] CTRL+C ile durdur\n")

sniff(
    iface="br-69df7f24270c",
    filter="ip dst 192.168.100.10",
    prn=analyze,
    store=False
)
