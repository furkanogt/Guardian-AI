from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time
import os

packets = []
OUTPUT_PATH = "/data/traffic.csv"

def extract_features(packet):
    features = {
        "timestamp": time.time(),
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "packet_size": len(packet),
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0,
        "ttl": 0,
        "label": "attack"
    }
    if IP in packet:
        features["src_ip"] = packet[IP].src
        features["dst_ip"] = packet[IP].dst
        features["protocol"] = packet[IP].proto
        features["ttl"] = packet[IP].ttl
    if TCP in packet:
        features["src_port"] = packet[TCP].sport
        features["dst_port"] = packet[TCP].dport
        features["tcp_flags"] = int(packet[TCP].flags)
    elif UDP in packet:
        features["src_port"] = packet[UDP].sport
        features["dst_port"] = packet[UDP].dport
    return features

def on_packet(packet):
    if IP not in packet:
        return
    features = extract_features(packet)
    packets.append(features)
    print(f"[+] {features['src_ip']} → {features['dst_ip']} | Proto: {features['protocol']} | Boyut: {features['packet_size']} byte")
    if len(packets) % 50 == 0:
        df = pd.DataFrame(packets)
        if os.path.exists(OUTPUT_PATH):
            df.to_csv(OUTPUT_PATH, mode='a', header=False, index=False)
        else:
            df.to_csv(OUTPUT_PATH, mode='w', header=True, index=False)
        print(f"[*] {len(packets)} paket kaydedildi")

print("[*] Guardian-AI Sniffer başlatılıyor...")
sniff(filter="ip", prn=on_packet, store=False)
