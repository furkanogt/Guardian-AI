from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import pickle
import requests
import pandas as pd
import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
import subprocess
import sys
sys.path.insert(0, '/home/furkan/guardian-ai/dashboard')
from waf import analyze_request

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

with open("/home/furkan/guardian-ai/ml/model_v2.pkl", "rb") as f:
    model = pickle.load(f)

ip_window = defaultdict(list)
ip_counter = defaultdict(int)
ip_last_reset = defaultdict(float)
banned_ips = set()
ban_time = {}
alerts = []

WHITELIST = ["127.0.0.1", "192.168.100.2", "192.168.100.3", "192.168.100.10"]
RISK_THRESHOLD = 49
BAN_DURATION = 60

subprocess.run(["iptables", "-F", "INPUT"])

def ban_ip(ip, score, attack_type="DDoS"):
    if ip in banned_ips:
        return
    banned_ips.add(ip)
    ban_time[ip] = time.time()
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    alert = {
        "time": time.strftime("%H:%M:%S"),
        "ip": ip,
        "risk": score,
        "type": attack_type,
        "status": "banned"
    }
    alerts.insert(0, alert)
    if len(alerts) > 50:
        alerts.pop()
    socketio.emit("alert", alert)
    socketio.emit("stats", get_stats())

def check_bans():
    now = time.time()
    expired = [ip for ip, t in ban_time.items()
               if now - t > BAN_DURATION and ip in banned_ips]
    for ip in expired:
        banned_ips.discard(ip)
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        socketio.emit("stats", get_stats())

def get_stats():
    return {
        "banned_count": len(banned_ips),
        "alert_count": len(alerts),
        "banned_ips": list(banned_ips)
    }

def analyze(packet):
    if IP not in packet:
        return
    check_bans()
    now = time.time()
    src = packet[IP].src

    if src in WHITELIST or src in banned_ips:
        return

    # IP sayacını güncelle
    if now - ip_last_reset[src] > 1:
        ip_counter[src] = 0
        ip_last_reset[src] = now
    ip_counter[src] += 1

    ip_window[src].append({
        "time": now,
        "size": len(packet),
        "dst_port": packet[TCP].dport if TCP in packet else
                    packet[UDP].dport if UDP in packet else 0,
        "src_port": packet[TCP].sport if TCP in packet else
                    packet[UDP].sport if UDP in packet else 0,
        "flags": int(packet[TCP].flags) if TCP in packet else 0
    })

    window = [p for p in ip_window[src] if now - p["time"] <= 5]
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

    # SYN flood kuralı
    if ip_counter[src] > 100:
        pred = "attack"
        score = 95

    # Port tarama tespiti
    unique_ports = len(set(p["dst_port"] for p in window))
    if unique_ports > 15:
        pred = "attack"
        score = 88
        ban_ip(src, score, "Port Scan")

    # WAF kontrolü
    # WAF kontrolü
    if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
        try:
            from scapy.all import Raw
            if Raw in packet:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
                print(f"[DEBUG-WAF] payload: {payload[:100]}")
                if "GET" in payload or "POST" in payload:
                    parts = payload.split(" ")
                    url = parts[1] if len(parts) > 1 else ""
                    from urllib.parse import unquote
                    url = unquote(url)
                    payload = unquote(payload)
                    threats = analyze_request(src, "HTTP", url, {}, payload)
                    for threat in threats:
                        print(f"[WAF] {src} → {threat['type']} | Risk: %{threat['score']}")
                        ban_ip(src, threat['score'], threat['type'])
        except Exception as e:
            print(f"[WAF-ERROR] {e}")

    if pred == "attack" and score >= RISK_THRESHOLD:
        ban_ip(src, score)

    socketio.emit("packet", {
        "src": src,
        "dst": packet[IP].dst,
        "size": len(packet),
        "pred": pred,
        "score": score
    })

def start_sniffer():
    sniff(
        iface="guardian-br0",
        filter="ip",
        prn=analyze,
        store=False
    )

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/alerts")
def get_alerts():
    return jsonify(alerts)

@app.route("/api/stats")
@app.route("/api/geoip/<ip>")
def geoip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,isp", timeout=3)
        return jsonify(r.json())
    except:
        return jsonify({"country": "Bilinmiyor", "city": "Bilinmiyor"})
@app.route("/api/whitelist", methods=["GET"])
def get_whitelist():
    return jsonify(WHITELIST)

@app.route("/api/whitelist/add", methods=["POST"])
def add_whitelist():
    from flask import request
    data = request.get_json()
    ip = data.get("ip")
    if ip and ip not in WHITELIST:
        WHITELIST.append(ip)
        return jsonify({"status": "ok", "ip": ip})
    return jsonify({"status": "already_exists"})

@app.route("/api/whitelist/remove", methods=["POST"])
def remove_whitelist():
    from flask import request
    data = request.get_json()
    ip = data.get("ip")
    if ip in WHITELIST:
        WHITELIST.remove(ip)
        return jsonify({"status": "ok", "ip": ip})
    return jsonify({"status": "not_found"})
@app.route("/api/export")
def export_alerts():
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Zaman", "IP", "Tür", "Risk"])
    for alert in alerts:
        writer.writerow([alert["time"], alert["ip"], alert.get("type", "DDoS"), alert["risk"]])
    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=guardian_alerts.csv"}
    )

def api_stats():
    return jsonify(get_stats())

if __name__ == "__main__":
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()
    print("[*] Guardian-AI Dashboard başlatılıyor → http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
