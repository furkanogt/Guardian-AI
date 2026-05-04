# Guardian-AI
ML-Powered IPS & WAF Security Platform

Makine ögrenmesi ve derin paket incelemesi kullanarak ag ve web saldirilarini gercek zamanli tespit eden, otomatik IP engelleme yapan kapsamli bir guvenlik platformu.

## Ozellikler

### Ag Guvenligi (IPS)
- DDoS / SYN Flood tespiti (Random Forest, yuzde 100 dogruluk)
- Port Scan tespiti
- Otomatik IP engelleme (iptables)

### Web Guvenligi (WAF)
- SQL Injection, XSS, LFI, RCE, SSRF, XXE, IDOR tespiti
- Brute Force korumasi
- URL decode destegi

### Dashboard
- Gercek zamanli trafik grafigi
- Saldiri turleri istatistikleri
- Cografi IP haritasi
- Whitelist yonetimi
- CSV export

## Teknolojiler
Python, Flask, Scapy, Scikit-learn, Docker, iptables, JavaScript, Chart.js

## Kurulum
git clone https://github.com/furkanogt/Guardian-AI.git
cd Guardian-AI
docker-compose up -d
