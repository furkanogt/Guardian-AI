# Guardian-AI Proje Durumu

## Tamamlanan Modüller

### Ağ Güvenliği (IPS)
- DDoS / SYN Flood tespiti ✓
- Otomatik IP ban (iptables) ✓
- IP sayaç tabanlı tespit ✓
- Port Scan tespiti ✓

### Web Güvenliği (WAF)
- SQL Injection tespiti ✓
- XSS tespiti ✓
- LFI tespiti ✓
- RCE, SSRF, XXE, IDOR tespiti ✓
- Brute Force koruması ✓
- URL decode desteği ✓
- Dashboard'da saldırı türü gösterimi ✓

## Yapılacaklar
- HTTPS desteği (reverse proxy)
- False positive azaltma
- Sistem bilgileri (CPU, RAM)

## Başlarken
source ~/guardian-ai/ml/venv/bin/activate
cd ~/guardian-ai && docker-compose up -d
sudo ~/guardian-ai/ml/venv/bin/python ~/guardian-ai/dashboard/app.py
