# Guardian-AI Proje Durumu

## Tamamlanan Modüller

### Ağ Güvenliği
- DDoS / SYN Flood tespiti ✓
- Otomatik IP ban (iptables) ✓
- IP sayaç tabanlı tespit ✓

### Web Güvenliği (WAF)
- SQL Injection tespiti ✓
- XSS tespiti ✓
- LFI tespiti ✓
- URL decode desteği ✓
- Dashboard'da saldırı türü gösterimi ✓

## Yapılacaklar
- Brute force tespiti
- Port tarama tespiti
- HTTPS desteği (reverse proxy)
- False positive azaltma

## Başlarken
source ~/guardian-ai/ml/venv/bin/activate
cd ~/guardian-ai && docker-compose up -d
sudo ~/guardian-ai/ml/venv/bin/python ~/guardian-ai/dashboard/app.py

## Arkadaş Bilgisayarı
ssh ekin@10.171.197.93
sudo python3 ~/guardian-ai/dashboard/app.py
