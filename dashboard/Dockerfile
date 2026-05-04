FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iptables \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN pip install flask flask-socketio scapy pandas scikit-learn

WORKDIR /app
COPY . .

CMD ["python", "app.py"]
