FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iputils-ping \
    net-tools \
    hping3 \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN pip install scapy pandas

WORKDIR /app
CMD ["python", "sniff.py"]
