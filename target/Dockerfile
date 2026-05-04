FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nginx \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
