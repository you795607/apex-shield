FROM python:3.11-slim

# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    tor \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o /tmp/nuclei.zip \
    && cd /tmp && unzip nuclei.zip && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei

# Install subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo "go not installed"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

# Start Tor in background then API
CMD sh -c "tor & uvicorn api.main:app --host 0.0.0.0 --port 8080"
