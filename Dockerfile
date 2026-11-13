FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl dnsutils git bash nmap nikto whatweb gobuster whois \
    && rm -rf /var/lib/apt/lists/*

# Go tools
RUN curl -fsSL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"
RUN go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/hahwul/dalfox/v2@latest \
    && go install github.com/Chocapikk/wpprobe@latest \
    && rm -rf /root/.cache/go-build /tmp/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# App source
COPY . .

# Data volumes
RUN mkdir -p data/sessions data/recon data/schedules

EXPOSE 5000 5001 5002

# Start all three dashboards
COPY <<'ENTRYPOINT' /app/entrypoint.sh
#!/bin/bash
python3 xploiter_app.py &
cd /app/misc_dashboard && python3 misc_app.py &
cd /app && exec gunicorn app:app \
    --bind 0.0.0.0:5000 \
    --workers 4 \
    --threads 8 \
    --worker-class gthread \
    --timeout 300 \
    --keep-alive 75 \
    --log-level info
ENTRYPOINT
RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]
