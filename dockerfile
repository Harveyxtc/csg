FROM debian:stable-slim

RUN apt update && apt install -y \
    python3 python3-pip \
    clamav clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# ClamAV runtime dir
RUN mkdir -p /run/clamav && \
    chown -R clamav:clamav /run/clamav

WORKDIR /app

# 👇 COPY ONLY requirements first (this is the big fix)
COPY requirements.txt .

RUN pip3 install --break-system-packages -r requirements.txt

# 👇 Copy the rest AFTER (so code changes don’t trigger reinstall)
COPY . /app

# Custom signatures
COPY signatures_custom.ndb /var/lib/clamav/

RUN chmod +x /app/start.sh

CMD ["bash", "/app/start.sh"]
