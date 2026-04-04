FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    strace tcpdump python3 python3-pip \
    poppler-utils libreoffice-core \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY runner.sh /runner.sh
RUN chmod +x /runner.sh

WORKDIR /samples
