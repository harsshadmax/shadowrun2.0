FROM python:3.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace git \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir setuptools wheel
WORKDIR /work
