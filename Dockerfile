# syntax=docker/dockerfile:1
# HackPilot configuration file
FROM kalilinux/kali-rolling

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
# This network drops long-lived HTTPS downloads mid-stream (IncompleteRead);
# make pip retry aggressively instead of failing the whole build on one blip.
ENV PIP_RETRIES=10
ENV PIP_DEFAULT_TIMEOUT=120

# Kali's http.kali.org redirector deterministically routes some package
# downloads to mirror.us.cdn-perfprod.com, which is unreachable from this
# network (TCP connect fails outright). Pin a single reachable static mirror
# instead of the redirector so no package can land on the dead backend.
RUN printf 'Types: deb\nURIs: http://kali.mirror.rafal.ca/kali/\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' > /etc/apt/sources.list.d/kali.sources

RUN apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=15 update && \
    apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=15 install -y \
    python3 \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    portaudio19-dev \
    git \
    curl \
    wget \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Deliberately NOT installing apt's python3-pip: it drags in python3-wheel and
# python3-packaging as dpkg-owned dependencies with no pip RECORD file, which
# pip can't cleanly upgrade later (uninstall-no-record-file) - and force-removing
# either one just breaks apt's dependency tree for every subsequent
# `apt-get install` instead (including every pentest tool installed below).
# Bootstrap a pip that's entirely pip's own, with zero dpkg entanglement.
RUN curl -sS -m 30 https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
    && python3 /tmp/get-pip.py --break-system-packages \
    && rm /tmp/get-pip.py

# Create working directory
WORKDIR /hackpilot

# Copy requirements first for better caching
COPY requirements.txt .

# Install CPU-only torch first. The default PyPI build drags in ~5GB of
# unused NVIDIA CUDA/cuDNN/cuBLAS wheels; this container has no GPU access,
# so pin the official CPU-only index before requirements.txt pulls torch itself.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages --index-url https://download.pytorch.org/whl/cpu "torch>=2.0.0,<3.0.0"

# Install Python dependencies. Cache mount means a retry after a mid-download
# network drop only re-fetches what wasn't already cached, instead of
# restarting this ~200-package install from scratch every time.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r requirements.txt --break-system-packages

# Copy the rest of the application. .dockerignore excludes local credentials,
# generated reports, caches and other host-only state from the build context.
COPY . .

# kali.mirror.rafal.ca (pinned above for the base apt-get layer) only carries a
# partial package set - it's missing most of the pentest tools' dependency
# chains (libpcap, perl/ruby/Qt libs), so install.sh's tool install silently
# installed zero tools. Switch back to the full kali.org CDN (with retries
# already configured) for install.sh's own apt-get, which has complete
# dependency coverage.
RUN printf 'Types: deb\nURIs: http://http.kali.org/kali/\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' > /etc/apt/sources.list.d/kali.sources

# Preserve the full host installer while using its deterministic container mode here.
# Container builds must not upgrade the base distribution, run a background model
# daemon, fetch a model, or create host-style global command links.
# Cache apt's downloaded .debs across rebuilds - install.sh has no cache mount
# of its own, so every source-code-only rebuild was re-downloading all ~24
# pentest tools and their dependencies from scratch (~800s) even though
# nothing about the apt install itself changed.
# docker-compose builds all 5 services' Dockerfiles in parallel, and they all
# hit this RUN instruction at once. sharing=locked deadlocked (each waited
# forever for a lock held by another of the five). The default shared mode
# avoided the deadlock but let concurrent writers race on the same apt
# cache/lists files, intermittently corrupting one build's view of the
# package index (nmap silently vanished from one image while installing
# fine in the other four). sharing=private gives each of the five builds
# its own isolated cache snapshot - no cross-service corruption or
# deadlock, at the cost of not sharing downloads between them within a
# single `docker compose build` run (rebuilds across separate invocations
# still benefit from whichever private cache instance BuildKit reuses).
RUN --mount=type=cache,target=/var/cache/apt,sharing=private \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=private \
    chmod +x install.sh && HACKPILOT_INSTALL_CONTEXT=container ./install.sh

# Keep both the historical external report path and the application-local runtime dirs.
RUN mkdir -p /reports /hackpilot/reports /hackpilot/logs /hackpilot/templates /hackpilot/database/migrations \
    && chmod 755 /reports /hackpilot/reports /hackpilot/logs /hackpilot/templates /hackpilot/database/migrations

# Expose web dashboard port
EXPOSE 5000

# Set entry point
ENTRYPOINT ["python3", "advance_hackpilot.py"]
