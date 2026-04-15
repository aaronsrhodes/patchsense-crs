# =============================================================================
# patchsense-crs Base Image (prepare phase)
# =============================================================================
# Contains Python 3.12, PatchSense package and all dependencies.
# Built once during prepare phase; used as base for validator.Dockerfile.
# =============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    rsync \
    curl \
    ca-certificates \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Python 3.12
RUN add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y \
    python3.12 python3.12-venv python3.12-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12
RUN ln -sf /usr/bin/python3.12 /usr/bin/python3 \
    && ln -sf python3 /usr/bin/python

# Install PatchSense and its dependencies.
# The patchsense package is copied from the repo root (context = repo root in bake).
COPY patchsense/ /opt/patchsense-crs/patchsense/
COPY pyproject.toml /opt/patchsense-crs/pyproject.toml
RUN pip3 install "/opt/patchsense-crs[mlx]"

# Install watchdog (required by libCRS)
RUN pip3 install watchdog>=6.0.0 requests>=2.28.0

# Git config
RUN git config --global user.email "patchsense@oss-crs.dev" \
    && git config --global user.name "PatchSense Validator" \
    && git config --global --add safe.directory '*'
