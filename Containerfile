# syntax=docker/dockerfile:1
# =============================================================================
# RHEL 9 / UBI 9 Hardened Base Image
# Ported from rhel8-hardened-base (UBI 8.10). DISA RHEL 9 STIG aligned.
# Compliance is verified out-of-band with OpenSCAP (see ./oscap).
# =============================================================================

# Pin to a digest after the first build for reproducibility:
#   docker inspect --format='{{index .RepoDigests 0}}' registry.access.redhat.com/ubi9/ubi:latest
FROM registry.access.redhat.com/ubi9/ubi:latest

# ---- metadata ----
LABEL \
  name="ubi9-hardened-base" \
  vendor="kelleyblackmore" \
  version="0.1.0" \
  release="2026-06-30" \
  summary="Hardened UBI9 base for downstream application images" \
  description="Patched, non-root ready, cache-cleaned, OpenShift-friendly permissions, DISA RHEL 9 STIG aligned" \
  io.k8s.description="Hardened UBI9 base, DISA RHEL 9 STIG aligned (verify with OpenSCAP)" \
  org.opencontainers.image.title="ubi9-hardened-base" \
  org.opencontainers.image.source="https://github.com/kelleyblackmore/rhel9-hardened-base" \
  org.opencontainers.image.licenses="MIT"

# ---- safety defaults ----
ENV \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  TZ=UTC

# Use bash shell to support pipefail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# ---- patch + minimal deps you actually want in a base ----
# Keep this list tiny. Many teams only need ca-certificates + tzdata.
RUN set -eux; \
    dnf -y update; \
    dnf -y install \
      ca-certificates \
      tzdata \
      jq; \
    # ---- attack-surface reduction: drop non-runtime packages that only add CVEs ----
    # These are not needed in a base image and carry the bulk of the image's CVEs
    # (editor, debugger, pip/setuptools wheels). Downstream can re-add if needed.
    # Tolerant: skip any that are absent or protected.
    for pkg in vim-minimal vim-common gdb gdb-gdbserver \
               python3-pip-wheel python3-setuptools-wheel; do \
      if rpm -q "$pkg" >/dev/null 2>&1; then dnf -y remove "$pkg" || true; fi; \
    done; \
    dnf -y clean all; \
    rm -rf /var/cache/dnf /var/cache/yum; \
    rm -rf /tmp/* /var/tmp/*

# ---- copy and execute STIG hardening scripts ----
# Supplementary container-aware hardening. The authoritative STIG controls are
# verified (and remediated) by OpenSCAP/SSG in ./oscap.
# NOTE: staged in /opt (NOT /tmp) on purpose -- stig-system-maintenance.sh runs
# `rm -rf /tmp/*`, which would delete the not-yet-run scripts if they lived in
# /tmp (the original rhel8-hardened-base bug: only the first script ever ran).
COPY scripts/ /opt/stig-scripts/
RUN set -eux; \
    chmod +x /opt/stig-scripts/*.sh; \
    /opt/stig-scripts/apply-all-stig.sh; \
    rm -rf /opt/stig-scripts

# ---- create a non-root user (OpenShift-friendly) ----
ARG APP_UID=10001
ARG APP_GID=0
ARG APP_USER=appuser
ARG APP_HOME=/app

RUN set -eux; \
    mkdir -p "${APP_HOME}"; \
    useradd \
      --uid "${APP_UID}" \
      --gid "${APP_GID}" \
      --home-dir "${APP_HOME}" \
      --no-create-home \
      --shell /sbin/nologin \
      "${APP_USER}"; \
    chown -R "${APP_UID}:${APP_GID}" "${APP_HOME}"; \
    chmod -R g=u "${APP_HOME}"

# ---- runtime defaults ----
WORKDIR /app
USER 10001

# Neutral entrypoint for a base image; downstream images set ENTRYPOINT/CMD.
CMD ["/bin/sh", "-lc", "echo 'Hardened UBI9 base image: override CMD/ENTRYPOINT in downstream image.' && sleep 3600"]
