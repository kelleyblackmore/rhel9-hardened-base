#!/usr/bin/env bash
# =============================================================================
# End-to-end OpenSCAP STIG workflow for the hardened UBI9 base.
#
#   1. build the hardened base image (remediation baked in)
#   2. build the scanner image (base + openscap-scanner + scap-security-guide)
#   3. regenerate the tailoring ("answer") file from oscap/not-applicable.rules
#   4. BASELINE scan  (no tailoring)            -> oscap/results/baseline/
#   5. TAILORED scan  (answer file applied)     -> oscap/results/tailored/
#
# Results are pulled out with `docker cp` (no bind mounts -> identical on
# Windows, macOS, and Linux).  Requires docker (or set RUNTIME=podman).
# Run from the repo root:  ./oscap/run-oscap.sh
# =============================================================================
set -euo pipefail

RUNTIME="${RUNTIME:-docker}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE_BASE="${IMAGE_BASE:-localhost/rhel9-hardened:latest}"
IMAGE_SCAN="${IMAGE_SCAN:-localhost/rhel9-hardened-scan:latest}"
RESULTS="$REPO_ROOT/oscap/results"
TAILOR_PROFILE="xccdf_mil.disa.stig_profile_stig_container"

echo "### 1/5 build hardened base"
"$RUNTIME" build -f Containerfile -t "$IMAGE_BASE" .

echo "### 2/5 build scanner image"
"$RUNTIME" build -f oscap/Containerfile.scan --build-arg BASE_IMAGE="$IMAGE_BASE" -t "$IMAGE_SCAN" .

echo "### 3/5 (re)generate the tailoring (answer) file"
"$RUNTIME" rm -f rhel9-stig-tailor >/dev/null 2>&1 || true
"$RUNTIME" run --name rhel9-stig-tailor --entrypoint /usr/local/bin/generate-tailoring.sh \
  "$IMAGE_SCAN" /scan/oscap/not-applicable.rules /scan/results/tailoring-rhel9-stig-container.xml
mkdir -p "$REPO_ROOT/oscap/tailoring"
"$RUNTIME" cp rhel9-stig-tailor:/scan/results/tailoring-rhel9-stig-container.xml \
  "$REPO_ROOT/oscap/tailoring/tailoring-rhel9-stig-container.xml"
"$RUNTIME" rm -f rhel9-stig-tailor >/dev/null 2>&1 || true
echo "==> answer file -> oscap/tailoring/tailoring-rhel9-stig-container.xml"

echo "### 4/5 baseline STIG scan (no tailoring)"
"$RUNTIME" rm -f rhel9-stig-baseline >/dev/null 2>&1 || true
"$RUNTIME" run --name rhel9-stig-baseline "$IMAGE_SCAN" || true
mkdir -p "$RESULTS/baseline"
"$RUNTIME" cp rhel9-stig-baseline:/scan/results/. "$RESULTS/baseline/"
"$RUNTIME" rm -f rhel9-stig-baseline >/dev/null 2>&1 || true

echo "### 5/5 tailored STIG scan (answer file applied)"
# Generate the answer file AND evaluate against it in the same container, so the
# freshly generated tailoring is guaranteed to be the one used.
"$RUNTIME" rm -f rhel9-stig-tailored >/dev/null 2>&1 || true
"$RUNTIME" run --name rhel9-stig-tailored --entrypoint bash "$IMAGE_SCAN" -c "
  /usr/local/bin/generate-tailoring.sh /scan/oscap/not-applicable.rules /scan/results/tailoring-rhel9-stig-container.xml
  TAILORING_FILE=/scan/results/tailoring-rhel9-stig-container.xml \
  TAILORING_PROFILE=$TAILOR_PROFILE \
  REMEDIATE=false /usr/local/bin/scan.sh
" || true
mkdir -p "$RESULTS/tailored"
"$RUNTIME" cp rhel9-stig-tailored:/scan/results/. "$RESULTS/tailored/"
"$RUNTIME" rm -f rhel9-stig-tailored >/dev/null 2>&1 || true

echo
echo "### DONE"
echo "--- baseline (no tailoring) ---"; cat "$RESULTS/baseline/summary.txt" 2>/dev/null || true
echo
echo "--- tailored (answer file) ---";  cat "$RESULTS/tailored/summary.txt" 2>/dev/null || true
echo
echo "HTML reports:"
echo "  $RESULTS/baseline/report.html"
echo "  $RESULTS/tailored/report.html"
