#!/bin/bash
# =============================================================================
# OpenSCAP DISA RHEL 9 STIG evaluation (run INSIDE the scanner container).
#
# Emits, into /scan/results:
#   - report.html         human-readable OpenSCAP report
#   - results-arf.xml     ARF (machine-readable, feeds STIG Viewer / eMASS)
#   - results-xccdf.xml   XCCDF results
#   - summary.txt         pass/fail/notapplicable counts + score
#
# Environment knobs:
#   PROFILE            default: xccdf_org.ssgproject.content_profile_stig
#   DATASTREAM         default: auto-detected ssg-rhel9-ds.xml
#   TAILORING_FILE     optional XCCDF tailoring ("answer") file
#   TAILORING_PROFILE  tailored profile id to evaluate (required with TAILORING_FILE)
#   REMEDIATE          "true" to apply SSG remediation, then re-evaluate
# =============================================================================
set -uo pipefail

OUT=/scan/results
mkdir -p "$OUT"

# ---- locate the SSG RHEL 9 datastream ------------------------------------
DATASTREAM="${DATASTREAM:-}"
if [[ -z "$DATASTREAM" ]]; then
  for c in \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds-1.2.xml; do
    [[ -f "$c" ]] && DATASTREAM="$c" && break
  done
fi
if [[ -z "$DATASTREAM" || ! -f "$DATASTREAM" ]]; then
  echo "ERROR: could not find an SSG RHEL 9 datastream (ssg-rhel9-ds.xml)." >&2
  echo "       Install scap-security-guide or pass DATASTREAM=/path/to/ssg-rhel9-ds.xml" >&2
  exit 3
fi

DEFAULT_PROFILE="xccdf_org.ssgproject.content_profile_stig"
PROFILE="${PROFILE:-$DEFAULT_PROFILE}"

# When a tailoring file is supplied, the profile to evaluate is the tailored id.
PROFILE_TO_USE="$PROFILE"
if [[ -n "${TAILORING_FILE:-}" ]]; then
  [[ -f "$TAILORING_FILE" ]] || { echo "ERROR: TAILORING_FILE '$TAILORING_FILE' not found" >&2; exit 4; }
  [[ -n "${TAILORING_PROFILE:-}" ]] || { echo "ERROR: set TAILORING_PROFILE when TAILORING_FILE is used" >&2; exit 4; }
  PROFILE_TO_USE="$TAILORING_PROFILE"
fi

echo "==> oscap version"; oscap --version | head -1
echo "==> datastream : $DATASTREAM"
echo "==> profile    : $PROFILE_TO_USE"
[[ -n "${TAILORING_FILE:-}" ]] && echo "==> tailoring  : $TAILORING_FILE"

# ---- assemble oscap args -------------------------------------------------
ARGS=(xccdf eval
  --profile "$PROFILE_TO_USE"
  --results-arf "$OUT/results-arf.xml"
  --results     "$OUT/results-xccdf.xml"
  --report      "$OUT/report.html")

[[ -n "${TAILORING_FILE:-}" ]] && ARGS+=(--tailoring-file "$TAILORING_FILE")
[[ "${REMEDIATE:-false}" == "true" ]] && { ARGS+=(--remediate); echo "==> remediation: ENABLED"; }

# oscap exit codes: 0 = all pass, 1 = error, 2 = at least one rule failed.
# 2 is normal output, not a harness failure.
oscap "${ARGS[@]}" "$DATASTREAM"
rc=$?
echo "==> oscap exit code: $rc"
[[ $rc -eq 1 ]] && { echo "ERROR: oscap reported an internal error" >&2; exit 1; }

# ---- summarize result distribution --------------------------------------
{
  echo "OpenSCAP DISA RHEL 9 STIG scan summary"
  echo "datastream : $DATASTREAM"
  echo "profile    : $PROFILE_TO_USE"
  echo "tailoring  : ${TAILORING_FILE:-<none>}"
  echo "remediate  : ${REMEDIATE:-false}"
  echo "----------------------------------------"
  for r in pass fail error unknown notapplicable notchecked notselected informational fixed; do
    n=$(grep -c "<result>$r</result>" "$OUT/results-xccdf.xml" 2>/dev/null)
    printf "%-14s %s\n" "$r" "${n:-0}"
  done
  echo "----------------------------------------"
  p=$(grep -c "<result>pass</result>" "$OUT/results-xccdf.xml" 2>/dev/null); p=${p:-0}
  f=$(grep -c "<result>fail</result>" "$OUT/results-xccdf.xml" 2>/dev/null); f=${f:-0}
  tot=$((p + f))
  if [[ $tot -gt 0 ]]; then
    printf "score (pass / pass+fail) : %s%%\n" "$(( 100 * p / tot ))"
  fi
} | tee "$OUT/summary.txt"

echo "==> wrote: $OUT/{report.html,results-arf.xml,results-xccdf.xml,summary.txt}"
