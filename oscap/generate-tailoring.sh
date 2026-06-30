#!/bin/bash
# =============================================================================
# Generate the XCCDF tailoring file (a.k.a. the "answer file") for the
# DISA RHEL 9 STIG profile, deselecting rules that are Not Applicable to a
# container base image.
#
# In OpenSCAP/SSG terms an "answer file" = an XCCDF *tailoring* file. Marking a
# rule Not Applicable is done by UN-SELECTING it (autotailor -u): its result
# becomes "notselected" and it is excluded from the compliance score. The
# rationale for each exclusion lives next to the rule id in
# oscap/not-applicable.rules and in oscap/not-applicable-rules.md.
#
# Usage:
#   generate-tailoring.sh [UNSELECT_LIST] [OUTPUT] [DATASTREAM] [BASE_PROFILE]
# =============================================================================
set -euo pipefail

UNSELECT_LIST="${1:-/scan/oscap/not-applicable.rules}"
OUTPUT="${2:-/scan/results/tailoring-rhel9-stig-container.xml}"
DATASTREAM="${3:-/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml}"
BASE_PROFILE="${4:-xccdf_org.ssgproject.content_profile_stig}"
NEW_PROFILE_ID="xccdf_mil.disa.stig_profile_stig_container"

command -v autotailor >/dev/null 2>&1 || { echo "ERROR: autotailor not found (install openscap-utils)" >&2; exit 2; }
[[ -f "$DATASTREAM" ]]    || { echo "ERROR: datastream not found: $DATASTREAM" >&2; exit 3; }
[[ -f "$UNSELECT_LIST" ]] || { echo "ERROR: unselect list not found: $UNSELECT_LIST" >&2; exit 4; }

mkdir -p "$(dirname "$OUTPUT")"

# Build the unselect args, skipping blank lines and # comments. autotailor in
# this SSG version uses short flags: -u (unselect), -p (new profile id),
# -o (output). The long form --unselect-rule is NOT accepted.
mapfile -t RULES < <(grep -vE '^\s*(#|$)' "$UNSELECT_LIST" | awk '{print $1}')
echo "==> deselecting ${#RULES[@]} Not-Applicable rules from $BASE_PROFILE"

ARGS=()
for r in "${RULES[@]}"; do
  ARGS+=(-u "$r")
done

autotailor \
  -o "$OUTPUT" \
  -p "$NEW_PROFILE_ID" \
  --title "DISA RHEL 9 STIG - Container Tailored (Not-Applicable rules deselected)" \
  "${ARGS[@]}" \
  "$DATASTREAM" \
  "$BASE_PROFILE"

echo "==> wrote tailoring (answer) file: $OUTPUT"
echo "==> tailored profile id          : $NEW_PROFILE_ID"
