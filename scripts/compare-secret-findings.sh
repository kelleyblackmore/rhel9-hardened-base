#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="${1:-results}"
NORMALIZED_DIR="${RESULTS_DIR}/normalized"
REPORT_FILE="${RESULTS_DIR}/secret-diff-report.txt"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to diff scanner outputs." >&2
  exit 1
fi

mkdir -p "${NORMALIZED_DIR}"

scanners=("trivy-secret" "trufflehog")

declare -A source_file=(
  [trivy-secret]="${RESULTS_DIR}/trivy-secrets.json"
  [trufflehog]="${RESULTS_DIR}/trufflehog-secrets.jsonl"
)

extract_trivy_secret_locations() {
  jq -r '
    .Results[]? as $result
    | ($result.Secrets // [])[]?
    | "\(($result.Target // .Target // "unknown")):\((.StartLine // .Start // .Line // 0))"
  ' "$1"
}

extract_trufflehog_locations() {
  jq -r '
    select(.SourceMetadata.Data.Filesystem.file?)
    | "\(.SourceMetadata.Data.Filesystem.file):\(.SourceMetadata.Data.Filesystem.line // 0)"
  ' "$1"
}

for scanner in "${scanners[@]}"; do
  in_file="${source_file[$scanner]}"
  out_file="${NORMALIZED_DIR}/${scanner}.locations.txt"

  if [[ ! -s "${in_file}" ]]; then
    : > "${out_file}"
    continue
  fi

  case "${scanner}" in
    trivy-secret)
      extract_trivy_secret_locations "${in_file}" ;;
    trufflehog)
      extract_trufflehog_locations "${in_file}" ;;
  esac | sort -u > "${out_file}" || true
done

{
  echo "Secret Diff Report"
  echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Results directory: ${RESULTS_DIR}"
  echo
  echo "Comparison basis: file:line locations of detected secret findings"
  echo
  echo "Per-scanner finding counts"

  max_count=-1
  min_count=999999999
  max_scanners=()
  min_scanners=()

  for scanner in "${scanners[@]}"; do
    count=$(wc -l < "${NORMALIZED_DIR}/${scanner}.locations.txt" | tr -d ' ')
    printf -- "- %-14s %s\n" "${scanner}:" "${count}"

    if (( count > max_count )); then
      max_count=${count}
      max_scanners=("${scanner}")
    elif (( count == max_count )); then
      max_scanners+=("${scanner}")
    fi

    if (( count < min_count )); then
      min_count=${count}
      min_scanners=("${scanner}")
    elif (( count == min_count )); then
      min_scanners+=("${scanner}")
    fi
  done

  file_a="${NORMALIZED_DIR}/trivy-secret.locations.txt"
  file_b="${NORMALIZED_DIR}/trufflehog.locations.txt"
  same=$(comm -12 "${file_a}" "${file_b}" | wc -l | tr -d ' ')
  only_a=$(comm -23 "${file_a}" "${file_b}" | wc -l | tr -d ' ')
  only_b=$(comm -13 "${file_a}" "${file_b}" | wc -l | tr -d ' ')

  echo
  echo "More findings: ${max_scanners[*]} (${max_count})"
  echo "Fewer findings: ${min_scanners[*]} (${min_count})"
  echo
  echo "Overlap summary"

  if cmp -s "${file_a}" "${file_b}"; then
    relation="same finding locations"
  else
    relation="different finding locations"
  fi

  echo "- trivy-secret vs trufflehog: same=${same}, only_trivy-secret=${only_a}, only_trufflehog=${only_b} (${relation})"
  echo
  echo "Normalized finding locations are under: ${NORMALIZED_DIR}/"
  echo "Note: secret scanners use different detectors, so overlap is based on detected location rather than secret type."
} > "${REPORT_FILE}"

echo "Wrote report: ${REPORT_FILE}"