#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="${1:-results}"
NORMALIZED_DIR="${RESULTS_DIR}/normalized"
REPORT_FILE="${RESULTS_DIR}/cve-diff-report.txt"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to diff scanner outputs." >&2
  exit 1
fi

mkdir -p "${NORMALIZED_DIR}"

scanners=("grype" "trivy" "docker-scout")

declare -A source_file=(
  [grype]="${RESULTS_DIR}/grype.json"
  [trivy]="${RESULTS_DIR}/trivy.json"
  [docker-scout]="${RESULTS_DIR}/docker-scout.sarif"
)

extract_grype() {
  jq -r '.matches[]?.vulnerability.id // empty' "$1"
}

extract_trivy() {
  jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID // empty' "$1"
}

extract_docker_scout() {
  jq -r '(.runs[]?.tool.driver.rules[]?.id // empty), (.runs[]?.results[]?.ruleId // empty)' "$1"
}

for scanner in "${scanners[@]}"; do
  in_file="${source_file[$scanner]}"
  out_file="${NORMALIZED_DIR}/${scanner}.cves.txt"

  if [[ ! -s "${in_file}" ]]; then
    : > "${out_file}"
    continue
  fi

  case "${scanner}" in
    grype)
      extract_grype "${in_file}" ;;
    trivy)
      extract_trivy "${in_file}" ;;
    docker-scout)
      extract_docker_scout "${in_file}" ;;
  esac | grep -E '^CVE-[0-9]{4}-[0-9]+' | sort -u > "${out_file}" || true

done

{
  echo "CVE Diff Report"
  echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Results directory: ${RESULTS_DIR}"
  echo
  echo "Per-scanner CVE counts"

  max_count=-1
  min_count=999999999
  max_scanners=()
  min_scanners=()

  for scanner in "${scanners[@]}"; do
    count=$(wc -l < "${NORMALIZED_DIR}/${scanner}.cves.txt" | tr -d ' ')
    printf -- "- %-12s %s\n" "${scanner}:" "${count}"

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

  echo
  echo "More CVEs found: ${max_scanners[*]} (${max_count})"
  echo "Fewer CVEs found: ${min_scanners[*]} (${min_count})"
  echo
  echo "Pairwise comparison (same/only)"

  for ((i = 0; i < ${#scanners[@]}; i++)); do
    for ((j = i + 1; j < ${#scanners[@]}; j++)); do
      a="${scanners[i]}"
      b="${scanners[j]}"
      file_a="${NORMALIZED_DIR}/${a}.cves.txt"
      file_b="${NORMALIZED_DIR}/${b}.cves.txt"

      same=$(comm -12 "${file_a}" "${file_b}" | wc -l | tr -d ' ')
      only_a=$(comm -23 "${file_a}" "${file_b}" | wc -l | tr -d ' ')
      only_b=$(comm -13 "${file_a}" "${file_b}" | wc -l | tr -d ' ')

      if cmp -s "${file_a}" "${file_b}"; then
        set_relation="same CVE set"
      else
        set_relation="different CVE set"
      fi

      echo "- ${a} vs ${b}: same=${same}, only_${a}=${only_a}, only_${b}=${only_b} (${set_relation})"
    done
  done

  echo
  echo "Normalized CVE lists are under: ${NORMALIZED_DIR}/"
} > "${REPORT_FILE}"

echo "Wrote report: ${REPORT_FILE}"
