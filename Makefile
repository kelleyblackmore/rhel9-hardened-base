SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

CONTAINER_RUNTIME ?= docker
IMAGE_NAME ?= localhost/rhel9-hardened
IMAGE_TAG ?= latest
IMAGE ?= $(IMAGE_NAME):$(IMAGE_TAG)

RESULTS_DIR ?= results
TOOLS_BIN ?= $(CURDIR)/.tools/bin
SECRET_SCAN_PATH ?= .
TRUFFLEHOG_EXCLUDES ?= $(CURDIR)/scripts/trufflehog-exclude-paths.txt

.PHONY: help all build install-tools install-grype install-trivy install-trufflehog install-docker-scout \
	ensure-results check-vuln-tools check-secret-tools scan-all scan-vulns scan-secrets \
	scan-grype scan-trivy scan-trivy-secrets scan-trufflehog scan-docker-scout \
	diff-cves diff-vulns diff-secrets clean-results

help:
	@echo "Targets:"
	@echo "  make build                 Build the container image ($(IMAGE))"
	@echo "  make install-tools         Install grype, trivy, trufflehog, and docker scout"
	@echo "  make scan-vulns            Run grype, trivy, and docker scout CVE scans"
	@echo "  make diff-cves             Compare CVE findings across vulnerability scanners"
	@echo "  make scan-secrets          Run trivy and trufflehog secret scans against $(SECRET_SCAN_PATH)"
	@echo "  make diff-secrets          Compare secret findings by detected location"
	@echo "  make scan-all              Run both vulnerability and secret scan workflows"
	@echo "  make all                   Build, run both scan workflows, and diff both result sets"
	@echo
	@echo "Variables (override with make VAR=value):"
	@echo "  CONTAINER_RUNTIME=$(CONTAINER_RUNTIME)"
	@echo "  IMAGE_NAME=$(IMAGE_NAME)"
	@echo "  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  RESULTS_DIR=$(RESULTS_DIR)"
	@echo "  SECRET_SCAN_PATH=$(SECRET_SCAN_PATH)"

all: build scan-vulns diff-vulns scan-secrets diff-secrets

build:
	$(CONTAINER_RUNTIME) build -f Containerfile -t "$(IMAGE)" .

install-tools: install-grype install-trivy install-trufflehog install-docker-scout

install-grype:
	mkdir -p "$(TOOLS_BIN)"
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$(TOOLS_BIN)"
	"$(TOOLS_BIN)/grype" version

install-trivy:
	mkdir -p "$(TOOLS_BIN)"
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$(TOOLS_BIN)"
	"$(TOOLS_BIN)/trivy" --version

install-trufflehog:
	mkdir -p "$(TOOLS_BIN)"
	curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$(TOOLS_BIN)"
	"$(TOOLS_BIN)/trufflehog" --version

install-docker-scout:
	mkdir -p "$$HOME/.docker/cli-plugins"
	curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s -- -b "$$HOME/.docker/cli-plugins"
	docker scout version

ensure-results:
	mkdir -p "$(RESULTS_DIR)"

check-vuln-tools:
	@export PATH="$(TOOLS_BIN):$$PATH"; \
	command -v grype >/dev/null || (echo "grype not found. Run: make install-grype" && exit 1); \
	command -v trivy >/dev/null || (echo "trivy not found. Run: make install-trivy" && exit 1); \
	docker scout version >/dev/null || (echo "docker scout not available. Run: make install-docker-scout" && exit 1)

check-secret-tools:
	@export PATH="$(TOOLS_BIN):$$PATH"; \
	command -v trivy >/dev/null || (echo "trivy not found. Run: make install-trivy" && exit 1); \
	command -v trufflehog >/dev/null || (echo "trufflehog not found. Run: make install-trufflehog" && exit 1)

scan-all: scan-vulns scan-secrets
	@echo "Scanner outputs written to $(RESULTS_DIR)/"

scan-vulns: ensure-results check-vuln-tools scan-grype scan-trivy scan-docker-scout
	@echo "Vulnerability scan outputs written to $(RESULTS_DIR)/"

scan-secrets: ensure-results check-secret-tools scan-trivy-secrets scan-trufflehog
	@echo "Secret scan outputs written to $(RESULTS_DIR)/"

scan-grype:
	@export PATH="$(TOOLS_BIN):$$PATH"; \
	grype "$(IMAGE)" -o json > "$(RESULTS_DIR)/grype.json"

scan-trivy:
	@export PATH="$(TOOLS_BIN):$$PATH"; \
	trivy image --format json --output "$(RESULTS_DIR)/trivy.json" "$(IMAGE)"

scan-trivy-secrets:
	@export PATH="$(TOOLS_BIN):$$PATH"; \
	trivy fs --scanners secret \
	  --skip-dirs .git \
	  --skip-dirs .tools \
	  --skip-dirs "$(RESULTS_DIR)" \
	  --format json \
	  --output "$(RESULTS_DIR)/trivy-secrets.json" \
	  "$(SECRET_SCAN_PATH)"

scan-trufflehog:
	@export PATH="$(TOOLS_BIN):$$PATH"; \
	trufflehog filesystem --json --no-update --exclude-paths "$(TRUFFLEHOG_EXCLUDES)" "$(SECRET_SCAN_PATH)" > "$(RESULTS_DIR)/trufflehog-secrets.jsonl" || true

scan-docker-scout:
	docker scout cves "$(IMAGE)" --format sarif --output "$(RESULTS_DIR)/docker-scout.sarif"

diff-cves: ensure-results
	./scripts/compare-scanner-cves.sh "$(RESULTS_DIR)"
	@echo "CVE diff report: $(RESULTS_DIR)/cve-diff-report.txt"

diff-vulns: diff-cves

diff-secrets: ensure-results
	./scripts/compare-secret-findings.sh "$(RESULTS_DIR)"
	@echo "Secret diff report: $(RESULTS_DIR)/secret-diff-report.txt"

clean-results:
	rm -rf "$(RESULTS_DIR)"

# ---------------------------------------------------------------------------
# OpenSCAP DISA RHEL 9 STIG compliance
# ---------------------------------------------------------------------------
SCAN_IMAGE ?= localhost/rhel9-hardened-scan:latest
OSCAP_OUT  ?= $(CURDIR)/oscap/results

.PHONY: oscap-all oscap-build-scanner oscap-baseline oscap-tailor oscap-scan oscap-report

## Full pipeline: build base+scanner, baseline scan, tailoring, tailored+remediated scan
oscap-all:
	./oscap/run-oscap.sh

## Build the scanner image (hardened base + openscap-scanner + scap-security-guide)
oscap-build-scanner: build
	$(CONTAINER_RUNTIME) build -f oscap/Containerfile.scan \
	  --build-arg BASE_IMAGE=$(IMAGE) -t "$(SCAN_IMAGE)" .

## Baseline STIG scan (no tailoring) -> oscap/results/baseline/
oscap-baseline: oscap-build-scanner
	mkdir -p "$(OSCAP_OUT)/baseline"
	-$(CONTAINER_RUNTIME) rm -f rhel9-stig-baseline
	-$(CONTAINER_RUNTIME) run --name rhel9-stig-baseline "$(SCAN_IMAGE)"
	$(CONTAINER_RUNTIME) cp rhel9-stig-baseline:/scan/results/. "$(OSCAP_OUT)/baseline/"
	$(CONTAINER_RUNTIME) rm -f rhel9-stig-baseline
	@cat "$(OSCAP_OUT)/baseline/summary.txt"

## Generate the tailoring ("answer") file from oscap/not-applicable.rules
oscap-tailor: oscap-build-scanner
	-$(CONTAINER_RUNTIME) rm -f rhel9-stig-tailor
	$(CONTAINER_RUNTIME) run --name rhel9-stig-tailor --entrypoint /usr/local/bin/generate-tailoring.sh \
	  "$(SCAN_IMAGE)" /scan/oscap/not-applicable.rules /scan/results/tailoring-rhel9-stig-container.xml
	mkdir -p "$(CURDIR)/oscap/tailoring"
	$(CONTAINER_RUNTIME) cp rhel9-stig-tailor:/scan/results/tailoring-rhel9-stig-container.xml \
	  "$(CURDIR)/oscap/tailoring/tailoring-rhel9-stig-container.xml"
	$(CONTAINER_RUNTIME) rm -f rhel9-stig-tailor

## Tailored + remediated STIG scan -> oscap/results/tailored/
oscap-scan: oscap-build-scanner
	mkdir -p "$(OSCAP_OUT)/tailored"
	-$(CONTAINER_RUNTIME) rm -f rhel9-stig-tailored
	-$(CONTAINER_RUNTIME) run --name rhel9-stig-tailored \
	  -e TAILORING_FILE=/scan/oscap/tailoring/tailoring-rhel9-stig-container.xml \
	  -e TAILORING_PROFILE=xccdf_mil.disa.stig_profile_stig_container \
	  -e REMEDIATE=true \
	  "$(SCAN_IMAGE)"
	$(CONTAINER_RUNTIME) cp rhel9-stig-tailored:/scan/results/. "$(OSCAP_OUT)/tailored/"
	$(CONTAINER_RUNTIME) rm -f rhel9-stig-tailored
	@cat "$(OSCAP_OUT)/tailored/summary.txt"

## Print where the HTML reports are
oscap-report:
	@echo "Baseline report: $(OSCAP_OUT)/baseline/report.html"
	@echo "Tailored report: $(OSCAP_OUT)/tailored/report.html"
