# RHEL 9 Hardened Base Container Image

A production-ready, security-hardened **Red Hat Enterprise Linux 9 (UBI 9)** base
container image with **DISA RHEL 9 STIG** compliance, verified end-to-end with
**OpenSCAP / SCAP Security Guide**, automated vulnerability scanning, and an
enterprise-grade CI/CD pipeline.

Ported from [`rhel8-hardened-base`](https://github.com/kelleyblackmore/rhel8-hardened-base)
(UBI 8.10) and re-targeted to UBI 9, with the STIG controls now **proven** by an
OpenSCAP scan rather than asserted.

---

## STIG compliance at a glance

The image is evaluated against the DISA RHEL 9 STIG profile
(`xccdf_org.ssgproject.content_profile_stig`) shipped in `scap-security-guide`.

| Scan | Meaning | pass / fail | Score |
|------|---------|------------:|------:|
| **Baseline** (plain UBI 9, original) | starting point | 63 / 8 | 88% |
| **Remediated** (this image, no answer file) | SSG fixes baked in | 69 / 2 | 97% |
| **Remediated + answer file** (this image, tailored) | 2 N/A rules deselected | 69 / 0 | **100%** |

OpenSCAP **auto-marks ~412 host-only rules `notapplicable`** for a container
(bootloader, partitions, GUI, boot-time kernel sysctls, auditd-as-a-service,
FIPS kernel mode, …). Those are excluded from the score automatically and need
no answer-file entry. The two rules that fail-but-are-Not-Applicable in a
container are deselected in the answer file:
`network_configure_name_resolution` (`/etc/resolv.conf` is injected by the
runtime) and `configure_crypto_policy` (FIPS:STIG needs kernel FIPS mode, a
host/node control). Full write-up:
[`oscap/not-applicable-rules.md`](oscap/not-applicable-rules.md).

> Live numbers are in `oscap/results/baseline/summary.txt` and
> `oscap/results/tailored/summary.txt` after you run a scan.

---

## The answer (tailoring) file — what the request was really about

In **OpenSCAP / SSG**, the "answer file" is an **XCCDF tailoring file**. You mark
a rule **Not Applicable** by **un-selecting** it; OpenSCAP then reports it as
`notselected` and drops it from the compliance score. (OpenSCAP scoring has no
literal "Not Applicable" verdict you can set by hand — you either let it
auto-detect N/A via CPE applicability, or you deselect the rule. To carry a true
DISA `Not_Applicable` status into a STIG Viewer `.ckl`, import the ARF and set it
there — see [`oscap/not-applicable-rules.md`](oscap/not-applicable-rules.md).)

**How it works here:**

1. [`oscap/not-applicable.rules`](oscap/not-applicable.rules) — the maintained
   list of N/A rule ids, each with its justification as an inline comment.
2. [`oscap/generate-tailoring.sh`](oscap/generate-tailoring.sh) — runs
   **`autotailor`** to turn that list into a real XCCDF tailoring file with a new
   tailored profile id `xccdf_mil.disa.stig_profile_stig_container`.
3. [`oscap/scan.sh`](oscap/scan.sh) — evaluates the tailored profile, passing the
   answer file via `--tailoring-file`.

```bash
# Generate the answer file (deselect Not-Applicable rules)
autotailor \
  -o tailoring-rhel9-stig-container.xml \
  -p xccdf_mil.disa.stig_profile_stig_container \
  --title "DISA RHEL 9 STIG - Container Tailored" \
  -u xccdf_org.ssgproject.content_rule_network_configure_name_resolution \
  -u xccdf_org.ssgproject.content_rule_configure_crypto_policy \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
  xccdf_org.ssgproject.content_profile_stig

# Scan WITH the answer file
oscap xccdf eval \
  --profile xccdf_mil.disa.stig_profile_stig_container \
  --tailoring-file tailoring-rhel9-stig-container.xml \
  --results-arf results-arf.xml --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

To add another Not-Applicable rule: add its id (with a justification comment) to
`oscap/not-applicable.rules` and the matching row to `oscap/not-applicable-rules.md`,
then re-run the scan.

---

## Quick start — run the whole thing

> Requires Docker (or set `RUNTIME=podman`). UBI 9 ships `openscap-scanner` but
> not `scap-security-guide`; the scanner image pulls the SSG datastream +
> `autotailor` from the Rocky 9 repos (a bit-for-bit RHEL 9 rebuild, so the STIG
> content matches RHEL 9).

```bash
# Build base + scanner, generate the answer file, run baseline + tailored scans
./oscap/run-oscap.sh

# Or via make:
make oscap-baseline      # build + scan, no tailoring   -> oscap/results/baseline/
make oscap-scan          # build + scan WITH answer file -> oscap/results/tailored/
make oscap-report        # paths to the HTML reports
```

Open `oscap/results/tailored/report.html` for the human-readable STIG report;
`oscap/results/tailored/results-arf.xml` is the machine-readable ARF for STIG
Viewer / eMASS.

### Use as a base image

```dockerfile
FROM ghcr.io/kelleyblackmore/rhel9-hardened-base:latest
COPY app/ /app/
RUN dnf -y install python3 && dnf clean all
USER 10001
CMD ["python3", "app.py"]
```

---

## Security features

### STIG compliance
- **Authoritative remediation**: failing, container-applicable STIG rules are
  fixed by SSG-generated remediation baked into the image
  ([`scripts/stig-oscap-remediation.sh`](scripts/stig-oscap-remediation.sh)),
  then re-scanned to prove the result.
- **Supplementary hardening**: container-aware account, filesystem, network,
  audit/logging, and system-maintenance hardening
  ([`scripts/`](scripts/)).
- **Answer file**: Not-Applicable rules deselected with documented justification.

### Container security best practices
- **Non-root by default** — runs as UID 10001 with OpenShift-compatible (group 0)
  permissions.
- **Minimal attack surface** — only `ca-certificates`, `tzdata`, `jq` added to UBI 9.
- **Clean builds** — no package caches, temp files, or scanner tooling in the
  shipped base (OpenSCAP lives only in the throwaway scanner image).

### Automated scanning (CI)
- [`oscap-stig-scan.yml`](.github/workflows/oscap-stig-scan.yml) — builds, scans
  baseline + tailored, uploads HTML/ARF, and **gates** on the tailored STIG score.
- [`container-scan.yml`](.github/workflows/container-scan.yml) — Trivy CVE +
  filesystem scans, GitLeaks secret scanning.

---

## FIPS crypto policy — a host/node control

The `configure_crypto_policy` STIG control wants the **`FIPS:STIG` system crypto
policy**. That cannot be set inside a container: `update-crypto-policies --set
FIPS:STIG` returns non-zero ("Unknown policy STIG", "FIPS mode is not enabled")
because real FIPS requires the **kernel in FIPS mode** (`fips-mode-setup
--enable` + reboot, bootloader/dracut changes) and a container shares the
host/node kernel. So this control is **Not Applicable to the image and inherited
from the node**, and is deselected in the answer file (not silently set).

To actually run in FIPS mode: enable FIPS on the **host/node** (`fips-mode-setup
--enable`, reboot). Containers on that node then operate against the FIPS kernel
automatically. Downstream images built `FROM` this base are **not** forced into a
restrictive crypto policy, so nothing breaks by default.

---

## Repository layout

```
Containerfile                       # the hardened UBI9 base (production)
scripts/
  apply-all-stig.sh                 # master: runs the hardening scripts in order
  stig-system-maintenance.sh        # updates, pkg removal, banner, cron perms
  stig-account-management.sh        # account locks, login.defs
  stig-filesystem.sh                # passwd/shadow perms, world-writable, SUID
  stig-network.sh                   # sysctl, ssh config, insecure-svc checks
  stig-audit-logging.sh             # audit rules, log perms, journald
  stig-oscap-remediation.sh         # AUTHORITATIVE SSG fixes (generated)
oscap/
  Containerfile.scan                # scanner image: base + oscap + SSG (Rocky 9)
  scan.sh                           # runs `oscap xccdf eval`, writes report+ARF
  generate-tailoring.sh             # builds the answer file via autotailor
  not-applicable.rules              # N/A rule ids (source for the answer file)
  not-applicable-rules.md           # justifications + methodology
  run-oscap.sh                      # end-to-end: build, tailor, baseline+tailored
  tailoring/                        # generated answer file (committed)
  results/                          # scan outputs (git-ignored)
Makefile                            # oscap-* targets + vuln/secret scan targets
.github/workflows/                  # CI
```

---

## Fixed vs. the original `rhel8-hardened-base`

- **UBI 8.10 -> UBI 9** base image.
- **Script staging bug fixed**: the original copied hardening scripts to
  `/tmp/stig-scripts/`, and the first script's `rm -rf /tmp/*` deleted the rest —
  so only `stig-system-maintenance.sh` ever ran. Scripts are now staged in `/opt`,
  and the master script tolerates a best-effort script's non-zero exit so the
  authoritative remediation always runs.
- **STIG controls are now proven** by an OpenSCAP scan, with a tailoring
  ("answer") file for Not-Applicable rules — not just asserted in the README.
- **LF enforced** via `.gitattributes` (CRLF breaks `#!/bin/bash` in Linux).
