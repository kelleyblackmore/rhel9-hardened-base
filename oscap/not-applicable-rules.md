# DISA RHEL 9 STIG — Not Applicable rules & the answer (tailoring) file

This document explains how this image reaches **100% of the *applicable* DISA
RHEL 9 STIG rules** and how Not-Applicable rules are recorded — what the request
called an **answer file**, which in OpenSCAP/SSG is an **XCCDF tailoring file**.

## TL;DR — the three numbers

| Scan | What it measures | pass / fail | Score |
|------|------------------|-------------|-------|
| **Baseline** (plain UBI 9, original) | where we started | 63 / 8 | 88% |
| **Remediated image, no answer file** | image after SSG remediation is baked in | 69 / 2 | 97% |
| **Remediated image + answer file** | same image, 2 N/A rules deselected | 69 / 0 | **100%** |

OpenSCAP additionally auto-marks **~412 rules `notapplicable`** for a container
(see below). Those are excluded from the score automatically — they do **not**
need to be in the answer file.

## "Answer file" vs "tailoring file" — terminology

- In **SCC / DISA / eMASS** workflows an *answer file* supplies a per-rule
  determination (`true` / `false` / **Not Applicable**) plus a justification.
- In **OpenSCAP / SCAP Security Guide**, the equivalent artifact is an **XCCDF
  tailoring file**. You mark a rule Not Applicable by **un-selecting** it; its
  result becomes `notselected` and it is removed from the compliance score.
- You cannot set a rule's result to the literal string "Not Applicable" *inside*
  OpenSCAP scoring — you either let OpenSCAP detect N/A automatically (CPE
  applicability) or you **deselect** it in the tailoring file. To produce a DISA
  checklist (`.ckl`) that shows status **Not_Applicable** with your
  justification, convert the ARF (`results-arf.xml`) in a STIG Viewer / STIG
  Manager and set the status there (see "Producing a DISA checklist" below).

## How the answer file is built here

1. `oscap/not-applicable.rules` — the human-maintained source list. One rule id
   per active line, with the N/A justification as an inline comment.
2. `oscap/generate-tailoring.sh` — runs **`autotailor`** (from `openscap-utils`)
   to turn that list into a real XCCDF tailoring file (tailored profile id
   `xccdf_mil.disa.stig_profile_stig_container`), then **embeds each rule's
   justification as an inline XML comment** next to its `<select>` so the answer
   file is self-documenting:

   ```bash
   # NOTE: this autotailor uses short flags -o/-p/-u (NOT --output/--unselect-rule)
   autotailor \
     -o oscap/tailoring/tailoring-rhel9-stig-container.xml \
     -p xccdf_mil.disa.stig_profile_stig_container \
     --title "DISA RHEL 9 STIG - Container Tailored" \
     -u xccdf_org.ssgproject.content_rule_network_configure_name_resolution \
     -u xccdf_org.ssgproject.content_rule_configure_crypto_policy \
     /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
     xccdf_org.ssgproject.content_profile_stig
   ```
3. `oscap/scan.sh` — evaluates the tailored profile, passing the answer file via
   `--tailoring-file` (see the example under "The answer file..." in the README).
4. `oscap/generate-na-attestation.py` — produces the **full per-control N/A
   justification attestation** (`stig-na-attestation.md` + `.csv`) covering all
   ~414 Not-Applicable controls (the 2 answer-file determinations + the ~412
   OpenSCAP auto-detected), grouped by category with STIG-ID, CCE, severity, and
   justification. Generated and uploaded as an artifact by the
   `oscap-stig-scan.yml` workflow on every push.

## Rules deselected in the answer file (Not Applicable to a container)

These are rules OpenSCAP would otherwise score as **FAIL** but which a human
determines are Not Applicable to a container base image.

| Rule | Why Not Applicable | Justification for the checklist |
|------|--------------------|---------------------------------|
| `network_configure_name_resolution` | `/etc/resolv.conf` is injected at runtime by the container engine / Kubernetes (kubelet); it cannot be set in the image, and SSG ships **no** automated remediation for it. | "DNS resolution is managed by the container runtime/orchestrator; `/etc/resolv.conf` is provided at deploy time. Configuring it in the image has no effect. Not Applicable for a container base image." |
| `configure_crypto_policy` | The STIG requires the `FIPS:STIG` crypto policy. Enforcing it needs the kernel in FIPS mode (`fips-mode-setup --enable` + reboot, bootloader/dracut changes) and the STIG sub-policy module — none of which exist in a container, which shares the host/node kernel. `update-crypto-policies --set FIPS:STIG` returns non-zero here. | "FIPS mode is a kernel/boot control enabled on the host/node; the container inherits the node's FIPS posture. The FIPS:STIG crypto policy cannot be set from within the image. Not Applicable / inherited from host." |

> Keep this table 1:1 with the active entries in `oscap/not-applicable.rules`.
> Every deselected rule needs a defensible, written justification for the AO.

## Rules OpenSCAP auto-marks Not Applicable (no action needed)

The DISA STIG content is written for a full RHEL 9 *host*. When evaluated against
a container, OpenSCAP's CPE applicability logic automatically returns
`notapplicable` for host-only rules — roughly **412** in this profile —
including these families:

- **Boot loader / GRUB2** — `grub2_password`, `grub2_uefi_password`,
  `grub2_pti_argument`, … (no bootloader in a container)
- **Disk partitioning & mount options** — `partition_for_var`,
  `mount_option_*_nodev/nosuid/noexec`, `encrypt_partitions` (host storage)
- **Kernel sysctls set at boot** — `sysctl_net_ipv4_*`, `sysctl_kernel_*`
  (set on the node, read-only in an unprivileged container)
- **Graphical desktop (GNOME/GDM)** — `dconf_gnome_*`, `gnome_gdm_*`
  (no GUI in a server/container base)
- **Audit daemon (auditd) running** — `service_auditd_enabled`,
  `audit_rules_*` (auditd runs on the node, not in the container)
- **PAM faillock / pwquality, smart-card, FIPS kernel mode, rsyslog remote,
  firewalld** — host/identity-provider/node responsibilities

These require **no** entry in the answer file — they are already out of scope of
the score. They are listed here only so a reviewer can see the full N/A picture.

## Rules remediated in the image (now PASS)

Baked into the image via `scripts/stig-oscap-remediation.sh` (authoritative SSG
`oscap xccdf generate fix` output, scoped to the failing rules):

| Rule | Fix |
|------|-----|
| `ensure_gpgcheck_local_packages` | `localpkg_gpgcheck=1` in `/etc/dnf/dnf.conf` |
| `use_pam_wheel_for_su` | `auth required pam_wheel.so use_uid` in `/etc/pam.d/su` |
| `file_permission_user_init_files_root` | tighten mode on root init files (`u-s,g-wxs,o=`) |
| `accounts_umask_etc_bashrc` | `umask 077` in `/etc/bashrc` |
| `accounts_umask_etc_profile` | `umask 077` in `/etc/profile` |
| `rootfiles_configured` | write `/etc/tmpfiles.d/rootfiles.conf` |

## Producing a DISA checklist (.ckl) with Not_Applicable status

If your ATO package needs a STIG Viewer checklist (not just the OpenSCAP HTML),
feed the ARF to a converter and the deselected rules carry through as
`Not_Reviewed`/`Not_Applicable` that you annotate with the justification above:

```bash
# Example with the 'stig-manager'/'openscap-report' style tooling or DISA STIG Viewer:
#   import oscap/results/tailored/results-arf.xml into STIG Viewer,
#   set the deselected rules to "Not Applicable", paste the justification.
```
