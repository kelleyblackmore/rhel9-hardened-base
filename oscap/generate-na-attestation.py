#!/usr/bin/env python3
"""
Generate a formal DISA RHEL 9 STIG "Not Applicable" justification attestation for
a container base image -- the auditor-facing companion to the answer (tailoring)
file. Output is a per-control matrix (Markdown + CSV) where every Not-Applicable
control carries a category-based justification, modeled on how minimal-image
vendors (e.g. Minimus / Chainguard) publish container STIG exception records.

Two classes of Not-Applicable are distinguished:
  * "Answer file (manual)"  -- a human determination; the rule would otherwise
                               FAIL, and is deselected in oscap/not-applicable.rules
  * "OpenSCAP CPE (auto)"   -- OpenSCAP's applicability logic already marked the
                               rule notapplicable for a container (host-only control)

Inputs:
  --results   BASELINE results-xccdf.xml (no tailoring; auto-N/A appear as notapplicable)
  --na-rules  oscap/not-applicable.rules  (manual determinations + justifications)
  --datastream  optional ssg-rhel9-ds.xml (adds Title + STIG-ID + SRG-ID columns)
  --out-md / --out-csv  output paths

Usage:
  generate-na-attestation.py --results results-xccdf.xml --na-rules not-applicable.rules \
      [--datastream ssg-rhel9-ds.xml] --out-md attestation.md --out-csv attestation.csv
"""
import argparse, csv, re, sys
import xml.etree.ElementTree as ET

PFX = "xccdf_org.ssgproject.content_rule_"

# Ordered (first match wins) category rules: (regex on short rule id, category, justification)
CATEGORIES = [
    (r"(grub2_|^zipl_|uefi_|bootloader|^file_(owner|groupowner|permissions)_grub2)",
     "Boot loader",
     "The container has no boot loader; GRUB2/UEFI is provided and controlled by the host/node. Not applicable to a container image."),
    (r"(partition_for_|encrypt_partitions|mount_option_|^mount_)",
     "Disk partitioning & mounts",
     "Filesystem partitioning and mount options are host/node storage concerns; a container shares the node's layout and has no independent partitions. Not applicable to a container image."),
    (r"(dconf_|gnome|gdm|xwindows|xorg|xdmcp|^package_(gdm|gnome))",
     "Graphical desktop (GNOME/GDM)",
     "No graphical desktop is installed in a server/container base image. Not applicable to a container image."),
    (r"(^selinux|_selinux|sebool|setroubleshoot|^package_(selinux-policy|policycoreutils|mcstrans|setroubleshoot))",
     "SELinux",
     "SELinux policy and enforcing state are configured on the host kernel, which the container shares; managed at the node. Not applicable to a container image."),
    (r"(auditd|audit_rules_|audit_tools|^audit_|var_log_audit|file_audit|audit_config)",
     "Audit subsystem (auditd)",
     "The Linux audit daemon runs in kernel/host space, not inside an unprivileged container; audit is a host/node responsibility. Not applicable to a container image."),
    (r"(^sysctl_|kernel_module_|grub2_.*_argument|coredump|disable_users_coredumps|^kernel_|^sysctl)",
     "Kernel parameters & modules",
     "Kernel sysctls and modules are set on the host/node kernel, which is shared and read-only to an unprivileged container. Enforced at the node. Not applicable to a container image."),
    (r"(_cron_|crontab|^cron|at_allow|at_deny|_at_)",
     "Cron / scheduled tasks",
     "No cron/at scheduler runs in a container base; scheduled jobs are orchestrated by the platform (e.g. Kubernetes CronJobs). Not applicable to a container image."),
    (r"(sshd|ssh_|openssh|harden_sshd|disable_host_auth)",
     "SSH server",
     "A base image exposes no SSH server; remote access is not provided by the image. Not applicable to a container image."),
    (r"(rsyslog|journald|logrotate|log_forwarding|^file_(owner|groupowner|permissions)_var_log)",
     "Logging daemons",
     "Containers emit logs to stdout/stderr; aggregation is performed by the node/orchestrator, not an in-container syslog/journald service. Not applicable to a container image."),
    (r"(firewalld|firewall|libreswan|ipsec|wireless|networkmanager|network_sniffer|^configure_bind|nftables|iptables)",
     "Host firewall / network services",
     "Host-based firewall, IPSec, and link-layer controls are enforced by the node/orchestrator network policy, not the image. Not applicable to a container image."),
    (r"(smartcard|opensc|pcsc|pam_pkcs11|certmap|pcscd)",
     "Smart card / CAC",
     "No smart-card reader or hardware token exists in a container; multifactor/CAC is a host/endpoint control. Not applicable to a container image."),
    (r"(ctrlaltdel|debug-shell|single.?user|emergency_target|require_singleuser|require_emergency|^serial|getty|logind|systemd_target)",
     "Console / init targets",
     "No interactive console, serial line, or systemd rescue/emergency target exists in a non-interactive container. Not applicable to a container image."),
    (r"(fapolicy|usbguard|^kernel_module_usb)",
     "Application & device control",
     "Application allow-listing (fapolicyd) and USB/device control are host/node daemons; a container has no direct device access. Not applicable to a container image."),
    (r"(fips|crypto_fips|^aide|rpm_verify|integrity_)",
     "FIPS / host integrity",
     "FIPS kernel mode and host file-integrity (AIDE) are enabled and verified on the host/node; the container inherits the node's FIPS posture. Not applicable to a container image."),
    (r"(^service_|^timer_|^socket_|^systemd_|_service_enabled|_service_disabled)",
     "systemd services/timers",
     "No init system (systemd) runs inside the container, so services, timers, and sockets are managed by the host/node, not the image. Not applicable to a container image."),
    (r"(pam_faillock|pam_pwquality|password_pam|accounts_password|passwords_pam|account_pam|pam_wheel|^pam_|authselect|sssd|^set_password_hashing)",
     "PAM / authentication",
     "No interactive local logins or PAM authentication stack is exercised by a container base; identity and authentication are handled by the platform/IdP. Not applicable to a container image."),
    (r"(^accounts_|^account_|no_empty_passwords|^gid_|group_unique|use_pam_wheel|no_shelllogin|systemaccounts|^display_login_attempts|^set_password)",
     "Local accounts",
     "A container base has no interactive local user accounts; account lifecycle is a platform concern. Not applicable to a container image."),
    (r"(^sudo|package_sudo|sudoers|disallow_bypass_password)",
     "sudo / privilege escalation",
     "Interactive privilege escalation via sudo does not occur in a container base (no interactive users). Not applicable to a container image."),
    (r"(banner|^motd|login_banner)",
     "Login banners",
     "Interactive console/login banners are not presented by a non-interactive container. Not applicable to a container image."),
    (r"^network_configure_name_resolution$",
     "DNS resolver",
     "/etc/resolv.conf is injected at runtime by the container engine / Kubernetes (kubelet); it cannot be set in the image and SSG ships no remediation. Not applicable to a container image."),
    (r"^configure_crypto_policy$",
     "System crypto policy",
     "The FIPS:STIG crypto policy requires the kernel in FIPS mode (fips-mode-setup --enable + reboot) and the STIG sub-policy module, neither present in a container; inherited from the host/node. Not applicable to a container image."),
    (r"(subscription-manager|rng-tools|tuned|chrony|ntp|^time_|postfix|mail_alias|sendmail|smtp|^package_)",
     "Host-managed packages/services",
     "This package/service is provided or managed by the host/node, not the container base image. Not applicable to a container image."),
]
DEFAULT_JUSTIFICATION = ("Host operating-system control that a container image cannot enforce; "
                         "it is the responsibility of, and inherited from, the host/node. "
                         "Not applicable to a container image.")
DEFAULT_CATEGORY = "Host OS control (inherited)"


def categorize(short_id):
    for rx, cat, just in CATEGORIES:
        if re.search(rx, short_id):
            return cat, just
    return DEFAULT_CATEGORY, DEFAULT_JUSTIFICATION


def localname(tag):
    return tag.rsplit('}', 1)[-1]


def parse_manual_rules(path):
    """Return {short_id: justification} from not-applicable.rules (justification =
    the comment block immediately preceding the rule id)."""
    manual = {}
    block = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s.startswith("#"):
                txt = s.lstrip("# ").rstrip()
                # skip section/template headers
                if txt and not txt.startswith("---") and "TEMPLATE" not in txt and "ACTIVE" not in txt:
                    block.append(txt)
            elif not s:
                block = []
            else:
                rid = s.split()[0]
                short = rid.replace(PFX, "")
                manual[short] = " ".join(block).strip()
                block = []
    return manual


def parse_results(path):
    """Return {short_id: (severity, result, cce)} from a results-xccdf.xml."""
    out = {}
    for _, el in ET.iterparse(path, events=("end",)):
        if localname(el.tag) == "rule-result":
            idref = el.get("idref", "")
            short = idref.replace(PFX, "")
            sev = el.get("severity", "unknown")
            result = ""
            cce = ""
            for ch in el:
                ln = localname(ch.tag)
                if ln == "result":
                    result = (ch.text or "").strip()
                elif ln == "ident" and "cce" in (ch.get("system", "")).lower():
                    cce = (ch.text or "").strip()
            out[short] = (sev, result, cce)
            el.clear()
    return out


def parse_datastream(path):
    """Best-effort {short_id: (title, stig_id, srg_id)} from the SSG datastream."""
    meta = {}
    try:
        for _, el in ET.iterparse(path, events=("end",)):
            if localname(el.tag) != "Rule":
                continue
            rid = el.get("id", "")
            if PFX not in rid:
                el.clear(); continue
            short = rid.replace(PFX, "")
            title = ""
            blob = []
            for d in el.iter():
                ln = localname(d.tag)
                if ln == "title" and not title:
                    title = "".join(d.itertext()).strip()
                if d.text:
                    blob.append(d.text)
            text = " ".join(blob)
            stig = re.search(r"RHEL-09-\d{6}", text)
            srg = re.search(r"SRG-OS-\d{6}", text)
            meta[short] = (title, stig.group(0) if stig else "", srg.group(0) if srg else "")
            el.clear()
    except Exception as e:  # datastream is optional
        sys.stderr.write(f"warning: could not parse datastream ({e}); STIG-ID/Title columns blank\n")
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--na-rules", required=True)
    ap.add_argument("--datastream", default="")
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--image", default="ghcr.io/kelleyblackmore/rhel9-hardened-base:latest")
    args = ap.parse_args()

    manual = parse_manual_rules(args.na_rules)
    results = parse_results(args.results)
    meta = parse_datastream(args.datastream) if args.datastream else {}

    rows = []  # (severity_rank, severity, stig, srg, cce, short, category, status, justification)
    sev_rank = {"high": 0, "medium": 1, "low": 2, "unknown": 3}

    # 1) manual determinations (answer file) -- precise per-rule justification
    for short, just in manual.items():
        sev, _res, cce = results.get(short, ("unknown", "", ""))
        title, stig, srg = meta.get(short, ("", "", ""))
        cat, _catjust = categorize(short)
        rows.append((sev_rank.get(sev, 3), sev, stig, srg, cce, short, cat,
                     "Not Applicable (answer file)", just or _catjust))

    # 2) auto N/A -- OpenSCAP CPE already excluded these (category justification)
    for short, (sev, result, cce) in results.items():
        if result != "notapplicable" or short in manual:
            continue
        title, stig, srg = meta.get(short, ("", "", ""))
        cat, just = categorize(short)
        rows.append((sev_rank.get(sev, 3), sev, stig, srg, cce, short, cat,
                     "Not Applicable (OpenSCAP CPE)", just))

    rows.sort(key=lambda r: (r[0], r[6], r[5]))

    # ---- CSV ----
    with open(args.out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Severity", "STIG ID", "SRG ID", "CCE", "Rule", "Category", "Status", "Justification"])
        for _, sev, stig, srg, cce, short, cat, status, just in rows:
            w.writerow([sev, stig, srg, cce, short, cat, status, just])

    # ---- Markdown ----
    by_cat = {}
    for r in rows:
        by_cat.setdefault(r[6], []).append(r)
    n_manual = sum(1 for r in rows if "answer file" in r[7])
    n_auto = len(rows) - n_manual

    with open(args.out_md, "w", encoding="utf-8") as fh:
        fh.write("# DISA RHEL 9 STIG — Not Applicable Justification Attestation\n\n")
        fh.write(f"**Image:** `{args.image}`  \n")
        fh.write(f"**Profile:** DISA STIG (`xccdf_org.ssgproject.content_profile_stig`), tailored "
                 f"`xccdf_mil.disa.stig_profile_stig_container`  \n")
        fh.write(f"**Not Applicable controls:** {len(rows)} "
                 f"({n_manual} deselected in the answer file, {n_auto} auto-detected by OpenSCAP CPE)\n\n")
        fh.write("Every control below is excluded from the STIG compliance score with the stated, "
                 "category-based justification. Controls deselected in the answer file are the human "
                 "determinations (the rule would otherwise FAIL but is Not Applicable to a container); "
                 "the rest are excluded automatically by OpenSCAP's container applicability checks.\n\n")
        for cat in sorted(by_cat):
            items = by_cat[cat]
            fh.write(f"## {cat} ({len(items)})\n\n")
            fh.write(f"> {categorize(items[0][5])[1]}\n\n")
            fh.write("| Severity | STIG ID | CCE | Rule | Status |\n")
            fh.write("|----------|---------|-----|------|--------|\n")
            for _, sev, stig, srg, cce, short, c, status, just in items:
                fh.write(f"| {sev} | {stig or '—'} | {cce or '—'} | `{short}` | {status} |\n")
            fh.write("\n")

    print(f"NA attestation: {len(rows)} controls "
          f"({n_manual} answer-file, {n_auto} auto) -> {args.out_md}, {args.out_csv}")


if __name__ == "__main__":
    main()
