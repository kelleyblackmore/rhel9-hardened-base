#!/bin/bash
# RHEL 9 STIG - Audit & Logging Controls
# Reference: RHEL-08-030000 through RHEL-08-030999 series

set -euo pipefail

echo "Applying STIG Audit & Logging hardening..."

# Logging: do NOT install rsyslog in a container base image.
# Containers emit logs to stdout/stderr and aggregation is handled by the node /
# orchestrator. Installing rsyslog adds a service that cannot run (no systemd)
# and creates /var/log/messages, which then trips the STIG rule
# file_permissions_var_log_messages (wants mode 0600). Configure rsyslog only if
# it is already present (e.g. a downstream image added it).
if rpm -q rsyslog >/dev/null 2>&1; then
    echo "rsyslog already present; applying STIG logging configuration"
fi

# RHEL-08-030020: Configure rsyslog to send logs to remote server
# Note: In container environments, logs typically go to stdout/stderr
if [ -f /etc/rsyslog.conf ]; then
    # Ensure rsyslog configuration exists
    if ! grep -q "*.* @@logserver:514" /etc/rsyslog.conf; then
        echo "# STIG: Remote logging configuration" >> /etc/rsyslog.conf
        echo "#*.* @@logserver:514  # Uncomment and configure for remote logging" >> /etc/rsyslog.conf
        echo "Added remote logging configuration template to rsyslog.conf"
    fi
fi

# RHEL-08-030030: Set proper ownership on log files
if [ -d /var/log ]; then
    find /var/log -type f -exec chown root:root {} \;
    find /var/log -type f -exec chmod 640 {} \;
    echo "Set proper ownership and permissions on log files"
fi

# RHEL-08-030100: Configure audit daemon (if available)
if [ -f /etc/audit/auditd.conf ]; then
    # Configure audit log retention
    sed -i 's/^max_log_file =.*/max_log_file = 8/' /etc/audit/auditd.conf
    sed -i 's/^num_logs =.*/num_logs = 5/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file_action =.*/max_log_file_action = rotate/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
    sed -i 's/^disk_full_action =.*/disk_full_action = halt/' /etc/audit/auditd.conf
    echo "Configured audit daemon settings"
fi

# RHEL-08-030200: Set audit rules for privileged commands
if [ -d /etc/audit/rules.d ]; then
    cat > /etc/audit/rules.d/stig-privileged.rules << 'EOF'
# STIG: Audit privileged command execution
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
EOF
    echo "Created STIG audit rules for privileged commands"
fi

# RHEL-08-030300: Audit file access attempts
if [ -d /etc/audit/rules.d ]; then
    cat > /etc/audit/rules.d/stig-access.rules << 'EOF'
# STIG: Audit unsuccessful file access attempts
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
EOF
    echo "Created STIG audit rules for file access attempts"
fi

# RHEL-08-030400: Audit administrative actions
if [ -d /etc/audit/rules.d ]; then
    cat > /etc/audit/rules.d/stig-admin.rules << 'EOF'
# STIG: Audit administrative actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
EOF
    echo "Created STIG audit rules for administrative actions"
fi

# RHEL-08-030500: Configure log rotation
if [ -f /etc/logrotate.conf ]; then
    # Ensure logs are rotated weekly and compressed
    sed -i 's/^weekly/weekly/' /etc/logrotate.conf
    sed -i 's/^#compress/compress/' /etc/logrotate.conf
    
    # Ensure proper log retention
    if ! grep -q "rotate 4" /etc/logrotate.conf; then
        sed -i '/weekly/a rotate 4' /etc/logrotate.conf
    fi
    echo "Configured log rotation settings"
fi

# RHEL-08-030600: Set proper permissions on audit files
if [ -d /var/log/audit ]; then
    chmod 750 /var/log/audit
    chown root:root /var/log/audit
    find /var/log/audit -type f -exec chmod 640 {} \;
    find /var/log/audit -type f -exec chown root:root {} \;
    echo "Set proper permissions on audit files"
fi

# RHEL-08-030700: Configure journald (if systemd present)
if [ -d /etc/systemd/journald.conf.d ]; then
    cat > /etc/systemd/journald.conf.d/stig.conf << 'EOF'
[Journal]
# STIG: Configure persistent logging
Storage=persistent
Compress=yes
SplitMode=uid
RateLimitInterval=30s
RateLimitBurst=10000
SystemMaxUse=1G
SystemMaxFileSize=128M
SystemMaxFiles=100
EOF
    echo "Configured systemd journald for STIG compliance"
fi

# RHEL-08-030800: Remove old log files to reduce attack surface
find /var/log -name "*.log.*" -mtime +30 -delete 2>/dev/null || true
find /var/log -name "*.[0-9]*" -mtime +30 -delete 2>/dev/null || true
echo "Cleaned old log files"

echo "Audit & Logging STIG controls applied successfully"