#!/bin/bash
# RHEL 9 STIG - System Maintenance & Updates
# Reference: RHEL-08-020000 through RHEL-08-020999 series

set -euo pipefail

echo "Applying STIG System Maintenance hardening..."

# RHEL-08-020010: Keep system updated with security patches
echo "Ensuring system is updated with latest security patches..."
dnf -y update --security
echo "Applied security updates"

# RHEL-08-020020: Remove unnecessary packages to reduce attack surface
echo "Removing unnecessary packages..."
UNWANTED_PACKAGES="telnet ftp rsh talk finger ntalk rwho rusers"

for package in $UNWANTED_PACKAGES; do
    if rpm -q "$package" >/dev/null 2>&1; then
        dnf -y remove "$package"
        echo "Removed package: $package"
    fi
done

# RHEL-08-020030: Disable unnecessary services
UNWANTED_SERVICES="avahi-daemon cups bluetooth nfs-server rpcbind"

for service in $UNWANTED_SERVICES; do
    if systemctl list-unit-files | grep -q "^${service}"; then
        systemctl disable "$service" 2>/dev/null || true
        systemctl stop "$service" 2>/dev/null || true
        echo "Disabled service: $service"
    fi
done

# RHEL-08-020040: Configure automatic security updates (container context)
if [ -f /etc/dnf/automatic.conf ]; then
    sed -i 's/^upgrade_type =.*/upgrade_type = security/' /etc/dnf/automatic.conf
    sed -i 's/^apply_updates =.*/apply_updates = yes/' /etc/dnf/automatic.conf
    echo "Configured automatic security updates"
fi

# RHEL-08-020050: Set kernel parameters for security
# Note: Many of these may not be writable in containers
KERNEL_PARAMS="
kernel.dmesg_restrict=1
kernel.kptr_restrict=1
kernel.yama.ptrace_scope=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
"

echo "Attempting to set kernel security parameters..."
for param in $KERNEL_PARAMS; do
    key=$(echo "$param" | cut -d= -f1)
    value=$(echo "$param" | cut -d= -f2)
    sysctl_path="/proc/sys/$(echo "$key" | tr '.' '/')"
    
    if [ -f "$sysctl_path" ]; then
        echo "$value" > "$sysctl_path" 2>/dev/null && echo "Set $key = $value" || echo "Could not set $key (read-only in container)"
    fi
done

# RHEL-08-020060: Disable core dumps for security
if [ -f /etc/security/limits.conf ]; then
    if ! grep -q "* hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
        echo "Disabled core dumps in limits.conf"
    fi
fi

# Create systemd override for core dumps
if [ -d /etc/systemd/system.conf.d ]; then
    cat > /etc/systemd/system.conf.d/stig-coredump.conf << 'EOF'
[Manager]
DumpCore=no
DefaultLimitCORE=0
EOF
    echo "Disabled core dumps in systemd configuration"
fi

# RHEL-08-020070: Remove development tools in production images
DEV_PACKAGES="gcc gcc-c++ make cmake gdb strace ltrace"

echo "Checking for development packages that should be removed in production..."
for package in $DEV_PACKAGES; do
    if rpm -q "$package" >/dev/null 2>&1; then
        echo "Warning: Development package found: $package"
        # Uncomment to remove in production builds:
        # dnf -y remove "$package"
    fi
done

# RHEL-08-020080: Set proper permissions on cron files
if [ -f /etc/crontab ]; then
    chmod 600 /etc/crontab
    chown root:root /etc/crontab
    echo "Set secure permissions on /etc/crontab"
fi

for crondir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
        chmod 700 "$crondir"
        chown root:root "$crondir"
        echo "Set secure permissions on $crondir"
    fi
done

# RHEL-08-020090: Configure system banners
cat > /etc/motd << 'EOF'
***************************************************************************
                            NOTICE TO USERS

This system is for the use of authorized users only. Individuals using
this computer system without authority, or in excess of their authority,
are subject to having all of their activities on this system monitored
and recorded by system personnel.

In the course of monitoring individuals improperly using this system, or
in the course of system maintenance, the activities of authorized users
may also be monitored.

Anyone using this system expressly consents to such monitoring and is
advised that if such monitoring reveals possible evidence of criminal
activity, system personnel may provide the evidence to law enforcement.
***************************************************************************
EOF
echo "Created security banner in /etc/motd"

# RHEL-08-020100: Clean package cache and temporary files
dnf clean all
rm -rf /var/cache/dnf /var/cache/yum
rm -rf /tmp/* /var/tmp/* 2>/dev/null || true
echo "Cleaned package caches and temporary files"

# RHEL-08-020110: Set proper permissions on system libraries
find /lib /lib64 /usr/lib /usr/lib64 -type f -perm /022 -exec chmod go-w {} \; 2>/dev/null || true
echo "Secured system library permissions"

# RHEL-08-020120: Remove backup files that might contain sensitive data
find / -name "*.bak" -o -name "*~" -o -name "#*#" -type f -delete 2>/dev/null || true
echo "Removed backup files"

echo "System Maintenance STIG controls applied successfully"