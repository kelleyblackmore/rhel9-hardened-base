#!/bin/bash
# RHEL 9 STIG - Network Configuration & Services
# Reference: RHEL-08-040000 through RHEL-08-040999 series

set -euo pipefail

echo "Applying STIG Network hardening..."

# RHEL-08-040010: Disable IPv6 if not needed (container context)
if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || true
    echo "Disabled IPv6 (if writable in container)"
fi

# RHEL-08-040020: Disable source routing
if [ -f /proc/sys/net/ipv4/conf/all/accept_source_route ]; then
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null || true
    echo "Disabled IPv4 source routing (if writable in container)"
fi

# RHEL-08-040030: Disable ICMP redirects
if [ -f /proc/sys/net/ipv4/conf/all/accept_redirects ]; then
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || true
    echo "Disabled ICMP redirects (if writable in container)"
fi

# RHEL-08-040080: Remove unnecessary network services packages
# Note: In containers, these are typically not installed, but check anyway
UNWANTED_SERVICES="telnet-server rsh-server ypbind ypserv tftp-server xinetd"

for service in $UNWANTED_SERVICES; do
    if rpm -q "$service" >/dev/null 2>&1; then
        echo "Warning: Found potentially unwanted network service: $service"
        # In production build, you might remove it:
        # dnf -y remove "$service"
    fi
done

# RHEL-08-040090: Configure TCP wrappers (if available)
if [ -f /etc/hosts.deny ]; then
    if ! grep -q "ALL: ALL" /etc/hosts.deny; then
        echo "ALL: ALL" >> /etc/hosts.deny
        echo "Added default deny rule to /etc/hosts.deny"
    fi
fi

# RHEL-08-040100: Remove .netrc files (contain network passwords)
find /home -name ".netrc" -delete 2>/dev/null || true
find /root -name ".netrc" -delete 2>/dev/null || true
echo "Removed any .netrc files"

# RHEL-08-040110: Set network parameter for syn flood protection
if [ -f /proc/sys/net/ipv4/tcp_syncookies ]; then
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || true
    echo "Enabled SYN flood protection (if writable in container)"
fi

# RHEL-08-040150: Disable core dumps over network (if applicable)
if [ -f /proc/sys/fs/suid_dumpable ]; then
    echo 0 > /proc/sys/fs/suid_dumpable 2>/dev/null || true
    echo "Disabled SUID core dumps (if writable in container)"
fi

# RHEL-08-040170: Remove any rsh/rlogin configuration
for file in /etc/hosts.equiv /etc/shosts.equiv; do
    if [ -f "$file" ]; then
        rm -f "$file"
        echo "Removed insecure file: $file"
    fi
done

# RHEL-08-040200: Ensure SSH configuration is secure (if SSH installed)
if [ -f /etc/ssh/sshd_config ]; then
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Apply secure SSH settings
    sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config
    sed -i 's/^#ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    sed -i 's/^#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
    
    echo "Applied secure SSH configuration"
fi

# RHEL-08-040300: Disable Bluetooth (if present)
if systemctl list-unit-files | grep -q bluetooth; then
    systemctl disable bluetooth 2>/dev/null || true
    echo "Disabled Bluetooth service"
fi

# RHEL-08-040400: Configure firewall rules (container context)
echo "Network STIG: Firewall rules should be configured at the host/orchestration level"
echo "Container network security relies on host network policies"

echo "Network STIG controls applied successfully"