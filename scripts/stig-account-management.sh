#!/bin/bash
# RHEL 9 STIG - Account Management Controls
# Reference: RHEL-08-010010 through RHEL-08-010200 series

set -euo pipefail

echo "Applying STIG Account Management hardening..."

# RHEL-08-010070: Disable unused accounts
# Lock system accounts that shouldn't be used for login
for user in games ftp news uucp operator gopher; do
    if id "$user" >/dev/null 2>&1; then
        usermod -L "$user" 2>/dev/null || true
        usermod -s /sbin/nologin "$user" 2>/dev/null || true
        echo "Locked account: $user"
    fi
done

# RHEL-08-010080: Set minimum password age
# Configure in /etc/login.defs
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    echo "Set minimum password age to 1 day"
fi

# RHEL-08-010090: Set maximum password age
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
    echo "Set maximum password age to 60 days"
fi

# RHEL-08-010100: Set password warning age
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    echo "Set password warning age to 7 days"
fi

# RHEL-08-010150: Ensure accounts are disabled after 35 days of inactivity
if [ -f /etc/default/useradd ]; then
    sed -i 's/^INACTIVE.*/INACTIVE=35/' /etc/default/useradd
    echo "Set account inactivity timeout to 35 days"
fi

# RHEL-08-010190: Remove .shosts files
find /home -name ".shosts" -delete 2>/dev/null || true
find /root -name ".shosts" -delete 2>/dev/null || true
echo "Removed any .shosts files"

# RHEL-08-010200: Remove shosts.equiv files  
find /home -name "shosts.equiv" -delete 2>/dev/null || true
find /root -name "shosts.equiv" -delete 2>/dev/null || true
echo "Removed any shosts.equiv files"

echo "Account Management STIG controls applied successfully"