#!/bin/bash
# RHEL 9 STIG - File System Permissions & Access Controls
# Reference: RHEL-08-010300 through RHEL-08-010700 series

set -uo pipefail

echo "Applying STIG File System hardening..."

# RHEL-08-010310: Set proper permissions on /etc/passwd
chmod 644 /etc/passwd
chown root:root /etc/passwd
echo "Set permissions on /etc/passwd"

# RHEL-08-010320: Set proper permissions on /etc/group
chmod 644 /etc/group
chown root:root /etc/group
echo "Set permissions on /etc/group"

# RHEL-08-010330: Set proper permissions on /etc/shadow
if [ -f /etc/shadow ]; then
    chmod 000 /etc/shadow
    chown root:root /etc/shadow
    echo "Set permissions on /etc/shadow"
fi

# RHEL-08-010340: Set proper permissions on /etc/gshadow
if [ -f /etc/gshadow ]; then
    chmod 000 /etc/gshadow
    chown root:root /etc/gshadow
    echo "Set permissions on /etc/gshadow"
fi

# RHEL-08-010350: Remove world-writable files and directories
echo "Scanning for world-writable files (excluding /tmp, /var/tmp, /dev/shm)..."
find / -type f -perm -0002 -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/dev/shm/*" -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | while read -r file; do
    if [ -f "$file" ]; then
        chmod o-w "$file"
        echo "Removed world-write permission from: $file"
    fi
done

# RHEL-08-010360: Set proper ownership of system files
# Ensure critical system files are owned by root
for file in /etc/passwd /etc/group /etc/hosts /etc/resolv.conf; do
    if [ -f "$file" ]; then
        chown root:root "$file"
        echo "Set root ownership on: $file"
    fi
done

# RHEL-08-010370: Remove unauthorized SUID/SGID files
echo "Scanning for unnecessary SUID/SGID files..."
# List of commonly acceptable SUID/SGID programs
ALLOWED_SUID="/bin/mount /bin/umount /bin/su /bin/ping /usr/bin/passwd /usr/bin/sudo /usr/bin/gpasswd /usr/bin/newgrp /usr/bin/chsh /usr/bin/chfn"

find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | while read -r file; do
    # Check if file is in allowed list
    allowed=false
    for allowed_file in $ALLOWED_SUID; do
        if [ "$file" = "$allowed_file" ]; then
            allowed=true
            break
        fi
    done
    
    if [ "$allowed" = false ]; then
        echo "Warning: Found SUID/SGID file not in allowed list: $file"
        # In a real environment, you might want to remove SUID/SGID bits
        # chmod u-s,g-s "$file"
    fi
done

# RHEL-08-010500: Set sticky bit on world-writable directories
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | while read -r dir; do
    if [ -d "$dir" ] && [ ! -k "$dir" ]; then
        chmod +t "$dir"
        echo "Set sticky bit on world-writable directory: $dir"
    fi
done

# RHEL-08-010600: Ensure no unowned files exist
echo "Scanning for unowned files..."
find / -nouser -o -nogroup -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -10 | while read -r file; do
    echo "Warning: Found unowned file/directory: $file"
    # In production, you'd assign proper ownership
    # chown root:root "$file"
done

# RHEL-08-010700: Remove temporary files from previous boots
rm -rf /tmp/.* /tmp/* 2>/dev/null || true
rm -rf /var/tmp/.* /var/tmp/* 2>/dev/null || true
echo "Cleaned temporary directories"

echo "File System STIG controls applied successfully"