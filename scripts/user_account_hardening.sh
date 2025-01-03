#!/bin/bash

# Ensure the script is being run as root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run this script as root."
    exit 1
fi

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1"
    exit 1
}

disable_inactive_accounts() {
    log "Disabling inactive user accounts..."
    userdel $(lastlog -b 30 | grep "Never logged in" | awk '{print $1}') || log "No inactive accounts to disable."
    log "Inactive accounts disabled."
}

enforce_password_policy() {
    log "Configuring password policies..."
    sed -i '/PASS_MAX_DAYS/s/99999/90/' /etc/login.defs
    sed -i '/PASS_MIN_DAYS/s/0/1/' /etc/login.defs
    sed -i '/PASS_WARN_AGE/s/7/14/' /etc/login.defs

    cat <<EOF > /etc/security/pwquality.conf
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

    log "Password policies applied."
}

# Main Execution
log "Starting user account hardening..."
disable_inactive_accounts
enforce_password_policy
log "User account hardening complete!"
