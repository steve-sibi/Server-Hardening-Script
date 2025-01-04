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

install_rsyslog() {
    log "Installing rsyslog..."
    if [ -f /etc/debian_version ]; then
        apt install rsyslog -y || error_exit "Failed to install rsyslog."
    elif [ -f /etc/redhat-release ]; then
        yum install rsyslog -y || error_exit "Failed to install rsyslog."
    fi
    systemctl enable rsyslog || error_exit "Failed to enable rsyslog."
    systemctl start rsyslog || error_exit "Failed to start rsyslog."
    log "rsyslog installed and running."
}

configure_log_rotation() {
    log "Configuring log rotation..."
    cat <<EOF > /etc/logrotate.d/custom
/var/log/auth.log
/var/log/syslog
/var/log/messages {
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        systemctl reload rsyslog > /dev/null
    endscript
}
EOF
    log "Log rotation configured."
}

# Main Execution
log "Setting up log monitoring..."
install_rsyslog
configure_log_rotation
log "Log monitoring setup complete!"
