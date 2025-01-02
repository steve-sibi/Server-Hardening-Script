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

update_system() {
    log "Updating system packages..."
    if [ -f /etc/debian_version ]; then
        apt update && apt upgrade -y || error_exit "Failed to update system packages."
    elif [ -f /etc/redhat-release ]; then
        yum update -y || error_exit "Failed to update system packages."
    else
        error_exit "Unsupported OS. Exiting."
    fi
}

disable_services() {
    log "Disabling unused services..."
    for service in telnet ftp rsync; do
        if systemctl is-active --quiet "$service.service"; then
            log "Stopping and disabling $service..."
            systemctl stop "$service.service" && systemctl disable "$service.service" || \
                error_exit "Failed to disable $service."
        else
            log "$service is already stopped and disabled."
        fi
    done
}

configure_firewall() {
    log "Configuring firewall..."
    if command -v ufw > /dev/null 2>&1; then
        log "Using UFW for firewall management."
        if ufw status | grep -q inactive; then
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw allow http
            ufw allow https
            ufw enable || error_exit "Failed to enable UFW."
        else
            log "UFW is already active."
        fi
    elif command -v firewall-cmd > /dev/null 2>&1; then
        log "Using Firewalld for firewall management."
        firewall-cmd --permanent --set-default-zone=drop || error_exit "Failed to set default zone."
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload || error_exit "Failed to reload Firewalld."
    else
        error_exit "No supported firewall tool found."
    fi
}

harden_ssh() {
    log "Hardening SSH configuration..."
    if [ ! -f /etc/ssh/sshd_config.bak ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || \
            error_exit "Failed to create SSH configuration backup."
        log "Backup created for SSH configuration."
    else
        log "SSH configuration backup already exists."
    fi

    sed -i 's/#Port 22/Port 2200/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    systemctl restart sshd || error_exit "Failed to restart SSH service."
    log "SSH configuration hardened and service restarted."
}

set_secure_permissions() {
    log "Setting secure file permissions..."
    chmod 700 /root || error_exit "Failed to set permissions for /root."
    chmod 600 /etc/ssh/sshd_config || error_exit "Failed to set permissions for /etc/ssh/sshd_config."

    for file in /etc/passwd /etc/shadow; do
        chmod 600 "$file" || error_exit "Failed to set permissions for $file."
    done
    log "File permissions set securely."
}

enable_auto_updates() {
    log "Enabling automatic security updates..."
    if [ -f /etc/debian_version ]; then
        apt install unattended-upgrades -y || error_exit "Failed to install unattended-upgrades."
        dpkg-reconfigure --priority=low unattended-upgrades || error_exit "Failed to configure unattended-upgrades."
    elif [ -f /etc/redhat-release ]; then
        yum install yum-cron -y || error_exit "Failed to install yum-cron."
        systemctl enable yum-cron || error_exit "Failed to enable yum-cron."
        systemctl start yum-cron || error_exit "Failed to start yum-cron."
    fi
    log "Automatic security updates enabled."
}

install_fail2ban() {
    log "Installing and configuring Fail2Ban..."
    if [ -f /etc/debian_version ]; then
        apt install fail2ban -y || error_exit "Failed to install Fail2Ban."
    elif [ -f /etc/redhat-release ]; then
        yum install fail2ban -y || error_exit "Failed to install Fail2Ban."
    fi
    systemctl enable fail2ban || error_exit "Failed to enable Fail2Ban."
    systemctl start fail2ban || error_exit "Failed to start Fail2Ban."
    log "Fail2Ban installed and running."
}

apply_kernel_hardening() {
    log "Applying kernel hardening settings..."
    cat <<EOF > /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
kernel.randomize_va_space=2
EOF
    sysctl --system || error_exit "Failed to apply kernel hardening settings."
    log "Kernel hardening settings applied."
}

# Main Script Execution
log "Starting server hardening process..."
update_system
disable_services
configure_firewall
harden_ssh
set_secure_permissions
enable_auto_updates
install_fail2ban
apply_kernel_hardening
log "Server hardening complete!"
