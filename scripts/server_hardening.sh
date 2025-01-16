#!/bin/bash

# --------------------------- Configuration Variables ------------------------ #

# Configurable SSH port
SSH_PORT=2200

# Services to disable (add or remove services as needed)
SERVICES_TO_DISABLE=("telnet" "ftp" "rsync" "nfs" "smb")

# Error log file
ERROR_LOG="/var/log/server_hardening_error.log"

# Firewall allowed ports (add or remove ports as needed)
FIREWALL_ALLOWED_PORTS=("ssh" "http" "https")
# Include custom SSH port if different from default
if [ "$SSH_PORT" -ne 22 ]; then
    FIREWALL_ALLOWED_PORTS+=("$SSH_PORT/tcp")
fi

# --------------------------- Function Definitions --------------------------- #

# Ensure the script is being run as root
if [ "$EUID" -ne 0 ]; then
    # If the effective user ID is not 0 (root), display an error message and exit
    echo "[ERROR] Please run this script as root." | tee -a "$ERROR_LOG" >&2
    exit 1
fi

# Log function to standardize informational messages with timestamps
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

# Function to log error messages and exit the script with a failure status
error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1" | tee -a "$ERROR_LOG" >&2
    exit 1
}

# Abstract package manager commands
if command -v apt > /dev/null 2>&1; then
    PM_UPDATE="apt update && apt upgrade -y"
    PM_INSTALL="apt install -y"
    PM_CONFIGURE_AUTO_UPDATES() {
        apt install unattended-upgrades -y || error_exit "Failed to install unattended-upgrades."
        dpkg-reconfigure --priority=low unattended-upgrades || error_exit "Failed to configure unattended-upgrades."
    }
elif command -v dnf > /dev/null 2>&1; then
    PM_UPDATE="dnf update -y"
    PM_INSTALL="dnf install -y"
    PM_CONFIGURE_AUTO_UPDATES() {
        dnf install dnf-automatic -y || error_exit "Failed to install dnf-automatic."
        systemctl enable --now dnf-automatic.timer || error_exit "Failed to enable dnf-automatic.timer."
    }
elif command -v yum > /dev/null 2>&1; then
    PM_UPDATE="yum update -y"
    PM_INSTALL="yum install -y"
    PM_CONFIGURE_AUTO_UPDATES() {
        yum install yum-cron -y || error_exit "Failed to install yum-cron."
        systemctl enable yum-cron || error_exit "Failed to enable yum-cron."
        systemctl start yum-cron || error_exit "Failed to start yum-cron."
    }
else
    error_exit "No supported package manager found. Exiting."
fi

# Function to update the system's package repositories and installed packages
update_system() {
    log "Updating system packages..."
    eval "$PM_UPDATE" || error_exit "Failed to update system packages."
}

# Function to disable unnecessary and potentially insecure services
disable_services() {
    log "Disabling unused services..."
    for service in telnet ftp rsync; do
        if systemctl is-active --quiet "$service.service"; then
            # Stop and disable the service if it is active
            log "Stopping and disabling $service..."
            systemctl stop "$service.service" && systemctl disable "$service.service" || \
                error_exit "Failed to disable $service."
        else
            # Inform if the service is already disabled
            log "$service is already stopped and disabled."
        fi
    done
}

# Function to configure and enable a firewall
configure_firewall() {
    log "Configuring firewall..."
    if command -v ufw > /dev/null 2>&1; then
        # Configure UFW (Uncomplicated Firewall) if it is installed
        log "Using UFW for firewall management."
        if ufw status | grep -q inactive; then
            # Set default policies and allow common services
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw allow http
            ufw allow https
            # Enable UFW with error handling
            ufw enable || error_exit "Failed to enable UFW."
        else
            # Inform if UFW is already active
            log "UFW is already active."
        fi
    elif command -v firewall-cmd > /dev/null 2>&1; then
        # Configure Firewalld if it is installed
        log "Using Firewalld for firewall management."
        firewall-cmd --permanent --set-default-zone=drop || error_exit "Failed to set default zone."
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        # Reload Firewalld configuration
        firewall-cmd --reload || error_exit "Failed to reload Firewalld."
    else
        # Exit if no firewall tool is found
        error_exit "No supported firewall tool found."
    fi
}

# Function to harden the SSH configuration
harden_ssh() {
    log "Hardening SSH configuration..."
    if [ ! -f /etc/ssh/sshd_config.bak ]; then
        # Backup the SSH configuration file if a backup does not exist
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || \
            error_exit "Failed to create SSH configuration backup."
        log "Backup created for SSH configuration."
    else
        log "SSH configuration backup already exists."
    fi

    # Modify SSH configuration for enhanced security
    sed -i 's/#Port 22/Port 2200/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Restart SSH service to apply changes
    systemctl restart sshd || error_exit "Failed to restart SSH service."
    log "SSH configuration hardened and service restarted."
}

# Function to set secure file and directory permissions
set_secure_permissions() {
    log "Setting secure file permissions..."
    chmod 700 /root || error_exit "Failed to set permissions for /root."
    chmod 600 /etc/ssh/sshd_config || error_exit "Failed to set permissions for /etc/ssh/sshd_config."

    # Secure permissions for critical system files
    for file in /etc/passwd /etc/shadow; do
        chmod 600 "$file" || error_exit "Failed to set permissions for $file."
    done
    log "File permissions set securely."
}

# Function to enable automatic security updates
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

# Function to install and configure Fail2Ban for intrusion prevention
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

# Function to apply kernel hardening settings
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
