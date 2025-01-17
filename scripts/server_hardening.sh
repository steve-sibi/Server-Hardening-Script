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
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-active --quiet "$service.service"; then
            log "Stopping and disabling $service..."
            systemctl stop "$service.service" && systemctl disable "$service.service" || \
                error_exit "Failed to disable $service."
        else
            log "$service is already stopped and disabled."
        fi
    done
}

# Function to configure and enable a firewall
configure_firewall() {
    log "Configuring firewall..."
    if command -v ufw > /dev/null 2>&1; then
        log "Using UFW for firewall management."
        if ufw status | grep -q inactive; then
            log "Setting default UFW policies..."
            ufw default deny incoming
            ufw default allow outgoing
            for port in "${FIREWALL_ALLOWED_PORTS[@]}"; do
                ufw allow "$port" || error_exit "Failed to allow port $port in UFW."
            done
            ufw --force enable || error_exit "Failed to enable UFW."
        else
            log "UFW is already active. Ensuring allowed ports are configured..."
            for port in "${FIREWALL_ALLOWED_PORTS[@]}"; do
                if ! ufw status | grep -qw "$port"; then
                    ufw allow "$port" || error_exit "Failed to allow port $port in UFW."
                fi
            done
            log "UFW is active and allowed ports are configured."
        fi
    elif command -v firewall-cmd > /dev/null 2>&1; then
        log "Using Firewalld for firewall management."
        if ! systemctl is-active --quiet firewalld; then
            systemctl enable firewalld || error_exit "Failed to enable Firewalld."
            systemctl start firewalld || error_exit "Failed to start Firewalld."
        fi
        for port in "${FIREWALL_ALLOWED_PORTS[@]}"; do
            if [[ "$port" == *"/tcp" ]]; then
                PORT_NUM=$(echo "$port" | cut -d'/' -f1)
                firewall-cmd --permanent --add-port="$PORT_NUM/tcp" || error_exit "Failed to add port $PORT_NUM/tcp to Firewalld."
            else
                firewall-cmd --permanent --add-service="$port" || error_exit "Failed to add service $port to Firewalld."
            fi
        done
        firewall-cmd --permanent --set-default-zone=drop || error_exit "Failed to set default zone in Firewalld."
        firewall-cmd --reload || error_exit "Failed to reload Firewalld."
    else
        error_exit "No supported firewall tool found. Exiting."
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
    PM_CONFIGURE_AUTO_UPDATES
    log "Automatic security updates enabled."
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

# Function to manage user accounts and enforce password policies
manage_users() {
    log "Managing user accounts and enforcing password policies..."

    # Remove or disable unnecessary user accounts
    UNNECESSARY_USERS=("games" "ftp" "mail")
    for user in "${UNNECESSARY_USERS[@]}"; do
        if id "$user" &>/dev/null; then
            log "Disabling user account: $user"
            usermod -L "$user" || error_exit "Failed to lock user account $user."
        else
            log "User account $user does not exist. Skipping."
        fi
    done

    # Enforce strong password policies using PAM
    PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
    if [ -f "$PAM_COMMON_PASSWORD" ]; then
        log "Configuring PAM for strong password policies..."
        sed -i 's/^password\s\+requisite\s\+pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/' "$PAM_COMMON_PASSWORD" || \
            error_exit "Failed to configure PAM password policies."
        log "PAM password policies updated."
    fi

    log "User account management and password policies enforced."
}

# --------------------------- Main Script Execution -------------------------- #

log "================= Starting Server Hardening Process ================="

update_system
disable_services
configure_firewall
harden_ssh
set_secure_permissions
enable_auto_updates
install_fail2ban
apply_kernel_hardening
manage_users

log "================= Server Hardening Process Complete! ================="
