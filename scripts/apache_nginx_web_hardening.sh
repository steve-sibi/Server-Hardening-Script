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

harden_apache() {
    log "Hardening Apache web server..."
    a2enmod headers || error_exit "Failed to enable headers module."
    echo "Header always set X-Frame-Options DENY" >> /etc/apache2/conf-enabled/security.conf
    echo "Header always set X-Content-Type-Options nosniff" >> /etc/apache2/conf-enabled/security.conf
    echo "Header always set Content-Security-Policy \"default-src 'self'\"" >> /etc/apache2/conf-enabled/security.conf

    systemctl restart apache2 || error_exit "Failed to restart Apache."
    log "Apache web server hardened."
}

harden_nginx() {
    log "Hardening Nginx web server..."
    cat <<EOF >> /etc/nginx/conf.d/security.conf
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header Content-Security-Policy "default-src 'self'";
EOF

    systemctl restart nginx || error_exit "Failed to restart Nginx."
    log "Nginx web server hardened."
}

# Main Execution
if command -v apache2 > /dev/null 2>&1; then
    harden_apache
elif command -v nginx > /dev/null 2>&1; then
    harden_nginx
else
    error_exit "No supported web server found."
fi
