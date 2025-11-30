#!/bin/bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

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

restart_service() {
    local service=$1
    if command -v systemctl > /dev/null 2>&1; then
        systemctl reload "$service" || systemctl restart "$service" || error_exit "Failed to reload or restart $service."
    else
        service "$service" reload || service "$service" restart || error_exit "Failed to reload or restart $service."
    fi
}

harden_apache() {
    local apache_conf=""

    if [ -d /etc/apache2 ]; then
        apache_conf="/etc/apache2/conf-available/security-headers.conf"
        mkdir -p /etc/apache2/conf-available
        cat << 'EOF' > "$apache_conf"
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Content-Security-Policy "default-src 'self'"
</IfModule>
EOF
        command -v a2enmod > /dev/null 2>&1 || error_exit "a2enmod not found; cannot enable headers module."
        a2enmod headers > /dev/null
        command -v a2enconf > /dev/null 2>&1 || error_exit "a2enconf not found; cannot enable security headers config."
        a2enconf security-headers > /dev/null
        restart_service apache2
    elif [ -d /etc/httpd ]; then
        apache_conf="/etc/httpd/conf.d/security-headers.conf"
        cat << 'EOF' > "$apache_conf"
<IfModule headers_module>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Content-Security-Policy "default-src 'self'"
</IfModule>
EOF
        restart_service httpd
    else
        error_exit "Apache configuration directory not found."
    fi

    log "Apache web server hardened. Config written to $apache_conf"
}

harden_nginx() {
    local nginx_conf="/etc/nginx/conf.d/security.conf"

    [ -d /etc/nginx/conf.d ] || error_exit "Nginx conf.d directory not found."
    cat << 'EOF' > "$nginx_conf"
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
EOF

    restart_service nginx
    log "Nginx web server hardened. Config written to $nginx_conf"
}

apache_present=false
nginx_present=false

if command -v apache2 > /dev/null 2>&1 || command -v apachectl > /dev/null 2>&1 || command -v httpd > /dev/null 2>&1; then
    apache_present=true
elif [ -d /etc/apache2 ] || [ -d /etc/httpd ]; then
    apache_present=true
fi

if command -v nginx > /dev/null 2>&1; then
    nginx_present=true
elif [ -d /etc/nginx ]; then
    nginx_present=true
fi

if [ "$apache_present" = false ] && [ "$nginx_present" = false ]; then
    error_exit "No supported web server found."
fi

if [ "$apache_present" = true ]; then
    log "Apache detected; applying hardening."
    harden_apache
fi

if [ "$nginx_present" = true ]; then
    log "Nginx detected; applying hardening."
    harden_nginx
fi
