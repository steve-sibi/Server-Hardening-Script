#!/bin/bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run this script as root."
    exit 1
fi

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $*"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $*"
    exit 1
}

cmd_exists() {
    command -v "$1" > /dev/null 2>&1
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

server_hint="${SERVER_HINT:-}"

detect_apache() {
    if cmd_exists apache2 || cmd_exists apache2ctl || cmd_exists apachectl || cmd_exists httpd; then
        return 0
    fi

    if [ -d /etc/apache2 ] || [ -d /etc/httpd ]; then
        return 0
    fi

    if cmd_exists systemctl && systemctl list-unit-files --type=service 2> /dev/null | grep -qiE '^(apache2|httpd)\.service'; then
        return 0
    fi

    if cmd_exists dpkg && dpkg -s apache2 > /dev/null 2>&1; then
        return 0
    fi
    if cmd_exists rpm && rpm -q httpd > /dev/null 2>&1; then
        return 0
    fi

    if cmd_exists pgrep && { pgrep -x apache2 > /dev/null 2>&1 || pgrep -x httpd > /dev/null 2>&1; }; then
        return 0
    fi

    return 1
}

detect_nginx() {
    if cmd_exists nginx; then
        return 0
    fi

    if [ -d /etc/nginx ]; then
        return 0
    fi

    if cmd_exists systemctl && systemctl list-unit-files --type=service 2> /dev/null | grep -qi '^nginx\.service'; then
        return 0
    fi

    if cmd_exists dpkg && dpkg -s nginx > /dev/null 2>&1; then
        return 0
    fi
    if cmd_exists rpm && rpm -q nginx > /dev/null 2>&1; then
        return 0
    fi

    if cmd_exists pgrep && pgrep -x nginx > /dev/null 2>&1; then
        return 0
    fi

    return 1
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --server=*)
                server_hint="${1#*=}"
                ;;
            --server)
                shift
                if [ "$#" -eq 0 ]; then
                    error_exit "Missing value for --server (apache|nginx|both)."
                fi
                server_hint="$1"
                ;;
            *)
                error_exit "Unknown argument: $1"
                ;;
        esac
        shift
    done
}

server_hint_normalized() {
    case "$server_hint" in
        apache | nginx | both | "")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

detection_debug() {
    local apache2_bin apachectl_bin httpd_bin nginx_bin
    apache2_bin=$(command -v apache2 2> /dev/null || true)
    apachectl_bin=$(command -v apachectl 2> /dev/null || command -v apache2ctl 2> /dev/null || true)
    httpd_bin=$(command -v httpd 2> /dev/null || true)
    nginx_bin=$(command -v nginx 2> /dev/null || true)

    log "Detection summary: hint=${server_hint:-none} apache=${apache_present} nginx=${nginx_present}"
    log " - PATH: $PATH"
    log " - binaries: apache2=${apache2_bin:-missing}, apachectl=${apachectl_bin:-missing}, httpd=${httpd_bin:-missing}, nginx=${nginx_bin:-missing}"
    log " - config dirs: /etc/apache2=$(if [ -d /etc/apache2 ]; then echo present; else echo missing; fi), /etc/httpd=$(if [ -d /etc/httpd ]; then echo present; else echo missing; fi), /etc/nginx=$(if [ -d /etc/nginx ]; then echo present; else echo missing; fi)"
}

parse_args "$@"
if ! server_hint_normalized; then
    error_exit "Invalid server hint '$server_hint'. Use apache, nginx, or both."
fi

case "$server_hint" in
    apache)
        apache_present=true
        ;;
    nginx)
        nginx_present=true
        ;;
    both)
        apache_present=true
        nginx_present=true
        ;;
    *) ;;
esac

if [ "$apache_present" = false ] && detect_apache; then
    apache_present=true
fi

if [ "$nginx_present" = false ] && detect_nginx; then
    nginx_present=true
fi

detection_debug

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
