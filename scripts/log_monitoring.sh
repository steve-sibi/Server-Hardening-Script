#!/bin/bash

set -euo pipefail

LOGROTATE_CONF="/etc/logrotate.d/hardening-logs"
LOGWATCH_CONF="/etc/logwatch/conf/logwatch.conf"
LOGWATCH_OUTPUT_DIR="/var/log/logwatch"
LOGROTATE_STATE="/var/lib/logrotate/hardening.status"
RSYSLOG_STATE_DIR="/var/lib/rsyslog"

OS_FAMILY=""
PKG_MANAGER=""
APT_UPDATED=false
LOG_FILES=()
LOGROTATE_SU_GROUP="root"

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $*"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $*" >&2
    exit 1
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        error_exit "Please run this script as root."
    fi
}

detect_os() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
    fi

    case "${ID_LIKE:-$ID}" in
        *debian*)
            OS_FAMILY="debian"
            PKG_MANAGER="apt"
            LOG_FILES=(/var/log/syslog /var/log/auth.log)
            LOGROTATE_SU_GROUP="adm"
            ;;
        *rhel*|*fedora*|*centos*)
            OS_FAMILY="rhel"
            if command -v dnf >/dev/null 2>&1; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            LOG_FILES=(/var/log/messages /var/log/secure)
            LOGROTATE_SU_GROUP="root"
            ;;
        *)
            if [ -f /etc/debian_version ]; then
                OS_FAMILY="debian"
                PKG_MANAGER="apt"
                LOG_FILES=(/var/log/syslog /var/log/auth.log)
                LOGROTATE_SU_GROUP="adm"
            elif [ -f /etc/redhat-release ]; then
                OS_FAMILY="rhel"
                if command -v dnf >/dev/null 2>&1; then
                    PKG_MANAGER="dnf"
                else
                    PKG_MANAGER="yum"
                fi
                LOG_FILES=(/var/log/messages /var/log/secure)
                LOGROTATE_SU_GROUP="root"
            else
                error_exit "Unsupported distribution. Only Debian- or RHEL-based systems are supported."
            fi
            ;;
    esac
}

is_installed() {
    local pkg="$1"
    case "$PKG_MANAGER" in
        apt)
            dpkg -s "$pkg" >/dev/null 2>&1
            ;;
        dnf|yum)
            rpm -q "$pkg" >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

install_packages() {
    local packages=("$@")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if ! is_installed "$pkg"; then
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -eq 0 ]; then
        return
    fi

    case "$PKG_MANAGER" in
        apt)
            if [ "$APT_UPDATED" = false ]; then
                log "Updating apt package index..."
                apt-get update -y
                APT_UPDATED=true
            fi
            log "Installing packages: ${to_install[*]}"
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
            ;;
        dnf)
            log "Installing packages: ${to_install[*]}"
            dnf install -y "${to_install[@]}"
            ;;
        yum)
            log "Installing packages: ${to_install[*]}"
            yum install -y "${to_install[@]}"
            ;;
        *)
            error_exit "Unsupported package manager: $PKG_MANAGER"
            ;;
    esac
}

enable_and_start_rsyslog() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable rsyslog >/dev/null 2>&1 || true
        systemctl start rsyslog >/dev/null 2>&1 || true
    else
        log "systemctl not available; please ensure rsyslog is enabled manually."
    fi
}

install_rsyslog_stack() {
    log "Ensuring rsyslog and logrotate are installed..."
    install_packages rsyslog logrotate
    mkdir -p "$RSYSLOG_STATE_DIR"
    touch "$RSYSLOG_STATE_DIR/imjournal.state"
    chmod 0755 "$RSYSLOG_STATE_DIR"
    enable_and_start_rsyslog
    log "rsyslog installed and running."
}

configure_log_rotation() {
    log "Configuring log rotation for system/auth logs at $LOGROTATE_CONF"

    mkdir -p /var/lib/logrotate

    # Ensure target log files exist with correct ownership/perms to avoid logrotate warnings
    for logfile in "${LOG_FILES[@]}"; do
        touch "$logfile"
        chown root:"$LOGROTATE_SU_GROUP" "$logfile" || true
        chmod 0640 "$logfile" || true
    done

    local log_file_list
    log_file_list="$(printf "%s " "${LOG_FILES[@]}")"

    cat <<EOF > "$LOGROTATE_CONF"
$log_file_list{
    su root $LOGROTATE_SU_GROUP
    rotate 7
    daily
    create 0640 root $LOGROTATE_SU_GROUP
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
EOF
}

validate_logrotate_config() {
    if command -v logrotate >/dev/null 2>&1; then
        log "Validating logrotate configuration..."
        mkdir -p "$(dirname "$LOGROTATE_STATE")"
        if ! logrotate -d -s "$LOGROTATE_STATE" "$LOGROTATE_CONF" >/tmp/logrotate-validate.log 2>&1; then
            log "logrotate dry-run reported issues (see /tmp/logrotate-validate.log); continuing."
        fi
    else
        log "logrotate not found; skipping validation."
    fi
}

configure_logwatch() {
    log "Installing logwatch and configuring daily summary to file..."
    if [ "$OS_FAMILY" = "rhel" ] && ! is_installed epel-release; then
        install_packages epel-release
    fi
    install_packages logwatch

    mkdir -p /etc/logwatch/conf "$LOGWATCH_OUTPUT_DIR"

    cat <<EOF > "$LOGWATCH_CONF"
MailTo = root
Output = file
Format = text
Filename = $LOGWATCH_OUTPUT_DIR/logwatch.log
Range = yesterday
Detail = Med
EOF
}

run_logwatch_once() {
    if command -v logwatch >/dev/null 2>&1; then
        log "Running logwatch once (range: today) to verify output..."
        logwatch --output file --filename "$LOGWATCH_OUTPUT_DIR/logwatch-latest.log" --range today --detail Med >/dev/null
    else
        log "logwatch not found; skipping initial run."
    fi
}

main() {
    require_root
    detect_os
    log "Detected $OS_FAMILY system; using $PKG_MANAGER."

    install_rsyslog_stack
    configure_log_rotation
    validate_logrotate_config
    configure_logwatch
    run_logwatch_once

    log "Log monitoring setup complete."
}

main "$@"
