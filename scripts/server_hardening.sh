#!/bin/bash

###############################################################################
# Script Name: server_hardening.sh
# Description:
#   Harden Debian- or Red Hat-based servers by applying secure defaults for
#   updates, services, firewall rules, SSH, file permissions, automatic updates,
#   Fail2Ban, kernel parameters, and user-account policies.
#   Options make each step optional and configurable so the script can be safely
#   re-run without undoing prior customisations.
#
# Usage:
#   sudo ./server_hardening.sh [options]
#
# Requirements:
#   - Root privileges
#   - Supported package manager (apt, dnf, or yum)
#   - Internet connectivity for package installations and updates
###############################################################################

set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

SSH_PORT_DEFAULT=2200
SSH_PORT="$SSH_PORT_DEFAULT"
SSH_PORT_EXPLICIT=false
SSH_DISABLE_PASSWORD_AUTH=true
EFFECTIVE_SSH_PORT=22
DISABLE_IPV6=true

declare -a FIREWALL_ALLOWED_PORTS=("ssh" "http" "https")
declare -a SERVICES_TO_DISABLE=("telnet" "ftp" "rsync" "nfs" "smb")
declare -a UNNECESSARY_USERS=("games" "ftp" "mail")
declare -a ADDITIONAL_FIREWALL_PORTS=()
declare -a CUSTOM_SERVICES_TO_DISABLE=()
declare -a ADDITIONAL_USERS_TO_LOCK=()

LOG_FILE="/var/log/server_hardening.log"
ERROR_LOG="/var/log/server_hardening_error.log"

LOG_MONITORING_LOGROTATE_CONF="/etc/logrotate.d/hardening-logs"
LOG_MONITORING_LOGWATCH_CONF="/etc/logwatch/conf/logwatch.conf"
LOG_MONITORING_LOGWATCH_OUTPUT_DIR="/var/log/logwatch"
LOG_MONITORING_LOGROTATE_STATE="/var/lib/logrotate/hardening.status"
LOG_MONITORING_RSYSLOG_STATE_DIR="/var/lib/rsyslog"
LOG_MONITORING_OS_FAMILY=""
LOG_MONITORING_LOGROTATE_SU_GROUP="root"
declare -a LOG_MONITORING_LOG_FILES=()

PKG_MANAGER=""
FIREWALL_TOOL=""
APT_UPDATED=false

INTERACTIVE=false
FORCE_NON_INTERACTIVE=false

ensure_python3() {
    if command -v python3 > /dev/null 2>&1; then
        return
    fi

    case "$PKG_MANAGER" in
        apt)
            install_packages python3
            ;;
        dnf)
            install_packages python3
            ;;
        yum)
            install_packages python3
            ;;
        *)
            error_exit "python3 is required but could not be installed."
            ;;
    esac
}

SKIP_UPDATES=false
SKIP_SERVICES=false
SKIP_FIREWALL=false
SKIP_SSH=false
SKIP_PERMISSIONS=false
SKIP_AUTO_UPDATES=false
SKIP_FAIL2BAN=false
SKIP_KERNEL=false
SKIP_USERS=false
SKIP_LOG_MONITORING=false

LOG_MONITORING_EXPLICIT=false

LOCK_INACTIVE_USERS=false
USER_INACTIVITY_THRESHOLD=30

log() {
    local message
    message="$(date +'%Y-%m-%d %H:%M:%S') [INFO] $*"
    echo "$message" | tee -a "$LOG_FILE"
}

error_exit() {
    trap - ERR
    local message
    message="$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $*"
    echo "$message" | tee -a "$LOG_FILE" >&2
    echo "$message" >> "$ERROR_LOG"
    exit 1
}

handle_unexpected_error() {
    local exit_code=$?
    local line=${BASH_LINENO[0]:-0}
    error_exit "Unexpected error (exit code ${exit_code}) occurred on or near line ${line}. Review $ERROR_LOG for details."
}

trap 'handle_unexpected_error' ERR

init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE" "$ERROR_LOG"
    chmod 600 "$LOG_FILE" "$ERROR_LOG"
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] Please run this script as root." >&2
        exit 1
    fi
}

display_usage() {
    cat << 'EOF'
Usage: sudo ./server_hardening.sh [options]

Options:
  --interactive				Prompt for hardening selections
  --non-interactive			Do not prompt; run with provided flags/defaults
  --enable-log-monitoring	Enable log monitoring (rsyslog/logrotate/logwatch)
  --skip-log-monitoring		Skip log monitoring setup
  --lock-inactive-users		Lock inactive local accounts (uid >= 1000)
  --inactive-threshold <days>	Inactivity threshold in days (default: 30)
  --ssh-port <port>		  Set SSH port (default: 2200)
  --allow-port <value>	   Allow additional firewall port/service (e.g. 8080/tcp)
  --disable-service <name>   Add a service (without .service) to disable
  --lock-user <username>	 Add a user account to lock
  --keep-ipv6				Do not disable IPv6 via sysctl
  --skip-updates			 Skip system package updates
  --skip-services			Skip disabling unnecessary services
  --skip-firewall			Skip firewall configuration
  --skip-ssh				 Skip SSH hardening
  --skip-permissions		 Skip file permission adjustments
  --skip-auto-updates		Skip automatic security update configuration
  --skip-fail2ban			Skip Fail2Ban installation/configuration
  --skip-kernel			  Skip kernel hardening
  --skip-users			   Skip user account hardening
  -h, --help				 Display this help message
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interactive)
                INTERACTIVE=true
                ;;
            --non-interactive)
                FORCE_NON_INTERACTIVE=true
                INTERACTIVE=false
                ;;
            --enable-log-monitoring)
                SKIP_LOG_MONITORING=false
                LOG_MONITORING_EXPLICIT=true
                ;;
            --skip-log-monitoring)
                SKIP_LOG_MONITORING=true
                LOG_MONITORING_EXPLICIT=true
                ;;
            --lock-inactive-users)
                LOCK_INACTIVE_USERS=true
                ;;
            --inactive-threshold)
                local days="${2:-}"
                if [[ -z "$days" ]]; then
                    error_exit "Missing value for --inactive-threshold."
                fi
                if ! [[ "$days" =~ ^[0-9]+$ ]]; then
                    error_exit "--inactive-threshold must be a non-negative integer."
                fi
                USER_INACTIVITY_THRESHOLD="$days"
                LOCK_INACTIVE_USERS=true
                shift
                ;;
            --ssh-port)
                local port="${2:-}"
                if [[ -z "$port" ]]; then
                    error_exit "Missing value for --ssh-port."
                fi
                if ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
                    error_exit "SSH port must be an integer between 1 and 65535."
                fi
                SSH_PORT="$port"
                SSH_PORT_EXPLICIT=true
                shift
                ;;
            --allow-port)
                local fw_value="${2:-}"
                if [[ -z "$fw_value" ]]; then
                    error_exit "Missing value for --allow-port."
                fi
                ADDITIONAL_FIREWALL_PORTS+=("$fw_value")
                shift
                ;;
            --disable-service)
                local svc="${2:-}"
                if [[ -z "$svc" ]]; then
                    error_exit "Missing value for --disable-service."
                fi
                CUSTOM_SERVICES_TO_DISABLE+=("$svc")
                shift
                ;;
            --lock-user)
                local user="${2:-}"
                if [[ -z "$user" ]]; then
                    error_exit "Missing value for --lock-user."
                fi
                ADDITIONAL_USERS_TO_LOCK+=("$user")
                shift
                ;;
            --keep-ipv6)
                DISABLE_IPV6=false
                ;;
            --skip-updates)
                SKIP_UPDATES=true
                ;;
            --skip-services)
                SKIP_SERVICES=true
                ;;
            --skip-firewall)
                SKIP_FIREWALL=true
                ;;
            --skip-ssh)
                SKIP_SSH=true
                ;;
            --skip-permissions)
                SKIP_PERMISSIONS=true
                ;;
            --skip-auto-updates)
                SKIP_AUTO_UPDATES=true
                ;;
            --skip-fail2ban)
                SKIP_FAIL2BAN=true
                ;;
            --skip-kernel)
                SKIP_KERNEL=true
                ;;
            --skip-users)
                SKIP_USERS=true
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
        shift
    done
}

trim_whitespace() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

prompt_yes_no() {
    local prompt="$1"
    local default_yes="$2"
    local answer=""

    while true; do
        if [ "$default_yes" = true ]; then
            if ! read -r -p "${prompt} [Y/n]: " answer; then
                error_exit "Input aborted."
            fi
            answer="${answer:-Y}"
        else
            if ! read -r -p "${prompt} [y/N]: " answer; then
                error_exit "Input aborted."
            fi
            answer="${answer:-N}"
        fi

        case "${answer,,}" in
            y | yes)
                return 0
                ;;
            n | no)
                return 1
                ;;
            *)
                echo "Please answer y or n."
                ;;
        esac
    done
}

prompt_toggle_skip_var() {
    local prompt="$1"
    local skip_var="$2"
    local default_run=true

    if [ "${!skip_var}" = true ]; then
        default_run=false
    fi

    if prompt_yes_no "$prompt" "$default_run"; then
        printf -v "$skip_var" 'false'
    else
        printf -v "$skip_var" 'true'
    fi
}

prompt_append_csv() {
    local prompt="$1"
    local target_array_name="$2"
    local -n target_array="$target_array_name"
    local input=""
    local -a parts=()

    if ! read -r -p "$prompt" input; then
        error_exit "Input aborted."
    fi
    input="$(trim_whitespace "$input")"
    if [ -z "$input" ]; then
        return
    fi

    IFS=',' read -r -a parts <<< "$input"
    for part in "${parts[@]}"; do
        part="$(trim_whitespace "$part")"
        [ -z "$part" ] && continue
        target_array+=("$part")
    done
}

array_remove_exact() {
    local array_name="$1"
    local needle="$2"
    local -n array_ref="$array_name"
    local -a filtered=()
    local item

    for item in "${array_ref[@]}"; do
        if [ "$item" != "$needle" ]; then
            filtered+=("$item")
        fi
    done

    array_ref=("${filtered[@]}")
}

interactive_configure() {
    if [ "$FORCE_NON_INTERACTIVE" = true ]; then
        return
    fi

    if [ "$INTERACTIVE" = false ]; then
        return
    fi

    if [ ! -t 0 ]; then
        error_exit "Interactive mode requires a TTY. Remove --interactive or run this script from a terminal."
    fi

    log "Interactive mode enabled. Press Enter to accept defaults."
    log "Warning: SSH hardening may change the SSH port and disable password authentication."
    log "Warning: Inactive account locking can lock real user accounts; enable it only when you understand the impact."

    prompt_toggle_skip_var "Apply system updates" SKIP_UPDATES
    prompt_toggle_skip_var "Disable unnecessary services" SKIP_SERVICES
    prompt_toggle_skip_var "Configure firewall (UFW/Firewalld)" SKIP_FIREWALL
    prompt_toggle_skip_var "Harden SSH (port/root/password auth)" SKIP_SSH
    prompt_toggle_skip_var "Set secure file permissions" SKIP_PERMISSIONS
    prompt_toggle_skip_var "Enable automatic security updates" SKIP_AUTO_UPDATES
    prompt_toggle_skip_var "Install/configure Fail2Ban" SKIP_FAIL2BAN
    prompt_toggle_skip_var "Apply kernel hardening (sysctl)" SKIP_KERNEL
    prompt_toggle_skip_var "Apply user account hardening" SKIP_USERS
    prompt_toggle_skip_var "Set up log monitoring (rsyslog/logrotate/logwatch)" SKIP_LOG_MONITORING

    if [ "$SKIP_SSH" = false ]; then
        local port_input=""
        while true; do
            if ! read -r -p "SSH port [${SSH_PORT}]: " port_input; then
                error_exit "Input aborted."
            fi
            port_input="$(trim_whitespace "$port_input")"
            if [ -z "$port_input" ]; then
                break
            fi
            if ! [[ "$port_input" =~ ^[0-9]+$ ]] || ((port_input < 1 || port_input > 65535)); then
                echo "SSH port must be an integer between 1 and 65535."
                continue
            fi
            SSH_PORT="$port_input"
            SSH_PORT_EXPLICIT=true
            break
        done

        if prompt_yes_no "Disable SSH password authentication (keys only)" "$SSH_DISABLE_PASSWORD_AUTH"; then
            SSH_DISABLE_PASSWORD_AUTH=true
        else
            SSH_DISABLE_PASSWORD_AUTH=false
        fi
    fi

    if [ "$SKIP_KERNEL" = false ]; then
        if prompt_yes_no "Disable IPv6 via sysctl" "$DISABLE_IPV6"; then
            DISABLE_IPV6=true
        else
            DISABLE_IPV6=false
        fi
    fi

    if [ "$SKIP_FIREWALL" = false ]; then
        if ! prompt_yes_no "Allow HTTP (80) through the firewall" true; then
            array_remove_exact FIREWALL_ALLOWED_PORTS "http"
        fi
        if ! prompt_yes_no "Allow HTTPS (443) through the firewall" true; then
            array_remove_exact FIREWALL_ALLOWED_PORTS "https"
        fi

        prompt_append_csv "Additional firewall ports/services (comma-separated, e.g. 8080/tcp,dns) [none]: " ADDITIONAL_FIREWALL_PORTS
    fi

    if [ "$SKIP_SERVICES" = false ]; then
        prompt_append_csv "Additional services to disable (comma-separated, without .service) [none]: " CUSTOM_SERVICES_TO_DISABLE
    fi
    if [ "$SKIP_USERS" = false ]; then
        if prompt_yes_no "Lock inactive local user accounts (uid >= 1000)" "$LOCK_INACTIVE_USERS"; then
            LOCK_INACTIVE_USERS=true
            local threshold_input=""
            while true; do
                if ! read -r -p "Inactivity threshold in days [${USER_INACTIVITY_THRESHOLD}]: " threshold_input; then
                    error_exit "Input aborted."
                fi
                threshold_input="$(trim_whitespace "$threshold_input")"
                if [ -z "$threshold_input" ]; then
                    break
                fi
                if ! [[ "$threshold_input" =~ ^[0-9]+$ ]]; then
                    echo "Threshold must be a non-negative integer."
                    continue
                fi
                USER_INACTIVITY_THRESHOLD="$threshold_input"
                break
            done
        else
            LOCK_INACTIVE_USERS=false
        fi
        prompt_append_csv "Additional user accounts to lock (comma-separated) [none]: " ADDITIONAL_USERS_TO_LOCK
    fi

    echo
    log "Selections captured. Continuing with hardening run."
}

finalize_configuration() {
    if [ "${#CUSTOM_SERVICES_TO_DISABLE[@]}" -gt 0 ]; then
        SERVICES_TO_DISABLE+=("${CUSTOM_SERVICES_TO_DISABLE[@]}")
    fi
    if [ "${#ADDITIONAL_USERS_TO_LOCK[@]}" -gt 0 ]; then
        UNNECESSARY_USERS+=("${ADDITIONAL_USERS_TO_LOCK[@]}")
    fi
    if [ "${#ADDITIONAL_FIREWALL_PORTS[@]}" -gt 0 ]; then
        FIREWALL_ALLOWED_PORTS+=("${ADDITIONAL_FIREWALL_PORTS[@]}")
    fi

    EFFECTIVE_SSH_PORT="$SSH_PORT"
    if [ "$SKIP_SSH" = true ] && [ "$SSH_PORT_EXPLICIT" = false ]; then
        EFFECTIVE_SSH_PORT="$(detect_current_sshd_port)"
    fi

    if [ "$EFFECTIVE_SSH_PORT" -ne 22 ]; then
        FIREWALL_ALLOWED_PORTS+=("${EFFECTIVE_SSH_PORT}/tcp")
    fi
}

detect_package_manager() {
    if command -v apt-get > /dev/null 2>&1; then
        PKG_MANAGER="apt"
        export DEBIAN_FRONTEND=noninteractive
    elif command -v dnf > /dev/null 2>&1; then
        PKG_MANAGER="dnf"
    elif command -v yum > /dev/null 2>&1; then
        PKG_MANAGER="yum"
    else
        error_exit "No supported package manager found. Exiting."
    fi
}

install_packages() {
    local packages=("$@")
    case "$PKG_MANAGER" in
        apt)
            if [ "$APT_UPDATED" = false ]; then
                apt-get update || error_exit "apt-get update failed."
                APT_UPDATED=true
            fi
            apt-get install -y "${packages[@]}" || error_exit "Failed to install packages: ${packages[*]}"
            ;;
        dnf)
            dnf install -y "${packages[@]}" || error_exit "Failed to install packages: ${packages[*]}"
            ;;
        yum)
            yum install -y "${packages[@]}" || error_exit "Failed to install packages: ${packages[*]}"
            ;;
        *)
            error_exit "Package manager not initialised."
            ;;
    esac
}

update_system() {
    log "Updating system packages..."
    case "$PKG_MANAGER" in
        apt)
            apt-get update || error_exit "apt-get update failed."
            apt-get upgrade -y || error_exit "apt-get upgrade failed."
            APT_UPDATED=true
            ;;
        dnf)
            dnf upgrade -y || error_exit "dnf upgrade failed."
            ;;
        yum)
            yum update -y || error_exit "yum update failed."
            ;;
        *)
            error_exit "Package manager not initialised."
            ;;
    esac
    log "System packages updated."
}

disable_services() {
    if [ "${#SERVICES_TO_DISABLE[@]}" -eq 0 ]; then
        log "No services configured for disabling."
        return
    fi

    log "Disabling unused services..."
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        local unit="$service"
        [[ "$unit" != *.service ]] && unit="${unit}.service"

        if ! systemctl list-unit-files | awk '{print $1}' | grep -Fxq "$unit"; then
            log "Service $unit not found. Skipping."
            continue
        fi

        if systemctl is-active --quiet "$unit"; then
            log "Stopping $unit..."
            systemctl stop "$unit" || error_exit "Failed to stop $unit."
        else
            log "$unit is not active."
        fi

        if systemctl is-enabled --quiet "$unit"; then
            log "Disabling $unit..."
            systemctl disable --now "$unit" || error_exit "Failed to disable $unit."
        else
            log "$unit is already disabled or static."
        fi
    done
}

determine_firewall_tool() {
    if command -v ufw > /dev/null 2>&1; then
        FIREWALL_TOOL="ufw"
        return
    fi

    if command -v firewall-cmd > /dev/null 2>&1; then
        FIREWALL_TOOL="firewalld"
        return
    fi

    case "$PKG_MANAGER" in
        apt)
            log "Installing UFW for firewall management..."
            install_packages ufw
            FIREWALL_TOOL="ufw"
            ;;
        dnf | yum)
            log "Installing Firewalld for firewall management..."
            install_packages firewalld
            FIREWALL_TOOL="firewalld"
            ;;
        *)
            error_exit "Unable to determine firewall tool."
            ;;
    esac
}

configure_firewall() {
    log "Configuring firewall..."
    determine_firewall_tool

    case "$FIREWALL_TOOL" in
        ufw)
            configure_ufw
            ;;
        firewalld)
            configure_firewalld
            ;;
        *)
            error_exit "Firewall tool not available."
            ;;
    esac
}

configure_ufw() {
    local ufw_state="active"
    if ufw status 2> /dev/null | grep -qi "inactive"; then
        ufw_state="inactive"
    fi

    ufw default deny incoming || error_exit "Failed to set UFW default incoming policy."
    ufw default allow outgoing || error_exit "Failed to set UFW default outgoing policy."

    for port in "${FIREWALL_ALLOWED_PORTS[@]}"; do
        if ufw allow "$port" > /dev/null; then
            log "Ensured UFW allows $port."
        else
            error_exit "Failed to allow $port via UFW."
        fi
    done

    if [ "$ufw_state" = "inactive" ]; then
        ufw --force enable || error_exit "Failed to enable UFW."
    else
        ufw reload || error_exit "Failed to reload UFW."
    fi

    log "UFW configured."
}

configure_firewalld() {
    systemctl enable --now firewalld || error_exit "Failed to enable Firewalld."

    local target_zone
    target_zone="$(firewall-cmd --get-default-zone 2> /dev/null || echo public)"

    if [ "$target_zone" != "drop" ]; then
        firewall-cmd --set-default-zone=drop > /dev/null 2>&1 || error_exit "Failed to set Firewalld runtime default zone."
        target_zone="drop"
    fi

    for port in "${FIREWALL_ALLOWED_PORTS[@]}"; do
        if [[ "$port" =~ ^[0-9]+(/[a-z]+)?$ ]]; then
            local rule="$port"
            if [[ "$port" != */* ]]; then
                rule="${port}/tcp"
            fi
            if ! firewall-cmd --permanent --zone="$target_zone" --query-port="$rule" > /dev/null 2>&1; then
                firewall-cmd --permanent --zone="$target_zone" --add-port="$rule" || error_exit "Failed to add port $rule to Firewalld zone $target_zone."
                log "Added Firewalld port rule $rule in zone $target_zone."
            else
                log "Port rule $rule already present in Firewalld zone $target_zone."
            fi
        else
            if ! firewall-cmd --permanent --zone="$target_zone" --query-service="$port" > /dev/null 2>&1; then
                firewall-cmd --permanent --zone="$target_zone" --add-service="$port" || error_exit "Failed to add service $port to Firewalld zone $target_zone."
                log "Added Firewalld service $port in zone $target_zone."
            else
                log "Service $port already allowed in Firewalld zone $target_zone."
            fi
        fi
    done

    firewall-cmd --runtime-to-permanent > /dev/null 2>&1 || error_exit "Failed to persist Firewalld configuration."
    firewall-cmd --reload || error_exit "Failed to reload Firewalld."
    log "Firewalld configured."
}

set_sshd_option() {
    local key="$1"
    local value="$2"
    local ssh_config="/etc/ssh/sshd_config"

    if grep -qi "^[[:space:]#]*${key}[[:space:]]" "$ssh_config"; then
        sed -i -E "s|^[[:space:]#]*${key}[[:space:]].*|${key} ${value}|I" "$ssh_config" || error_exit "Failed to update ${key} in $ssh_config."
    else
        printf "\n%s %s\n" "$key" "$value" >> "$ssh_config" || error_exit "Failed to append ${key} to $ssh_config."
    fi
}

restart_ssh_service() {
    local ssh_service="sshd"
    if systemctl status ssh > /dev/null 2>&1; then
        ssh_service="ssh"
    fi
    systemctl restart "$ssh_service" || error_exit "Failed to restart $ssh_service service."
    log "Restarted $ssh_service service."
}

detect_current_sshd_port() {
    local ssh_config="/etc/ssh/sshd_config"
    local port=""

    if [ -f "$ssh_config" ]; then
        port="$(awk 'tolower($1) == "port" {print $2; exit}' "$ssh_config" 2> /dev/null || true)"
    fi

    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        echo "$port"
        return
    fi

    echo 22
}

harden_ssh() {
    log "Hardening SSH configuration..."
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_backup="/etc/ssh/sshd_config.bak"

    if [ ! -f "$ssh_config" ]; then
        error_exit "SSH configuration file $ssh_config not found."
    fi

    if [ ! -f "$ssh_backup" ]; then
        cp -p "$ssh_config" "$ssh_backup" || error_exit "Failed to create SSH configuration backup."
        log "Backup created at $ssh_backup."
    else
        log "SSH configuration backup already exists at $ssh_backup."
    fi

    set_sshd_option "Port" "$SSH_PORT"
    set_sshd_option "PermitRootLogin" "no"
    if [ "$SSH_DISABLE_PASSWORD_AUTH" = true ]; then
        set_sshd_option "PasswordAuthentication" "no"
    else
        set_sshd_option "PasswordAuthentication" "yes"
    fi
    set_sshd_option "Protocol" "2"

    restart_ssh_service
    log "SSH configuration hardened."
}

ensure_permission() {
    local path="$1"
    local desired_mode="$2"

    if [ ! -e "$path" ]; then
        log "Skipping permission update for $path (not found)."
        return
    fi

    local current_mode
    current_mode="$(stat -c "%a" "$path")"
    if [ "$current_mode" -ne "$desired_mode" ]; then
        chmod "$desired_mode" "$path" || error_exit "Failed to set permissions for $path."
        log "Set $path permissions to $desired_mode."
    else
        log "$path permissions already set to $desired_mode."
    fi
}

set_secure_permissions() {
    log "Setting secure file permissions..."
    ensure_permission "/root" 700
    ensure_permission "/etc/ssh/sshd_config" 600
    ensure_permission "/etc/passwd" 644
    ensure_permission "/etc/shadow" 600
    log "File permissions verified."
}

enable_auto_updates() {
    log "Enabling automatic security updates..."
    case "$PKG_MANAGER" in
        apt)
            if ! dpkg -s unattended-upgrades > /dev/null 2>&1; then
                install_packages unattended-upgrades
            fi
            dpkg-reconfigure --priority=low unattended-upgrades > /dev/null 2>&1 || error_exit "Failed to configure unattended-upgrades."
            ;;
        dnf)
            if ! systemctl list-unit-files | awk '{print $1}' | grep -Fxq "dnf-automatic.timer"; then
                install_packages dnf-automatic
            fi
            systemctl enable --now dnf-automatic.timer || error_exit "Failed to enable dnf-automatic.timer."
            ;;
        yum)
            if ! rpm -q yum-cron > /dev/null 2>&1; then
                install_packages yum-cron
            fi
            systemctl enable yum-cron || error_exit "Failed to enable yum-cron."
            systemctl start yum-cron || error_exit "Failed to start yum-cron."
            ;;
        *)
            error_exit "Package manager not initialised."
            ;;
    esac
    log "Automatic security updates enabled."
}

configure_fail2ban() {
    local jail_dir="/etc/fail2ban/jail.d"
    mkdir -p "$jail_dir"

    local log_path=""
    for candidate in /var/log/auth.log /var/log/secure /var/log/messages; do
        if [ -f "$candidate" ]; then
            log_path="$candidate"
            break
        fi
    done

    if [ -z "$log_path" ]; then
        log_path="/var/log/auth.log"
        touch "$log_path"
    fi

    cat << EOF > "${jail_dir}/00-server-hardening.conf"
[sshd]
enabled = true
port    = ${EFFECTIVE_SSH_PORT}
logpath = ${log_path}
backend = systemd
maxretry = 5
bantime = 3600
EOF
}

install_fail2ban() {
    log "Installing and configuring Fail2Ban..."
    if ! command -v fail2ban-client > /dev/null 2>&1; then
        case "$PKG_MANAGER" in
            apt)
                install_packages fail2ban
                ;;
            dnf)
                if ! rpm -q epel-release > /dev/null 2>&1; then
                    dnf install -y epel-release || error_exit "Failed to install epel-release."
                fi
                dnf install -y fail2ban || error_exit "Failed to install Fail2Ban."
                ;;
            yum)
                if ! rpm -q epel-release > /dev/null 2>&1; then
                    yum install -y epel-release || error_exit "Failed to install epel-release."
                fi
                yum install -y fail2ban || error_exit "Failed to install Fail2Ban."
                ;;
            *)
                error_exit "Unsupported package manager. Cannot install Fail2Ban."
                ;;
        esac
    fi

    configure_fail2ban
    systemctl enable fail2ban || error_exit "Failed to enable Fail2Ban."
    systemctl restart fail2ban || error_exit "Failed to start Fail2Ban."
    log "Fail2Ban installed and running."
}

apply_kernel_hardening() {
    log "Applying kernel hardening settings..."
    local hardening_conf="/etc/sysctl.d/99-server-hardening.conf"
    mkdir -p "$(dirname "$hardening_conf")" || error_exit "Failed to create $(dirname "$hardening_conf")."

    if ! command -v sysctl > /dev/null 2>&1; then
        case "$PKG_MANAGER" in
            apt)
                install_packages procps
                ;;
            dnf)
                install_packages procps-ng
                ;;
            yum)
                install_packages procps-ng
                ;;
            *)
                error_exit "sysctl command not available and package manager is unsupported."
                ;;
        esac
    fi

    {
        echo "# Managed by server_hardening.sh on $(date +'%Y-%m-%d %H:%M:%S')"
        echo "net.ipv4.ip_forward=0"
        echo "net.ipv4.conf.all.accept_source_route=0"
        echo "net.ipv4.conf.default.accept_source_route=0"
        echo "net.ipv4.conf.all.send_redirects=0"
        echo "net.ipv4.conf.default.send_redirects=0"
        echo "net.ipv4.tcp_syncookies=1"
        echo "net.ipv4.conf.all.rp_filter=1"
        echo "net.ipv4.conf.default.rp_filter=1"
        echo "kernel.randomize_va_space=2"
        if [ "$DISABLE_IPV6" = true ]; then
            echo "net.ipv6.conf.all.disable_ipv6=1"
            echo "net.ipv6.conf.default.disable_ipv6=1"
        fi
    } > "$hardening_conf" || error_exit "Failed to write $hardening_conf."

    sysctl -p "$hardening_conf" > /dev/null || error_exit "Failed to apply kernel hardening settings."
    log "Kernel hardening settings applied."
}

disable_unnecessary_accounts() {
    if [ "${#UNNECESSARY_USERS[@]}" -eq 0 ]; then
        log "No user accounts configured for locking."
        return
    fi

    for user in "${UNNECESSARY_USERS[@]}"; do
        if id "$user" > /dev/null 2>&1; then
            local status
            status="$(passwd -S "$user" | awk '{print $2}')"
            if [[ "$status" == "L" || "$status" == "LK" ]]; then
                log "User $user is already locked."
            else
                usermod -L "$user" || error_exit "Failed to lock user $user."
                log "Locked user $user."
            fi
        else
            log "User $user not present. Skipping."
        fi
    done
}

lock_inactive_accounts() {
    local threshold_days="$1"

    if ! command -v lastlog > /dev/null 2>&1; then
        error_exit "lastlog is required to lock inactive accounts."
    fi
    if ! command -v getent > /dev/null 2>&1; then
        error_exit "getent is required to lock inactive accounts."
    fi
    if ! command -v usermod > /dev/null 2>&1; then
        error_exit "usermod is required to lock inactive accounts."
    fi
    if ! command -v chage > /dev/null 2>&1; then
        error_exit "chage is required to expire inactive accounts."
    fi

    log "Evaluating user accounts inactive for at least ${threshold_days} days..."

    local tmp_all tmp_inactive
    tmp_all="$(mktemp)" || error_exit "Unable to create temporary file."
    tmp_inactive="$(mktemp)" || {
        rm -f "$tmp_all"
        error_exit "Unable to create temporary file."
    }

    if ! lastlog 2> /dev/null | tail -n +2 | awk '{print $1}' | sort -u > "$tmp_all"; then
        rm -f "$tmp_all" "$tmp_inactive"
        error_exit "Failed to read the lastlog database."
    fi

    if ! lastlog -b "$threshold_days" 2> /dev/null | tail -n +2 | awk '{print $1}' | sort -u > "$tmp_inactive"; then
        rm -f "$tmp_all" "$tmp_inactive"
        error_exit "Failed to determine inactive users from lastlog."
    fi

    local -a inactive_users=()
    mapfile -t inactive_users < <(comm -12 "$tmp_all" "$tmp_inactive")
    local status=$?
    rm -f "$tmp_all" "$tmp_inactive"
    if [ $status -ne 0 ]; then
        error_exit "Unable to compute inactive account list."
    fi

    if [ ${#inactive_users[@]} -eq 0 ]; then
        log "No eligible inactive local accounts were found."
        return
    fi

    local user
    for user in "${inactive_users[@]}"; do
        [ -z "$user" ] && continue

        local passwd_entry
        if ! passwd_entry="$(getent passwd "$user")"; then
            log "Skipping unknown user ${user}."
            continue
        fi

        local uid shell
        uid="$(echo "$passwd_entry" | cut -d: -f3)"
        shell="$(echo "$passwd_entry" | cut -d: -f7)"

        if [ "$uid" -lt 1000 ] || [ "$user" = "nobody" ]; then
            log "Skipping system account ${user} (uid ${uid})."
            continue
        fi

        case "$shell" in
            */nologin | /bin/false)
                log "Skipping service account ${user} (shell ${shell})."
                continue
                ;;
        esac

        local lock_status
        lock_status="$(passwd -S "$user" 2> /dev/null | awk '{print $2}' || true)"
        if [[ "$lock_status" == "L" || "$lock_status" == "LK" ]]; then
            log "User ${user} is already locked."
        else
            usermod -L "$user" || error_exit "Failed to lock user ${user}."
            log "Locked user ${user}."
        fi

        chage -E 0 "$user" || error_exit "Failed to expire account ${user}."
        log "Expired account ${user}."
    done
}

update_login_defs_setting() {
    local key="$1"
    local value="$2"
    local file="/etc/login.defs"

    if [ ! -f "$file" ]; then
        log "File $file not found; skipping $key update."
        return
    fi

    if grep -q "^${key}" "$file"; then
        sed -i -E "s|^${key}.*|${key}	${value}|" "$file" || error_exit "Failed to update $key in $file."
    else
        printf "%s	%s\n" "$key" "$value" >> "$file" || error_exit "Failed to append $key to $file."
    fi
}

ensure_pam_pwquality_installed() {
    if compgen -G '/lib*/security/pam_pwquality.so' > /dev/null; then
        return
    fi
    if compgen -G '/usr/lib*/security/pam_pwquality.so' > /dev/null; then
        return
    fi

    case "$PKG_MANAGER" in
        apt)
            install_packages libpam-pwquality
            ;;
        dnf | yum)
            install_packages libpwquality
            ;;
        *)
            error_exit "Package manager not initialised."
            ;;
    esac
}

enforce_password_policy() {
    log "Enforcing password policies..."
    update_login_defs_setting "PASS_MAX_DAYS" "90"
    update_login_defs_setting "PASS_MIN_DAYS" "1"
    update_login_defs_setting "PASS_WARN_AGE" "14"

    local pam_file=""
    if [ -f /etc/pam.d/common-password ]; then
        pam_file="/etc/pam.d/common-password"
    elif [ -f /etc/pam.d/system-auth ]; then
        pam_file="/etc/pam.d/system-auth"
    else
        log "No recognised PAM password file found; skipping PAM policy update."
        return
    fi

    ensure_pam_pwquality_installed

    if command -v authselect > /dev/null 2>&1; then
        authselect apply-changes || true
    fi

    local desired_line="password	requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1"
    ensure_python3
    python3 - "$pam_file" "$desired_line" << 'PY' || error_exit "Failed to update pam_pwquality configuration."
import pathlib, re, sys
pam_path = pathlib.Path(sys.argv[1])
desired = sys.argv[2]
text = pam_path.read_text()
pattern = re.compile(r'^password\s+(?:requisite|required)\s+pam_pwquality\.so.*$', re.IGNORECASE | re.MULTILINE)
if pattern.search(text):
	text = pattern.sub(desired, text, count=1)
else:
	if not text.endswith('\n'):
		text += '\n'
	text += desired + '\n'
pam_path.write_text(text)
PY

    local pwquality_dir="/etc/security/pwquality.conf.d"
    mkdir -p "$pwquality_dir"
    cat << 'EOF' > "${pwquality_dir}/99-server-hardening.conf"
# Managed by server_hardening.sh
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
EOF
    log "Password policies configured."
}

manage_users() {
    log "Managing user accounts and enforcing password policies..."
    disable_unnecessary_accounts
    if [ "$LOCK_INACTIVE_USERS" = true ]; then
        lock_inactive_accounts "$USER_INACTIVITY_THRESHOLD"
    else
        log "Skipping inactive account locking (disabled). Use --lock-inactive-users or --inactive-threshold to enable."
    fi
    enforce_password_policy
    log "User account management and password policy enforcement complete."
}

package_installed() {
    local pkg="$1"
    case "$PKG_MANAGER" in
        apt)
            dpkg -s "$pkg" > /dev/null 2>&1
            ;;
        dnf | yum)
            rpm -q "$pkg" > /dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

detect_log_monitoring_settings() {
    LOG_MONITORING_LOG_FILES=()
    LOG_MONITORING_OS_FAMILY=""
    LOG_MONITORING_LOGROTATE_SU_GROUP="root"

    case "$PKG_MANAGER" in
        apt)
            LOG_MONITORING_OS_FAMILY="debian"
            LOG_MONITORING_LOG_FILES=(/var/log/syslog /var/log/auth.log)
            LOG_MONITORING_LOGROTATE_SU_GROUP="adm"
            ;;
        dnf | yum)
            LOG_MONITORING_OS_FAMILY="rhel"
            LOG_MONITORING_LOG_FILES=(/var/log/messages /var/log/secure)
            LOG_MONITORING_LOGROTATE_SU_GROUP="root"
            ;;
        *)
            error_exit "Unsupported package manager for log monitoring: $PKG_MANAGER"
            ;;
    esac
}

enable_and_start_rsyslog() {
    if command -v systemctl > /dev/null 2>&1; then
        systemctl enable rsyslog > /dev/null 2>&1 || true
        systemctl start rsyslog > /dev/null 2>&1 || true
    else
        log "systemctl not available; please ensure rsyslog is enabled manually."
    fi
}

install_rsyslog_stack() {
    log "Ensuring rsyslog and logrotate are installed..."
    install_packages rsyslog logrotate

    mkdir -p "$LOG_MONITORING_RSYSLOG_STATE_DIR"
    touch "$LOG_MONITORING_RSYSLOG_STATE_DIR/imjournal.state"
    chmod 0755 "$LOG_MONITORING_RSYSLOG_STATE_DIR"

    enable_and_start_rsyslog
    log "rsyslog installed and running."
}

configure_log_rotation() {
    log "Configuring log rotation for system/auth logs at $LOG_MONITORING_LOGROTATE_CONF"

    mkdir -p "$(dirname "$LOG_MONITORING_LOGROTATE_STATE")"

    for logfile in "${LOG_MONITORING_LOG_FILES[@]}"; do
        touch "$logfile"
        chown root:"$LOG_MONITORING_LOGROTATE_SU_GROUP" "$logfile" || true
        chmod 0640 "$logfile" || true
    done

    local log_file_list
    log_file_list="$(printf "%s " "${LOG_MONITORING_LOG_FILES[@]}")"

    mkdir -p "$(dirname "$LOG_MONITORING_LOGROTATE_CONF")"
    cat << EOF > "$LOG_MONITORING_LOGROTATE_CONF"
$log_file_list{
    su root $LOG_MONITORING_LOGROTATE_SU_GROUP
    rotate 7
    daily
    create 0640 root $LOG_MONITORING_LOGROTATE_SU_GROUP
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
    if ! command -v logrotate > /dev/null 2>&1; then
        log "logrotate not found; skipping validation."
        return
    fi

    log "Validating logrotate configuration..."
    mkdir -p "$(dirname "$LOG_MONITORING_LOGROTATE_STATE")"
    if ! logrotate -d -s "$LOG_MONITORING_LOGROTATE_STATE" "$LOG_MONITORING_LOGROTATE_CONF" > /tmp/logrotate-validate.log 2>&1; then
        log "logrotate dry-run reported issues (see /tmp/logrotate-validate.log); continuing."
    fi
}

configure_logwatch() {
    log "Installing logwatch and configuring daily summary to file..."

    if [ "$LOG_MONITORING_OS_FAMILY" = "rhel" ] && ! package_installed epel-release; then
        install_packages epel-release
    fi
    install_packages logwatch

    mkdir -p "$(dirname "$LOG_MONITORING_LOGWATCH_CONF")" "$LOG_MONITORING_LOGWATCH_OUTPUT_DIR"
    cat << EOF > "$LOG_MONITORING_LOGWATCH_CONF"
MailTo = root
Output = file
Format = text
Filename = $LOG_MONITORING_LOGWATCH_OUTPUT_DIR/logwatch.log
Range = yesterday
Detail = Med
EOF
}

run_logwatch_once() {
    if ! command -v logwatch > /dev/null 2>&1; then
        log "logwatch not found; skipping initial run."
        return
    fi

    log "Running logwatch once (range: today) to verify output..."
    if ! logwatch --output file --filename "$LOG_MONITORING_LOGWATCH_OUTPUT_DIR/logwatch-latest.log" --range today --detail Med > /dev/null 2>&1; then
        log "logwatch initial run reported issues; continuing."
    fi
}

setup_log_monitoring() {
    log "Setting up log monitoring (rsyslog/logrotate/logwatch)..."
    detect_log_monitoring_settings

    install_rsyslog_stack
    configure_log_rotation
    validate_logrotate_config
    configure_logwatch
    run_logwatch_once

    log "Log monitoring setup complete."
}

declare -a HARDENING_STEP_ORDER=(
    updates
    services
    firewall
    ssh
    permissions
    auto_updates
    fail2ban
    kernel
    users
    log_monitoring
)

declare -A HARDENING_STEP_LABEL=(
    [updates]="System updates"
    [services]="Service disablement"
    [firewall]="Firewall configuration"
    [ssh]="SSH hardening"
    [permissions]="File permissions"
    [auto_updates]="Automatic security updates"
    [fail2ban]="Fail2Ban"
    [kernel]="Kernel hardening"
    [users]="User account hardening"
    [log_monitoring]="Log monitoring"
)

declare -A HARDENING_STEP_SKIP_VAR=(
    [updates]="SKIP_UPDATES"
    [services]="SKIP_SERVICES"
    [firewall]="SKIP_FIREWALL"
    [ssh]="SKIP_SSH"
    [permissions]="SKIP_PERMISSIONS"
    [auto_updates]="SKIP_AUTO_UPDATES"
    [fail2ban]="SKIP_FAIL2BAN"
    [kernel]="SKIP_KERNEL"
    [users]="SKIP_USERS"
    [log_monitoring]="SKIP_LOG_MONITORING"
)

declare -A HARDENING_STEP_SKIP_FLAG=(
    [updates]="--skip-updates"
    [services]="--skip-services"
    [firewall]="--skip-firewall"
    [ssh]="--skip-ssh"
    [permissions]="--skip-permissions"
    [auto_updates]="--skip-auto-updates"
    [fail2ban]="--skip-fail2ban"
    [kernel]="--skip-kernel"
    [users]="--skip-users"
    [log_monitoring]="--skip-log-monitoring"
)

declare -A HARDENING_STEP_FUNCTION=(
    [updates]="update_system"
    [services]="disable_services"
    [firewall]="configure_firewall"
    [ssh]="harden_ssh"
    [permissions]="set_secure_permissions"
    [auto_updates]="enable_auto_updates"
    [fail2ban]="install_fail2ban"
    [kernel]="apply_kernel_hardening"
    [users]="manage_users"
    [log_monitoring]="setup_log_monitoring"
)

run_hardening_steps() {
    local step
    for step in "${HARDENING_STEP_ORDER[@]}"; do
        local label="${HARDENING_STEP_LABEL[$step]}"
        local skip_var="${HARDENING_STEP_SKIP_VAR[$step]}"
        local skip_flag="${HARDENING_STEP_SKIP_FLAG[$step]}"
        local func="${HARDENING_STEP_FUNCTION[$step]}"

        if [ "${!skip_var}" = true ]; then
            log "Skipping ${label} (${skip_flag})."
            continue
        fi

        log "---- ${label} ----"
        "$func"
    done
}

summary_line() {
    local label="$1"
    local skipped="$2"
    shift 2
    local details="$*"

    if [ "$skipped" = true ]; then
        if [ -n "$details" ]; then
            log " - ${label}: skipped (${details})"
        else
            log " - ${label}: skipped"
        fi
        return
    fi

    if [ -n "$details" ]; then
        log " - ${label}: applied (${details})"
    else
        log " - ${label}: applied"
    fi
}

print_hardening_summary() {
    log "----------------- Hardening Summary -----------------"

    summary_line "System updates" "$SKIP_UPDATES" "package-manager=${PKG_MANAGER}"
    summary_line "Service disablement" "$SKIP_SERVICES" "targets=${SERVICES_TO_DISABLE[*]}"

    if [ "$SKIP_FIREWALL" = true ]; then
        summary_line "Firewall" true
    else
        summary_line "Firewall" false "tool=${FIREWALL_TOOL:-unknown} allowed=${FIREWALL_ALLOWED_PORTS[*]}"
    fi

    if [ "$SKIP_SSH" = true ]; then
        summary_line "SSH hardening" true
    else
        local ssh_port
        ssh_port="$(detect_current_sshd_port)"
        local password_auth_status="enabled"
        if [ "$SSH_DISABLE_PASSWORD_AUTH" = true ]; then
            password_auth_status="disabled"
        fi
        summary_line "SSH hardening" false "port=${ssh_port} password_auth=${password_auth_status}"
    fi

    summary_line "File permissions" "$SKIP_PERMISSIONS"
    summary_line "Automatic security updates" "$SKIP_AUTO_UPDATES"

    if [ "$SKIP_FAIL2BAN" = true ]; then
        summary_line "Fail2Ban" true
    else
        summary_line "Fail2Ban" false "sshd-port=${EFFECTIVE_SSH_PORT}"
    fi

    if [ "$SKIP_KERNEL" = true ]; then
        summary_line "Kernel hardening" true
    else
        summary_line "Kernel hardening" false "disable_ipv6=${DISABLE_IPV6}"
    fi

    if [ "$SKIP_USERS" = true ]; then
        summary_line "User account hardening" true
    else
        local inactive_locking="disabled"
        if [ "$LOCK_INACTIVE_USERS" = true ]; then
            inactive_locking="enabled(threshold=${USER_INACTIVITY_THRESHOLD}d)"
        fi
        summary_line "User account hardening" false "inactive_locking=${inactive_locking} lock_list=${UNNECESSARY_USERS[*]}"
    fi
    if [ "$SKIP_LOG_MONITORING" = true ]; then
        summary_line "Log monitoring" true "use --enable-log-monitoring"
    else
        summary_line "Log monitoring" false "logrotate=${LOG_MONITORING_LOGROTATE_CONF} logwatch_dir=${LOG_MONITORING_LOGWATCH_OUTPUT_DIR}"
    fi
    log "Logs written to $LOG_FILE (errors: $ERROR_LOG)"
}

main() {
    local original_argc=$#
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            display_usage
            exit 0
        fi
    done

    require_root
    init_logging
    parse_arguments "$@"
    if [ "$FORCE_NON_INTERACTIVE" = false ] && [ "$INTERACTIVE" = false ] && [ "$original_argc" -eq 0 ] && [ -t 0 ]; then
        INTERACTIVE=true
    fi
    if [ "$INTERACTIVE" = false ] && [ "$LOG_MONITORING_EXPLICIT" = false ]; then
        SKIP_LOG_MONITORING=true
    fi
    interactive_configure
    finalize_configuration
    detect_package_manager

    log "================= Starting Server Hardening Process ================="
    run_hardening_steps

    print_hardening_summary
    log "================= Server Hardening Process Complete! ================="
}

main "$@"
