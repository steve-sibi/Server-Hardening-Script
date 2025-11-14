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

SSH_PORT_DEFAULT=2200
SSH_PORT="$SSH_PORT_DEFAULT"
DISABLE_IPV6=true

declare -a FIREWALL_ALLOWED_PORTS=("ssh" "http" "https")
declare -a SERVICES_TO_DISABLE=("telnet" "ftp" "rsync" "nfs" "smb")
declare -a UNNECESSARY_USERS=("games" "ftp" "mail")
declare -a ADDITIONAL_FIREWALL_PORTS=()
declare -a CUSTOM_SERVICES_TO_DISABLE=()
declare -a ADDITIONAL_USERS_TO_LOCK=()

LOG_FILE="/var/log/server_hardening.log"
ERROR_LOG="/var/log/server_hardening_error.log"

PKG_MANAGER=""
FIREWALL_TOOL=""
APT_UPDATED=false

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
  --skip-users			   Skip user/password policy enforcement
  -h, --help				 Display this help message
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ssh-port)
                local port="${2:-}"
                if [[ -z "$port" ]]; then
                    error_exit "Missing value for --ssh-port."
                fi
                if ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
                    error_exit "SSH port must be an integer between 1 and 65535."
                fi
                SSH_PORT="$port"
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
    if [ "$SSH_PORT" -ne 22 ]; then
        FIREWALL_ALLOWED_PORTS+=("$SSH_PORT/tcp")
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

    for port in "${FIREWALL_ALLOWED_PORTS[@]}"; do
        if [[ "$port" =~ ^[0-9]+(/[a-z]+)?$ ]]; then
            local rule="$port"
            if [[ "$port" != */* ]]; then
                rule="${port}/tcp"
            fi
            if ! firewall-cmd --permanent --query-port="$rule" > /dev/null 2>&1; then
                firewall-cmd --permanent --add-port="$rule" || error_exit "Failed to add port $rule to Firewalld."
                log "Added Firewalld port rule $rule."
            else
                log "Port rule $rule already present in Firewalld."
            fi
        else
            if ! firewall-cmd --permanent --query-service="$port" > /dev/null 2>&1; then
                firewall-cmd --permanent --add-service="$port" || error_exit "Failed to add service $port to Firewalld."
                log "Added Firewalld service $port."
            else
                log "Service $port already allowed in Firewalld."
            fi
        fi
    done

    firewall-cmd --set-default-zone=drop > /dev/null 2>&1 || error_exit "Failed to set Firewalld runtime default zone."
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
    set_sshd_option "PasswordAuthentication" "no"
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
    enforce_password_policy
    log "User account management and password policy enforcement complete."
}

main() {
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            display_usage
            exit 0
        fi
    done

    require_root
    init_logging
    parse_arguments "$@"
    finalize_configuration
    detect_package_manager

    log "================= Starting Server Hardening Process ================="

    if [ "$SKIP_UPDATES" = true ]; then
        log "Skipping system updates (--skip-updates)."
    else
        update_system
    fi

    if [ "$SKIP_SERVICES" = true ]; then
        log "Skipping service disablement (--skip-services)."
    else
        disable_services
    fi

    if [ "$SKIP_FIREWALL" = true ]; then
        log "Skipping firewall configuration (--skip-firewall)."
    else
        configure_firewall
    fi

    if [ "$SKIP_SSH" = true ]; then
        log "Skipping SSH hardening (--skip-ssh)."
    else
        harden_ssh
    fi

    if [ "$SKIP_PERMISSIONS" = true ]; then
        log "Skipping permission updates (--skip-permissions)."
    else
        set_secure_permissions
    fi

    if [ "$SKIP_AUTO_UPDATES" = true ]; then
        log "Skipping automatic update configuration (--skip-auto-updates)."
    else
        enable_auto_updates
    fi

    if [ "$SKIP_FAIL2BAN" = true ]; then
        log "Skipping Fail2Ban configuration (--skip-fail2ban)."
    else
        install_fail2ban
    fi

    if [ "$SKIP_KERNEL" = true ]; then
        log "Skipping kernel hardening (--skip-kernel)."
    else
        apply_kernel_hardening
    fi

    if [ "$SKIP_USERS" = true ]; then
        log "Skipping user management (--skip-users)."
    else
        manage_users
    fi

    log "================= Server Hardening Process Complete! ================="
}

main "$@"
