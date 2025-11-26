#!/bin/bash

# Harden local user accounts by locking stale logins and enforcing password aging/quality
# requirements. The script is cautious: actions can be previewed via --dry-run and it
# merges configuration instead of clobbering vendor-supplied files.

DRY_RUN=false
INACTIVITY_THRESHOLD=30

# ------------- Logging helpers -------------

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1"
    exit 1
}

# ------------- CLI parsing / validation -------------

usage() {
    cat << EOF
Usage: $0 [--threshold DAYS] [--dry-run]

Options:
  -t, --threshold DAYS  Lock accounts inactive for at least DAYS (default: ${INACTIVITY_THRESHOLD})
  -n, --dry-run         Show what would change without making modifications
  -h, --help            Display this help text
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t | --threshold)
                shift
                [[ -z "$1" ]] && error_exit "Missing value for --threshold."
                if ! [[ "$1" =~ ^[0-9]+$ ]]; then
                    error_exit "Threshold must be a positive integer."
                fi
                INACTIVITY_THRESHOLD="$1"
                ;;
            -n | --dry-run)
                DRY_RUN=true
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                usage
                error_exit "Unknown option: $1"
                ;;
        esac
        shift
    done
}

ensure_root() {
    if [ "$EUID" -ne 0 ]; then
        error_exit "Please run this script as root."
    fi
}

# ------------- Configuration helpers -------------

update_login_def() {
    local key="$1"
    local desired="$2"
    local file="/etc/login.defs"
    local current

    current=$(awk -v key="$key" '$1 == key {print $2}' "$file" | tail -n 1)

    if [ "$DRY_RUN" = true ]; then
        if [ -n "$current" ]; then
            log "[DRY-RUN] Would set ${key} from ${current:-unset} to ${desired} in ${file}."
        else
            log "[DRY-RUN] Would add ${key} ${desired} to ${file}."
        fi
        return
    fi

    if [ -n "$current" ]; then
        if ! sed -i -E "s/^(${key})[[:space:]]+.*/\1\t${desired}/" "$file"; then
            error_exit "Failed to update ${key} in ${file}."
        fi
    else
        echo "${key} ${desired}" >> "$file" || error_exit "Failed to append ${key} to ${file}."
    fi
}

set_pwquality_option() {
    local file="$1"
    local key="$2"
    local value="$3"

    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would enforce pwquality option ${key}=${value} in ${file}."
        return
    fi

    if ! crudini --set "$file" '' "$key" "$value"; then
        error_exit "Failed to set ${key} in ${file}."
    fi
}

disable_inactive_accounts() {
    # Build two sorted lists from lastlog: everyone seen and those inactive for the threshold.
    log "Evaluating user accounts inactive for at least ${INACTIVITY_THRESHOLD} days..."

    local tmp_all tmp_inactive
    tmp_all=$(mktemp) || error_exit "Unable to create temporary file."
    tmp_inactive=$(mktemp) || {
        rm -f "$tmp_all"
        error_exit "Unable to create temporary file."
    }

    if ! lastlog 2> /dev/null | tail -n +2 | awk '{print $1}' | sort -u > "$tmp_all"; then
        rm -f "$tmp_all" "$tmp_inactive"
        error_exit "Failed to read the lastlog database."
    fi

    if ! lastlog -b "$INACTIVITY_THRESHOLD" 2> /dev/null | tail -n +2 | awk '{print $1}' | sort -u > "$tmp_inactive"; then
        rm -f "$tmp_all" "$tmp_inactive"
        error_exit "Failed to determine inactive users."
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

    # Iterate user-by-user so we can skip system/service accounts and fail fast if locking fails.
    for user in "${inactive_users[@]}"; do
        [[ -z "$user" ]] && continue

        local passwd_entry
        if ! passwd_entry=$(getent passwd "$user"); then
            log "Skipping unknown user ${user}."
            continue
        fi

        local uid shell
        uid=$(echo "$passwd_entry" | cut -d: -f3)
        shell=$(echo "$passwd_entry" | cut -d: -f7)

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

        if [ "$DRY_RUN" = true ]; then
            log "[DRY-RUN] Would lock and expire account ${user}."
            continue
        fi

        if ! usermod -L "$user"; then
            error_exit "Failed to lock user ${user}."
        fi
        if ! chage -E 0 "$user"; then
            error_exit "Failed to expire user ${user}."
        fi
        log "Locked and expired account ${user}."
    done
}

enforce_password_policy() {
    # Enforce both password aging (in login.defs) and pwquality complexity using a drop-in file.
    log "Configuring password policies..."
    command -v crudini > /dev/null 2>&1 || error_exit "crudini is required to manage pwquality drop-in files."

    update_login_def "PASS_MAX_DAYS" "90"
    update_login_def "PASS_MIN_DAYS" "1"
    update_login_def "PASS_WARN_AGE" "14"

    local dropin_dir="/etc/security/pwquality.conf.d"
    local dropin_file="${dropin_dir}/50-hardening.conf"

    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would ensure ${dropin_dir} exists."
        log "[DRY-RUN] Would write enforced values to ${dropin_file}."
    else
        install -d -m 0755 "$dropin_dir" || error_exit "Failed to create ${dropin_dir}."
        touch "$dropin_file" || error_exit "Failed to prepare ${dropin_file}."
    fi

    set_pwquality_option "$dropin_file" "minlen" "12"
    set_pwquality_option "$dropin_file" "dcredit" "-1"
    set_pwquality_option "$dropin_file" "ucredit" "-1"
    set_pwquality_option "$dropin_file" "ocredit" "-1"
    set_pwquality_option "$dropin_file" "lcredit" "-1"

    log "Password policies applied."
}

# ------------- Main execution flow -------------
# 1. Parse CLI arguments (threshold, dry run, help)
# 2. Ensure we are running as root before making system changes
# 3. Disable inactive accounts
# 4. Enforce password aging + quality policies
parse_args "$@"
ensure_root
log "Starting user account hardening..."
disable_inactive_accounts
enforce_password_policy
log "User account hardening complete!"
