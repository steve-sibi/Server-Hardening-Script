# Automated Linux Server Hardening Scripts

This project contains Bash scripts that harden Linux servers and set up supporting controls like log monitoring. They improve security by disabling unused services, configuring firewall rules and SSH, enforcing password policies, and ensuring logs are collected, rotated, and summarized.

The primary goal is to reduce the attack surface and add operational visibility with minimal manual intervention.

## Features

- **Server hardening (scripts/server_hardening.sh)**: System updates, service pruning, UFW/Firewalld rules, SSH hardening (defaults to port 2200), permissions tightening, automatic security updates, Fail2Ban, kernel sysctls, and idempotent re-runs.
- **User/account hardening (scripts/user_account_hardening.sh)**: Password aging, pwquality defaults, and locking stale accounts.
- **Web server hardening (scripts/apache_nginx_web_hardening.sh)**: Apache/Nginx security headers and TLS defaults.
- **Log monitoring (scripts/log_monitoring.sh)**:
  - Detects Debian/Ubuntu vs RHEL/Rocky, installs rsyslog + logrotate (and EPEL on RHEL for logwatch), and starts rsyslog.
  - Writes a distro-aware logrotate policy for system/auth logs with `su` and `create` to avoid permission errors; pre-creates log files with correct ownership.
  - Uses a dedicated logrotate state file under `/var/lib/logrotate/hardening.status`.
  - Installs logwatch and generates text summaries under `/var/log/logwatch/`, with a verification run.
  - Safe to re-run (idempotent) on supported distros.
- **Root privilege verification**: All scripts check and require root/sudo.
- **Error handling/logging**: Clear INFO/ERROR messages and early exits on failure.

## How to Use

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/server-hardening-script.git
   cd server-hardening-script

   ```

2. **Make the Script Executable:**

    Navigate to the scripts directory and make the script executable:

    ```bash
    cd scripts
    chmod +x server_hardening.sh
    ```

3. **Run the Server Hardening Script with Root Privileges:**

    Execute the script using sudo to ensure it has the necessary permissions to modify the system configurations:
    
    ```bash
    sudo ./server_hardening.sh
    ```

    - Interactive mode: when run from a terminal with no flags, the script prompts you to pick which hardening modules to apply.
    - Automation: use `--non-interactive` (and/or `--skip-*`) to avoid prompts in CI or unattended runs.

4. **Run the Log Monitoring Script (rsyslog + logrotate + logwatch):**

    ```bash
    sudo ./log_monitoring.sh
    ```

    - Debian/Ubuntu: rotates `/var/log/syslog` and `/var/log/auth.log` as root:adm.
    - RHEL/Rocky: rotates `/var/log/messages` and `/var/log/secure` as root:root and enables EPEL for logwatch.
    - Outputs logwatch summaries to `/var/log/logwatch/` and uses `/var/lib/logrotate/hardening.status` for rotation state.

5. **Reboot the Server (Optional but Recommended):**

    After running the script, it's advisable to reboot the server to ensure all changes take effect.

    ```bash
    sudo reboot
    ```

## Compatibility

This script is compatible with the following Linux distributions:

- **Debian-based systems** (e.g., Ubuntu, Debian)
- **Red Hat-based systems** (e.g., CentOS, RHEL)

Ensure you are running the script as `root` or using `sudo` to allow it to make system-level changes.

## CI Workflows

Each script has a dedicated GitHub Actions workflow that runs on pull requests and pushes to `main` when the script or its workflow file changes. Highlights:

- **Server Hardening Tests (`.github/workflows/server_hardening.yml`)**: Lints `scripts/server_hardening.sh` with ShellCheck/shfmt, then runs it in systemd-backed containers for Ubuntu 22.04, Debian 12, and Rocky 9. It bootstraps SSH + the appropriate firewall, executes `./scripts/server_hardening.sh --skip-updates`, and asserts SSH listens on 2200/tcp, firewall rules are in place, Fail2Ban is enabled, and key sysctls are set; on failures it prints the hardening logs.
- **Apache/Nginx Web Hardening Tests (`.github/workflows/apache_nginx_web_hardening.yml`)**: Lints `scripts/apache_nginx_web_hardening.sh`, installs Apache or Nginx on Ubuntu/Debian/Rocky matrices, runs the script with server hints, and verifies security header drop-ins exist, config tests pass, and `curl -I` returns `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'self'`.
- **User Account Hardening (`.github/workflows/user_account_hardening.yml`)**: Spins up an Ubuntu 22.04 container with a dormant user, runs `scripts/user_account_hardening.sh --threshold 0`, and checks the user is locked plus `/etc/login.defs` and `pwquality` defaults enforce the intended aging and complexity values.
- **Log Monitoring Tests (`.github/workflows/log_monitoring.yml`)**: Runs `scripts/log_monitoring.sh` on Ubuntu 22.04, Debian 12, and Rocky 9 containers, tolerates rsyslog restarts if needed, and validates the logrotate drop-in/state file plus logwatch outputs at `/var/log/logwatch/` (ensuring `logwatch-latest.log` is non-empty).

See `docs/workflows.md` for a readable breakdown of each workflow.

## Contributing

Contributions are welcome! These implementations are based off experiences I have had at work. If you have ideas for improvements or new features, feel free to open an issue or create a pull request.

### Contribution Guidelines

- Fork the repository.
- Create a new branch (`git checkout -b feature-branch`).
- Commit your changes (`git commit -m 'Add a feature'`).
- Push to the branch (`git push origin feature-branch`).
- Open a Pull Request.

Please ensure your code follows the existing style and includes comments where necessary.
