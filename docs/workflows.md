# GitHub Actions Workflows

Each script has a dedicated GitHub Actions workflow that runs on pull requests and pushes to `main` when the script or its workflow file changes. They lint the Bash code and execute end-to-end tests inside fresh containers so the hardening logic is validated on the distributions the scripts target.

## Server Hardening Tests (`.github/workflows/server_hardening.yml`)

- **Purpose:** Lint `scripts/server_hardening.sh` and verify it hardens Ubuntu 22.04, Debian 12, and Rocky 9.
- **Lint:** Runs ShellCheck and shfmt.
- **End-to-end:** Boots systemd containers for each distro, installs SSH and the right firewall (UFW or firewalld), then runs `./scripts/server_hardening.sh --non-interactive --skip-updates --enable-log-monitoring`.
- **Assertions:** SSH listens on port 2200, firewall rules allow 2200/tcp, Fail2Ban is enabled and running, key sysctls are set (e.g., `net.ipv4.tcp_syncookies=1`), and log monitoring outputs exist (rsyslog/logrotate/logwatch). If anything fails, the workflow prints `/var/log/server_hardening*.log`.

## Apache/Nginx Web Hardening Tests (`.github/workflows/apache_nginx_web_hardening.yml`)

- **Purpose:** Lint and verify `scripts/apache_nginx_web_hardening.sh` against Apache and Nginx on Ubuntu 22.04, Debian 12, and Rocky 9.
- **Lint:** Runs ShellCheck and shfmt.
- **End-to-end:** For each distro/server pair, installs Apache or Nginx, enables the service, then runs the script with `--server` hints.
- **Assertions:** Confirms the security header drop-in exists, config tests pass (`apache2ctl -M`/`httpd -M` header module checks when applicable), and `curl -I` shows `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'self'`. On failure, it dumps service status, the security config, and relevant web server logs.

## User Account Hardening (`.github/workflows/user_account_hardening.yml`)

- **Purpose:** Prove `scripts/user_account_hardening.sh` locks stale accounts and enforces password policy defaults.
- **Flow:** Starts an Ubuntu 22.04 container, installs PAM/password utilities, and creates a dormant test user. Runs the script with `--threshold 0` to immediately treat that user as stale.
- **Assertions:** The test user is locked (`passwd -S ... L`), `PASS_MAX_DAYS=90`, `PASS_MIN_DAYS=1`, `PASS_WARN_AGE=14` in `/etc/login.defs`, and `/etc/security/pwquality.conf.d/50-hardening.conf` enforces `minlen=12` plus `dcredit/ucredit/ocredit/lcredit = -1`.

## Log Monitoring

Log monitoring (rsyslog/logrotate/logwatch) is validated as part of the server hardening end-to-end job in `.github/workflows/server_hardening.yml`.
