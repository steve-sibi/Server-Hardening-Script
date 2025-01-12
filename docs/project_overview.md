# Project Overview: Automated Linux Server Hardening Script

## Purpose

Server hardening refers to the process of securing a server by reducing its attack surface. This project automates several important hardening steps to enhance the security posture of a Linux-based server while ensuring safe, idempotent operations. The script checks the system's current state before applying any changes, allowing it to be run multiple times without introducing redundant actions or breaking system configurations.

# Security Measures Implemented

## server_hardening.sh

### 1. System Updates
Regular updates are crucial for patching known vulnerabilities. The script ensures that all system packages are updated to their latest versions, reducing the risk of exploits. This step is safe to run repeatedly, as the package manager handles updates without redundancy.

### 2. Disabling Unnecessary Services
Unused services often run in the background, consuming resources and potentially introducing vulnerabilities. The script checks whether services such as Telnet, FTP, and rsync are active before stopping and disabling them, ensuring no redundant actions are taken. By disabling these services, we reduce the number of entry points for attackers.

### 3. Firewall Configuration
A properly configured firewall is essential for controlling traffic to and from the server. The script configures the firewall (UFW for Debian-based systems or Firewalld for Red Hat-based systems) to allow only necessary traffic (e.g., SSH, HTTP, HTTPS) while blocking all other ports. It checks whether the firewall is already configured before making any changes, ensuring safe and idempotent operation.

### 4. SSH Hardening
SSH is a common attack vector for brute-force attacks. The script checks the current SSH configuration and applies hardening measures only if necessary. These measures include changing the default SSH port, disabling root login, and enforcing key-based authentication. This ensures that redundant changes aren't applied if the system is already secure.

### 5. File Permissions
Incorrect file permissions can expose sensitive files to unauthorized users. The script checks the current permissions for critical directories and files (such as `/root`, `/etc/ssh/sshd_config`, `/etc/passwd`, and `/etc/shadow`) and only applies changes if the permissions are not already set correctly. This prevents unnecessary changes and ensures that file permissions are always secure.

### 6. Automatic Security Updates
To ensure the server remains protected, the script enables automatic installation of security updates for both Debian and Red Hat-based systems. Before doing so, it checks if the appropriate package (e.g., `unattended-upgrades` or `yum-cron`) is already installed and configured, avoiding redundant installations.

### 7. Fail2Ban Setup
Fail2Ban is a log-based intrusion prevention tool that monitors failed login attempts and bans IP addresses exhibiting suspicious behavior, helping to prevent brute-force attacks. The script checks if Fail2Ban is already installed and enabled before attempting to install or configure it, ensuring idempotent behavior and avoiding redundant installations.

### 8. Kernel Hardening
This script applies kernel-level hardening measures to protect the server against common network-based attacks and improve overall system security. These measures include:
- Disabling IP forwarding.
- Preventing source routing.
- Enabling TCP SYN cookies to protect against SYN flood attacks.
- Randomizing virtual address space layout (ASLR) to prevent memory-based attacks.

---

## user_account_hardening.sh

### Root Privilege Check:
- Ensures the script is executed with root permissions. If not, it exits with an error message.

### Logging Mechanism:
- Provides timestamped logs for both informational messages and error handling, making the script's execution easier to track and debug.

### Disabling Inactive User Accounts:
- Identifies and removes user accounts that have never logged in (based on the last 30 days of activity) using the lastlog command and userdel.
- Outputs a message if no inactive accounts are found.

### Enforcing Password Policies:
- Updates the /etc/login.defs file to set:
    - A maximum password age of 90 days.
    - A minimum password age of 1 day.
    - A password expiration warning 14 days before expiration.
- Configures stricter password quality requirements in /etc/security/pwquality.conf, including:
    - Minimum password length of 12 characters.
    - Enforced inclusion of at least one digit, uppercase letter, lowercase letter, and special character.

### Main Execution:
- The script runs the functions sequentially:
   1. Disables inactive accounts.
   2. Configures password policies.
- Outputs progress logs to inform the user about each step of the process.

### The script aims to strengthen system security by:
- Reducing the risk of unauthorized access through inactive accounts.
- Enforcing strong password policies to mitigate password-based attacks.

---

## apache_nginx_web_hardening.sh
### Root User Verification:
Ensures the script is executed with root privileges to make necessary changes to system configurations.

### Logging:
Provides clear and timestamped logs for both standard operations (log()) and error handling (error_exit()), enhancing script transparency and debugging.

### Web Server Detection:
Automatically identifies whether Apache or Nginx is installed on the system. If neither is found, the script terminates with an error message.

### Hardening Apache:
Enables the headers module if not already enabled.
Appends security headers to the security.conf configuration file:

### X-Frame-Options: 
    - DENY: Prevents clickjacking by disallowing the embedding of the site in iframes.
### X-Content-Type-Options: 
    - nosniff: Prevents browsers from interpreting files as a different MIME type.
### Content-Security-Policy: 
    - default-src 'self': Restricts the loading of content (e.g., scripts, images) to the same origin as the web server.
Restarts Apache to apply changes.

### Hardening Nginx:
Adds security headers to a custom configuration file (/etc/nginx/conf.d/security.conf):
Same headers as described for Apache.
Restarts Nginx to apply changes.


---

## log_monitoring.sh
Root User Verification:

Ensures the script is executed with root privileges to modify system configurations and install necessary packages.
Logging and Error Handling:

Provides timestamped logs for key actions (log()), enhancing clarity during execution.
Gracefully exits the script with error messages if any critical operation fails (error_exit()).
rsyslog Installation:

Detects the Linux distribution (Debian-based or Red Hat-based) and installs the rsyslog package using the appropriate package manager (apt or yum).
Enables and starts the rsyslog service to ensure that log messages are properly captured and recorded.
Log Rotation Configuration:

Sets up a custom log rotation policy by creating a configuration file in /etc/logrotate.d/.
Configures the following:
Targets critical log files such as /var/log/auth.log, /var/log/syslog, and /var/log/messages.
Retains logs for 7 days and rotates them daily.
Compresses old log files to save disk space.
Skips rotation if logs are missing or empty.
Ensures that rsyslog is reloaded after each rotation to maintain proper logging.
Automation:

The script is designed to be executed once but can be reused to reapply configurations or troubleshoot logging setup issues.


## Customization

The script is designed to be flexible and customizable. Users can modify it to suit their specific server environments, such as:
- Adding or removing services to be disabled.
- Adjusting firewall rules based on specific server roles or applications.
- Changing the SSH port or other SSH hardening settings.

Because of its idempotent design, users can safely rerun the script after making modifications without the risk of redundant changes or breaking existing configurations.
