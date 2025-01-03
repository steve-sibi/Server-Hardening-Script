# Project Overview: Automated Linux Server Hardening Script

## Purpose

Server hardening refers to the process of securing a server by reducing its attack surface. This project automates several important hardening steps to enhance the security posture of a Linux-based server while ensuring safe, idempotent operations. The script checks the system's current state before applying any changes, allowing it to be run multiple times without introducing redundant actions or breaking system configurations.

## Security Measures Implemented

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

## Customization

The script is designed to be flexible and customizable. Users can modify it to suit their specific server environments, such as:
- Adding or removing services to be disabled.
- Adjusting firewall rules based on specific server roles or applications.
- Changing the SSH port or other SSH hardening settings.

Because of its idempotent design, users can safely rerun the script after making modifications without the risk of redundant changes or breaking existing configurations.
