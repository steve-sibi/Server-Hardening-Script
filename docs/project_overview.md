# Project Overview: Automated Linux Server Hardening Script

## Purpose

Server hardening refers to the process of securing a server by reducing its attack surface. This project automates several important hardening steps to enhance the security posture of a Linux-based server.

## Security Measures Implemented

### 1. System Updates
Regular updates are crucial for patching known vulnerabilities. The script ensures that all system packages are updated to their latest versions, reducing the risk of exploits.

### 2. Disabling Unnecessary Services
Unused services often run in the background, consuming resources and potentially introducing vulnerabilities. By disabling services such as Telnet, FTP, and rsync, we reduce the number of entry points for attackers.

### 3. Firewall Configuration
A properly configured firewall is essential for controlling traffic to and from the server. The script configures the firewall (UFW or Firewalld) to allow only necessary traffic (e.g., SSH, HTTP, HTTPS) while blocking all other ports.

### 4. SSH Hardening
SSH is a common attack vector for brute-force attacks. By changing the default port, disabling root login, and enforcing key-based authentication, the script helps secure SSH access.

### 5. File Permissions
Incorrect file permissions can expose sensitive files to unauthorized users. The script sets strict permissions for critical directories and files, such as `/root`, `/etc/ssh/sshd_config`, `/etc/passwd`, and `/etc/shadow`.

### 6. Automatic Security Updates
To ensure the server remains protected, the script enables automatic installation of security updates, keeping the server up to date without manual intervention.

### 7. Fail2Ban Setup
Fail2Ban is a log-based intrusion prevention tool that monitors failed login attempts and bans IP addresses exhibiting suspicious behavior, helping to prevent brute-force attacks.

## Customization

Users can easily modify the script to suit their specific server environments, such as adding or removing services to be disabled, adjusting firewall rules, or changing the SSH port.
