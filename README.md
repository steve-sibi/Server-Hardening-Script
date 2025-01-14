# Automated Linux Server Hardening Script

This project contains a Bash script designed to automatically harden a Linux server by applying various security configurations. The script helps improve server security by disabling unused services, configuring firewall rules, securing SSH settings, and applying other security best practices.

The primary goal of this script is to reduce the attack surface of the server, making it more resilient to cyberattacks. It is intended for administrators who want to automate the process of server hardening with minimal manual intervention.

## Features

- **System Updates**: Automatically updates and upgrades system packages to ensure the latest security patches are installed.
- **Disables Unnecessary Services**: Checks if services such as Telnet, FTP, and rsync are active before stopping and disabling them to minimize attack vectors without redundancy.
- **Firewall Configuration**:
  - Configures UFW (for Debian-based systems) or Firewalld (for Red Hat-based systems) to only allow necessary traffic (SSH, HTTP, HTTPS) and checks if the firewall is already configured.
- **SSH Hardening**:
  - Checks if the default SSH port (22) is used and changes it to port 2200 if necessary.
  - Disables root login and password-based authentication, ensuring changes are only applied if required.
- **File Permissions**: Ensures strict file permissions for critical directories and system files, only adjusting permissions if they aren't already correctly set.
- **Automatic Security Updates**: Enables automatic installation of security updates for Debian and Red Hat-based systems, with checks to ensure these services are not redundantly installed or configured.
- **Fail2Ban Setup**: Checks if Fail2Ban is already installed and enabled, protecting against brute-force attacks by monitoring failed login attempts and banning offending IP addresses.
- **Idempotent Operations**: The script is designed to be idempotent, meaning it can be run multiple times without causing redundant actions or breaking the system.
---
- Root Privilege Verification:

Ensures the script is run as root to perform necessary system-level operations.
---
- Automated rsyslog Installation:

Detects the server's Linux distribution and installs the rsyslog package using the appropriate package manager (apt for Debian-based systems, yum for Red Hat-based systems).

Enables and starts the rsyslog service to ensure logs are captured properly.
---
Log Rotation Configuration:

Creates a custom log rotation policy for critical log files:

/var/log/auth.log

/var/log/syslog

/var/log/messages

Retains logs for 7 days and rotates them daily.

Compresses old log files to save disk space.

Reloads the rsyslog service after each log rotation.

Error Handling and Logging:

Provides clear logs for each operation, including error messages if any step fails.

Ensures the script exits gracefully if an error occurs.

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

3. **Run the Script with Root Privileges:**

    Execute the script using sudo to ensure it has the necessary permissions to modify the system configurations:
    
    ```bash
    sudo ./server_hardening.sh
    ```

4. **Reboot the Server (Optional but Recommended):**

    After running the script, it's advisable to reboot the server to ensure all changes take effect.

    ```bash
    sudo reboot
    ```

## Compatibility

This script is compatible with the following Linux distributions:

- **Debian-based systems** (e.g., Ubuntu, Debian)
- **Red Hat-based systems** (e.g., CentOS, RHEL)

Ensure you are running the script as `root` or using `sudo` to allow it to make system-level changes.

## Contributing

Contributions are welcome! These implementations are based off experiences I have had at work. If you have ideas for improvements or new features, feel free to open an issue or create a pull request.

### Contribution Guidelines

- Fork the repository.
- Create a new branch (`git checkout -b feature-branch`).
- Commit your changes (`git commit -m 'Add a feature'`).
- Push to the branch (`git push origin feature-branch`).
- Open a Pull Request.

Please ensure your code follows the existing style and includes comments where necessary.



