#!/bin/bash

# Ensure the script is being run as root
if [ "$EUID" -ne 0 ]
then 
  echo "Please run as root"
  exit
fi

# Step 1: Update the system (Idempotent as it always checks for new packages)
echo "Updating system packages..."
if [ -f /etc/debian_version ]; then
    apt update && apt upgrade -y
elif [ -f /etc/redhat-release ]; then
    yum update -y
else
    echo "Unsupported OS."
    exit 1
fi

# Step 2: Disable unused services (Only stop/disable if the service is active)
echo "Disabling unused services..."
for service in telnet ftp rsync; do
    if systemctl is-active --quiet $service.service; then
        echo "Stopping and disabling $service..."
        systemctl stop $service.service
        systemctl disable $service.service
    else
        echo "$service is already stopped and disabled."
    fi
done

# Step 3: Configure firewall (Check if UFW/Firewalld is active before configuring)
echo "Configuring firewall..."
if command -v ufw > /dev/null 2>&1; then
    if ufw status | grep -q inactive; then
        echo "Setting up UFW firewall..."
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow http
        ufw allow https
        ufw enable
    else
        echo "UFW is already active."
    fi
elif command -v firewall-cmd > /dev/null 2>&1; then
    echo "Setting up Firewalld firewall..."
    firewall-cmd --permanent --set-default-zone=drop
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
else
    echo "No firewall tool found. Skipping..."
fi

# Step 4: Harden SSH (Check if changes have already been applied)
echo "Hardening SSH configuration..."

# Backup only if not already backed up
if [ ! -f /etc/ssh/sshd_config.bak ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    echo "Backup created for SSH configuration."
else
    echo "Backup for SSH configuration already exists."
fi

# Only change SSH config if necessary
if grep -q "#Port 22" /etc/ssh/sshd_config; then
    sed -i 's/#Port 22/Port 2200/' /etc/ssh/sshd_config
    echo "Changed SSH port to 2200."
else
    echo "SSH port already set to 2200 or non-default."
fi

if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    echo "Disabled root login."
else
    echo "Root login is already disabled."
fi

if grep -q "#PasswordAuthentication yes" /etc/ssh/sshd_config; then
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    echo "Disabled password authentication."
else
    echo "Password authentication already disabled."
fi

# Restart SSH service only if config has changed
systemctl restart sshd
echo "SSH service restarted."

# Step 5: Set secure file permissions (Only apply changes if permissions are incorrect)
echo "Setting secure file permissions..."

if [ "$(stat -c %a /root)" != "700" ]; then
    chmod 700 /root
    echo "Permissions for /root set to 700."
else
    echo "Permissions for /root already set correctly."
fi

if [ "$(stat -c %a /etc/ssh/sshd_config)" != "600" ]; then
    chmod 600 /etc/ssh/sshd_config
    echo "Permissions for /etc/ssh/sshd_config set to 600."
else
    echo "Permissions for /etc/ssh/sshd_config already set correctly."
fi

for file in /etc/passwd /etc/shadow; do
    if [ "$(stat -c %a $file)" != "600" ]; then
        chmod 600 $file
        echo "Permissions for $file set to 600."
    else
        echo "Permissions for $file already set correctly."
    fi
done

# Step 6: Enable automatic security updates (Check if it's already enabled)
echo "Enabling automatic security updates..."
if [ -f /etc/debian_version ]; then
    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed"; then
        echo "Unattended upgrades already installed."
    else
        apt install unattended-upgrades -y
        dpkg-reconfigure --priority=low unattended-upgrades
        echo "Unattended upgrades installed and configured."
    fi
elif [ -f /etc/redhat-release ]; then
    if yum list installed yum-cron &>/dev/null; then
        echo "yum-cron already installed."
    else
        yum install yum-cron -y
        systemctl enable yum-cron
        systemctl start yum-cron
        echo "yum-cron installed and enabled."
    fi
fi

# Step 7: Install and configure fail2ban (Check if it's already installed)
echo "Installing fail2ban..."
if [ -f /etc/debian_version ]; then
    if dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -q "install ok installed"; then
        echo "Fail2ban already installed."
    else
        apt install fail2ban -y
        systemctl enable fail2ban
        systemctl start fail2ban
        echo "Fail2ban installed and enabled."
    fi
elif [ -f /etc/redhat-release ]; then
    if yum list installed fail2ban &>/dev/null; then
        echo "Fail2ban already installed."
    else
        yum install fail2ban -y
        systemctl enable fail2ban
        systemctl start fail2ban
        echo "Fail2ban installed and enabled."
    fi
fi

echo "Server hardening complete!"
