#!/bin/bash

# Ensure the script is being run as root
if [ "$EUID" -ne 0 ]
then 
  echo "Please run as root"
  exit
fi

# Step 1: Update the system
echo "Updating system packages..."
if [ -f /etc/debian_version ]; then
    apt update && apt upgrade -y
elif [ -f /etc/redhat-release ]; then
    yum update -y
else
    echo "Unsupported OS."
    exit 1
fi

# Step 2: Disable unused services
echo "Disabling unused services..."
systemctl stop telnet.service
systemctl disable telnet.service
systemctl stop ftp.service
systemctl disable ftp.service
systemctl stop rsync.service
systemctl disable rsync.service

# Step 3: Configure firewall
echo "Configuring firewall..."
if command -v ufw > /dev/null 2>&1; then
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw enable
elif command -v firewall-cmd > /dev/null 2>&1; then
    firewall-cmd --permanent --set-default-zone=drop
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
else
    echo "No firewall tool found. Skipping..."
fi

# Step 4: Harden SSH
echo "Hardening SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/#Port 22/Port 2200/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Step 5: Set secure file permissions
echo "Setting secure file permissions..."
chmod 700 /root
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/passwd
chmod 600 /etc/shadow

# Step 6: Enable automatic security updates
echo "Enabling automatic security updates..."
if [ -f /etc/debian_version ]; then
    apt install unattended-upgrades -y
    dpkg-reconfigure --priority=low unattended-upgrades
elif [ -f /etc/redhat-release ]; then
    yum install yum-cron -y
    systemctl enable yum-cron
    systemctl start yum-cron
fi

# Step 7: Install and configure fail2ban
echo "Installing fail2ban..."
if [ -f /etc/debian_version ]; then
    apt install fail2ban -y
elif [ -f /etc/redhat-release ]; then
    yum install fail2ban -y
fi
systemctl enable fail2ban
systemctl start fail2ban

echo "Server hardening complete!"
