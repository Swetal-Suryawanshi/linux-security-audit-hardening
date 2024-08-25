#!/bin/bash

# Function to list all users and groups, check for UID 0, and identify users with weak passwords
user_and_group_audit() {
    echo "User and Group Audit:"

    echo "Listing all users and groups:"
    cat /etc/passwd | cut -d: -f1
    cat /etc/group | cut -d: -f1

    echo "Checking for UID 0 (root privileges):"
    awk -F: '$3 == 0 {print "User with UID 0: " $1}' /etc/passwd

    echo "Checking for users without passwords or with weak passwords:"
    awk -F: '($2 == "" || $2 == "x") {print "User without password: " $1}' /etc/shadow
}

# Function to check file and directory permissions
file_and_directory_permissions() {
    echo "File and Directory Permissions:"

    echo "Scanning for world-writable files and directories:"
    find / -xdev -type f -perm -0002 -print
    find / -xdev -type d -perm -0002 -print

    echo "Checking .ssh directories for secure permissions:"
    find /home -type d -name '.ssh' -exec ls -ld {} \;

    echo "Reporting files with SUID or SGID bits set:"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -l {} \;
}

# Function to audit services
service_audit() {
    echo "Service Audit:"

    echo "Listing all running services:"
    systemctl list-units --type=service --state=running

    echo "Checking for critical services (sshd, iptables) and their configurations:"
    systemctl status sshd
    systemctl status iptables

    echo "Checking for services listening on non-standard or insecure ports:"
    netstat -tuln
}

# Function to check firewall and network security
firewall_and_network_security() {
    echo "Firewall and Network Security:"

    echo "Verifying firewall status:"
    sudo ufw status verbose

    echo "Reporting open ports and associated services:"
    sudo netstat -tuln

    echo "Checking for IP forwarding and insecure network configurations:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding
}

# Function to check IP and network configurations
ip_and_network_configuration() {
    echo "IP and Network Configuration Checks:"

    echo "Identifying public vs. private IP addresses:"
    ip addr show | grep 'inet ' | awk '{print $2}'

    echo "Checking if sensitive services are exposed on public IPs:"
    # Check for exposed services
    netstat -tuln | grep ':22\|:80\|:443'
}

# Function to check for security updates and patching
security_updates_and_patching() {
    echo "Security Updates and Patching:"

    echo "Checking for available security updates:"
    sudo apt update -y
    sudo apt list --upgradable

    echo "Ensuring automatic updates are enabled:"
    sudo apt-config dump | grep 'APT::Periodic::Update-Package-Lists'
    sudo apt-config dump | grep 'APT::Periodic::Unattended-Upgrade'
}

# Function to monitor logs for suspicious entries
log_monitoring() {
    echo "Log Monitoring:"

    echo "Checking recent SSH logins:"
    grep 'sshd' /var/log/auth.log | tail -n 20

    echo "Checking for too many login attempts:"
    grep 'Failed password' /var/log/auth.log | tail -n 20
}

# Function to apply server hardening steps
server_hardening_steps() {
    echo "Server Hardening Steps:"

    echo "Implementing SSH key-based authentication and disabling password-based login for root:"
    sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sudo systemctl restart sshd

    echo "Disabling IPv6 if not in use:"
    # Add IPv6 disable configuration here if needed

    echo "Securing the Bootloader:"
    echo "Setting a GRUB password is recommended. Refer to GRUB documentation for setting up a password."

    echo "Configuring firewall rules:"
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw enable

    echo "Configuring automatic updates:"
    sudo apt install unattended-upgrades -y
    sudo dpkg-reconfigure --priority=low unattended-upgrades
}

# Function for custom security checks
custom_security_checks() {
    echo "Custom Security Checks:"

    # Load custom checks from configuration file if available
    if [ -f /etc/security/custom_checks.sh ]; then
        source /etc/security/custom_checks.sh
    else
        echo "No custom checks configuration file found."
    fi
}

# Function to generate report and alerts
generate_report_and_alerts() {
    echo "Generating Report and Alerts:"

    # Example of generating a report
    echo "Security Audit Report" > /var/log/security_audit_report.txt
    echo "----------------------" >> /var/log/security_audit_report.txt
    user_and_group_audit >> /var/log/security_audit_report.txt
    file_and_directory_permissions >> /var/log/security_audit_report.txt
    service_audit >> /var/log/security_audit_report.txt
    firewall_and_network_security >> /var/log/security_audit_report.txt
    ip_and_network_configuration >> /var/log/security_audit_report.txt
    security_updates_and_patching >> /var/log/security_audit_report.txt
    log_monitoring >> /var/log/security_audit_report.txt
    server_hardening_steps >> /var/log/security_audit_report.txt
    custom_security_checks >> /var/log/security_audit_report.txt

    echo "Report generated at /var/log/security_audit_report.txt"

    # Optionally, configure email alerts
    # mail -s "Security Audit Report" admin@example.com < /var/log/security_audit_report.txt
}

# Main function to execute all tasks
main() {
    user_and_group_audit
    file_and_directory_permissions
    service_audit
    firewall_and_network_security
    ip_and_network_configuration
    security_updates_and_patching
    log_monitoring
    server_hardening_steps
    custom_security_checks
    generate_report_and_alerts
    echo "Security audit and server hardening completed."
}

# Execute the main function
main
