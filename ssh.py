#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import time
import re
import json
from typing import List, Optional, Dict, Tuple
from datetime import datetime

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Configuration paths
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
BACKUP_SSHD_CONFIG_PATH = "/etc/ssh/sshd_config.bak"
LOGIN_DEFS_PATH = "/etc/login.defs"
PAM_LOGIN_PATH = "/etc/pam.d/login"
AUDIT_LOG_PATH = "/var/log/ssh_security_audit.log"

SSH_TEMPLATE = """
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port {ssh_port}
AddressFamily inet
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
LogLevel VERBOSE

# Authentication:

LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2

PasswordAuthentication no
PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin prohibit-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 2
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
"""

class SecurityAudit:
    def __init__(self):
        self.audit_results = {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def check_ssh_config(self) -> Dict[str, any]:
        """Audit SSH configuration settings"""
        results = {
            'status': 'unknown',
            'checks': {},
            'recommendations': []
        }
        
        if not os.path.exists(SSHD_CONFIG_PATH):
            results['status'] = 'error'
            results['error'] = 'SSH config file not found'
            return results
        
        try:
            with open(SSHD_CONFIG_PATH, 'r') as f:
                config_content = f.read()
            
            # Define security checks
            security_checks = {
                'port_changed': {
                    'pattern': r'^Port\s+(?!22\s*$)(\d+)',
                    'description': 'SSH port changed from default (22)',
                    'severity': 'medium'
                },
                'root_login_disabled': {
                    'pattern': r'^PermitRootLogin\s+(no|prohibit-password)',
                    'description': 'Root login disabled',
                    'severity': 'high'
                },
                'password_auth_disabled': {
                    'pattern': r'^PasswordAuthentication\s+no',
                    'description': 'Password authentication disabled',
                    'severity': 'high'
                },
                'pubkey_auth_enabled': {
                    'pattern': r'^PubkeyAuthentication\s+yes',
                    'description': 'Public key authentication enabled',
                    'severity': 'high'
                },
                'max_auth_tries_limited': {
                    'pattern': r'^MaxAuthTries\s+[1-5]',
                    'description': 'Maximum authentication tries limited (≤5)',
                    'severity': 'medium'
                },
                'max_sessions_limited': {
                    'pattern': r'^MaxSessions\s+[1-5]',
                    'description': 'Maximum sessions limited (≤5)',
                    'severity': 'medium'
                },
                'login_grace_time_limited': {
                    'pattern': r'^LoginGraceTime\s+[1-9][0-9]?',
                    'description': 'Login grace time limited (≤99 seconds)',
                    'severity': 'low'
                },
                'client_alive_interval': {
                    'pattern': r'^ClientAliveInterval\s+[1-9]\d*',
                    'description': 'Client alive interval configured',
                    'severity': 'low'
                },
                'strict_modes_enabled': {
                    'pattern': r'^StrictModes\s+yes',
                    'description': 'Strict modes enabled',
                    'severity': 'medium'
                },
                'log_level_verbose': {
                    'pattern': r'^LogLevel\s+(VERBOSE|DEBUG)',
                    'description': 'Detailed logging enabled',
                    'severity': 'low'
                }
            }
            
            # Check each security setting
            for check_name, check_info in security_checks.items():
                if re.search(check_info['pattern'], config_content, re.MULTILINE):
                    results['checks'][check_name] = {
                        'status': 'pass',
                        'description': check_info['description'],
                        'severity': check_info['severity']
                    }
                else:
                    results['checks'][check_name] = {
                        'status': 'fail',
                        'description': check_info['description'],
                        'severity': check_info['severity']
                    }
                    if check_info['severity'] == 'high':
                        results['recommendations'].append(f"Configure {check_info['description'].lower()}")
            
            # Overall status
            failed_high = sum(1 for check in results['checks'].values() 
                            if check['status'] == 'fail' and check['severity'] == 'high')
            failed_medium = sum(1 for check in results['checks'].values() 
                              if check['status'] == 'fail' and check['severity'] == 'medium')
            
            if failed_high == 0 and failed_medium <= 2:
                results['status'] = 'good'
            elif failed_high <= 1:
                results['status'] = 'fair'
            else:
                results['status'] = 'poor'
                
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def check_firewall_status(self) -> Dict[str, any]:
        """Check firewall configuration and SSH rules"""
        results = {
            'status': 'unknown',
            'checks': {},
            'recommendations': []
        }
        
        try:
            # Check if iptables is available
            subprocess.run(["iptables", "--version"], capture_output=True, check=True)
            
            # Get current iptables rules
            result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
            rules = result.stdout
            
            # Check firewall status
            checks = {
                'default_input_drop': 'Chain INPUT (policy DROP)' in rules,
                'ssh_rules_present': 'tcp dpt:' in rules or 'dport' in rules,
                'loopback_allowed': 'ACCEPT.*lo' in rules,
                'established_allowed': 'ESTABLISHED' in rules
            }
            
            results['checks'] = {
                'firewall_active': {
                    'status': 'pass' if any(checks.values()) else 'fail',
                    'description': 'Firewall rules are active',
                    'severity': 'high'
                },
                'restrictive_input_policy': {
                    'status': 'pass' if checks['default_input_drop'] else 'fail',
                    'description': 'Default INPUT policy is restrictive (DROP)',
                    'severity': 'high'
                },
                'ssh_access_controlled': {
                    'status': 'pass' if checks['ssh_rules_present'] else 'fail',
                    'description': 'SSH access rules are configured',
                    'severity': 'medium'
                },
                'essential_traffic_allowed': {
                    'status': 'pass' if checks['loopback_allowed'] and checks['established_allowed'] else 'fail',
                    'description': 'Essential traffic (loopback, established) allowed',
                    'severity': 'medium'
                }
            }
            
            # Generate recommendations
            for check_name, check_info in results['checks'].items():
                if check_info['status'] == 'fail':
                    results['recommendations'].append(f"Fix: {check_info['description']}")
            
            # Overall status
            failed_high = sum(1 for check in results['checks'].values() 
                            if check['status'] == 'fail' and check['severity'] == 'high')
            
            if failed_high == 0:
                results['status'] = 'good'
            elif failed_high == 1:
                results['status'] = 'fair'
            else:
                results['status'] = 'poor'
                
        except FileNotFoundError:
            results['status'] = 'error'
            results['error'] = 'iptables not found'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def check_system_hardening(self) -> Dict[str, any]:
        """Check additional system hardening measures"""
        results = {
            'status': 'unknown',
            'checks': {},
            'recommendations': []
        }
        
        try:
            checks = {}
            
            # Check fail2ban
            try:
                subprocess.run(["systemctl", "is-active", "fail2ban"], 
                             capture_output=True, check=True, text=True)
                checks['fail2ban_active'] = True
            except subprocess.CalledProcessError:
                checks['fail2ban_active'] = False
            
            # Check automatic updates
            checks['unattended_upgrades'] = os.path.exists('/etc/apt/apt.conf.d/50unattended-upgrades')
            
            # Check password policies
            if os.path.exists(LOGIN_DEFS_PATH):
                with open(LOGIN_DEFS_PATH, 'r') as f:
                    login_defs = f.read()
                checks['password_max_days'] = bool(re.search(r'^PASS_MAX_DAYS\s+[1-9][0-9]?$', login_defs, re.MULTILINE))
                checks['password_min_len'] = bool(re.search(r'^PASS_MIN_LEN\s+[8-9]|[1-9][0-9]+', login_defs, re.MULTILINE))
            else:
                checks['password_max_days'] = False
                checks['password_min_len'] = False
            
            # Check for unnecessary services
            try:
                result = subprocess.run(["systemctl", "list-unit-files", "--type=service", "--state=enabled"], 
                                      capture_output=True, text=True)
                enabled_services = result.stdout.lower()
                checks['telnet_disabled'] = 'telnet' not in enabled_services
                checks['rsh_disabled'] = 'rsh' not in enabled_services
                checks['ftp_disabled'] = 'vsftpd' not in enabled_services and 'proftpd' not in enabled_services
            except subprocess.CalledProcessError:
                checks['telnet_disabled'] = True  # Assume disabled if can't check
                checks['rsh_disabled'] = True
                checks['ftp_disabled'] = True
            
            # Map checks to results
            results['checks'] = {
                'fail2ban_protection': {
                    'status': 'pass' if checks['fail2ban_active'] else 'fail',
                    'description': 'Fail2ban intrusion detection active',
                    'severity': 'medium'
                },
                'automatic_updates': {
                    'status': 'pass' if checks['unattended_upgrades'] else 'fail',
                    'description': 'Automatic security updates configured',
                    'severity': 'medium'
                },
                'password_aging': {
                    'status': 'pass' if checks['password_max_days'] else 'fail',
                    'description': 'Password aging policy configured',
                    'severity': 'low'
                },
                'password_complexity': {
                    'status': 'pass' if checks['password_min_len'] else 'fail',
                    'description': 'Minimum password length enforced',
                    'severity': 'medium'
                },
                'insecure_services_disabled': {
                    'status': 'pass' if all([checks['telnet_disabled'], checks['rsh_disabled'], checks['ftp_disabled']]) else 'fail',
                    'description': 'Insecure services (telnet, rsh, ftp) disabled',
                    'severity': 'high'
                }
            }
            
            # Generate recommendations
            if not checks['fail2ban_active']:
                results['recommendations'].append("Install and configure fail2ban: apt install fail2ban")
            if not checks['unattended_upgrades']:
                results['recommendations'].append("Enable automatic updates: dpkg-reconfigure unattended-upgrades")
            if not checks['password_max_days']:
                results['recommendations'].append("Configure password aging in /etc/login.defs")
            
            # Overall status
            failed_high = sum(1 for check in results['checks'].values() 
                            if check['status'] == 'fail' and check['severity'] == 'high')
            failed_medium = sum(1 for check in results['checks'].values() 
                              if check['status'] == 'fail' and check['severity'] == 'medium')
            
            if failed_high == 0 and failed_medium <= 1:
                results['status'] = 'good'
            elif failed_high == 0 and failed_medium <= 3:
                results['status'] = 'fair'
            else:
                results['status'] = 'poor'
                
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def check_user_accounts(self) -> Dict[str, any]:
        """Check user account security"""
        results = {
            'status': 'unknown',
            'checks': {},
            'recommendations': []
        }
        
        try:
            # Read passwd file
            with open('/etc/passwd', 'r') as f:
                passwd_lines = f.readlines()
            
            # Read shadow file if accessible
            shadow_data = {}
            try:
                with open('/etc/shadow', 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            shadow_data[parts[0]] = parts[1]
            except PermissionError:
                pass  # May not have access, that's ok
            
            # Analyze accounts
            total_accounts = 0
            locked_accounts = 0
            no_password_accounts = 0
            sudo_users = []
            
            # Check who has sudo access
            try:
                result = subprocess.run(["getent", "group", "sudo"], capture_output=True, text=True)
                if result.returncode == 0:
                    sudo_line = result.stdout.strip()
                    if ':' in sudo_line:
                        sudo_users = sudo_line.split(':')[-1].split(',') if sudo_line.split(':')[-1] else []
            except subprocess.CalledProcessError:
                pass
            
            for line in passwd_lines:
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    username = parts[0]
                    uid = int(parts[2])
                    shell = parts[6]
                    
                    # Only check human user accounts (UID >= 1000, valid shell)
                    if uid >= 1000 and shell not in ['/bin/false', '/usr/sbin/nologin', '/bin/sync']:
                        total_accounts += 1
                        
                        # Check if account is locked
                        if username in shadow_data:
                            if shadow_data[username].startswith('!') or shadow_data[username] == '*':
                                locked_accounts += 1
                            elif shadow_data[username] == '':
                                no_password_accounts += 1
            
            results['checks'] = {
                'no_empty_passwords': {
                    'status': 'pass' if no_password_accounts == 0 else 'fail',
                    'description': f'No accounts with empty passwords (found: {no_password_accounts})',
                    'severity': 'high'
                },
                'sudo_users_limited': {
                    'status': 'pass' if len(sudo_users) <= 3 else 'warn',
                    'description': f'Limited sudo users (found: {len(sudo_users)})',
                    'severity': 'medium'
                },
                'account_review': {
                    'status': 'info',
                    'description': f'Total user accounts: {total_accounts}, Locked: {locked_accounts}',
                    'severity': 'low'
                }
            }
            
            if no_password_accounts > 0:
                results['recommendations'].append(f"Secure {no_password_accounts} accounts with empty passwords")
            if len(sudo_users) > 3:
                results['recommendations'].append("Review and limit sudo access")
            
            results['status'] = 'poor' if no_password_accounts > 0 else 'good'
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def generate_full_audit(self) -> Dict[str, any]:
        """Generate comprehensive security audit"""
        print_step("Performing comprehensive security audit")
        
        audit_results = {
            'timestamp': self.timestamp,
            'ssh_config': self.check_ssh_config(),
            'firewall': self.check_firewall_status(),
            'system_hardening': self.check_system_hardening(),
            'user_accounts': self.check_user_accounts()
        }
        
        # Calculate overall security score
        scores = {
            'good': 3,
            'fair': 2,
            'poor': 1,
            'error': 0,
            'unknown': 0
        }
        
        total_score = 0
        max_score = 0
        for category, results in audit_results.items():
            if category != 'timestamp' and 'status' in results:
                total_score += scores.get(results['status'], 0)
                max_score += 3
        
        if max_score > 0:
            security_percentage = (total_score / max_score) * 100
            if security_percentage >= 80:
                overall_status = 'good'
            elif security_percentage >= 60:
                overall_status = 'fair'
            else:
                overall_status = 'poor'
        else:
            overall_status = 'unknown'
            security_percentage = 0
        
        audit_results['overall'] = {
            'status': overall_status,
            'security_score': f"{security_percentage:.1f}%",
            'raw_score': f"{total_score}/{max_score}"
        }
        
        # Save audit log
        self.save_audit_log(audit_results)
        
        return audit_results

    def save_audit_log(self, audit_data: Dict[str, any]):
        """Save audit results to log file"""
        try:
            log_entry = {
                'timestamp': audit_data['timestamp'],
                'overall_score': audit_data['overall']['security_score'],
                'status': audit_data['overall']['status'],
                'details': audit_data
            }
            
            # Ensure log directory exists
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            
            # Append to log file
            with open(AUDIT_LOG_PATH, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            print_warning(f"Could not save audit log: {e}")

def print_banner():
    """Display an attractive banner for the script"""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}         SSH Security Configuration & Audit Tool{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.YELLOW}    Secure, Audit, and Manage your server's remote access{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}\n")

def print_success(message: str):
    """Print success message in green"""
    print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")

def print_warning(message: str):
    """Print warning message in yellow"""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.ENDC}")

def print_error(message: str):
    """Print error message in red"""
    print(f"{Colors.RED}✗ {message}{Colors.ENDC}")

def print_info(message: str):
    """Print info message in blue"""
    print(f"{Colors.BLUE}ℹ {message}{Colors.ENDC}")

def print_step(step: str):
    """Print step message with emphasis"""
    print(f"{Colors.BOLD}{Colors.CYAN}▶ {step}{Colors.ENDC}")

def spinner_animation(duration: float = 1.5):
    """Show a spinner animation"""
    spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"\r{Colors.CYAN}{spinner_chars[i % len(spinner_chars)]} Processing...{Colors.ENDC}", end='', flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r{Colors.GREEN}✓ Complete!{Colors.ENDC}    ")

def validate_port(port_str: str) -> bool:
    """Validate if the port is valid"""
    if not port_str.isdigit():
        return False
    port = int(port_str)
    return 1 <= port <= 65535

def validate_subnet(subnet: str) -> bool:
    """Validate if the subnet format is correct"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, subnet):
        return False
    
    # Additional validation for IP ranges
    try:
        ip_part, cidr_part = subnet.split('/')
        octets = ip_part.split('.')
        cidr = int(cidr_part)
        
        # Check each octet is 0-255
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                return False
        
        # Check CIDR is 0-32
        if not (0 <= cidr <= 32):
            return False
            
        return True
    except ValueError:
        return False

def display_audit_results(audit_results: Dict[str, any]):
    """Display comprehensive audit results"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}🔍 Security Audit Results{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    
    # Overall status
    overall = audit_results.get('overall', {})
    status = overall.get('status', 'unknown')
    score = overall.get('security_score', 'N/A')
    
    status_colors = {
        'good': Colors.GREEN,
        'fair': Colors.YELLOW,
        'poor': Colors.RED,
        'unknown': Colors.BLUE
    }
    
    status_icons = {
        'good': '🟢',
        'fair': '🟡',
        'poor': '🔴',
        'unknown': '⚪'
    }
    
    print(f"\n{Colors.BOLD}Overall Security Status: {status_colors.get(status, Colors.BLUE)}{status_icons.get(status, '⚪')} {status.upper()}{Colors.ENDC}")
    print(f"{Colors.BOLD}Security Score: {status_colors.get(status, Colors.BLUE)}{score}{Colors.ENDC}")
    print(f"{Colors.BLUE}Audit performed: {audit_results.get('timestamp', 'Unknown')}{Colors.ENDC}")
    
    # Categories
    categories = [
        ('ssh_config', '🔐 SSH Configuration'),
        ('firewall', '🛡️ Firewall Protection'),
        ('system_hardening', '🔧 System Hardening'),
        ('user_accounts', '👤 User Account Security')
    ]
    
    for category_key, category_title in categories:
        if category_key in audit_results:
            category_data = audit_results[category_key]
            category_status = category_data.get('status', 'unknown')
            
            print(f"\n{Colors.BOLD}{category_title}{Colors.ENDC}")
            print(f"Status: {status_colors.get(category_status, Colors.BLUE)}{status_icons.get(category_status, '⚪')} {category_status.upper()}{Colors.ENDC}")
            
            if 'error' in category_data:
                print(f"{Colors.RED}Error: {category_data['error']}{Colors.ENDC}")
            
            # Display individual checks
            checks = category_data.get('checks', {})
            for check_name, check_data in checks.items():
                check_status = check_data.get('status', 'unknown')
                description = check_data.get('description', check_name)
                severity = check_data.get('severity', 'unknown')
                
                if check_status == 'pass':
                    icon = f"{Colors.GREEN}✓{Colors.ENDC}"
                elif check_status == 'fail':
                    icon = f"{Colors.RED}✗{Colors.ENDC}"
                elif check_status == 'warn':
                    icon = f"{Colors.YELLOW}⚠{Colors.ENDC}"
                elif check_status == 'info':
                    icon = f"{Colors.BLUE}ℹ{Colors.ENDC}"
                else:
                    icon = f"{Colors.BLUE}?{Colors.ENDC}"
                
                severity_color = {
                    'high': Colors.RED,
                    'medium': Colors.YELLOW,
                    'low': Colors.BLUE
                }.get(severity, Colors.BLUE)
                
                print(f"  {icon} {description} {severity_color}({severity}){Colors.ENDC}")
            
            # Display recommendations
            recommendations = category_data.get('recommendations', [])
            if recommendations:
                print(f"  {Colors.YELLOW}📋 Recommendations:{Colors.ENDC}")
                for rec in recommendations:
                    print(f"    • {rec}")
    
    # Summary recommendations
    all_recommendations = []
    for category_key, _ in categories:
        if category_key in audit_results:
            all_recommendations.extend(audit_results[category_key].get('recommendations', []))
    
    if all_recommendations:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}🚨 Priority Actions Needed:{Colors.ENDC}")
        for i, rec in enumerate(all_recommendations[:5], 1):  # Show top 5
            print(f"  {i}. {rec}")
        
        if len(all_recommendations) > 5:
            print(f"  ... and {len(all_recommendations) - 5} more recommendations")
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BLUE}💾 Full audit log saved to: {AUDIT_LOG_PATH}{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}\n")

def prompt_for_port() -> str:
    """Prompt user for SSH port with validation and suggestions"""
    print(f"\n{Colors.BOLD}SSH Port Configuration{Colors.ENDC}")
    print(f"{Colors.BLUE}Configure the SSH port for your server{Colors.ENDC}")
    print(f"{Colors.YELLOW}Recommended: Use a high port number (1024-65535) to avoid conflicts{Colors.ENDC}")
    print(f"{Colors.GREEN}Popular choices: 2222, 9769, 22222{Colors.ENDC}")
    
    while True:
        port = input(f"\n{Colors.CYAN}Enter SSH port{Colors.ENDC} [default: {Colors.GREEN}9769{Colors.ENDC}]: ").strip()
        
        if port == "":
            print_success(f"Using default port: 9769")
            return "9769"
        
        if validate_port(port):
            port_num = int(port)
            if port_num < 1024:
                print_warning(f"Port {port} is a system port. Consider using a higher port (1024+)")
                confirm = input(f"{Colors.YELLOW}Continue anyway?{Colors.ENDC} (y/N): ").strip().lower()
                if confirm in ['y', 'yes']:
                    print_success(f"Using port: {port}")
                    return port
            else:
                print_success(f"Using port: {port}")
                return port
        
        print_error("Invalid port number. Please enter a number between 1-65535")

def prompt_for_subnets() -> List[str]:
    """Prompt user for allowed subnets with validation and examples"""
    print(f"\n{Colors.BOLD}Network Access Configuration{Colors.ENDC}")
    print(f"{Colors.BLUE}Define which networks can access SSH{Colors.ENDC}")
    print(f"{Colors.GREEN}Examples:{Colors.ENDC}")
    print(f"  • Home network: {Colors.CYAN}192.168.1.0/24{Colors.ENDC}")
    print(f"  • Office network: {Colors.CYAN}10.0.0.0/8{Colors.ENDC}")
    print(f"  • VPN network: {Colors.CYAN}172.16.0.0/12{Colors.ENDC}")
    print(f"  • Single IP: {Colors.CYAN}203.0.113.5/32{Colors.ENDC}")
    
    while True:
        subnets_input = input(f"\n{Colors.CYAN}Enter allowed subnets{Colors.ENDC} (comma-separated): ").strip()
        
        if not subnets_input:
            print_error("Input cannot be empty")
            continue
        
        subnets = [s.strip() for s in subnets_input.split(",")]
        invalid_subnets = []
        
        for subnet in subnets:
            if not validate_subnet(subnet):
                invalid_subnets.append(subnet)
        
        if invalid_subnets:
            print_error(f"Invalid subnet format: {', '.join(invalid_subnets)}")
            print_info("Each subnet must be in CIDR notation (e.g., 192.168.1.0/24)")
            continue
        
        print_success(f"Configured {len(subnets)} allowed subnet(s):")
        for subnet in subnets:
            print(f"  • {Colors.GREEN}{subnet}{Colors.ENDC}")
        
        return subnets

def backup_sshd_config() -> bool:
    """Backup current SSH config with better feedback"""
    print_step("Creating SSH configuration backup")
    
    if os.path.exists(BACKUP_SSHD_CONFIG_PATH):
        print_warning(f"Backup already exists at {BACKUP_SSHD_CONFIG_PATH}")
        return True
    
    try:
        shutil.copy2(SSHD_CONFIG_PATH, BACKUP_SSHD_CONFIG_PATH)
        spinner_animation(1.0)
        print_success(f"Backup created: {BACKUP_SSHD_CONFIG_PATH}")
        return True
    except Exception as e:
        print_error(f"Failed to create backup: {e}")
        return False

def write_new_sshd_config(port: str) -> bool:
    """Write new SSH config with progress indication"""
    print_step(f"Configuring SSH with port {port}")
    
    try:
        config_text = SSH_TEMPLATE.format(ssh_port=port)
        with open(SSHD_CONFIG_PATH, "w") as f:
            f.write(config_text)
        spinner_animation(1.0)
        print_success("SSH configuration updated")
        return True
    except Exception as e:
        print_error(f"Failed to write SSH config: {e}")
        return False

def restart_sshd() -> bool:
    """Restart SSH service with feedback"""
    print_step("Restarting SSH service")
    
    try:
        subprocess.run(["systemctl", "restart", "ssh"], check=True, capture_output=True)
        spinner_animation(2.0)
        print_success("SSH service restarted successfully")
        return True
    except subprocess.CalledProcessError as e:
        print_error("Failed to restart SSH service")
        print_warning("You may need to restart manually: sudo systemctl restart ssh")
        return False

def configure_iptables(subnets: List[str], port: str) -> bool:
    """Configure iptables with detailed progress"""
    print_step("Configuring firewall rules")
    
    try:
        print_info("Flushing existing rules...")
        subprocess.run(["iptables", "-F"], check=True)
        subprocess.run(["iptables", "-X"], check=True)
        
        print_info("Setting security policies...")
        subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
        subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
        
        print_info("Allowing essential traffic...")
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
        
        print_info(f"Configuring SSH access on port {port}...")
        for i, subnet in enumerate(subnets, 1):
            print(f"  {Colors.CYAN}[{i}/{len(subnets)}]{Colors.ENDC} Adding rule for {Colors.GREEN}{subnet}{Colors.ENDC}")
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-p", "tcp",
                "-s", subnet,
                "--dport", port,
                "-m", "conntrack",
                "--ctstate", "NEW,ESTABLISHED",
                "-j", "ACCEPT"
            ], check=True)
        
        print_info("Blocking unauthorized SSH attempts...")
        subprocess.run([
            "iptables", "-A", "INPUT",
            "-p", "tcp",
            "--dport", port,
            "-j", "DROP"
        ], check=True)
        
        print_info("Saving firewall rules...")
        try:
            subprocess.run(["netfilter-persistent", "save"], check=True)
            spinner_animation(1.5)
            print_success("Firewall configured and rules saved")
            return True
        except FileNotFoundError:
            print_warning("netfilter-persistent not found - rules won't persist after reboot")
            print_info("Install with: sudo apt install iptables-persistent")
            return True
            
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to configure firewall: {e}")
        return False

def revert_sshd_config() -> bool:
    """Revert SSH config with user feedback"""
    print_step("Reverting SSH configuration")
    
    if not os.path.exists(BACKUP_SSHD_CONFIG_PATH):
        print_error(f"No backup file found at {BACKUP_SSHD_CONFIG_PATH}")
        return False
    
    try:
        shutil.copy2(BACKUP_SSHD_CONFIG_PATH, SSHD_CONFIG_PATH)
        spinner_animation(1.0)
        print_success("SSH configuration restored from backup")
        return restart_sshd()
    except Exception as e:
        print_error(f"Failed to restore SSH config: {e}")
        return False

def revert_iptables() -> bool:
    """Revert iptables rules with feedback"""
    print_step("Clearing firewall rules")
    
    try:
        print_info("Flushing all rules...")
        subprocess.run(["iptables", "-F"], check=True)
        subprocess.run(["iptables", "-X"], check=True)
        
        print_info("Restoring default policies...")
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
        
        try:
            subprocess.run(["netfilter-persistent", "save"], check=True)
            spinner_animation(1.0)
            print_success("Firewall rules cleared and defaults restored")
        except FileNotFoundError:
            print_warning("netfilter-persistent not found - changes won't persist after reboot")
        
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to clear firewall rules: {e}")
        return False

def print_security_summary(port: str, subnets: List[str]):
    """Display comprehensive security configuration summary"""
    print(f"\n{Colors.GREEN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.GREEN}    🔒 SSH Security Configuration Complete!{Colors.ENDC}")
    print(f"{Colors.GREEN}{'='*70}{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}{Colors.BLUE}Security Features Enabled:{Colors.ENDC}")
    print(f"{Colors.GREEN}  ✓{Colors.ENDC} SSH port changed to: {Colors.CYAN}{port}{Colors.ENDC}")
    print(f"{Colors.GREEN}  ✓{Colors.ENDC} Root login disabled")
    print(f"{Colors.GREEN}  ✓{Colors.ENDC} Password authentication disabled")
    print(f"{Colors.GREEN}  ✓{Colors.ENDC} Key-based authentication only")
    print(f"{Colors.GREEN}  ✓{Colors.ENDC} Connection limits: 3 auth tries, 2 max sessions")
    print(f"{Colors.GREEN}  ✓{Colors.ENDC} Client timeout configured (300s)")
    print(f"{Colors.GREEN}  ✓{Colors.ENDC} Firewall configured with network restrictions")
    
    print(f"\n{Colors.BOLD}{Colors.BLUE}Allowed Networks:{Colors.ENDC}")
    for subnet in subnets:
        print(f"  {Colors.GREEN}•{Colors.ENDC} {Colors.CYAN}{subnet}{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}{Colors.YELLOW}Connection Instructions:{Colors.ENDC}")
    print(f"{Colors.CYAN}ssh -p {port} username@server-ip{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}{Colors.YELLOW}Important Notes:{Colors.ENDC}")
    print(f"{Colors.YELLOW}  •{Colors.ENDC} Ensure your public key is in ~/.ssh/authorized_keys")
    print(f"{Colors.YELLOW}  •{Colors.ENDC} Test the connection before closing this session!")
    print(f"{Colors.YELLOW}  •{Colors.ENDC} Keep backup config: {BACKUP_SSHD_CONFIG_PATH}")
    print(f"{Colors.YELLOW}  •{Colors.ENDC} Run security audit regularly to monitor status")
    
    print(f"\n{Colors.RED}{Colors.BOLD}⚠ IMPORTANT: Test SSH access before disconnecting!{Colors.ENDC}")
    print(f"{Colors.GREEN}{'='*70}{Colors.ENDC}\n")

def get_user_choice() -> Optional[str]:
    """Get user's menu choice with colorful interface"""
    print(f"{Colors.BOLD}{Colors.BLUE}Available Options:{Colors.ENDC}")
    print(f"  {Colors.GREEN}1){Colors.ENDC} {Colors.CYAN}Configure SSH Security{Colors.ENDC} - Harden SSH and setup firewall")
    print(f"  {Colors.BLUE}2){Colors.ENDC} {Colors.CYAN}Security Audit{Colors.ENDC} - Check current security status")
    print(f"  {Colors.YELLOW}3){Colors.ENDC} {Colors.CYAN}Revert Configuration{Colors.ENDC} - Restore previous settings")
    print(f"  {Colors.RED}4){Colors.ENDC} {Colors.CYAN}Exit{Colors.ENDC} - Quit without changes")
    
    while True:
        choice = input(f"\n{Colors.BOLD}Select option{Colors.ENDC} [{Colors.GREEN}1{Colors.ENDC}/{Colors.BLUE}2{Colors.ENDC}/{Colors.YELLOW}3{Colors.ENDC}/{Colors.RED}4{Colors.ENDC}]: ").strip()
        
        if choice in ['1', '2', '3', '4']:
            return choice
        
        print_error("Invalid choice. Please enter 1, 2, 3, or 4")

def confirm_action(action: str, warning: bool = False) -> bool:
    """Get confirmation for potentially dangerous actions"""
    color = Colors.RED if warning else Colors.YELLOW
    prompt = f"{color}Are you sure you want to {action}?{Colors.ENDC} (yes/no): "
    
    while True:
        response = input(prompt).strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            print_error("Please enter 'yes' or 'no'")

def check_prerequisites() -> bool:
    """Check if system meets requirements"""
    print_step("Checking system prerequisites")
    
    # Check if running as root
    if os.geteuid() != 0:
        print_error("This script must be run as root")
        print_info("Please run: sudo python3 ssh_security.py")
        return False
    
    # Check if SSH config exists
    if not os.path.exists(SSHD_CONFIG_PATH):
        print_error(f"SSH config file not found: {SSHD_CONFIG_PATH}")
        return False
    
    # Check if iptables is available
    try:
        subprocess.run(["iptables", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error("iptables not found - firewall configuration will fail")
        return False
    
    print_success("System prerequisites met")
    return True

def display_audit_menu():
    """Display audit sub-menu options"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}🔍 Security Audit Options:{Colors.ENDC}")
    print(f"  {Colors.GREEN}1){Colors.ENDC} {Colors.CYAN}Full Security Audit{Colors.ENDC} - Complete system security check")
    print(f"  {Colors.YELLOW}2){Colors.ENDC} {Colors.CYAN}Quick SSH Check{Colors.ENDC} - SSH configuration only")
    print(f"  {Colors.BLUE}3){Colors.ENDC} {Colors.CYAN}View Audit History{Colors.ENDC} - Show previous audit results")
    print(f"  {Colors.RED}4){Colors.ENDC} {Colors.CYAN}Back to Main Menu{Colors.ENDC}")
    
    while True:
        choice = input(f"\n{Colors.BOLD}Select audit option{Colors.ENDC} [1/2/3/4]: ").strip()
        if choice in ['1', '2', '3', '4']:
            return choice
        print_error("Invalid choice. Please enter 1, 2, 3, or 4")

def view_audit_history():
    """Display recent audit history"""
    print_step("Loading audit history")
    
    if not os.path.exists(AUDIT_LOG_PATH):
        print_warning("No audit history found")
        print_info("Run a security audit first to create history")
        return
    
    try:
        with open(AUDIT_LOG_PATH, 'r') as f:
            lines = f.readlines()
        
        if not lines:
            print_warning("Audit log is empty")
            return
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}📊 Recent Audit History{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        
        # Show last 10 entries
        recent_entries = lines[-10:]
        
        for line in recent_entries:
            try:
                entry = json.loads(line.strip())
                timestamp = entry.get('timestamp', 'Unknown')
                score = entry.get('overall_score', 'N/A')
                status = entry.get('status', 'unknown')
                
                status_colors = {
                    'good': Colors.GREEN,
                    'fair': Colors.YELLOW,
                    'poor': Colors.RED,
                    'unknown': Colors.BLUE
                }
                
                status_icons = {
                    'good': '🟢',
                    'fair': '🟡',
                    'poor': '🔴',
                    'unknown': '⚪'
                }
                
                color = status_colors.get(status, Colors.BLUE)
                icon = status_icons.get(status, '⚪')
                
                print(f"{Colors.BLUE}{timestamp}{Colors.ENDC} - {color}{icon} {status.upper()}{Colors.ENDC} ({score})")
                
            except json.JSONDecodeError:
                continue
        
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BLUE}💾 Full log available at: {AUDIT_LOG_PATH}{Colors.ENDC}\n")
        
    except Exception as e:
        print_error(f"Error reading audit history: {e}")

def main():
    """Main function with enhanced UX flow"""
    print_banner()
    
    if not check_prerequisites():
        sys.exit(1)
    
    while True:
        choice = get_user_choice()
        
        if choice == "1":
            print(f"\n{Colors.BOLD}{Colors.GREEN}🔧 Starting SSH Security Configuration{Colors.ENDC}")
            
            ssh_port = prompt_for_port()
            subnets = prompt_for_subnets()
            
            print(f"\n{Colors.BOLD}{Colors.YELLOW}Configuration Summary:{Colors.ENDC}")
            print(f"  SSH Port: {Colors.CYAN}{ssh_port}{Colors.ENDC}")
            print(f"  Allowed Networks: {Colors.CYAN}{', '.join(subnets)}{Colors.ENDC}")
            
            if not confirm_action("apply these security settings"):
                print_warning("Configuration cancelled by user")
                continue
            
            print(f"\n{Colors.BOLD}{Colors.BLUE}Applying security configuration...{Colors.ENDC}")
            
            success = True
            success &= backup_sshd_config()
            success &= write_new_sshd_config(ssh_port)
            success &= restart_sshd()
            success &= configure_iptables(subnets, ssh_port)
            
            if success:
                print_security_summary(ssh_port, subnets)
                print_info("💡 Tip: Run a security audit to verify your configuration")
            else:
                print_error("Configuration completed with some errors - please review above")
        
        elif choice == "2":
            audit_choice = display_audit_menu()
            
            if audit_choice == "1":
                # Full security audit
                auditor = SecurityAudit()
                audit_results = auditor.generate_full_audit()
                spinner_animation(2.0)
                display_audit_results(audit_results)
                
            elif audit_choice == "2":
                # Quick SSH check only
                print_step("Performing SSH configuration check")
                auditor = SecurityAudit()
                ssh_results = auditor.check_ssh_config()
                spinner_animation(1.0)
                
                # Display SSH results only
                mini_results = {
                    'timestamp': auditor.timestamp,
                    'ssh_config': ssh_results,
                    'overall': {
                        'status': ssh_results.get('status', 'unknown'),
                        'security_score': 'SSH Only',
                        'raw_score': 'N/A'
                    }
                }
                display_audit_results(mini_results)
                
            elif audit_choice == "3":
                # View audit history
                view_audit_history()
                
            elif audit_choice == "4":
                # Back to main menu
                continue
        
        elif choice == "3":
            print(f"\n{Colors.BOLD}{Colors.YELLOW}🔄 Reverting SSH Configuration{Colors.ENDC}")
            
            if not confirm_action("revert SSH config and clear firewall rules", warning=True):
                print_warning("Revert cancelled by user")
                continue
            
            print(f"\n{Colors.BOLD}{Colors.BLUE}Reverting configuration...{Colors.ENDC}")
            
            ssh_reverted = revert_sshd_config()
            if ssh_reverted:
                firewall_reverted = revert_iptables()
                if firewall_reverted:
                    print(f"\n{Colors.GREEN}✓ Configuration successfully reverted{Colors.ENDC}")
                    print_info("💡 Tip: Run a security audit to check current status")
                else:
                    print_warning("SSH reverted but firewall revert had issues")
            else:
                print_error("Revert failed - no backup found or error occurred")
        
        elif choice == "4":
            print(f"\n{Colors.CYAN}👋 Goodbye! Stay secure!{Colors.ENDC}")
            break
        
        # Ask if user wants to continue
        print(f"\n{Colors.BLUE}Press Enter to return to main menu, or Ctrl+C to exit...{Colors.ENDC}")
        try:
            input()
        except KeyboardInterrupt:
            print(f"\n\n{Colors.CYAN}👋 Goodbye! Stay secure!{Colors.ENDC}")
            break
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}Script execution complete.{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ Script interrupted by user{Colors.ENDC}")
        print(f"{Colors.CYAN}Goodbye!{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}✗ Unexpected error: {e}{Colors.ENDC}")
        sys.exit(1)
