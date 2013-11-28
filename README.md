compliance
==========
# Server Hardening

Authors : 
  - Vasanta Koli [ Solaris Admin <http://itsgateway.com> ]
  - Rahul Patil  [ Linux Admin <http://www.linuxian.com> ]

![compliance demo](https://raw.github.com/rahulinux/compliance/master/security.png)

# Why this script is required ?

if you want enhancing server security through a variety of means which results in a much more secure 
server operating environment, then script is useful for you.

you can easily add/modify paramater, in Configuration Section in Script. 


# How it will work ?

It will follow the server hardening process which is mention in "server hardening parameters".

  - Backup of any configuration file which are going to edit as `config-bkp-current-date`.
  - Comment old parameters and apply the new one.
  - Make configuration file read-only using chattr. 

# Prerequisites

  - The tools/commands are used in script, which almost available in all *nix destro, however you can make sure following list:
    `awk`,`sed`,`mktemp`,`chkconfig`,`stat`.
  - Tested and working in RHEL/CentOS 5.x


# List of Security Rules:

  - TCP Wrapper :- Deny all except ip associated with stdin  
  - SSH Security Check
     - Protocol version check
     - SyslogFacility Check
     - LogLevel Check
     - LoginGraceTime Check
     - PermitRootLogin Check
     - MaxAuthTries Check
     - PermitEmptyPasswords Check
     - PasswordAuthentication Check
     - ClientAliveInterval Check
     - ClientAliveCountMax Check
     - MaxStartups Check
     - Banner Check
  - Filesystems Security Check
     - /tmp partition permission 
     - tmpfs attributes check
  - Services Check
     - we have disabled unwated services and enable required services, however once go through the list define in script it self
  - Kernel Level Security
     - maximum number of incomplete tcp sessions remembered by system is set.
     - net.ipv4.tcp_syncookies is enabled .
     - simple routing checks for packets to handle some attempts at spoofing source address.
     - net.ipv4.conf.all.accept_source_route is disabled.
     - icmp redirect message is not accepted by system.
     - net.ipv4.conf.all.secure_redirects is disabled so that redirects form local router are disabled.
     - Set net.ipv4.conf.default.rp_filter is enabled
     - net.ipv4.conf.default.accept_source_route is disabled.
     - net.ipv4.conf.default.accept_redirects is disabled.
     - net.ipv4.conf.default.secure_redirects is disabled.
     - net.ipv4.icmp_echo_ignore_broadcasts is enabled.
     - net.ipv4.ip_forward is disabled unless this system is gateway or firewall.
     - net.ipv4.conf.all.send_redirects is disabled unless this system is gateway or firewall.
     - net.ipv4.conf.default.send_redirect is disabled unless this system is firewall or gateway.
     - net.ipv4.icmp_ignore_bogus_error_responses is enabled.

  - Log-in monitoring & audit control
     - Ensure  presense  of following log files:
        - /var/log/boot.log
        - /var/log/cron
        - /var/log/dmesg
        - /var/log/maillog
        - /var/log/messages*
        - /var/log/secure

  - Build & Maintain Security
     - Ensure passwd, shadow, and group File Permissions
     - Ensure unnecessary default user accounts are removed.
     - Ensure unnecessary default user accounts are removed. 
     - Remove unnecessary groups from /etc/group.
     - Ensure only authorized users have access to at and cron.

   
# What else?

If you have any questions or suggestions, you want to share anything else with me, feel free to drop me an e-mail . I appreciate any feedback, including constructive (and polite) criticism, improvement suggestions, questions about usage (if the documentation is unclear).


