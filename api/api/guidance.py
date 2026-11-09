"""Plain-English advice for the Defend pages: what to check at your own company.

Static text, written for IT and security staff. It never contains captured data. The pages show
an entry only when the honeypot actually saw the matching behaviour, so the list stays short.
"""

from __future__ import annotations

from typing import TypedDict


class TagAdvice(TypedDict):
    title: str
    what: str  # what the attackers do, one sentence
    look: list[str]  # where to look in your own logs
    fix: list[str]  # what to change


SERVICE_CHECKS: dict[str, list[str]] = {
    "ssh": [
        "Turn off SSH password logins on internet-facing servers and use keys.",
        "Check /var/log/auth.log (or journalctl -u ssh) for many failed logins from one address.",
        "Put administration behind a VPN or a bastion host instead of the open internet.",
    ],
    "telnet": [
        "Telnet should not be reachable at all. Look for devices (cameras, routers, printers) that still listen on port 23.",
        "Change default passwords on every embedded device and turn Telnet off.",
    ],
    "web": [
        "Keep PHP, your web server and your CMS patched, and remove files that should not be public (.env, backups, phpinfo).",
        "Search your web server access logs for the paths this honeypot saw attackers request.",
        "Put a web application firewall or an authenticating proxy in front of admin pages.",
    ],
    "rdp": [
        "Remote Desktop should not face the internet. Use a VPN or a gateway with multi-factor authentication.",
        "Enable Network Level Authentication and an account lockout policy; watch event ID 4625 for bursts of failures.",
    ],
    "smb": [
        "Block ports 139 and 445 at the internet edge and keep SMBv1 disabled.",
        "Install current Windows updates; worms such as EternalBlue need an unpatched SMB service.",
    ],
    "redis": [
        "Redis must never listen on a public address. Bind it to localhost or a private network and set a password.",
        "Check for unexpected keys, cron jobs or SSH keys written by an open Redis.",
    ],
    "docker": [
        "The Docker API (port 2375) must never be exposed without TLS and client certificates.",
        "Look for unknown containers, especially ones that mount the host file system or use a miner image.",
    ],
    "mysql": [
        "Database servers should listen on a private address only; allow just the application hosts.",
        "Use strong, unique database passwords and remove the anonymous and root remote accounts.",
    ],
    "mssql": [
        "Do not expose SQL Server (port 1433) to the internet; allow only the application hosts.",
        "Disable the sa account or give it a long random password, and disable xp_cmdshell unless needed.",
    ],
    "adb": [
        "Android Debug Bridge (port 5555) must be off on production devices and on every network that is reachable from outside.",
        "Check Android TV boxes, kiosks and signage for adb listening on the network.",
    ],
    "sip": [
        "Do not expose your PBX SIP port to the world; restrict it to your providers and users.",
        "Use strong extension passwords and set call limits and country restrictions to stop toll fraud.",
    ],
    "synology": [
        "Do not expose the DiskStation Manager login (ports 5000 and 5001) to the internet; use a VPN or the vendor's relay.",
        "Keep DSM and its packages up to date, turn on two-factor sign-in and automatic blocking, and keep an offline backup of your shares.",
    ],
}

TAG_ADVICE: dict[str, TagAdvice] = {
    "php2shell": {
        "title": "PHP remote code execution attempts",
        "what": "Attackers send crafted requests to PHP applications to run commands on the server.",
        "look": [
            "Web server logs: requests with PHP_SESSION_UPLOAD_PROGRESS or unusual upload-progress parameters.",
            "New or changed .php files in upload and web root folders.",
        ],
        "fix": [
            "Update PHP to a fixed release and restart the web server or PHP-FPM.",
            "Disable session.upload_progress where it is not needed, and run PHP as an unprivileged user.",
        ],
    },
    "wordpress-bruteforce": {
        "title": "WordPress password guessing",
        "what": "Bots try many passwords on wp-login.php and xmlrpc.php.",
        "look": [
            "Web server logs: many POST requests to /wp-login.php or /xmlrpc.php from one address.",
            "WordPress users you do not recognise.",
        ],
        "fix": [
            "Require multi-factor authentication for admins, block xmlrpc.php if unused, and rate limit logins.",
        ],
    },
    "phpmyadmin-bruteforce": {
        "title": "phpMyAdmin password guessing",
        "what": "Bots look for phpMyAdmin and try common database passwords.",
        "look": ["Web server logs: requests to /phpmyadmin, /pma and /dbadmin paths."],
        "fix": [
            "Remove phpMyAdmin from public servers or put it behind a VPN or an IP allow-list."
        ],
    },
    "env-file-probe": {
        "title": "Probing for secret files",
        "what": "Scanners request .env, .git and backup files hoping a server leaks passwords and keys.",
        "look": [
            "Web server logs: 200 responses for .env, .git/config, backup.zip, config.php.bak.",
        ],
        "fix": [
            "Make sure those files are not in the web root, deny dotfiles in the server config, and rotate any secret that was exposed.",
        ],
    },
    "sql-rce": {
        "title": "Database command execution",
        "what": "Attackers use database features to run operating-system commands.",
        "look": [
            "SQL Server: use of xp_cmdshell; MySQL: functions that write files or load libraries.",
            "Unexpected child processes of the database service.",
        ],
        "fix": [
            "Disable the feature, run the database as a low-privilege account and restrict network access."
        ],
    },
    "weak-credentials": {
        "title": "Guessing of weak passwords",
        "what": "Bots try short lists of default and common passwords on every service they find.",
        "look": [
            "Authentication logs: bursts of failures followed by a success from the same address."
        ],
        "fix": [
            "Ban default and common passwords, require multi-factor authentication, and lock accounts after repeated failures."
        ],
    },
    "credential-stuffing": {
        "title": "Stolen password lists",
        "what": "Attackers replay user and password pairs leaked from other sites.",
        "look": [
            "Login logs: many different user names from one address, each tried once or twice."
        ],
        "fix": [
            "Require multi-factor authentication and check new passwords against known leaked lists."
        ],
    },
    "malware-drop": {
        "title": "Malware downloads",
        "what": "After getting in, attackers download a program from another server and run it.",
        "look": [
            "Proxy and firewall logs: your servers fetching files with wget, curl or tftp from unknown hosts.",
            "Files in /tmp, /var/tmp and /dev/shm with execute permission.",
        ],
        "fix": [
            "Block outbound traffic from servers by default and allow only what they need.",
            "Add the hosts from the blocklist to your proxy or DNS filter.",
        ],
    },
    "mirai": {
        "title": "Mirai-style botnet loaders",
        "what": "Botnets take over routers, cameras and other devices with default passwords.",
        "look": [
            "Devices that open many outbound connections on port 23 or 2323, or restart without reason."
        ],
        "fix": [
            "Change default passwords, update firmware, and keep management interfaces off the internet."
        ],
    },
    "crypto-miner": {
        "title": "Cryptocurrency miners",
        "what": "Attackers install miners that use your CPU and your electricity bill.",
        "look": [
            "Hosts with sustained high CPU load, and processes named xmrig, kdevtmpfsi or similar.",
            "Outbound connections to mining pool ports (3333, 4444, 5555, 14444).",
        ],
        "fix": [
            "Block mining pools at the DNS or firewall level, and rebuild a compromised host instead of cleaning it."
        ],
    },
    "persistence": {
        "title": "Backdoors that survive a reboot",
        "what": "Attackers add their own SSH key or a scheduled job so they can come back.",
        "look": [
            "authorized_keys files you did not write, new cron entries, and new systemd services.",
        ],
        "fix": [
            "Compare against a known-good baseline, remove what does not belong and rotate the keys of the account."
        ],
    },
    "exec-attempt": {
        "title": "Remote command execution",
        "what": "Attackers run shell commands on a server they reached.",
        "look": [
            "Shell history and process accounting: curl or wget piped to sh, base64 -d, chmod +x."
        ],
        "fix": [
            "Limit who can log in, monitor process starts (auditd or EDR), and keep services unprivileged."
        ],
    },
    "recon": {
        "title": "Looking around after a login",
        "what": "Attackers check the machine type, users and network before choosing what to install.",
        "look": [
            "Shell history: uname -a, cat /proc/cpuinfo, whoami, ifconfig in quick succession."
        ],
        "fix": [
            "Treat such a session as a sign that a password or key is already known to an attacker."
        ],
    },
    "eternalblue": {
        "title": "SMB worm exploits",
        "what": "Attackers try the EternalBlue vulnerability in old Windows file sharing.",
        "look": ["Firewall logs: connections to TCP 445 from the internet."],
        "fix": ["Patch Windows, disable SMBv1 and block port 445 at the edge."],
    },
    "smb-v1-probe": {
        "title": "Old SMB1 probing",
        "what": "Scanners and old exploit kits speak SMBv1 to Windows file sharing to see whether it still answers. This alone does not say which exploit was meant.",
        "look": ["Firewall logs: connections to TCP 445 from the internet."],
        "fix": ["Disable SMBv1, patch Windows and block port 445 at the edge."],
    },
    "php-upload-progress-probe": {
        "title": "PHP upload-progress probing",
        "what": "Scanners touch the PHP upload-progress feature to see whether the server is a target. A probe carries no code.",
        "look": [
            "Web server logs: requests with PHP_SESSION_UPLOAD_PROGRESS and no PHP code in the value."
        ],
        "fix": [
            "Update PHP to a fixed release and disable session.upload_progress where it is not needed."
        ],
    },
    "bluekeep": {
        "title": "RDP vulnerability probing",
        "what": "Scanners look for Remote Desktop services that are vulnerable to BlueKeep.",
        "look": [
            "Windows event logs and firewall logs for connections to TCP 3389 from the internet."
        ],
        "fix": ["Patch Windows and move RDP behind a VPN or gateway."],
    },
    "rdp-cleartext": {
        "title": "RDP without protection",
        "what": "Clients ask for the weakest RDP security so they can guess passwords more easily.",
        "look": ["Windows security log, event ID 4625 with logon type 10."],
        "fix": ["Require Network Level Authentication and TLS on every RDP host."],
    },
    "redis-rogue-master": {
        "title": "Redis takeover",
        "what": "Attackers make an open Redis load a malicious module from their own server.",
        "look": ["Redis logs: SLAVEOF, MODULE LOAD and CONFIG SET dir commands."],
        "fix": [
            "Bind Redis to localhost, set a password and rename or disable the dangerous commands."
        ],
    },
    "container-escape": {
        "title": "Container breakout",
        "what": "Attackers start a privileged container to reach the host.",
        "look": ["docker ps -a: containers started with --privileged or with / mounted."],
        "fix": ["Never expose the Docker socket; use rootless Docker and drop capabilities."],
    },
    "db-ransom": {
        "title": "Database ransom",
        "what": "Attackers wipe or copy open databases and leave a ransom note.",
        "look": ["A new database or table with a name like README_TO_RECOVER."],
        "fix": ["Close the port, set passwords, and keep tested offline backups."],
    },
    "sip-fraud": {
        "title": "Phone toll fraud",
        "what": "Attackers register on open phone systems to place expensive calls.",
        "look": ["PBX logs: many REGISTER failures and international calls at night."],
        "fix": [
            "Restrict SIP to known addresses, use strong secrets and set spending limits with your provider."
        ],
    },
    "synology-exploit": {
        "title": "Synology NAS exploit attempts",
        "what": "Attackers send forged session ids or crafted headers to a Synology DiskStation Manager login to take over the NAS.",
        "look": [
            "DSM Log Center: sign-ins you do not recognise, new admin users, new scheduled tasks.",
            "Reverse proxy or firewall logs: requests to /webapi/entry.cgi from unknown addresses.",
        ],
        "fix": [
            "Install the latest DSM update, close ports 5000 and 5001 to the internet and turn on two-factor sign-in."
        ],
    },
    "c3rb3r": {
        "title": "NAS ransomware",
        "what": "Ransomware that targets network storage and encrypts the shared folders.",
        "look": [
            "Shared folders: files renamed with a new extension or a ransom note in each folder.",
            "Snapshots and backup jobs that were deleted or changed.",
        ],
        "fix": [
            "Keep offline or immutable backups, turn on snapshots, and do not expose the NAS to the internet."
        ],
    },
    "scanner": {
        "title": "Automated scanners",
        "what": "Tools that sweep the internet for anything that answers.",
        "look": ["Web server logs: user agents such as zgrab, masscan, Nuclei or python-requests."],
        "fix": [
            "Nothing specific to fix; use it to see which of your services are visible from outside."
        ],
    },
}
