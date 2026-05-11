#!/usr/bin/env python3
"""
fail2ban-cpanel-installer
=========================
Automated security stack installer for cPanel / AlmaLinux / Ubuntu / Debian VPS.

Installs and configures:
  - ipset (hash:net blocklist, 500k entries, iptables DROP rule)
  - Fail2ban with 8 hardened jails
  - Firehol Level 1 blocklist (4,400+ malicious networks, daily cron)
  - Apache-level scanner blocking (webshell/scanner paths → 403 before PHP spawns)
  - WP-Cron server-side replacement (prevents cron storms under attack)

Usage:
  python3 security_installer.py [--step N] [--dry-run] [--list]

Tested on:
  AlmaLinux 8.10 / Rocky Linux 9 / Ubuntu 22.04 / Debian 12
  cPanel 11.134 / Apache 2.4 / Fail2ban 1.0.2

Author: Andrei Ghițan (dffkt432hz)
License: MIT
"""

import os
import sys
import subprocess
import glob
import time
import argparse
import shutil
import socket

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

DRY_RUN = False

def ok(msg):   print(f"{GREEN}  ✅ {msg}{RESET}")
def warn(msg): print(f"{YELLOW}  ⚠️  {msg}{RESET}")
def err(msg):  print(f"{RED}  ❌ {msg}{RESET}")
def info(msg): print(f"{CYAN}  →  {msg}{RESET}")
def head(msg): print(f"\n{BOLD}{CYAN}{'═'*62}{RESET}\n{BOLD}  {msg}{RESET}\n{BOLD}{CYAN}{'═'*62}{RESET}")
def dry(msg):  print(f"{YELLOW}  [DRY-RUN] {msg}{RESET}")

def run(cmd, check=True, capture=False):
    if DRY_RUN:
        dry(cmd)
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and result.returncode != 0:
        err(f"Command failed: {cmd}")
        if capture and result.stderr:
            err(result.stderr.strip())
    return result

def write_file(path, content, mode=0o644):
    if DRY_RUN:
        dry(f"Write: {path}")
        return
    dirpath = os.path.dirname(path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    os.chmod(path, mode)
    ok(f"Written: {path}")

def append_if_missing(path, line):
    try:
        with open(path, 'r') as f:
            if line.strip() in f.read():
                warn(f"Already present: {line.strip()}")
                return
    except FileNotFoundError:
        pass
    if DRY_RUN:
        dry(f"Append to {path}: {line.strip()}")
        return
    with open(path, 'a') as f:
        f.write(f"\n{line}\n")
    ok(f"Appended to {path}: {line.strip()}")

def get_server_ip():
    """Get the primary public IP of this server."""
    try:
        result = subprocess.run(
            "curl -s --max-time 5 https://api.ipify.org || "
            "curl -s --max-time 5 https://ifconfig.me || "
            "hostname -I | awk '{print $1}'",
            shell=True, capture_output=True, text=True
        )
        ip = result.stdout.strip().split()[0]
        if ip:
            return ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""

# ── Distro detection ──────────────────────────────────────────────────────────
def detect_distro():
    """Returns ('rhel', pkg_manager) or ('debian', pkg_manager)"""
    if shutil.which("dnf"):
        return ("rhel", "dnf")
    if shutil.which("yum"):
        return ("rhel", "yum")
    if shutil.which("apt-get"):
        return ("debian", "apt-get")
    return ("rhel", "yum")  # fallback

def detect_cpanel():
    return os.path.exists("/usr/local/cpanel")

def detect_apache_log():
    candidates = [
        "/usr/local/apache/logs/access_log",   # cPanel RHEL
        "/etc/apache2/logs/access_log",         # cPanel alt
        "/var/log/apache2/access.log",          # Ubuntu/Debian
        "/var/log/httpd/access_log",            # RHEL non-cPanel
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    distro, _ = detect_distro()
    return "/var/log/apache2/access.log" if distro == "debian" else "/usr/local/apache/logs/access_log"

def detect_apache_conf():
    candidates = [
        "/etc/apache2/conf/httpd.conf",    # cPanel
        "/etc/httpd/conf/httpd.conf",      # RHEL
        "/etc/apache2/apache2.conf",       # Ubuntu/Debian
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    distro, _ = detect_distro()
    return "/etc/apache2/apache2.conf" if distro == "debian" else "/etc/httpd/conf/httpd.conf"

def detect_apache_confd():
    candidates = [
        "/etc/apache2/conf.d",             # cPanel / RHEL
        "/etc/httpd/conf.d",               # RHEL non-cPanel
        "/etc/apache2/conf-enabled",       # Ubuntu/Debian
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    distro, _ = detect_distro()
    return "/etc/apache2/conf-enabled" if distro == "debian" else "/etc/httpd/conf.d"

def detect_apache_service():
    if os.path.exists("/usr/sbin/httpd"):
        return "httpd"
    if os.path.exists("/usr/sbin/apache2"):
        return "apache2"
    return "httpd"

def detect_domlog_base():
    candidates = [
        "/etc/apache2/logs/domlogs",       # cPanel alt
        "/usr/local/apache/logs/domlogs",  # cPanel standard
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None  # non-cPanel — use global access log

def detect_ssh_log():
    candidates = [
        "/var/log/secure",       # RHEL/AlmaLinux
        "/var/log/auth.log",     # Ubuntu/Debian
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    distro, _ = detect_distro()
    return "/var/log/auth.log" if distro == "debian" else "/var/log/secure"

def detect_iptables_save_path():
    distro, _ = detect_distro()
    if distro == "debian":
        return None
    return "/etc/sysconfig/iptables"

def detect_ipset_save_path():
    distro, _ = detect_distro()
    if distro == "debian":
        return None
    return "/etc/sysconfig/ipset"


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — ipset + iptables
# ─────────────────────────────────────────────────────────────────────────────
def step1_ipset():
    head("STEP 1 — ipset + iptables")

    distro, pkg = detect_distro()
    info(f"Detected distro family: {distro} | package manager: {pkg}")

    if distro == "rhel":
        run(f"{pkg} install -y ipset ipset-service")
        run("systemctl enable ipset")
        run("systemctl start ipset")
    else:
        run("apt-get update -qq")
        run("apt-get install -y ipset iptables")

    # Create blocklist set
    result = run("ipset list blocklist", check=False, capture=True)
    if result.returncode != 0:
        run("ipset create blocklist hash:net maxelem 500000")
        ok("Created ipset blocklist")
    else:
        warn("ipset blocklist already exists — skipping")

    # iptables rules — localhost + RFC1918 always allowed first
    result = run("iptables -L INPUT -n | grep blocklist", check=False, capture=True)
    if "blocklist" not in result.stdout:
        run("iptables -I INPUT 1 -i lo -j ACCEPT")
        run("iptables -I INPUT 2 -s 127.0.0.0/8 -j ACCEPT")
        run("iptables -I INPUT 3 -s 10.0.0.0/8 -j ACCEPT")
        run("iptables -I INPUT 4 -s 172.16.0.0/12 -j ACCEPT")
        run("iptables -I INPUT 5 -s 192.168.0.0/16 -j ACCEPT")
        run("iptables -I INPUT 6 -m set --match-set blocklist src -j DROP")
        ok("iptables DROP rule added")
    else:
        warn("iptables blocklist rule already present")

    # Persist iptables
    save_path = detect_iptables_save_path()
    if save_path:
        run(f"iptables-save > {save_path}")
        ok(f"iptables rules saved → {save_path}")
    else:
        run("apt-get install -y iptables-persistent", check=False)
        run("netfilter-persistent save", check=False)
        ok("iptables rules saved (netfilter-persistent)")

    # Persist ipset
    ipset_save = detect_ipset_save_path()
    if ipset_save:
        run(f"ipset save > {ipset_save}")
        ok(f"ipset saved → {ipset_save}")


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — Fail2ban install
# ─────────────────────────────────────────────────────────────────────────────
def step2_fail2ban_install():
    head("STEP 2 — Fail2ban Install")

    distro, pkg = detect_distro()

    if distro == "rhel":
        # EPEL required for Fail2ban on RHEL/AlmaLinux/Rocky
        result = run("rpm -q epel-release", check=False, capture=True)
        if result.returncode != 0:
            run(f"{pkg} install -y epel-release")
            ok("EPEL repository installed")
        run(f"{pkg} install -y fail2ban fail2ban-systemd")
    else:
        run("apt-get update -qq")
        run("apt-get install -y fail2ban")

    run("systemctl enable fail2ban")
    ok("Fail2ban installed and enabled")


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — Fail2ban filters
# ─────────────────────────────────────────────────────────────────────────────
def step3_filters():
    head("STEP 3 — Fail2ban Filters")

    filters = {

        "apache-webshell": """\
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD) .*\.(php|asp|aspx|jsp|cgi|pl|py|sh|bash|cmd|exe|cfm|shtml)\?.*= HTTP
            ^<HOST> -.*"(GET|POST|HEAD) .*(shell|webshell|cmd|eval|base64|passwd|shadow|etc/passwd) HTTP
            ^<HOST> -.*"(GET|POST|HEAD) .*(c99|r57|b374k|wso|alfa|indoxploit|symlink|bypass) HTTP
ignoreregex =
""",

        "apache-php-scanner": """\
[Definition]
failregex = ^<HOST> -.*"(GET|POST) /.*.php.* HTTP/.*" 404
            ^<HOST> -.*"(GET|POST) /wp-content/plugins/.*.php HTTP
            ^<HOST> -.*"(GET|POST) /wp-includes/.*.php HTTP
ignoreregex = ^<HOST> -.*"GET /wp-admin/
              ^<HOST> -.*"GET /wp-content/themes/.*\.php HTTP
""",

        "apache-credentials": """\
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD) /\.env HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /(wp-config\.php|wp-config\.bak|wp-config\.txt) HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /\.git/(config|HEAD|index) HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /(aws|\.aws)/credentials HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /\.ssh/(id_rsa|authorized_keys|known_hosts) HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /(secrets|credentials|serviceAccountKey)\.json HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /\.aws/credentials HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /(api/\.env|backend/\.env|app/\.env) HTTP
ignoreregex =
""",

        "apache-enum": """\
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD) .*(admin|administrator|phpmyadmin|pma|myadmin|mysql|adminer) HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /xmlrpc\.php HTTP
ignoreregex = ^<HOST> -.*"(GET|POST) /wp-admin/
""",

        "apache-config-scan": """\
[Definition]
# Targets JSON config file harvesting with rotating user agents
failregex = ^<HOST> -.*"(GET|POST|HEAD) /\.dbeaver/credentials-config\.json HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /(aws|mysql|db|postgres|mongodb|s3|secrets?|credentials?|keys)/config\.json HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /(aws|mysql)/credentials(\.json)? HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /config\.(prod|dev|staging|production)\.json HTTP
            ^<HOST> -.*"(GET|POST|HEAD) /assets/config\.production\.json HTTP
ignoreregex = ^<HOST> -.*"GET /wp-json/
              ^<HOST> -.*"GET /wp-content/
              ^<HOST> -.*"GET /wp-admin/
""",

        "apache-wplogin": """\
[Definition]
# wp-login.php brute force — watches all hosted domains via glob in jail.local
failregex = ^<HOST> -.*"POST /wp-login\.php
ignoreregex =
""",

        "apache-wpcron-abuse": """\
[Definition]
# wp-cron.php flood prevention
# Legitimate cron is triggered server-side (server IP whitelisted via ignoreip)
# External IPs hammering wp-cron.php are bots or compromised servers
# Real-world catch: 167.86.93.191 sent 61,992 wp-cron requests from a Contabo server
failregex = ^<HOST> -.*"GET /wp-cron\.php
ignoreregex =
""",

    }

    for name, content in filters.items():
        path = f"/etc/fail2ban/filter.d/{name}.conf"
        if os.path.exists(path) and not DRY_RUN:
            warn(f"Filter exists: {path} — skipping (delete to reinstall)")
        else:
            write_file(path, content)


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — Fail2ban jail.local
# ─────────────────────────────────────────────────────────────────────────────
def step4_jails():
    head("STEP 4 — Fail2ban Jails (jail.local)")

    apache_log  = detect_apache_log()
    ssh_log     = detect_ssh_log()
    domlog_base = detect_domlog_base()
    is_cpanel   = detect_cpanel()
    server_ip   = get_server_ip()

    info(f"Apache log:  {apache_log}")
    info(f"SSH log:     {ssh_log}")
    info(f"cPanel:      {'yes' if is_cpanel else 'no'}")
    info(f"Domlog base: {domlog_base or 'not found (non-cPanel — using global log)'}")
    info(f"Server IP:   {server_ip or 'could not detect'}")

    # Build ignoreip — always include localhost + server's own IP
    ignoreip_parts = ["127.0.0.1/8", "::1"]
    if server_ip:
        ignoreip_parts.append(server_ip)
    ignoreip = " ".join(ignoreip_parts)

    # Build domlog-aware logpath for multi-domain jails
    exts = ["ro", "com", "net", "art", "uk", "dev", "es"]

    def build_domlog_logpath(base, indent="           "):
        if base and is_cpanel:
            lines = [f"logpath = {base}/*.{exts[0]}"]
            for ext in exts[1:]:
                lines.append(f"{indent}{base}/*.{ext}")
            return "\n".join(lines)
        return f"logpath = {apache_log}"

    wplogin_logpath  = build_domlog_logpath(domlog_base)
    wpcron_logpath   = build_domlog_logpath(domlog_base)

    jail_local = f"""\
# fail2ban-cpanel-installer — jail.local
# Generated by security_installer.py
# https://github.com/dffkt432hz/fail2ban-cpanel-installer

[DEFAULT]
# Never ban these IPs — localhost, server's own IP, and any home/office IPs you add
ignoreip = {ignoreip}
bantime  = 86400
findtime = 600
maxretry = 5
backend  = auto

# Use ipset for all bans — integrates with existing blocklist ipset
banaction = iptables-ipset-proto6-allports
banaction_allports = iptables-ipset-proto6-allports

# ── SSH ───────────────────────────────────────────────────────────────────────
[sshd]
enabled  = true
port     = ssh
logpath  = {ssh_log}
maxretry = 3
findtime = 60
bantime  = 604800

# ── Webshell scanning ─────────────────────────────────────────────────────────
[apache-webshell]
enabled  = true
port     = http,https
filter   = apache-webshell
logpath  = {apache_log}
maxretry = 2
findtime = 60
bantime  = 86400
banaction = iptables-ipset-proto6-allports

# ── PHP scanner (404 probing for vulnerable plugins/themes) ───────────────────
[apache-php-scanner]
enabled  = true
port     = http,https
filter   = apache-php-scanner
logpath  = {apache_log}
maxretry = 1
findtime = 60
bantime  = 86400
banaction = iptables-ipset-proto6-allports

# ── Credential harvesting (.env, wp-config, .git, aws/credentials) ───────────
[apache-credentials]
enabled  = true
port     = http,https
filter   = apache-credentials
logpath  = {apache_log}
maxretry = 2
findtime = 60
bantime  = 86400
banaction = iptables-ipset-proto6-allports

# ── Admin enumeration (phpmyadmin, xmlrpc, adminer) ──────────────────────────
[apache-enum]
enabled  = true
port     = http,https
filter   = apache-enum
logpath  = {apache_log}
maxretry = 5
findtime = 60
bantime  = 86400
banaction = iptables-ipset-proto6-allports

# ── JSON config file harvesting ───────────────────────────────────────────────
[apache-config-scan]
enabled  = true
port     = http,https
filter   = apache-config-scan
logpath  = {apache_log}
maxretry = 5
findtime = 60
bantime  = 86400
banaction = iptables-ipset-proto6-allports

# ── WordPress wp-login.php brute force ────────────────────────────────────────
# cPanel: watches all hosted domain logs via glob
# Non-cPanel: watches global Apache access log
[apache-wplogin]
enabled  = true
port     = http,https
filter   = apache-wplogin
{wplogin_logpath}
maxretry = 3
findtime = 60
bantime  = 86400
action   = iptables-multiport[name=wplogin, port="http,https", protocol=tcp]

# ── WordPress wp-cron.php flood ───────────────────────────────────────────────
# Server's own IP is whitelisted via ignoreip above — only external abusers banned
# cPanel: watches all hosted domain logs via glob
# Non-cPanel: watches global Apache access log
[apache-wpcron-abuse]
enabled  = true
port     = http,https
filter   = apache-wpcron-abuse
{wpcron_logpath}
maxretry = 20
findtime = 60
bantime  = 604800
action   = iptables-multiport[name=wpcronabuse, port="http,https", protocol=tcp]
"""

    jail_path = "/etc/fail2ban/jail.local"
    if os.path.exists(jail_path) and not DRY_RUN:
        backup = f"{jail_path}.bak.{int(time.time())}"
        run(f"cp {jail_path} {backup}")
        warn(f"Existing jail.local backed up → {backup}")

    write_file(jail_path, jail_local)


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 — Firehol Level 1 blocklist
# ─────────────────────────────────────────────────────────────────────────────
def step5_firehol():
    head("STEP 5 — Firehol Blocklist")

    distro, pkg = detect_distro()

    if not shutil.which("curl"):
        if distro == "rhel":
            run(f"{pkg} install -y curl")
        else:
            run("apt-get install -y curl")

    script = """\
#!/bin/bash
# Firehol Level 1 blocklist loader
# https://github.com/dffkt432hz/fail2ban-cpanel-installer
set -euo pipefail

TMPFILE=$(mktemp)
LOGFILE=/var/log/firehol-blocklist.log

echo "[$(date)] Updating Firehol blocklist..." >> "$LOGFILE"

curl -s https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset \\
  | grep -v "^#" | grep -v "^$" \\
  | grep -v "^127\\." \\
  | grep -v "^10\\." \\
  | grep -v "^192\\.168\\." \\
  | grep -v "^172\\.1[6-9]\\." \\
  | grep -v "^172\\.2[0-9]\\." \\
  | grep -v "^172\\.3[0-1]\\." \\
  > "$TMPFILE"

COUNT=$(wc -l < "$TMPFILE")

while IFS= read -r subnet; do
    ipset add blocklist "$subnet" 2>/dev/null || true
done < "$TMPFILE"

rm "$TMPFILE"
echo "[$(date)] Done. Loaded $COUNT networks." >> "$LOGFILE"
"""
    write_file("/usr/local/bin/firehol-blocklist.sh", script, mode=0o755)

    info("Downloading Firehol blocklist (may take 1–2 minutes)...")
    run("/usr/local/bin/firehol-blocklist.sh")
    ok("Firehol blocklist loaded")

    cron = "0 3 * * * root /usr/local/bin/firehol-blocklist.sh\n"
    write_file("/etc/cron.d/firehol-blocklist", cron)

    service = """\
[Unit]
Description=Firehol Blocklist Loader
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firehol-blocklist.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    write_file("/etc/systemd/system/firehol-blocklist.service", service)
    run("systemctl daemon-reload")
    run("systemctl enable firehol-blocklist.service")
    ok("Firehol systemd service enabled (loads on boot)")


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 — Apache URL blocking
# ─────────────────────────────────────────────────────────────────────────────
def step6_apache_blocking():
    head("STEP 6 — Apache URL Blocking")

    distro, pkg  = detect_distro()
    confd        = detect_apache_confd()
    conf_path    = os.path.join(confd, "block-scanners.conf")
    apache_conf  = detect_apache_conf()
    apache_svc   = detect_apache_service()

    scanner_conf = """\
# block-scanners.conf
# Blocks known attack paths at Apache level before PHP spawns.
# Critical during attacks: prevents php-fpm worker exhaustion.
# https://github.com/dffkt432hz/fail2ban-cpanel-installer

<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} (hellopress|wp-file-manager|adminer|phpspy|c99|r57|alfa|wso|timthumb|FilesMan) [NC]
    RewriteRule .* - [F,L]
</IfModule>

<LocationMatch "\\.php$">
    <If "%{REQUEST_URI} =~ /wso112233|ALFA_DATA|repeater|vuln|zoko|yasnu|xmu|uwu|uwa|solo1|spawns|pucci|puc|ref|one|t3s|sghb|ms-edit|wp-blog|wp-good|classwithtostring|adminfuns/">
        Require all denied
    </If>
</LocationMatch>

# Block common server status probes
<Location "/whm-server-status">
    Require all denied
</Location>

# Block known vulnerable plugin paths
<Location "/wp-content/plugins/hellopress/wp_filemanager.php">
    Require all denied
</Location>

# Block PHPUnit exploitation path (CVE widely abused)
<LocationMatch "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\\.php">
    Require all denied
</LocationMatch>

# Block direct server IP access (scanners hit raw IP, not domain)
<If "%{HTTP_HOST} == '%SERVER_ADDR%'">
    Require all denied
</If>
"""
    write_file(conf_path, scanner_conf)

    if distro == "debian":
        if shutil.which("a2enconf"):
            run(f"a2enconf {os.path.basename(conf_path).replace('.conf','')}", check=False)
            ok("Enabled via a2enconf")
        else:
            append_if_missing(apache_conf, f"Include {conf_path}")
        if shutil.which("a2enmod"):
            run("a2enmod rewrite", check=False)
    else:
        append_if_missing(apache_conf, f"Include {conf_path}")

    result = run("apachectl configtest", check=False, capture=True)
    if result.returncode == 0:
        ok("Apache config test passed")
        run(f"systemctl restart {apache_svc} || service {apache_svc} restart || true")
        ok(f"Apache restarted ({apache_svc})")
    else:
        err("Apache config test FAILED — check block-scanners.conf")
        if result.stderr:
            err(result.stderr.strip())


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 7 — WP-Cron server-side replacement
# ─────────────────────────────────────────────────────────────────────────────
def step7_wp_cron():
    head("STEP 7 — WP-Cron Hardening")

    search_patterns = [
        "/home/*/public_html/wp-config.php",   # cPanel
        "/var/www/*/wp-config.php",            # Debian/Ubuntu default
        "/var/www/html/wp-config.php",         # single-site
        "/srv/www/*/wp-config.php",            # openSUSE-style
    ]
    wp_configs = []
    for pattern in search_patterns:
        wp_configs.extend(glob.glob(pattern))
    wp_configs = list(set(wp_configs))

    info(f"Found {len(wp_configs)} WordPress installation(s)")

    php_bin = shutil.which("php") or "/usr/local/bin/php"

    cron_lines = []
    patched = skipped = 0

    for config_path in wp_configs:
        parts = config_path.split("/")
        try:
            stat = os.stat(config_path)
            import pwd
            user = pwd.getpwuid(stat.st_uid).pw_name
        except Exception:
            user = parts[2] if len(parts) > 2 else "www-data"

        wp_dir = os.path.dirname(config_path)

        if not DRY_RUN:
            with open(config_path, 'r') as f:
                content = f.read()
            if "DISABLE_WP_CRON" not in content:
                new_content = content.replace(
                    "<?php",
                    "<?php\ndefine('DISABLE_WP_CRON', true);",
                    1
                )
                with open(config_path, 'w') as f:
                    f.write(new_content)
                ok(f"Patched: {config_path}")
                patched += 1
            else:
                warn(f"Already patched: {config_path}")
                skipped += 1
        else:
            dry(f"Would patch DISABLE_WP_CRON: {config_path}")

        wp_cron = os.path.join(wp_dir, "wp-cron.php")
        if os.path.exists(wp_cron) or DRY_RUN:
            cron_lines.append(
                f"*/5 * * * * {user} {php_bin} {wp_cron} > /dev/null 2>&1"
            )

    if not DRY_RUN:
        info(f"Patched: {patched} | Already done: {skipped}")

    if cron_lines:
        content = (
            "# WP-Cron server-side replacement\n"
            "# Generated by fail2ban-cpanel-installer\n"
            "# https://github.com/dffkt432hz/fail2ban-cpanel-installer\n\n"
        )
        content += "\n".join(cron_lines) + "\n"
        write_file("/etc/cron.d/wp-cron-all", content)
        ok(f"Server-side WP cron written ({len(cron_lines)} site(s))")
    else:
        warn("No WP installations found — skipping WP-Cron step")


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 8 — Start Fail2ban + verify
# ─────────────────────────────────────────────────────────────────────────────
def step8_start_fail2ban():
    head("STEP 8 — Start & Verify Fail2ban")
    run("systemctl restart fail2ban")
    if not DRY_RUN:
        time.sleep(5)
    result = run("fail2ban-client status", check=False, capture=True)
    if result.returncode == 0:
        ok("Fail2ban running")
        print(result.stdout)
    else:
        err("Fail2ban failed to start")
        err("Check: journalctl -u fail2ban -n 50 --no-pager")


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 9 — Final verification
# ─────────────────────────────────────────────────────────────────────────────
def step9_verify():
    head("STEP 9 — Final Verification")

    checks = [
        ("ipset blocklist",        "ipset list blocklist | grep 'Number of entries'"),
        ("iptables DROP rule",     "iptables -L INPUT -n -v | grep blocklist"),
        ("Fail2ban jails",         "fail2ban-client status"),
        ("Firehol cron",           "cat /etc/cron.d/firehol-blocklist"),
        ("Apache URL blocking",    "curl -s -o /dev/null -w '%{http_code}' http://localhost/whm-server-status"),
        ("WP-Cron server cron",    "wc -l /etc/cron.d/wp-cron-all 2>/dev/null || echo 'not created (no WP installs found)'"),
        ("Fail2ban wpcron jail",   "fail2ban-client status apache-wpcron-abuse"),
    ]

    for label, cmd in checks:
        result = run(cmd, check=False, capture=True)
        if result.returncode == 0 and result.stdout.strip():
            ok(f"{label}")
            info(result.stdout.strip()[:200])
        else:
            warn(f"{label} — check manually")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
STEPS = [
    ("ipset + iptables",        step1_ipset),
    ("Fail2ban install",        step2_fail2ban_install),
    ("Fail2ban filters",        step3_filters),
    ("Fail2ban jails",          step4_jails),
    ("Firehol blocklist",       step5_firehol),
    ("Apache URL blocking",     step6_apache_blocking),
    ("WP-Cron hardening",       step7_wp_cron),
    ("Start Fail2ban",          step8_start_fail2ban),
    ("Final verification",      step9_verify),
]

BANNER = f"""\
{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════╗
║   fail2ban-cpanel-installer  v2.1                            ║
║   Automated VPS Security Stack                               ║
║   AlmaLinux · Rocky · RHEL · Ubuntu · Debian                 ║
║   cPanel & standalone Apache                                 ║
║   github.com/dffkt432hz/fail2ban-cpanel-installer            ║
╚══════════════════════════════════════════════════════════════╝
{RESET}
Installs:
  • ipset blocklist (500k capacity, iptables DROP)
  • Fail2ban — 8 hardened jails:
      apache-webshell      | apache-php-scanner   | apache-credentials
      apache-enum          | apache-config-scan   | apache-wplogin
      apache-wpcron-abuse  | sshd
  • Firehol Level 1 blocklist (4,400+ malicious networks, daily refresh)
  • Apache URL blocking (scanners → 403, before PHP spawns)
  • WP-Cron server-side replacement (prevents cron storms)
"""

def main():
    global DRY_RUN

    parser = argparse.ArgumentParser(
        description="Automated security stack installer — cPanel/AlmaLinux/Ubuntu/Debian"
    )
    parser.add_argument("--step", type=int, metavar="N", help="Run only step N (1–9)")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing")
    parser.add_argument("--list", action="store_true", help="List all steps and exit")
    args = parser.parse_args()

    DRY_RUN = args.dry_run
    print(BANNER)

    if args.list:
        for i, (label, _) in enumerate(STEPS, 1):
            print(f"  Step {i}: {label}")
        return

    if not DRY_RUN and os.geteuid() != 0:
        err("Must be run as root.  sudo python3 security_installer.py")
        sys.exit(1)

    if args.step:
        if not 1 <= args.step <= len(STEPS):
            err(f"Invalid step: {args.step}. Valid: 1–{len(STEPS)}")
            sys.exit(1)
        label, fn = STEPS[args.step - 1]
        info(f"Running step {args.step}: {label}")
        fn()
        return

    failed = []
    for i, (label, fn) in enumerate(STEPS, 1):
        try:
            fn()
        except Exception as e:
            err(f"Step {i} '{label}' raised: {e}")
            failed.append(label)
            warn("Continuing with next step...")

    print(f"""
{BOLD}{GREEN}
╔══════════════════════════════════════════════════════════════╗
║  Installation complete.                                      ║
╠══════════════════════════════════════════════════════════════╣
║  Active Fail2ban jails: 8                                    ║
║    apache-webshell      apache-php-scanner                   ║
║    apache-credentials   apache-enum                          ║
║    apache-config-scan   apache-wplogin                       ║
║    apache-wpcron-abuse  sshd                                 ║
╠══════════════════════════════════════════════════════════════╣
║  Remaining manual steps:                                     ║
║  • Add your home/office IP to ignoreip in jail.local         ║
║  • cPHulk (cPanel): WHM > Security Center > cPHulk           ║
║  • Imunify360: install via WHM if licensed                   ║
║  • Update block-scanners.conf as new attacks emerge          ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

    if failed:
        warn(f"Steps with errors: {', '.join(failed)}")


if __name__ == "__main__":
    main()
