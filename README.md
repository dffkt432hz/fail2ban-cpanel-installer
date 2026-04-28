# fail2ban-cpanel-installer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AlmaLinux](https://img.shields.io/badge/AlmaLinux-8%2B-blue)](https://almalinux.org/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420)](https://ubuntu.com/)
[![Debian](https://img.shields.io/badge/Debian-11%2B-A81D33)](https://debian.org/)
[![cPanel](https://img.shields.io/badge/cPanel-11.130%2B-FF6C2C)](https://cpanel.net/)
[![Python](https://img.shields.io/badge/python-3.6%2B-3776AB)](https://python.org)

**Automated security stack installer for Apache-based VPS servers.**

Deploys a production-hardened defense layer in a single command — ipset blocklist, 7 Fail2ban jails tuned for WordPress and cPanel environments, Firehol Level 1 network blocklist, Apache-level scanner blocking, and WP-Cron hardening.

Battle-tested against a sustained coordinated cyberattack: **750,000+ malicious requests, 500+ IPs, 7 simultaneous threat actors** — server load kept under control, zero breaches, zero data exfiltration.

---

## Compatibility

| OS | Supported | Notes |
|---|---|---|
| AlmaLinux 8 / 9 | ✅ | Primary target, fully tested |
| Rocky Linux 8 / 9 | ✅ | Same package stack as AlmaLinux |
| RHEL 8 / 9 | ✅ | Uses `dnf` |
| CentOS Stream 8 / 9 | ✅ | Uses `dnf` |
| Ubuntu 20.04 / 22.04 / 24.04 | ✅ | Uses `apt`, `a2enconf`, `a2enmod` |
| Debian 11 / 12 | ✅ | Uses `apt`, `a2enconf`, `a2enmod` |
| cPanel / WHM | ✅ | Auto-detects domlog paths for wp-login jail |
| Standalone Apache (no cPanel) | ✅ | Falls back to global access log |

The installer **auto-detects** your OS, package manager, Apache paths, and log locations — no manual configuration needed before running.

---

## What it installs

| Component | Details |
|---|---|
| **ipset** | `hash:net` blocklist, 500k entry capacity, iptables DROP rule, boot persistence |
| **Fail2ban** | 7 hardened jails (see below), auto-bans attackers within seconds |
| **Firehol Level 1** | 4,400+ known malicious networks blocked at kernel level, daily cron refresh at 03:00 |
| **Apache URL blocking** | Webshell/scanner paths → 403 before PHP ever spawns — kills load spikes immediately |
| **WP-Cron hardening** | Replaces per-request WP-Cron with server-side cron — prevents cron storms under attack |

### Fail2ban jails (7)

| Jail | Targets | maxretry | bantime |
|---|---|---|---|
| `apache-webshell` | Webshell upload attempts, known shell filenames | 2 | 24h |
| `apache-php-scanner` | PHP 404 probing for vulnerable plugins/themes | 1 | 24h |
| `apache-credentials` | `.env`, `wp-config`, `.git/config`, `aws/credentials` harvesting | 2 | 24h |
| `apache-enum` | phpMyAdmin, xmlrpc.php, adminer enumeration | 5 | 24h |
| `apache-config-scan` | JSON config file harvesting with rotating user agents | 5 | 24h |
| `apache-wplogin` | `wp-login.php` brute force across all hosted domains | 3 | 24h |
| `sshd` | SSH brute force | 3 | 24h |

---

## Requirements

- Python 3.6+
- Root / sudo access
- Apache 2.4
- One of: AlmaLinux / Rocky / RHEL / CentOS Stream / Ubuntu / Debian

---

## Quick start

```bash
# Download
curl -O https://raw.githubusercontent.com/dffkt432hz/fail2ban-cpanel-installer/main/security_installer.py

# Full install (all 9 steps)
sudo python3 security_installer.py

# Dry run — preview all actions without executing
sudo python3 security_installer.py --dry-run

# Run a single step
sudo python3 security_installer.py --step 5

# List all steps
python3 security_installer.py --list
```

---

## Step-by-step breakdown

```
Step 1: ipset + iptables       — blocklist set, DROP rule, iptables persistence
Step 2: Fail2ban install       — package install + systemd enable
Step 3: Fail2ban filters       — 6 filter files → /etc/fail2ban/filter.d/
Step 4: Fail2ban jails         — jail.local, 7 jails, auto-detects all paths
Step 5: Firehol blocklist      — download script + daily cron + systemd boot service
Step 6: Apache URL blocking    — block-scanners.conf + Apache config include
Step 7: WP-Cron hardening      — DISABLE_WP_CRON across all WP installs + server cron
Step 8: Start Fail2ban         — restart + verify all 7 jails active
Step 9: Final verification     — ipset, iptables, jails, crons, Apache
```

---

## Auto-detection

The installer auto-detects your environment — no pre-configuration needed:

| What | RHEL-family | Debian/Ubuntu |
|---|---|---|
| Package manager | `dnf` or `yum` | `apt-get` |
| Apache access log | `/usr/local/apache/logs/access_log` (cPanel) or `/var/log/httpd/access_log` | `/var/log/apache2/access.log` |
| SSH log | `/var/log/secure` | `/var/log/auth.log` |
| Apache conf.d | `/etc/apache2/conf.d` or `/etc/httpd/conf.d` | `/etc/apache2/conf-enabled` |
| Apache main conf | `/etc/apache2/conf/httpd.conf` or `/etc/httpd/conf/httpd.conf` | `/etc/apache2/apache2.conf` |
| iptables persistence | `iptables-save → /etc/sysconfig/iptables` | `netfilter-persistent` |
| Apache module enable | N/A | `a2enconf` + `a2enmod rewrite` |
| WP-login log glob | cPanel domlogs `*.ro *.com *.net ...` | Global access log |
| WP install search | `/home/*/public_html/` (cPanel) | `/var/www/*/` + `/srv/www/*/` |

---

## After installation

### Monitoring

```bash
# All jail statuses
fail2ban-client status

# Specific jail
fail2ban-client status apache-wplogin

# Blocklist size
ipset list blocklist | grep "Number of entries"

# Dropped packet count
iptables -L INPUT -n -v | grep blocklist

# Firehol update log
tail -f /var/log/firehol-blocklist.log
```

### Manually block IPs / subnets

```bash
# Single IP
ipset add blocklist 1.2.3.4

# Entire subnet
ipset add blocklist 192.3.0.0/16

# Persist
iptables-save > /etc/sysconfig/iptables      # RHEL-family
# OR
netfilter-persistent save                    # Debian/Ubuntu
```

### Force-update Firehol blocklist

```bash
/usr/local/bin/firehol-blocklist.sh
```

### Update Apache block list

Add new attack paths to `/etc/apache2/conf.d/block-scanners.conf` (or `/etc/httpd/conf.d/` on RHEL without cPanel) as you discover them, then restart Apache.

---

## Manual steps (not automated)

| Step | Where |
|---|---|
| **cPHulk** (cPanel only) | WHM → Security Center → cPHulk Brute Force Protection → Enable |
| **Imunify360** (cPanel) | WHM → Imunify360 → Install (if licensed) |
| **UFW** (Ubuntu) | If UFW is active, allow ports 80/443/22 before enabling it |

---

## File locations after install

```
/etc/fail2ban/jail.local
/etc/fail2ban/filter.d/apache-webshell.conf
/etc/fail2ban/filter.d/apache-php-scanner.conf
/etc/fail2ban/filter.d/apache-credentials.conf
/etc/fail2ban/filter.d/apache-enum.conf
/etc/fail2ban/filter.d/apache-config-scan.conf
/etc/fail2ban/filter.d/apache-wplogin.conf
/usr/local/bin/firehol-blocklist.sh
/etc/cron.d/firehol-blocklist
/etc/cron.d/wp-cron-all
/etc/apache2/conf.d/block-scanners.conf      ← cPanel / RHEL
/etc/apache2/conf-enabled/block-scanners.conf ← Ubuntu / Debian
/etc/systemd/system/firehol-blocklist.service
/var/log/firehol-blocklist.log
```

---

## Background

This installer was built in response to a coordinated multi-vector cyberattack (April–May 2026):

- **750,000+ malicious requests** across 17 days
- **7 simultaneous threat actors**: Microsoft Azure (AS8075), Bucklog SARL (AS211590), F.N.S. Holdings via ExpressVPN/IPXO, ColoCrossing, Google Cloud, Bloom.host, IONOS and others
- **Attack types**: webshell scanning, credential harvesting, JSON config probing, wp-login brute force, PHP plugin enumeration, WP-Cron storms
- **Peak server load**: 85.92
- **Outcome**: zero breaches, zero data exfiltration

The attack patterns are encoded directly into the Fail2ban filter regexes.

---

## Contributing

PRs welcome. If you discover new attack patterns, open an issue with:
- The Apache log line (anonymize your IP)
- The attack type
- Suggested filter regex

Use the **New Attack Pattern** issue template.

---

## License

MIT — use freely, modify freely, no warranty.
