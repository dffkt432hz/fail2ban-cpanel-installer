# fail2ban-cpanel-installer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-AlmaLinux%208%2B-blue)](https://almalinux.org/)
[![cPanel](https://img.shields.io/badge/cPanel-11.130%2B-orange)](https://cpanel.net/)
[![Python](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)

**Automated security stack installer for cPanel / AlmaLinux VPS servers.**

Deploys a production-hardened defense layer in a single command — ipset blocklist, 7 Fail2ban jails tuned for WordPress and cPanel environments, Firehol Level 1 network blocklist, Apache-level scanner blocking, and WP-Cron hardening.

Battle-tested against a sustained coordinated cyberattack: **750,000+ malicious requests, 500+ IPs, 7 simultaneous threat actors** — server load kept under control, zero breaches.

---

## What it installs

| Component | Details |
|---|---|
| **ipset** | `hash:net` blocklist, 500k entry capacity, iptables DROP rule, boot persistence |
| **Fail2ban** | 7 hardened jails (see below), auto-bans attackers within seconds |
| **Firehol Level 1** | 4,400+ known malicious networks blocked at kernel level, daily cron refresh |
| **Apache URL blocking** | Webshell/scanner paths return 403 before PHP ever spawns — kills load spikes |
| **WP-Cron hardening** | Replaces per-request cron with server-side cron — prevents cron storms under attack |

### Fail2ban jails (7)

| Jail | Targets | maxretry | bantime |
|---|---|---|---|
| `apache-webshell` | Webshell upload attempts, known shell names | 2 | 24h |
| `apache-php-scanner` | PHP 404 probing for vulnerable plugins/themes | 1 | 24h |
| `apache-credentials` | `.env`, `wp-config`, `.git/config`, `aws/credentials` harvesting | 2 | 24h |
| `apache-enum` | phpMyAdmin, xmlrpc.php, adminer enumeration | 5 | 24h |
| `apache-config-scan` | JSON config file harvesting with rotating user agents | 5 | 24h |
| `apache-wplogin` | `wp-login.php` brute force across **all hosted domains** | 3 | 24h |
| `sshd` | SSH brute force | 3 | 24h |

---

## Requirements

- AlmaLinux 8+ (or RHEL 8+ / Rocky Linux 8+)
- cPanel / WHM (tested on 11.130+)
- Apache 2.4
- Python 3.6+
- Root access

---

## Quick start

```bash
# Download
curl -O https://raw.githubusercontent.com/dffkt432hz/fail2ban-cpanel-installer/main/security_installer.py

# Full install (runs all 9 steps)
sudo python3 security_installer.py

# Dry run — see what it would do without executing
sudo python3 security_installer.py --dry-run

# Run a single step
sudo python3 security_installer.py --step 5

# List all steps
python3 security_installer.py --list
```

---

## Step-by-step breakdown

```
Step 1: ipset + iptables       — blocklist set + DROP rule + boot persistence
Step 2: Fail2ban install       — yum install + enable
Step 3: Fail2ban filters       — 6 filter files → /etc/fail2ban/filter.d/
Step 4: Fail2ban jails         — jail.local with all 7 jails, auto-detects log paths
Step 5: Firehol blocklist      — script + daily cron + systemd service
Step 6: Apache URL blocking    — block-scanners.conf + httpd.conf include
Step 7: WP-Cron hardening      — DISABLE_WP_CRON in all wp-config.php + server cron
Step 8: Start Fail2ban         — restart + verify all jails active
Step 9: Final verification     — ipset, iptables, jails, crons, Apache
```

---

## Auto-detection

The installer auto-detects your environment:

| Path | Candidates checked |
|---|---|
| Apache access log | `/usr/local/apache/logs/access_log` · `/etc/apache2/logs/access_log` · `/var/log/apache2/access.log` |
| Apache conf.d | `/etc/apache2/conf.d` · `/etc/httpd/conf.d` |
| Domlog base (wp-login jail) | `/etc/apache2/logs/domlogs` · `/usr/local/apache/logs/domlogs` |

---

## After installation

### Manual steps (not automated)

- **cPHulk**: WHM → Security Center → cPHulk Brute Force Protection → Enable
- **Imunify360**: Install via WHM if licensed
- **Update Apache blocklist**: Add new attack paths to `/etc/apache2/conf.d/block-scanners.conf` as you discover them

### Monitoring

```bash
# Check all jail statuses
fail2ban-client status

# Check specific jail
fail2ban-client status apache-wplogin

# Check blocklist size
ipset list blocklist | grep "Number of entries"

# Check dropped packet count
iptables -L INPUT -n -v | grep blocklist

# Check Firehol cron log
tail -f /var/log/firehol-blocklist.log
```

### Adding IPs to blocklist manually

```bash
# Block a single IP
ipset add blocklist 1.2.3.4
iptables-save > /etc/sysconfig/iptables

# Block an entire subnet
ipset add blocklist 192.3.0.0/16
iptables-save > /etc/sysconfig/iptables
```

---

## Background

This installer was developed in response to a coordinated cyberattack against a cPanel VPS (April–May 2026):

- **750,000+ malicious requests** over 17 days
- **7 simultaneous threat actors**: Microsoft Azure (AS8075), Bucklog SARL (AS211590), F.N.S. Holdings via ExpressVPN/IPXO, ColoCrossing, Google Cloud, Bloom.host, IONOS
- **Peak server load**: 85.92
- **Outcome**: Zero breaches, zero data exfiltration

The attack patterns detected — webshell scanning, credential harvesting, JSON config probing, wp-login brute force, PHP plugin scanners — are now encoded directly into the filter regexes.

---

## Updating the blocklist manually

The Firehol blocklist auto-updates daily at 03:00. To update immediately:

```bash
/usr/local/bin/firehol-blocklist.sh
```

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
/etc/apache2/conf.d/block-scanners.conf
/etc/systemd/system/firehol-blocklist.service
/var/log/firehol-blocklist.log
```

---

## Contributing

PRs welcome. If you discover new attack patterns, open an issue with:
- The Apache log line (anonymize your IP)
- The attack type
- Suggested filter regex

---

## License

MIT — use freely, modify freely, no warranty.
