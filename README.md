# fail2ban-cpanel-installer

[![Python](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-AlmaLinux%20%7C%20Rocky%20%7C%20Ubuntu%20%7C%20Debian-lightgrey)](https://github.com/dffkt432hz/fail2ban-cpanel-installer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Battle tested](https://img.shields.io/badge/battle--tested-900k%2B%20requests-red)](https://github.com/dffkt432hz/fail2ban-cpanel-installer)

**Automated security stack installer for cPanel / AlmaLinux VPS servers.**

Deploys a production-hardened defense layer in a single command — ipset blocklist with **iptables DROP as rule #1**, 10 Fail2ban jails using **ipset-based blocking** (not multiport chains), Firehol Level 1 network blocklist, Apache-level scanner blocking, WP-Cron hardening, and an automated AbuseIPDB blocklist sync system.

Battle-tested against a sustained coordinated cyberattack: **900,000+ malicious requests, 900+ IPs, 115+ subnets, 8 attack waves** — server never breached, zero data exfiltrated.

---

## What it installs

| Component | Details |
|---|---|
| **ipset** | `hash:net` blocklist, 500k entry capacity, **iptables DROP inserted as rule #1** |
| **Fail2ban** | 10 hardened jails, all using `iptables-ipset-proto6-allports` action |
| **Firehol Level 1** | 4,500+ known malicious networks blocked at kernel level, daily cron refresh |
| **AbuseIPDB sync** | 10,000 confirmed abusers (90%+ confidence) pulled daily, published to fleet |
| **Apache URL blocking** | Webshell/scanner paths return 403 before PHP ever spawns — kills load spikes |
| **WP-Cron hardening** | Replaces per-request cron with server-side cron — prevents cron storms under attack |
| **IPv6 blocking** | Azure `2602:fb54::/32` superblock + configurable ip6tables rules |

---

## Fail2ban jails (10)

| Jail | Targets | maxretry | bantime | Action |
|---|---|---|---|---|
| `sshd` | SSH brute force | 3 | 7 days | ipset |
| `apache-webshell` | Webshell upload attempts, known shell names | 2 | 24h | ipset |
| `apache-php-scanner` | PHP 404 probing for vulnerable plugins/themes | 1 | 24h | ipset |
| `apache-credentials` | `.env`, `wp-config`, `.git/config`, `aws/credentials` harvesting | 2 | 24h | ipset |
| `apache-enum` | phpMyAdmin, xmlrpc.php, adminer enumeration | 5 | 24h | ipset |
| `apache-config-scan` | JSON config file harvesting with rotating user agents | 5 | 24h | ipset |
| `apache-wplogin` | `wp-login.php` brute force across **all hosted domains** | 3 | 24h | multiport |
| `apache-wpcron-abuse` | `wp-cron.php` flooding from external IPs | 20 | 7 days | multiport |
| `apache-wpscan` | WPScan tool, plugin/theme readme enumeration, user enumeration via `?author=` | 2 | 24h | ipset |
| `apache-phpunit` | PHPUnit RCE (CVE-2017-9841) + ThinkPHP `invokefunction` RCE | 2 | 7 days | ipset |

> **All jails use `iptables-ipset-proto6-allports`** (kernel-level ipset DROP) by default.  
> `wplogin` and `wpcron-abuse` use `iptables-multiport` for domain-glob logpath compatibility.

---

## iptables rule order

The installer places the blocklist DROP as **rule #1** in the INPUT chain — before any ACCEPT rules. This ensures all 4,500+ Firehol networks and manually blocked IPs are dropped at the kernel level without reaching Apache.

```
Chain INPUT (policy ACCEPT)
DROP    all  -- 0.0.0.0/0  0.0.0.0/0  match-set blocklist src       ← Rule #1
REJECT  tcp  -- 0.0.0.0/0  0.0.0.0/0  match-set f2b-apache-webshell src
REJECT  tcp  -- 0.0.0.0/0  0.0.0.0/0  match-set f2b-apache-credentials src
...
```

---

## AbuseIPDB fleet sync

For multi-server deployments, the installer supports a master/slave blocklist sync:

**On the master server** — generates and publishes `blocklist.txt` daily:
```bash
# /usr/local/bin/abuseipdb-blocklist.sh runs at 02:00
# Pulls 10,000 IPs (90%+ confidence) from AbuseIPDB API
# Merges with local ipset (manual blocks + Firehol)
# Publishes to /home/<user>/public_html/blocklist.txt
# Guard: only publishes if entry count > 1000 (prevents empty-file wipe)
```

**On slave servers** — pull and apply at 02:30:
```bash
cat > /usr/local/bin/sync-blocklist.sh << 'SCRIPT'
#!/bin/bash
curl -s https://yourdomain.com/blocklist.txt -o /tmp/master_blocklist.txt
[ -s /tmp/master_blocklist.txt ] || exit 1
while read net; do ipset add blocklist $net 2>/dev/null; done < /tmp/master_blocklist.txt
ipset save > /etc/sysconfig/ipset
logger "sync-blocklist: $(ipset list blocklist | grep 'Number of entries')"
SCRIPT
chmod +x /usr/local/bin/sync-blocklist.sh
echo "30 2 * * * root /usr/local/bin/sync-blocklist.sh >/dev/null 2>&1" > /etc/cron.d/sync-blocklist
```

**Timing stack:**
- `02:00` — Master pulls AbuseIPDB, updates ipset, publishes blocklist.txt
- `02:30` — Slaves pull blocklist.txt, update their ipsets
- `03:00` — Firehol refreshes on all servers

---

## IPv6 blocking

Block entire Azure IPv6 superblock (replaces chasing individual /48s):
```bash
ip6tables -I INPUT 1 -s 2602:fb54::/32 -j DROP
ip6tables-save > /etc/sysconfig/ip6tables
```

Persist across reboots by saving to `/etc/sysconfig/ip6tables` (RHEL-family) or via `netfilter-persistent save` (Debian/Ubuntu).

---

## Requirements

- AlmaLinux 8+ / Rocky Linux 8+ / RHEL 8+ / Ubuntu 22.04+ / Debian 12+
- cPanel / WHM (tested on 11.130+)
- Apache 2.4
- Python 3.6+
- Root access

---

## Quick start

```bash
wget https://raw.githubusercontent.com/dffkt432hz/fail2ban-cpanel-installer/main/security_installer.py
python3 security_installer.py
```

### Options

```bash
python3 security_installer.py --list        # Show all steps
python3 security_installer.py --dry-run     # Preview without changes
python3 security_installer.py --step 4      # Run only step 4 (Fail2ban jails)
```

---

## Steps

| Step | What it does |
|---|---|
| 1 | Install & configure ipset — create `blocklist` ipset, insert DROP as iptables rule #1 |
| 2 | Install & configure Fail2ban |
| 3 | Write Fail2ban filter files (10 filters) |
| 4 | Write `jail.local` with all 10 jails using ipset-based actions |
| 5 | Install Firehol Level 1 blocklist + daily cron |
| 6 | Configure Apache URL blocking (webshell/scanner paths → 403) |
| 7 | WP-Cron hardening (`DISABLE_WP_CRON` across all WordPress installs) |
| 8 | Start Fail2ban + verify |
| 9 | Final verification |

---

## Verify everything is working

```bash
# All 10 jails active
fail2ban-client status | grep "Jail list"

# iptables chains — blocklist DROP at top + f2b-* ipset rules
iptables -L INPUT -n | grep -E "blocklist|f2b"

# Blocklist size
ipset list blocklist | grep "Number of entries"

# Active bans per jail
for jail in apache-webshell apache-php-scanner apache-credentials apache-enum \
            apache-config-scan apache-wplogin apache-wpcron-abuse apache-wpscan \
            apache-phpunit sshd; do
  echo -n "$jail: "
  fail2ban-client status $jail | grep "Currently banned"
done
```

---

## Common issues

**Jail shows "Currently banned: N" but IPs still reach Apache**  
Old configurations used `iptables-multiport` which creates named chains but may not wire correctly. This installer uses `iptables-ipset-proto6-allports` — each jail gets its own ipset with a REJECT rule in INPUT. Verify with `iptables -L | grep f2b`.

**blocklist DROP rule missing after reboot**  
The installer saves iptables to `/etc/sysconfig/iptables` (RHEL) or via `netfilter-persistent` (Debian/Ubuntu) and installs a systemd service to restore the Firehol blocklist on boot. If rules don't survive reboot, run `systemctl enable firehol-blocklist.service`.

**AbuseIPDB blocklist publishes 0 entries**  
The publish script uses a 1000-entry guard — if ipset returns fewer than 1000 entries (e.g. after a reboot before ipset is fully restored), it skips the publish to avoid wiping the file. Run the script manually after ipset is restored: `/usr/local/bin/abuseipdb-blocklist.sh`.

**Fail2ban ban chains not appearing in iptables**  
Chains are only created when the first IP is banned. Force-test: `fail2ban-client set apache-credentials banip 1.2.3.4 && iptables -L | grep f2b && fail2ban-client set apache-credentials unbanip 1.2.3.4`

---

## File locations

| File | Purpose |
|---|---|
| `/etc/fail2ban/jail.local` | Main jail configuration |
| `/etc/fail2ban/filter.d/apache-*.conf` | Custom filter files (10 filters) |
| `/usr/local/bin/firehol-blocklist.sh` | Firehol blocklist refresh script |
| `/usr/local/bin/abuseipdb-blocklist.sh` | AbuseIPDB sync + blocklist.txt publisher |
| `/usr/local/bin/sync-blocklist.sh` | Slave server blocklist pull script |
| `/etc/cron.d/firehol-blocklist` | Daily 03:00 cron for Firehol refresh |
| `/etc/cron.d/abuseipdb-blocklist` | Daily 02:00 cron for AbuseIPDB sync |
| `/etc/cron.d/sync-blocklist` | Daily 02:30 cron for slave server sync |
| `/etc/sysconfig/ipset` | Persisted ipset state (RHEL-family) |
| `/etc/sysconfig/iptables` | Persisted iptables rules (RHEL-family) |
| `/etc/sysconfig/ip6tables` | Persisted ip6tables rules (RHEL-family) |

---

## Background

Built and battle-tested during a sustained multi-wave cyberattack campaign (April–June 2026) against a 39-site cPanel/Apache server running WordPress. The attack generated 900,000+ malicious requests from 40+ threat actors across 8 attack waves — webshell scanning, credential harvesting (GCP service account keys, Terraform state files, `.env`), PHP scanner floods, JSON config harvesting, wp-login brute force, wp-cron storms, and PHPUnit/ThinkPHP RCE attempts.

The server was never compromised. This installer encodes everything learned during that defense.

A criminal complaint was filed with ZAC Bayern (case `BY0257-500359-26/8`), abuse reports submitted to AbuseIPDB (900+ IPs reported), and ISP abuse notifications sent to Microsoft, Google Cloud, Hetzner, Contabo, and others.

---

## License

MIT — Andrei Ghițan
