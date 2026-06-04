# fail2ban-cpanel-installer

[![Python](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-AlmaLinux%20%7C%20Rocky%20%7C%20Ubuntu%20%7C%20Debian-lightgrey)](https://github.com/dffkt432hz/fail2ban-cpanel-installer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Battle tested](https://img.shields.io/badge/battle--tested-900k%2B%20requests-red)](https://github.com/dffkt432hz/fail2ban-cpanel-installer)

**Automated security stack installer for cPanel / AlmaLinux VPS servers.**

Deploys a production-hardened defense layer in a single command — ipset blocklist with **iptables DROP as rule #1**, 10 Fail2ban jails using **ipset-based blocking**, a **reboot-safe ipset-restore service** (the critical piece most setups get wrong), Firehol Level 1 network blocklist, Apache-level scanner blocking, WP-Cron hardening, and an automated AbuseIPDB blocklist sync system.

Battle-tested against a sustained coordinated cyberattack: **900,000+ malicious requests, 900+ IPs, 115+ subnets, 8 attack waves** — server never breached, zero data exfiltrated.

---

## The critical lesson this installer encodes

> **A populated ipset with no activating iptables DROP rule drops zero packets.**

During a fleet-wide audit (June 2026), three of four hardened servers were found to have 20,000+ entry blocklists that were **completely inert** after reboots — the ipset was restored but the DROP rule wasn't. Every blocked IP was getting through. The `ipset-restore-critical` service this installer deploys fixes this permanently: it guarantees both the ipset contents **and** the DROP rule survive every reboot, and uses `-C` checks to stay idempotent.

This is the single most important thing this installer does differently from a basic fail2ban setup.

---

## What it installs

| Component | Details |
|---|---|
| **ipset** | `hash:net` blocklist, 500k entry capacity, **iptables DROP inserted as rule #1** |
| **ipset-restore-critical** | Systemd service that enforces both ipset contents AND the DROP rule on every boot |
| **Fail2ban** | 10 hardened jails, all using `iptables-ipset-proto6-allports` action |
| **Firehol Level 1** | 4,500+ known malicious networks blocked at kernel level, daily cron refresh |
| **AbuseIPDB sync** | 10,000 confirmed abusers (90%+ confidence) pulled daily, published to fleet |
| **Apache URL blocking** | Webshell/scanner paths return 403 before PHP ever spawns |
| **WP-Cron hardening** | Replaces per-request cron with server-side cron |
| **IPv6 blocking** | Azure `2602:fb54::/32` superblock (one rule covers entire Azure IPv6 fleet) |

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
| `apache-wplogin` | `wp-login.php` brute force across all hosted domains | 3 | 24h | multiport |
| `apache-wpcron-abuse` | `wp-cron.php` flooding from external IPs | 20 | 7 days | multiport |
| `apache-wpscan` | WPScan tool, plugin/theme readme enumeration, user enumeration | 2 | 24h | ipset |
| `apache-phpunit` | PHPUnit RCE (CVE-2017-9841) + ThinkPHP `invokefunction` RCE | 2 | 7 days | ipset |

---

## iptables rule order

The installer places the blocklist DROP as **rule #1** in the INPUT chain — before any ACCEPT rules. The `ipset-restore-critical` service enforces this on every boot.

```
Chain INPUT (policy ACCEPT)
DROP    all  -- 0.0.0.0/0  0.0.0.0/0  match-set blocklist src       ← Rule #1
REJECT  tcp  -- 0.0.0.0/0  0.0.0.0/0  match-set f2b-apache-webshell src
REJECT  tcp  -- 0.0.0.0/0  0.0.0.0/0  match-set f2b-apache-credentials src
...
ACCEPT  all  -- lo
ACCEPT  all  -- 127.0.0.0/8
```

**Why rule #1 matters:** If fail2ban restarts or the iptables service loads before the ipset, your jail rules appear but the blocklist DROP can be pushed down the chain or absent entirely — and a DROP rule at position #7 with 5 ACCEPT rules above it may still let blocked traffic through depending on how your chain evaluates. The restore service uses `iptables -C` to check and re-insert at position 1 if needed.

---

## The ipset-restore-critical service

This is the most important piece. Deployed to `/etc/systemd/system/ipset-restore-critical.service`, it runs at boot and guarantees:

1. The `blocklist` ipset exists and is populated from `/etc/sysconfig/ipset`
2. The IPv4 DROP rule exists in INPUT (creates it if missing, idempotent `-C` check)
3. The IPv6 `2602:fb54::/32` superblock rule exists in ip6tables

```bash
# Verify it's armed after any reboot:
iptables -L INPUT -n -v | grep "match-set blocklist"
# pkts column should be > 0 if any attack traffic has hit since boot
# If pkts = 0 after hours of uptime, the rule exists but ipset may be empty
```

**Fleet-tested failure mode (June 2026):** On 3 of 4 production servers, the `iptables` service was disabled. After reboots, fail2ban recreated its own jail rules but the blocklist DROP rule was never inserted. 20,000+ entry blocklists were running for weeks dropping zero packets. This service prevents that silently.

---

## AbuseIPDB fleet sync

**On the master server** — generates and publishes `blocklist.txt` daily at 02:00:
```bash
# /usr/local/bin/abuseipdb-blocklist.sh
# Pulls 10,000 IPs (90%+ confidence) from AbuseIPDB API
# Merges with local ipset (manual blocks + Firehol)
# Guard: only publishes if entry count > 1000 (prevents empty-file wipe on failed run)
# Publishes to /home/<user>/public_html/blocklist.txt
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

**Daily timing:** 02:00 master pulls → 02:30 slaves sync → 03:00 Firehol refreshes

---

## Azure blocking at scale

Instead of chasing individual /24s, block Azure's primary attack ranges as superblocks:

```bash
# Covers the bulk of Azure attack traffic in 6 rules
for net in 20.0.0.0/11 40.64.0.0/10 4.128.0.0/9 52.128.0.0/11 52.160.0.0/11 52.224.0.0/11; do
  ipset add blocklist $net 2>/dev/null
done
ipset save > /etc/sysconfig/ipset
```

For IPv6, a single rule covers the entire Azure IPv6 fleet:
```bash
ip6tables -I INPUT 1 -s 2602:fb54::/32 -j DROP
ip6tables-save > /etc/sysconfig/ip6tables
```

**Note:** If your server sits behind Cloudflare for some sites, Azure IPv6 may appear in Apache logs as `CF-Connecting-IP` forwarded headers — the actual connection comes from Cloudflare's IPv4. Server-level IPv6 blocking won't catch these; block at the Cloudflare edge instead.

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
| 1 | Install & configure ipset — create `blocklist` ipset, insert DROP as iptables **rule #1** |
| 2 | Install & configure Fail2ban |
| 3 | Write Fail2ban filter files (10 filters) |
| 4 | Write `jail.local` with all 10 jails using ipset-based actions |
| 5 | Install Firehol Level 1 blocklist + daily cron + systemd service |
| 5b | Deploy `ipset-restore-critical` service — enforces DROP rule + ipset on every reboot |
| 6 | Configure Apache URL blocking (webshell/scanner paths → 403) |
| 7 | WP-Cron hardening (`DISABLE_WP_CRON` across all WordPress installs) |
| 8 | Start Fail2ban + verify |
| 9 | Final verification |

---

## Verify everything is working

```bash
# All 10 jails active
fail2ban-client status | grep "Jail list"

# Blocklist DROP at position 1 with hit counter
iptables -L INPUT -n -v --line-numbers | grep "match-set blocklist"
# pkts > 0 = actively dropping attack traffic

# Ipset size
ipset list blocklist | grep "Number of entries"

# Restore service is armed
systemctl is-active ipset-restore-critical.service

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

**Blocklist DROP rule missing after reboot**
The `ipset-restore-critical` service handles this. If rules don't survive reboot: `systemctl status ipset-restore-critical` — check if it ran and whether the `iptables` service is enabled. The restore service is designed to work even when the iptables service is disabled.

**ipset has 20,000+ entries but blocklist drops zero packets**
Classic phantom protection. Run `iptables -L INPUT -n | grep "match-set blocklist"` — if empty, the DROP rule is missing. The restore service will fix it: `systemctl restart ipset-restore-critical`. This was the real-world failure mode that prompted the service design.

**Jail shows "Currently banned: N" but IPs still reach Apache**
Old configurations used `iptables-multiport` without ipset integration. This installer uses `iptables-ipset-proto6-allports` — each jail gets its own named ipset. Verify: `iptables -L | grep f2b`.

**AbuseIPDB blocklist publishes 0 entries**
The publish script has a 1000-entry guard — if ipset returns fewer entries than expected (e.g. right after a reboot before ipset is fully restored), it skips the publish to avoid wiping the file. Run manually after ipset is restored: `/usr/local/bin/abuseipdb-blocklist.sh`.

---

## File locations

| File | Purpose |
|---|---|
| `/etc/fail2ban/jail.local` | Main jail configuration |
| `/etc/fail2ban/filter.d/apache-*.conf` | Custom filter files (10 filters) |
| `/usr/local/bin/ipset-restore-critical.sh` | Boot restore script (ipset + DROP rule enforcement) |
| `/etc/systemd/system/ipset-restore-critical.service` | Systemd service for the above |
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

The server was never compromised. A fleet-wide audit in June 2026 discovered that 3 of 4 servers had been running with inert blocklists for weeks — the phantom-protection problem described above. This installer encodes that lesson permanently.

A criminal complaint was filed with ZAC Bayern (case `BY0257-500359-26/8`), 900+ IPs reported to AbuseIPDB, and ISP abuse notifications sent to Microsoft, Google Cloud, Hetzner, and others.

---

## License

MIT — Andrei Ghițan
