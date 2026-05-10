# fail2ban-cpanel-installer

Production-hardened Fail2ban configuration for cPanel servers (AlmaLinux / CentOS 8+).
Built and battle-tested during a sustained multi-wave cyberattack campaign (April–May 2026)
against a 35-site cPanel/Apache server running 750,000+ malicious requests from 30+ threat actors.

---

## Jails

| Jail | Filter | maxretry | findtime | bantime | Watches |
|------|--------|----------|----------|---------|---------|
| `apache-webshell` | PHP webshell names | 2 | 60s | 24h | domlogs |
| `apache-php-scanner` | PHP scanner patterns | 2 | 60s | 24h | access_log |
| `apache-credentials` | .env / AWS / wp-config harvesting | 2 | 60s | 24h | domlogs |
| `apache-enum` | CMS path enumeration | 2 | 60s | 24h | domlogs |
| `apache-config-scan` | JSON config file harvesting | 2 | 60s | 24h | domlogs |
| `apache-wplogin` | WordPress wp-login.php brute force | 3 | 60s | 24h | domlogs |
| `apache-wpcron-abuse` | WordPress wp-cron.php flood | 20 | 60s | 7 days | domlogs |
| `sshd` | SSH brute force | 2 | 60s | 7 days | /var/log/secure |

---

## Filters

### apache-webshell
Catches requests for known PHP webshell filenames:
`alfa, c99, r57, wso, webshell, wp_filemanager, classwithtostring, adminfuns` and many others.

### apache-php-scanner
Catches automated PHP scanner tools probing for vulnerable PHP files across multiple paths.

### apache-credentials
Catches credential harvesting sweeps targeting:
- `.env` variants (`.env.local`, `.env.production`, `.env.docker`, etc.)
- `aws/credentials`, `wp-config.php.bak`, `s3_config.json`
- `application.yml`, `settings.yml`, `appsettings.json`

### apache-enum
Catches CMS path enumeration targeting:
- `/ALFA_DATA/`, `/admin/fckeditor/`, `/vendor/phpunit/`
- `/sites/default/files/`, `/images/stories/`

### apache-config-scan
Catches JSON config file harvesting:
- `/.dbeaver/credentials-config.json`
- `/aws/config.json`, `/mysql/credentials`
- `/config.prod.json`, `/assets/config.production.json`

Ignores: `/wp-json/`, `/wp-content/`, `/wp-admin/` (legitimate WP traffic).

### apache-wplogin
Catches brute force attacks on `/wp-login.php` via POST requests.

### apache-wpcron-abuse
Catches automated flooding of `/wp-cron.php`. Legitimate cron hits come from the server
itself (already whitelisted via `ignoreip`). External IPs hitting wp-cron repeatedly
are bots or compromised servers — banned for 7 days on the 20th hit within 60 seconds.

Real-world catch: `167.86.93.191` sent **61,992 wp-cron requests** from a Contabo server
before this jail was deployed.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/dffkt432hz/fail2ban-cpanel-installer.git
cd fail2ban-cpanel-installer

# Copy filter files
cp filter.d/*.conf /etc/fail2ban/filter.d/

# Append jail config (review first)
cat jail.local >> /etc/fail2ban/jail.local

# Reload Fail2ban
fail2ban-client reload

# Verify all jails are active
fail2ban-client status
```

---

## Important: ignoreip

Always add your server's own IP to `ignoreip` in `[DEFAULT]`:

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 YOUR.HOME.IP.HERE YOUR.SERVER.IP.HERE
```

This prevents your server from banning itself when running staggered wp-cron jobs
or any other internal HTTP requests. Failure to do this caused real issues during
wp-cron storm containment.

---

## Recommended complementary setup

These jails work best alongside:

1. **ipset + Firehol Level 1 blocklist** — drops known bad IPs at kernel level before
   Apache even sees the request. Firehol runs daily at 03:00 via cron.

2. **block_azure.py** — blocks all 41,747+ Azure IPv4 prefixes via ipset. Useful if
   your server is not a Microsoft customer and you want to drop Azure scanning entirely.
   Includes dynamic Exchange Online exclusion so outbound mail still works.

3. **ModSecurity OWASP CRS** — application-layer WAF running in front of Fail2ban.
   Catches and 403s attacks before they hit PHP. Note: ModSecurity blocks to
   `error_log`, not `access_log` — Fail2ban won't see these unless you add a
   dedicated error_log jail (TODO item).

4. **Apache rate limiting for high-value targets** — if a specific site is repeatedly
   targeted (e.g. andradadesign.ro), add per-vhost config:

```apache
<IfModule mod_limitipconn.c>
    MaxConnPerIP 10
</IfModule>
<Location /wp-login.php>
    <IfModule mod_ratelimit.c>
        SetOutputFilter RATE_LIMIT
        SetEnv rate-limit 400
    </IfModule>
</Location>
<Location /xmlrpc.php>
    Require all denied
</Location>
```

---

## Tested on

- AlmaLinux 8.10
- cPanel 11.134
- Apache 2.4.67 (EasyApache4)
- Fail2ban 1.0.2
- ModSecurity 2.9.12 with OWASP CRS 3.3.9

---

## License

MIT
