#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# CleanShift — Plesk Server Reconnaissance Script
# Target: server-06.example-hosting.com
# Purpose: Gather full server inventory before cleanup
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

echo "═══════════════════════════════════════════════════════════"
echo "  CleanShift Plesk Reconnaissance"
echo "  Server: $(hostname)"
echo "  Time:   $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "═══════════════════════════════════════════════════════════"

# ─── 1. SERVER INFO ─────────────────────────────────────────────
echo ""
echo "=== SERVER INFO ==="
hostname -f 2>/dev/null || hostname
cat /etc/*release 2>/dev/null | head -5
echo "IP: $(hostname -I 2>/dev/null | awk '{print $1}')"
uptime
echo "Kernel: $(uname -r)"
echo "CPU cores: $(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)"
free -h | head -3
df -h / | tail -1

# ─── 2. PLESK VERSION & STATUS ─────────────────────────────────
echo ""
echo "=== PLESK VERSION ==="
plesk version 2>/dev/null || echo "plesk version command not found"
plesk bin server_pref --show 2>/dev/null | head -10 || true

# ─── 3. WEB SERVER ─────────────────────────────────────────────
echo ""
echo "=== WEB SERVER ==="
if command -v nginx &>/dev/null; then
    echo "Nginx: $(nginx -v 2>&1)"
fi
if command -v httpd &>/dev/null; then
    echo "Apache: $(httpd -v 2>&1 | head -1)"
elif command -v apache2 &>/dev/null; then
    echo "Apache: $(apache2 -v 2>&1 | head -1)"
fi
# Check if Plesk is using nginx as proxy
plesk bin server_pref --show-web-server-type 2>/dev/null || true

# ─── 4. ALL DOMAINS / SUBSCRIPTIONS ────────────────────────────
echo ""
echo "=== SUBSCRIPTIONS ==="
plesk bin subscription --list 2>/dev/null || echo "subscription list not available"

echo ""
echo "=== DOMAINS ==="
plesk bin domain --list 2>/dev/null || echo "domain list not available"

echo ""
echo "=== SITE LIST ==="
plesk bin site --list 2>/dev/null || echo "site list not available"

# ─── 5. DOMAIN DETAILS (IP, status, hosting type) ──────────────
echo ""
echo "=== DOMAIN DETAILS ==="
for domain in $(plesk bin domain --list 2>/dev/null); do
    echo "---"
    echo "DOMAIN: $domain"
    plesk bin domain --info "$domain" 2>/dev/null | grep -E "Domain|Hosting|IP|Status|PHP|Document" || true
done

# ─── 6. WORDPRESS DISCOVERY ────────────────────────────────────
echo ""
echo "=== WORDPRESS SITES ==="
# Method 1: Plesk WordPress Toolkit
if plesk ext wp-toolkit --list 2>/dev/null; then
    echo "(via wp-toolkit)"
else
    echo "(wp-toolkit not available, scanning filesystem)"
fi

# Method 2: Filesystem scan (always run as fallback)
echo ""
echo "=== WORDPRESS FILESYSTEM SCAN ==="
find /var/www/vhosts/ -maxdepth 4 -name "wp-config.php" ! -name "wp-config-sample.php" 2>/dev/null | while read wpconfig; do
    dir=$(dirname "$wpconfig")
    user=$(stat -c '%U' "$wpconfig" 2>/dev/null || ls -la "$wpconfig" | awk '{print $3}')
    
    # Extract WP version
    wpver="unknown"
    version_file="$dir/wp-includes/version.php"
    if [ -f "$version_file" ]; then
        wpver=$(grep "^\$wp_version" "$version_file" 2>/dev/null | grep -oP "'[^']+'" | tr -d "'" || echo "unknown")
    fi
    
    # Extract DB prefix
    prefix=$(grep '^\$table_prefix' "$wpconfig" 2>/dev/null | grep -oP "'[^']+'" | tr -d "'" || echo "wp_")
    
    # Extract DB name
    dbname=$(grep "DB_NAME" "$wpconfig" 2>/dev/null | grep -oP "'[^']+'" | tail -1 | tr -d "'" || echo "unknown")
    
    echo "WP|$user|$dir|$wpver|$prefix|$dbname"
done

# ─── 7. OTHER CMS DETECTION ────────────────────────────────────
echo ""
echo "=== OTHER CMS DETECTION ==="
# Joomla
echo "-- Joomla --"
find /var/www/vhosts/ -maxdepth 4 -name "configuration.php" -path "*/libraries/*" 2>/dev/null | head -10 || true
find /var/www/vhosts/ -maxdepth 4 -name "joomla.xml" 2>/dev/null | while read f; do
    dir=$(dirname "$f")
    echo "JOOMLA|$dir"
done

# Drupal
echo "-- Drupal --"
find /var/www/vhosts/ -maxdepth 4 -name "core.services.yml" -path "*/core/*" 2>/dev/null | head -10 || true

# Custom / Static
echo "-- Static/Other --"
for vhost in /var/www/vhosts/*/httpdocs/; do
    if [ -d "$vhost" ] && [ ! -f "$vhost/wp-config.php" ] && [ ! -f "$vhost/configuration.php" ]; then
        if ls "$vhost"*.html "$vhost"*.php 2>/dev/null | head -1 > /dev/null; then
            echo "OTHER|$(stat -c '%U' "$vhost" 2>/dev/null)|$vhost"
        fi
    fi
done

# ─── 8. DISK USAGE BY DOMAIN ───────────────────────────────────
echo ""
echo "=== DISK USAGE ==="
du -sh /var/www/vhosts/*/httpdocs/ 2>/dev/null | sort -rh | head -30

echo ""
echo "=== TOTAL VHOSTS DISK ==="
du -sh /var/www/vhosts/ 2>/dev/null || true

# ─── 9. IOC SCAN (Quick pass) ──────────────────────────────────
echo ""
echo "=== IOC QUICK SCAN ==="

echo "-- Known backdoor files --"
find /var/www/vhosts/ -name "defaults.php" -path "*/wp-admin/*" 2>/dev/null
find /var/www/vhosts/ -name "wp-img.php" -path "*/wp-includes/*" 2>/dev/null
find /var/www/vhosts/ -name "shell.php" 2>/dev/null
find /var/www/vhosts/ -name "about.php" -maxdepth 4 ! -path "*/wp-admin/*" ! -path "*/wp-includes/*" 2>/dev/null

echo "-- PHP in uploads --"
find /var/www/vhosts/ -path "*/wp-content/uploads/*.php" ! -name "index.php" 2>/dev/null | head -30

echo "-- Large .ico files (possible webshells) --"
find /var/www/vhosts/ -name "*.ico" -size +50k 2>/dev/null

echo "-- Random-name PHP files in uploads --"
find /var/www/vhosts/ -path "*/wp-content/uploads/*" -name "*.php" -regex '.*/[a-z]\{8,12\}\.php' 2>/dev/null

echo "-- Hidden PHP in hidden dirs --"
find /var/www/vhosts/ -path "*/uploads/.*/*.php" 2>/dev/null

echo "-- 0-byte PHP files --"
find /var/www/vhosts/ -path "*/wp-content/uploads/*.php" -size 0 2>/dev/null

# ─── 10. DATABASE IOC CHECK ────────────────────────────────────
echo ""
echo "=== DATABASE IOC CHECK ==="
# Find all WP databases and check for hack_file markers
find /var/www/vhosts/ -maxdepth 4 -name "wp-config.php" ! -name "wp-config-sample.php" 2>/dev/null | while read wpconfig; do
    dir=$(dirname "$wpconfig")
    
    dbname=$(grep "DB_NAME" "$wpconfig" 2>/dev/null | grep -oP "'[^']+'" | tail -1 | tr -d "'")
    dbuser=$(grep "DB_USER" "$wpconfig" 2>/dev/null | grep -oP "'[^']+'" | tail -1 | tr -d "'")
    dbpass=$(grep "DB_PASSWORD" "$wpconfig" 2>/dev/null | grep -oP "'[^']+'" | tail -1 | tr -d "'")
    prefix=$(grep '^\$table_prefix' "$wpconfig" 2>/dev/null | grep -oP "'[^']+'" | tr -d "'" || echo "wp_")
    
    if [ -n "$dbname" ] && [ -n "$dbuser" ] && [ -n "$dbpass" ]; then
        # Check hack_file marker
        hackfile=$(mysql -u"$dbuser" -p"$dbpass" "$dbname" -N -e "SELECT option_value FROM ${prefix}options WHERE option_name='hack_file' LIMIT 1" 2>/dev/null || true)
        
        # Check script injections
        scripts=$(mysql -u"$dbuser" -p"$dbpass" "$dbname" -N -e "SELECT COUNT(*) FROM ${prefix}options WHERE option_value LIKE '%<script%src=%' AND option_name NOT IN ('blogdescription','blogname')" 2>/dev/null || true)
        
        # Check rogue admins
        rogues=$(mysql -u"$dbuser" -p"$dbpass" "$dbname" -N -e "SELECT COUNT(*) FROM ${prefix}users u JOIN ${prefix}usermeta m ON u.ID=m.user_id WHERE m.meta_key='${prefix}capabilities' AND m.meta_value LIKE '%administrator%' AND u.user_email LIKE '%@org.com'" 2>/dev/null || true)
        
        # Check litespeed artifacts
        lsc=$(mysql -u"$dbuser" -p"$dbpass" "$dbname" -N -e "SELECT COUNT(*) FROM ${prefix}options WHERE option_name LIKE 'litespeed%'" 2>/dev/null || true)
        
        # Check suspicious options
        suspicious=$(mysql -u"$dbuser" -p"$dbpass" "$dbname" -N -e "SELECT COUNT(*) FROM ${prefix}options WHERE option_value LIKE '%base64_decode%' OR option_value LIKE '%eval(%' OR option_value LIKE '%gzinflate%'" 2>/dev/null || true)
        
        echo "DB|$dir|$dbname|hack_file=$hackfile|scripts=$scripts|rogues=$rogues|litespeed=$lsc|suspicious=$suspicious"
    fi
done

# ─── 11. LITESPEED CACHE PLUGIN CHECK ──────────────────────────
echo ""
echo "=== LITESPEED CACHE PLUGIN CHECK ==="
find /var/www/vhosts/ -path "*/wp-content/plugins/litespeed-cache" -maxdepth 5 -type d 2>/dev/null | while read lsc_dir; do
    version="unknown"
    readme="$lsc_dir/readme.txt"
    if [ -f "$readme" ]; then
        version=$(grep -i "Stable tag:" "$readme" 2>/dev/null | awk '{print $NF}' || echo "unknown")
    fi
    echo "LSC|$lsc_dir|version=$version"
done

# ─── 12. WP VERSION AUDIT ──────────────────────────────────────
echo ""
echo "=== WP VERSION AUDIT ==="
find /var/www/vhosts/ -maxdepth 4 -path "*/wp-includes/version.php" 2>/dev/null | while read vf; do
    dir=$(dirname "$(dirname "$vf")")
    ver=$(grep "^\$wp_version" "$vf" 2>/dev/null | grep -oP "'[^']+'" | tr -d "'" || echo "unknown")
    echo "WPVER|$dir|$ver"
done

# ─── 13. SECURITY SERVICES CHECK ───────────────────────────────
echo ""
echo "=== SECURITY SERVICES ==="
# Check for Imunify360
if command -v imunify360-agent &>/dev/null; then
    echo "Imunify360: installed"
    imunify360-agent version 2>/dev/null || true
else
    echo "Imunify360: not installed"
fi

# Check for ModSecurity
if plesk bin server_pref --show 2>/dev/null | grep -i modsecurity; then
    echo "ModSecurity: configured via Plesk"
fi

# Check for fail2ban
if systemctl is-active fail2ban &>/dev/null; then
    echo "fail2ban: active"
else
    echo "fail2ban: not active"
fi

# ─── 14. RECENT SUSPICIOUS ACTIVITY ────────────────────────────
echo ""
echo "=== RECENT LOGINS ==="
last -n 20 2>/dev/null | head -20

echo ""
echo "=== CRON JOBS (system + user) ==="
for u in $(plesk bin subscription --list 2>/dev/null | head -20); do
    sysuser=$(plesk bin subscription --info "$u" 2>/dev/null | grep "System user" | awk '{print $NF}')
    if [ -n "$sysuser" ]; then
        crontab -l -u "$sysuser" 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "(user: $sysuser)" || true
    fi
done
# Root crontab
echo "-- Root crontab --"
crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "(empty)"

# ─── 15. MAIL QUEUE (spam indicator) ───────────────────────────
echo ""
echo "=== MAIL QUEUE ==="
if command -v postqueue &>/dev/null; then
    echo "Postfix queue count: $(postqueue -p 2>/dev/null | tail -1)"
elif command -v exim &>/dev/null; then
    echo "Exim queue count: $(exim -bpc 2>/dev/null)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  RECONNAISSANCE COMPLETE"
echo "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "═══════════════════════════════════════════════════════════"
