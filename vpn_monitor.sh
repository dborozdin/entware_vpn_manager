#!/bin/sh
# VPN Monitor - Health check daemon for xray VLESS proxy
# Checks claude.ai accessibility via SOCKS proxy, auto-switches on failure.
# Smart failover: if VPN server is up but target is blocked, restart HydraRoute first.

CONFIG_DIR="/opt/etc/vpnmanager"
CONFIG_FILE="$CONFIG_DIR/config.json"
STATUS_FILE="$CONFIG_DIR/monitor_status.json"
LOG_FILE="/opt/var/log/vpnmonitor.log"
LOCK_FILE="$CONFIG_DIR/.lock"
MANAGER_API="http://127.0.0.1:3000"

MAX_LOG_SIZE=1048576  # 1MB

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

# Read a value from config.json using python3
cfg_get() {
    python3 -c "import json; c=json.load(open('$CONFIG_FILE')); print($1)" 2>/dev/null
}

# Write monitor status
write_status() {
    # $1=last_result $2=fail_count $3=switch_reason (optional)
    python3 -c "
import json, os
from datetime import datetime
status = {}
try:
    status = json.load(open('$STATUS_FILE'))
except: pass
status['last_check'] = datetime.now().isoformat()
status['last_result'] = '$1'
status['consecutive_failures'] = $2
switch_reason = '$3'
if switch_reason:
    status['last_switch'] = datetime.now().isoformat()
    status['last_switch_reason'] = switch_reason
with open('${STATUS_FILE}.tmp', 'w') as f:
    json.dump(status, f, indent=2)
os.rename('${STATUS_FILE}.tmp', '$STATUS_FILE')
" 2>/dev/null
}

# Truncate log if too big
rotate_log() {
    if [ -f "$LOG_FILE" ]; then
        size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
            tail -c 512000 "$LOG_FILE" > "${LOG_FILE}.tmp"
            mv "${LOG_FILE}.tmp" "$LOG_FILE"
            log_msg "Log rotated"
        fi
    fi
}

# Check if target URL is accessible through SOCKS proxy
# Any HTTP response (even 403/503 from Cloudflare) means the proxy works.
# Only 000 (timeout/connection failure) means real failure.
check_proxy() {
    local socks_port="$1"
    local check_url="$2"
    local timeout="$3"

    HTTP_CODE=$(curl -s --max-time "$timeout" -o /dev/null -w "%{http_code}" \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        --socks5-hostname "127.0.0.1:$socks_port" "$check_url" 2>/dev/null)

    case "$HTTP_CODE" in
        000) return 1 ;;  # timeout or connection failure - proxy broken
        *)   return 0 ;;  # any HTTP response means proxy is working
    esac
}

# TCP ping: check if host:port is reachable (returns 0 if reachable)
tcp_check() {
    local host="$1"
    local port="$2"
    local timeout="${3:-5}"

    python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout($timeout)
    s.connect(('$host', $port))
    s.close()
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null
}

# Get current VPN server host and port from config
get_current_server() {
    python3 -c "
import json
c = json.load(open('$CONFIG_FILE'))
g = c['active_group']
i = c['active_server_index']
srv = c['subscription_groups'][g]['servers'][i]
print(srv['host'], srv['port'])
" 2>/dev/null
}

# Find best server by TCP ping (excluding current + excluded countries)
find_best_server() {
    python3 -c "
import json, socket, time, sys

config = json.load(open('$CONFIG_FILE'))
group_idx = config['active_group']
group = config['subscription_groups'][group_idx]
current_idx = config['active_server_index']
excludes = config.get('monitor', {}).get('exclude_countries', [])

best_idx = -1
best_ms = 99999

for i, srv in enumerate(group['servers']):
    if i == current_idx:
        continue
    # Check country exclusion
    name = srv.get('name', '')
    skip = False
    for ex in excludes:
        if ex.lower() in name.lower():
            skip = True
            break
    if skip:
        continue
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        t0 = time.monotonic()
        sock.connect((srv['host'], srv['port']))
        ms = (time.monotonic() - t0) * 1000
        sock.close()
        if ms < best_ms:
            best_ms = ms
            best_idx = i
    except:
        pass

print(best_idx)
" 2>/dev/null
}

# Switch server via the web API
switch_to_server() {
    local server_idx="$1"
    local group_idx
    group_idx=$(cfg_get "c['active_group']")

    result=$(curl -s --max-time 10 -X POST "$MANAGER_API/api/switch" \
        -H "Content-Type: application/json" \
        -d "{\"group\": $group_idx, \"server\": $server_idx}" 2>/dev/null)

    echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get('ok') else 1)" 2>/dev/null
    return $?
}

# Restart HydraRoute (read init script path from config)
restart_hydra() {
    HYDRA_SCRIPT=$(cfg_get "c.get('services',{}).get('hydra_init_script','')")
    if [ -z "$HYDRA_SCRIPT" ] || [ ! -x "$HYDRA_SCRIPT" ]; then
        log_msg "HydraRoute init script not configured or not found, skipping"
        return 1
    fi
    log_msg "Restarting HydraRoute ($HYDRA_SCRIPT)..."
    "$HYDRA_SCRIPT" restart >/dev/null 2>&1
    sleep 10
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

main() {
    log_msg "=== VPN Monitor starting ==="

    # Read initial settings
    CHECK_INTERVAL=$(cfg_get "c['monitor']['check_interval']")
    FAIL_THRESHOLD=$(cfg_get "c['monitor']['fail_threshold']")
    CHECK_URL=$(cfg_get "c['monitor']['check_url']")
    CHECK_TIMEOUT=$(cfg_get "c['monitor']['check_timeout']")
    SOCKS_PORT=$(cfg_get "c['monitor']['socks_port']")
    HYDRA_ATTEMPTS=$(cfg_get "c['monitor']['hydra_restart_attempts']")

    # Defaults
    CHECK_INTERVAL=${CHECK_INTERVAL:-60}
    FAIL_THRESHOLD=${FAIL_THRESHOLD:-3}
    CHECK_URL=${CHECK_URL:-"https://claude.ai"}
    CHECK_TIMEOUT=${CHECK_TIMEOUT:-10}
    SOCKS_PORT=${SOCKS_PORT:-10808}
    HYDRA_ATTEMPTS=${HYDRA_ATTEMPTS:-2}

    log_msg "Settings: interval=${CHECK_INTERVAL}s threshold=${FAIL_THRESHOLD} url=${CHECK_URL} socks=${SOCKS_PORT}"

    FAIL_COUNT=0

    while true; do
        # Check if monitoring is enabled
        ENABLED=$(cfg_get "c['monitor']['enabled']")
        if [ "$ENABLED" = "False" ] || [ "$ENABLED" = "false" ] || [ "$ENABLED" = "0" ]; then
            sleep "$CHECK_INTERVAL"
            continue
        fi

        # Reload settings periodically (they might be changed via UI)
        CHECK_INTERVAL=$(cfg_get "c['monitor']['check_interval']")
        FAIL_THRESHOLD=$(cfg_get "c['monitor']['fail_threshold']")
        CHECK_URL=$(cfg_get "c['monitor']['check_url']")
        SOCKS_PORT=$(cfg_get "c['monitor']['socks_port']")
        HYDRA_ATTEMPTS=$(cfg_get "c['monitor']['hydra_restart_attempts']")
        CHECK_INTERVAL=${CHECK_INTERVAL:-60}
        FAIL_THRESHOLD=${FAIL_THRESHOLD:-3}
        HYDRA_ATTEMPTS=${HYDRA_ATTEMPTS:-2}

        # Step 1: Check target through proxy
        if check_proxy "$SOCKS_PORT" "$CHECK_URL" "$CHECK_TIMEOUT"; then
            # All good
            if [ "$FAIL_COUNT" -gt 0 ]; then
                log_msg "Recovery: target accessible again (was $FAIL_COUNT failures)"
            fi
            FAIL_COUNT=0
            write_status "ok" 0
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            log_msg "FAIL ($FAIL_COUNT/$FAIL_THRESHOLD): $CHECK_URL unreachable through proxy"
            write_status "fail" "$FAIL_COUNT"

            if [ "$FAIL_COUNT" -ge "$FAIL_THRESHOLD" ]; then
                # Step 2: Check if VPN server itself is reachable
                CURRENT_SERVER=$(get_current_server)
                CURRENT_HOST=$(echo "$CURRENT_SERVER" | awk '{print $1}')
                CURRENT_PORT=$(echo "$CURRENT_SERVER" | awk '{print $2}')

                if tcp_check "$CURRENT_HOST" "$CURRENT_PORT" 5; then
                    # VPN server is up, but target is blocked
                    log_msg "VPN server $CURRENT_HOST:$CURRENT_PORT is REACHABLE."

                    # Try restarting HydraRoute if configured
                    HYDRA_SCRIPT=$(cfg_get "c.get('services',{}).get('hydra_init_script','')")
                    if [ -n "$HYDRA_SCRIPT" ] && [ "$HYDRA_ATTEMPTS" -gt 0 ]; then
                        log_msg "Trying HydraRoute restart..."
                        HYDRA_OK=0
                        ATTEMPT=0
                        while [ "$ATTEMPT" -lt "$HYDRA_ATTEMPTS" ]; do
                            ATTEMPT=$((ATTEMPT + 1))
                            log_msg "HydraRoute restart attempt $ATTEMPT/$HYDRA_ATTEMPTS"
                            restart_hydra

                            if check_proxy "$SOCKS_PORT" "$CHECK_URL" "$CHECK_TIMEOUT"; then
                                log_msg "HydraRoute restart fixed the issue!"
                                HYDRA_OK=1
                                FAIL_COUNT=0
                                write_status "ok" 0 "hydra-restart fixed issue"
                                break
                            fi
                        done

                        if [ "$HYDRA_OK" -eq 1 ]; then
                            sleep "$CHECK_INTERVAL"
                            continue
                        fi
                        log_msg "HydraRoute restart did not help. Switching VPN server..."
                    else
                        log_msg "HydraRoute not configured, switching VPN server..."
                    fi
                else
                    log_msg "VPN server $CURRENT_HOST:$CURRENT_PORT is UNREACHABLE"
                fi

                # Step 3: Find best server and switch
                log_msg "Finding best available server..."
                BEST_IDX=$(find_best_server)

                if [ -n "$BEST_IDX" ] && [ "$BEST_IDX" != "-1" ]; then
                    log_msg "Switching to server index $BEST_IDX"
                    if switch_to_server "$BEST_IDX"; then
                        FAIL_COUNT=0
                        write_status "switched" 0 "auto-failover"
                        log_msg "Switch successful. Waiting 15s for stabilization..."
                        sleep 15
                        continue
                    else
                        log_msg "ERROR: Switch via API failed"
                        write_status "switch_failed" "$FAIL_COUNT"
                    fi
                else
                    log_msg "ERROR: No reachable server found (all excluded or unreachable)"
                    write_status "no_server" "$FAIL_COUNT"
                fi
            fi
        fi

        rotate_log
        sleep "$CHECK_INTERVAL"
    done
}

main "$@"
