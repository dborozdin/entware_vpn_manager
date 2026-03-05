#!/opt/bin/python3
"""VPN Manager - Web UI and API for managing Xray VLESS proxy on Keenetic router."""

import json
import os
import sys
import time
import socket
import base64
import fcntl
import subprocess
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

CONFIG_DIR = "/opt/etc/vpnmanager"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
STATUS_FILE = os.path.join(CONFIG_DIR, "monitor_status.json")
LOCK_FILE = os.path.join(CONFIG_DIR, ".lock")
XRAY_CONFIG = "/opt/etc/xray/config.json"
XRAY_INIT = "/opt/etc/init.d/S24xray"
LOG_FILE = "/opt/var/log/vpnmanager.log"

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3000

config_lock = threading.Lock()

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("vpnmanager")


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default_config()


def save_config(cfg):
    with config_lock:
        fd = os.open(LOCK_FILE, os.O_WRONLY | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            tmp = CONFIG_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            os.rename(tmp, CONFIG_FILE)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def default_config():
    return {
        "subscription_groups": [],
        "active_group": 0,
        "active_server_index": 0,
        "monitor": {
            "enabled": True,
            "check_interval": 60,
            "fail_threshold": 3,
            "hydra_restart_attempts": 2,
            "check_url": "https://claude.ai",
            "check_timeout": 10,
            "socks_port": 10808,
            "exclude_countries": ["\u0420\u043e\u0441\u0441\u0438\u044f", "\u0423\u043a\u0440\u0430\u0438\u043d\u0430"],
        },
        "services": {
            "xray_config_path": XRAY_CONFIG,
            "xray_init_script": XRAY_INIT,
            "xray_proxy_port": 12345,
            "socks_port": 10808,
            "hydra_init_script": "/opt/etc/init.d/S99hrneo",
        },
        "xray_config_path": XRAY_CONFIG,
        "xray_init_script": XRAY_INIT,
        "xray_proxy_port": 12345,
    }


def load_monitor_status():
    try:
        with open(STATUS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# VLESS subscription parsing (ported from fetch_subscription.py)
# ---------------------------------------------------------------------------

def parse_vless_link(link):
    link = link.strip()
    if not link.startswith("vless://"):
        return None
    rest = link[len("vless://"):]
    if "#" in rest:
        rest, fragment = rest.rsplit("#", 1)
        name = unquote(fragment)
    else:
        name = ""
    if "?" in rest:
        rest, query_str = rest.split("?", 1)
        params = parse_qs(query_str)
        params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    else:
        params = {}
    uuid, hostport = rest.split("@", 1)
    if ":" in hostport:
        host, port = hostport.rsplit(":", 1)
    else:
        host = hostport
        port = "443"
    return {
        "name": name,
        "uuid": uuid,
        "host": host,
        "port": int(port),
        "params": params,
    }


def fetch_subscription(url):
    """Fetch and parse a VLESS subscription URL. Returns list of server dicts."""
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": "v2rayN/7.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        decoded = raw.decode("utf-8", errors="replace")
    servers = []
    for line in decoded.strip().split("\n"):
        line = line.strip()
        if line.startswith("vless://"):
            parsed = parse_vless_link(line)
            if parsed:
                servers.append(parsed)
    return servers


# ---------------------------------------------------------------------------
# Xray config building
# ---------------------------------------------------------------------------

def build_xray_outbound(server):
    """Build xray proxy outbound for a VLESS server (TLS or Reality)."""
    security = server["params"].get("security", "tls")
    user = {"id": server["uuid"], "encryption": "none"}
    if security == "reality":
        user["flow"] = server["params"].get("flow", "xtls-rprx-vision")

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server["host"],
                    "port": server["port"],
                    "users": [user],
                }
            ]
        },
        "streamSettings": {
            "network": server["params"].get("type", "tcp"),
            "security": security,
            "sockopt": {"mark": 255},
        },
    }

    if security == "tls":
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": server["host"],
            "alpn": [server["params"].get("alpn", "h2")],
            "allowInsecure": False,
        }
    elif security == "reality":
        outbound["streamSettings"]["realitySettings"] = {
            "serverName": server["params"].get("sni", ""),
            "publicKey": server["params"].get("pbk", ""),
            "shortId": server["params"].get("sid", ""),
            "fingerprint": server["params"].get("fp", "chrome"),
        }

    return outbound


def _get_service_paths(cfg):
    """Get service paths from config, with fallback to legacy top-level keys."""
    svc = cfg.get("services", {})
    return {
        "xray_config_path": svc.get("xray_config_path", cfg.get("xray_config_path", XRAY_CONFIG)),
        "xray_init_script": svc.get("xray_init_script", cfg.get("xray_init_script", XRAY_INIT)),
        "xray_proxy_port": svc.get("xray_proxy_port", cfg.get("xray_proxy_port", 12345)),
        "socks_port": svc.get("socks_port", cfg.get("monitor", {}).get("socks_port", 10808)),
        "hydra_init_script": svc.get("hydra_init_script", ""),
    }


def switch_server(group_idx, server_idx):
    """Switch xray to a different VLESS server. Returns (ok, message)."""
    cfg = load_config()
    svc = _get_service_paths(cfg)
    xray_config = svc["xray_config_path"]
    xray_init = svc["xray_init_script"]

    groups = cfg.get("subscription_groups", [])
    if group_idx < 0 or group_idx >= len(groups):
        return False, "Invalid group index"
    servers = groups[group_idx].get("servers", [])
    if server_idx < 0 or server_idx >= len(servers):
        return False, "Invalid server index"

    server = servers[server_idx]
    new_outbound = build_xray_outbound(server)

    # Load current xray config
    try:
        with open(xray_config, "r") as f:
            xray_cfg = json.load(f)
    except Exception as e:
        return False, f"Cannot read xray config: {e}"

    # Replace proxy outbound (first outbound with tag "proxy", or index 0)
    replaced = False
    for i, ob in enumerate(xray_cfg.get("outbounds", [])):
        if ob.get("tag") == "proxy":
            xray_cfg["outbounds"][i] = new_outbound
            replaced = True
            break
    if not replaced:
        if xray_cfg.get("outbounds"):
            xray_cfg["outbounds"][0] = new_outbound
        else:
            return False, "No outbounds in xray config"

    # Write xray config atomically (must keep .json extension for xray -test)
    tmp = xray_config.replace(".json", ".new.json")
    try:
        with open(tmp, "w") as f:
            json.dump(xray_cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        return False, f"Cannot write xray config: {e}"

    # Validate (use full path since daemon may not have /opt/bin in PATH)
    xray_bin = "/opt/bin/xray"
    if not os.path.exists(xray_bin):
        xray_bin = "xray"
    result = subprocess.run(
        [xray_bin, "run", "-test", "-config", tmp],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        err_msg = (result.stderr or result.stdout or "unknown error").strip()
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False, f"Xray config validation failed: {err_msg}"

    os.rename(tmp, xray_config)

    # Restart xray
    result = subprocess.run(
        [xray_init, "restart"], capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        log.warning("Xray restart returned non-zero: %s", result.stderr)

    # Update vpnmanager config
    cfg["active_group"] = group_idx
    cfg["active_server_index"] = server_idx
    save_config(cfg)

    # Invalidate IP cache
    VPNManagerHandler._ip_cache = {"ip": "", "ts": 0}

    log.info("Switched to server: %s (%s)", server["name"], server["host"])
    return True, f"Switched to {server['name']} ({server['host']})"


# ---------------------------------------------------------------------------
# TCP ping
# ---------------------------------------------------------------------------

def tcp_ping(host, port, timeout=5):
    """Measure TCP connect time in ms. Returns -1 if unreachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.monotonic()
        sock.connect((host, port))
        elapsed = (time.monotonic() - start) * 1000
        sock.close()
        return round(elapsed)
    except Exception:
        return -1


def ping_servers(servers, max_workers=10):
    """Ping all servers in parallel. Returns list of ms values."""
    results = [-1] * len(servers)

    def _ping(idx):
        ms = tcp_ping(servers[idx]["host"], servers[idx]["port"])
        results[idx] = ms

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for i in range(len(servers)):
            pool.submit(_ping, i)
    return results


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class VPNManagerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default stderr logging

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        qs = parse_qs(urlparse(self.path).query)

        if path == "/":
            self._send_html(HTML_PAGE)
        elif path == "/api/status":
            self._handle_status()
        elif path == "/api/servers":
            group = int(qs.get("group", ["-1"])[0])
            self._handle_servers(group)
        elif path == "/api/groups":
            self._handle_groups()
        elif path == "/api/myip":
            self._handle_myip()
        else:
            self.send_error(404)

    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            body = self._read_body()
        except Exception:
            body = {}

        if path == "/api/switch":
            self._handle_switch(body)
        elif path == "/api/group/add":
            self._handle_group_add(body)
        elif path == "/api/group/fetch":
            self._handle_group_fetch(body)
        elif path == "/api/group/edit":
            self._handle_group_edit(body)
        elif path == "/api/group/delete":
            self._handle_group_delete(body)
        elif path == "/api/ping":
            self._handle_ping(body)
        elif path == "/api/settings":
            self._handle_save_settings(body)
        elif path == "/api/check":
            self._handle_check(body)
        else:
            self.send_error(404)

    # --- API handlers ---

    def _handle_status(self):
        cfg = load_config()
        mon = load_monitor_status()
        groups = cfg.get("subscription_groups", [])
        ag = cfg.get("active_group", 0)
        ai = cfg.get("active_server_index", 0)
        current_server = None
        if 0 <= ag < len(groups):
            servers = groups[ag].get("servers", [])
            if 0 <= ai < len(servers):
                current_server = servers[ai]
        self._send_json({
            "active_group": ag,
            "active_group_name": groups[ag]["name"] if 0 <= ag < len(groups) else "",
            "active_server_index": ai,
            "current_server": current_server,
            "monitor": mon,
            "monitor_settings": cfg.get("monitor", {}),
            "services": _get_service_paths(cfg),
        })

    def _handle_servers(self, group_idx):
        cfg = load_config()
        groups = cfg.get("subscription_groups", [])
        if group_idx < 0:
            group_idx = cfg.get("active_group", 0)
        if group_idx < 0 or group_idx >= len(groups):
            self._send_json({"servers": [], "active_index": -1, "group": group_idx})
            return
        servers = groups[group_idx].get("servers", [])
        active_idx = cfg.get("active_server_index", -1) if group_idx == cfg.get("active_group", -1) else -1
        self._send_json({
            "servers": servers,
            "active_index": active_idx,
            "group": group_idx,
        })

    def _handle_groups(self):
        cfg = load_config()
        groups = cfg.get("subscription_groups", [])
        result = []
        for i, g in enumerate(groups):
            result.append({
                "index": i,
                "name": g["name"],
                "url": g.get("url", ""),
                "server_count": len(g.get("servers", [])),
                "last_fetched": g.get("last_fetched", ""),
                "active": i == cfg.get("active_group", -1),
            })
        self._send_json({"groups": result, "active_group": cfg.get("active_group", 0)})

    def _handle_switch(self, body):
        group = body.get("group", -1)
        server = body.get("server", -1)
        ok, msg = switch_server(group, server)
        self._send_json({"ok": ok, "message": msg}, 200 if ok else 500)

    def _handle_group_add(self, body):
        name = body.get("name", "").strip()
        url = body.get("url", "").strip()
        if not name:
            self._send_json({"ok": False, "message": "Name required"}, 400)
            return
        cfg = load_config()
        cfg["subscription_groups"].append({
            "name": name,
            "url": url,
            "servers": [],
            "last_fetched": "",
        })
        save_config(cfg)
        self._send_json({"ok": True, "message": f"Group '{name}' added"})

    def _handle_group_edit(self, body):
        group_idx = body.get("group", -1)
        cfg = load_config()
        groups = cfg.get("subscription_groups", [])
        if group_idx < 0 or group_idx >= len(groups):
            self._send_json({"ok": False, "message": "Invalid group"}, 400)
            return
        name = body.get("name", "").strip()
        url = body.get("url", "").strip()
        if not name:
            self._send_json({"ok": False, "message": "Name required"}, 400)
            return
        groups[group_idx]["name"] = name
        if url != groups[group_idx].get("url", ""):
            groups[group_idx]["url"] = url
            groups[group_idx]["servers"] = []
            groups[group_idx]["last_fetched"] = ""
        save_config(cfg)
        self._send_json({"ok": True, "message": f"Group '{name}' updated"})

    def _handle_group_fetch(self, body):
        group_idx = body.get("group", -1)
        cfg = load_config()
        groups = cfg.get("subscription_groups", [])
        if group_idx < 0 or group_idx >= len(groups):
            self._send_json({"ok": False, "message": "Invalid group"}, 400)
            return
        url = groups[group_idx].get("url", "")
        if not url:
            self._send_json({"ok": False, "message": "No subscription URL"}, 400)
            return
        try:
            servers = fetch_subscription(url)
        except Exception as e:
            self._send_json({"ok": False, "message": f"Fetch failed: {e}"}, 502)
            return
        groups[group_idx]["servers"] = servers
        groups[group_idx]["last_fetched"] = datetime.now().isoformat()
        save_config(cfg)
        self._send_json({"ok": True, "message": f"Fetched {len(servers)} servers"})

    def _handle_group_delete(self, body):
        group_idx = body.get("group", -1)
        cfg = load_config()
        groups = cfg.get("subscription_groups", [])
        if group_idx < 0 or group_idx >= len(groups):
            self._send_json({"ok": False, "message": "Invalid group"}, 400)
            return
        name = groups[group_idx]["name"]
        groups.pop(group_idx)
        # Adjust active_group if needed
        if cfg["active_group"] >= len(groups):
            cfg["active_group"] = max(0, len(groups) - 1)
        if cfg["active_group"] == group_idx:
            cfg["active_server_index"] = 0
        save_config(cfg)
        self._send_json({"ok": True, "message": f"Deleted group '{name}'"})

    _ip_cache = {"ip": "", "ts": 0}

    def _handle_myip(self):
        now = time.time()
        cache = VPNManagerHandler._ip_cache
        if now - cache["ts"] < 30 and cache["ip"]:
            self._send_json({"ip": cache["ip"]})
            return
        try:
            cfg = load_config()
            svc = _get_service_paths(cfg)
            socks_port = svc["socks_port"]
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", "--socks5-hostname",
                 f"127.0.0.1:{socks_port}", "https://api.ipify.org"],
                capture_output=True, text=True, timeout=8,
            )
            ip = result.stdout.strip()
            if ip:
                cache["ip"] = ip
                cache["ts"] = now
            self._send_json({"ip": ip})
        except Exception:
            self._send_json({"ip": ""})

    def _handle_ping(self, body):
        group_idx = body.get("group", -1)
        cfg = load_config()
        groups = cfg.get("subscription_groups", [])
        if group_idx < 0 or group_idx >= len(groups):
            self._send_json({"ok": False, "message": "Invalid group"}, 400)
            return
        servers = groups[group_idx].get("servers", [])
        pings = ping_servers(servers)
        result = [{"index": i, "ms": pings[i]} for i in range(len(servers))]
        self._send_json({"ok": True, "pings": result})

    def _handle_save_settings(self, body):
        cfg = load_config()
        mon = cfg.get("monitor", {})
        # Update monitor fields
        for key in ("check_url", "check_timeout", "check_interval",
                     "fail_threshold", "hydra_restart_attempts", "exclude_countries",
                     "enabled"):
            if key in body:
                mon[key] = body[key]
        cfg["monitor"] = mon
        # Update service fields
        if "services" in body:
            svc = cfg.get("services", {})
            for key in ("xray_config_path", "xray_init_script", "xray_proxy_port",
                         "socks_port", "hydra_init_script"):
                if key in body["services"]:
                    svc[key] = body["services"][key]
            cfg["services"] = svc
            # Keep monitor.socks_port in sync
            if "socks_port" in body["services"]:
                mon["socks_port"] = body["services"]["socks_port"]
        save_config(cfg)
        log.info("Settings updated")
        self._send_json({"ok": True, "message": "Settings saved"})

    def _handle_check(self, body):
        """Manual health check: curl check_url through SOCKS proxy."""
        cfg = load_config()
        mon = cfg.get("monitor", {})
        svc = _get_service_paths(cfg)
        check_url = body.get("url", mon.get("check_url", "https://claude.ai"))
        socks_port = svc["socks_port"]
        timeout = mon.get("check_timeout", 10)
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", str(timeout), "-o", "/dev/null",
                 "-w", "%{http_code}", "-A",
                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                 "--socks5-hostname", f"127.0.0.1:{socks_port}", check_url],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            http_code = result.stdout.strip()
            ok = http_code != "000" and http_code != ""
            self._send_json({
                "ok": ok,
                "http_code": http_code,
                "url": check_url,
                "message": f"HTTP {http_code}" if ok else "Connection failed (timeout/unreachable)",
            })
        except Exception as e:
            self._send_json({"ok": False, "http_code": "000", "url": check_url,
                             "message": f"Error: {e}"})


# ---------------------------------------------------------------------------
# HTML Page (embedded SPA)
# ---------------------------------------------------------------------------

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Manager</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: #1a1a2e;
  color: #e0e0e0;
  min-height: 100vh;
}
.header {
  background: #0f1a2e;
  padding: 12px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #2a2a4a;
}
.header h1 { font-size: 18px; color: #4a9eff; }
.header-actions { display: flex; gap: 8px; }

/* --- Status Card (top) --- */
.status-card {
  background: #12203a;
  padding: 16px 20px;
  border-bottom: 2px solid #2a2a4a;
}
.status-main {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 8px;
}
.status-flag { font-size: 36px; line-height: 1; }
.status-info { flex: 1; }
.status-server-name {
  font-size: 18px;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 2px;
}
.status-server-host {
  font-size: 14px;
  color: #a0b4d0;
  font-family: monospace;
}
.status-ip {
  font-size: 15px;
  font-weight: 600;
  color: #4ade80;
  text-align: right;
}
.status-ip .ip-label { font-size: 11px; color: #6b8ab0; font-weight: 400; display: block; }
.status-details {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  font-size: 13px;
  color: #8899b0;
  padding-top: 8px;
  border-top: 1px solid #1e2e4a;
}
.status-details span { display: inline-flex; align-items: center; gap: 4px; }
.health-dot {
  display: inline-block;
  width: 10px; height: 10px;
  border-radius: 50%;
}
.health-ok { background: #4ade80; box-shadow: 0 0 6px #4ade80; }
.health-fail { background: #ff4a4a; box-shadow: 0 0 6px #ff4a4a; }
.health-warn { background: #fbbf24; box-shadow: 0 0 6px #fbbf24; }
.health-text { font-weight: 600; }
.health-text-ok { color: #4ade80; }
.health-text-fail { color: #ff4a4a; }
.health-text-warn { color: #fbbf24; }

/* --- Tabs --- */
.tabs {
  display: flex;
  gap: 4px;
  padding: 10px 20px 0;
  background: #16213e;
  flex-wrap: wrap;
  align-items: center;
}
.tab {
  padding: 8px 16px;
  border-radius: 6px 6px 0 0;
  cursor: pointer;
  background: #1a1a2e;
  color: #888;
  border: 1px solid #2a2a4a;
  border-bottom: none;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
  transition: all 0.15s;
}
.tab:hover { color: #bbb; }
.tab.active { background: #1a1a2e; color: #4a9eff; border-color: #4a9eff; font-weight: 600; }
.tab .count {
  font-size: 11px; background: #2a2a4a; padding: 1px 6px;
  border-radius: 8px; font-weight: 400;
}
.tab .del-btn { font-size: 14px; color: #555; cursor: pointer; margin-left: 2px; }
.tab .del-btn:hover { color: #ff4a4a; }
.tab-add {
  padding: 8px 12px; cursor: pointer; color: #4a9eff; background: none;
  border: 1px dashed #4a9eff; border-radius: 6px 6px 0 0; font-size: 14px;
  border-bottom: none;
}
.tab-add:hover { background: #16213e; }

/* --- Toolbar --- */
.toolbar {
  display: flex; gap: 8px; padding: 10px 20px;
  background: #1a1a2e; border-bottom: 1px solid #2a2a4a;
  align-items: center;
}
.btn {
  padding: 6px 14px; border-radius: 4px; border: none;
  cursor: pointer; font-size: 13px; color: #fff;
}
.btn-primary { background: #4a9eff; }
.btn-primary:hover { background: #3a8eef; }
.btn-secondary { background: #2a2a4a; color: #ccc; }
.btn-secondary:hover { background: #3a3a5a; }
.btn-danger { background: #ff4a4a; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-sm { padding: 5px 12px; font-size: 12px; }

/* --- Table --- */
.table-wrap { padding: 0 20px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; margin-top: 4px; }
th {
  text-align: left; padding: 8px 12px; background: #16213e;
  color: #6b8ab0; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.5px;
  border-bottom: 1px solid #2a2a4a;
  position: sticky; top: 0; z-index: 2;
}
td {
  padding: 7px 12px; border-bottom: 1px solid #1e1e3e;
  font-size: 13px; white-space: nowrap;
}
tr { transition: background 0.15s; }
tr:hover { background: #1e2640; }
tr.active-row { background: #162a50; }
tr.active-row td:first-child { border-left: 3px solid #4a9eff; padding-left: 9px; }
.server-flag { font-size: 18px; margin-right: 6px; vertical-align: middle; }
.server-name { color: #d0d8e8; }

.ping-val { font-family: monospace; font-size: 12px; font-weight: 600; }
.ping-good { color: #4ade80; }
.ping-medium { color: #fbbf24; }
.ping-bad { color: #ff4a4a; }
.ping-unknown { color: #555; }
.ping-loading { color: #4a9eff; font-style: italic; font-weight: 400; }

/* --- Modal --- */
.modal-overlay {
  display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.6); z-index: 100;
  justify-content: center; align-items: center;
}
.modal-overlay.show { display: flex; }
.modal {
  background: #1e1e3e; border-radius: 8px; padding: 24px;
  min-width: 420px; border: 1px solid #2a2a4a;
}
.modal h3 { margin-bottom: 16px; color: #4a9eff; font-size: 16px; }
.modal input {
  width: 100%; padding: 10px 12px; margin-bottom: 12px;
  background: #16213e; border: 1px solid #2a2a4a; border-radius: 4px;
  color: #e0e0e0; font-size: 14px;
}
.modal input:focus { outline: none; border-color: #4a9eff; }
.modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px; }

.empty-state { text-align: center; padding: 60px 20px; color: #555; }
.empty-state p { margin-bottom: 16px; }
.loading { opacity: 0.5; pointer-events: none; }
.toolbar-info { color: #556; font-size: 12px; margin-left: 8px; }

/* --- Settings panel --- */
.settings-panel {
  display: none; background: #12203a; padding: 16px 20px;
  border-bottom: 1px solid #2a2a4a;
}
.settings-panel.show { display: block; }
.settings-panel h3 { color: #4a9eff; font-size: 15px; margin-bottom: 12px; }
.settings-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 10px 20px;
}
.settings-grid label {
  font-size: 12px; color: #8899b0; display: block; margin-bottom: 3px;
}
.settings-grid input, .settings-grid select {
  width: 100%; padding: 7px 10px; background: #16213e;
  border: 1px solid #2a2a4a; border-radius: 4px;
  color: #e0e0e0; font-size: 13px;
}
.settings-grid input:focus { outline: none; border-color: #4a9eff; }
.settings-grid .full-width { grid-column: 1 / -1; }
.settings-actions {
  display: flex; gap: 8px; margin-top: 12px; align-items: center;
}
.check-result {
  font-size: 13px; margin-left: 12px; font-family: monospace;
}
.check-ok { color: #4ade80; }
.check-fail { color: #ff4a4a; }
</style>
</head>
<body>

<div class="header">
  <h1>VPN Manager</h1>
  <div class="header-actions">
    <button class="btn btn-secondary btn-sm" onclick="toggleSettings()">Settings</button>
    <button class="btn btn-secondary btn-sm" onclick="refreshAll()">Refresh</button>
  </div>
</div>

<!-- Status Card -->
<div class="status-card" id="statusCard">
  <div class="status-main">
    <div class="status-flag" id="statusFlag">--</div>
    <div class="status-info">
      <div class="status-server-name" id="statusName">Loading...</div>
      <div class="status-server-host" id="statusHost">--</div>
    </div>
    <div class="status-ip" id="statusIP">
      <span class="ip-label">External IP</span>
      <span id="statusIPValue">...</span>
    </div>
  </div>
  <div class="status-details" id="statusDetails">
    <span>Health: <span class="health-dot health-ok"></span> <span class="health-text health-text-ok">--</span></span>
    <span>Failures: <b>0</b></span>
    <span>Last check: --</span>
    <span>Last switch: --</span>
  </div>
</div>

<!-- Settings Panel -->
<div class="settings-panel" id="settingsPanel">
  <h3>Monitor Settings</h3>
  <div class="settings-grid">
    <div class="full-width">
      <label>Check URL (site to verify VPN is working)</label>
      <input type="text" id="setCheckUrl" placeholder="https://claude.ai">
    </div>
    <div>
      <label>Check interval (seconds)</label>
      <input type="number" id="setCheckInterval" min="10" max="600">
    </div>
    <div>
      <label>Check timeout (seconds)</label>
      <input type="number" id="setCheckTimeout" min="3" max="60">
    </div>
    <div>
      <label>Fail threshold (failures before action)</label>
      <input type="number" id="setFailThreshold" min="1" max="20">
    </div>
    <div>
      <label>HydraRoute restart attempts (0 = disabled)</label>
      <input type="number" id="setHydraAttempts" min="0" max="5">
    </div>
    <div class="full-width">
      <label>Exclude countries (comma-separated)</label>
      <input type="text" id="setExcludeCountries" placeholder="Russia, Ukraine">
    </div>
    <div class="full-width">
      <label>
        <input type="checkbox" id="setEnabled" style="width:auto;margin-right:6px;vertical-align:middle">
        Monitoring enabled
      </label>
    </div>
  </div>
  <div class="settings-actions">
    <button class="btn btn-primary btn-sm" onclick="saveSettings()">Save</button>
    <button class="btn btn-secondary btn-sm" id="btnCheck" onclick="manualCheck()">Check Now</button>
    <span class="check-result" id="checkResult"></span>
  </div>

  <h3 style="margin-top:20px; padding-top:14px; border-top:1px solid #2a2a4a;">Services</h3>
  <div class="settings-grid">
    <div>
      <label>Xray config path</label>
      <input type="text" id="setSvcXrayConfig" placeholder="/opt/etc/xray/config.json">
    </div>
    <div>
      <label>Xray init script</label>
      <input type="text" id="setSvcXrayInit" placeholder="/opt/etc/init.d/S24xray">
    </div>
    <div>
      <label>Xray proxy port (transparent)</label>
      <input type="number" id="setSvcXrayPort" min="1" max="65535">
    </div>
    <div>
      <label>SOCKS proxy port</label>
      <input type="number" id="setSvcSocksPort" min="1" max="65535">
    </div>
    <div class="full-width">
      <label>HydraRoute init script (empty = not installed)</label>
      <input type="text" id="setSvcHydraInit" placeholder="/opt/etc/init.d/S99hrneo">
    </div>
  </div>
</div>

<!-- Tabs -->
<div class="tabs" id="tabs"></div>

<!-- Toolbar -->
<div class="toolbar">
  <button class="btn btn-primary btn-sm" id="btnPing" onclick="pingAll()">Ping All</button>
  <button class="btn btn-secondary btn-sm" id="btnFetch" onclick="fetchSubscription()">Update Subscription</button>
  <span class="toolbar-info" id="toolbar-info"></span>
</div>

<!-- Server Table -->
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th style="width:30px">#</th>
        <th>Server</th>
        <th>Address</th>
        <th>Port</th>
        <th>Type</th>
        <th style="width:90px">Ping</th>
        <th style="width:90px">Action</th>
      </tr>
    </thead>
    <tbody id="serverBody"></tbody>
  </table>
  <div class="empty-state" id="emptyState" style="display:none;">
    <p>No servers. Add a subscription group and fetch servers.</p>
  </div>
</div>

<!-- Group Modal (Add / Edit) -->
<div class="modal-overlay" id="groupModal">
  <div class="modal">
    <h3 id="groupModalTitle">Add Subscription Group</h3>
    <input type="text" id="groupModalName" placeholder="Group name (e.g. myVPN)">
    <input type="text" id="groupModalUrl" placeholder="Subscription URL (https://...)">
    <div class="modal-actions">
      <button class="btn btn-secondary btn-sm" onclick="closeGroupModal()">Cancel</button>
      <button class="btn btn-primary btn-sm" id="groupModalSubmit" onclick="submitGroup()">Add</button>
    </div>
  </div>
</div>

<script>
let currentGroup = -1;
let pingData = {};
let serverData = [];
let activeIndex = -1;
let statusData = {};
let autoPinged = false;
let groupsData = [];
let editingGroupIdx = -1;

async function api(path, method, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(path, opts);
  return resp.json();
}

/* --- Flag extraction --- */
function extractCC(name) {
  if (!name) return '';
  // Check for Unicode regional indicator pairs -> extract CC
  const cp = [...name];
  if (cp.length >= 2) {
    const c0 = cp[0].codePointAt(0);
    if (c0 >= 0x1F1E6 && c0 <= 0x1F1FF) {
      const c1 = cp[1].codePointAt(0);
      return String.fromCharCode(c0 - 0x1F1A5) + String.fromCharCode(c1 - 0x1F1A5);
    }
  }
  // 2-letter uppercase country code at start
  const m = name.match(/^([A-Z]{2})[\s,.\-_|]/);
  if (m) return m[1];
  return '';
}

function flagImg(cc, size) {
  if (!cc) return '';
  size = size || 20;
  return `<img src="https://flagcdn.com/w40/${cc.toLowerCase()}.png" width="${size}" height="${Math.round(size*0.75)}" style="vertical-align:middle" onerror="this.style.display='none'" alt="${cc}">`;
}

function stripFlag(name) {
  if (!name) return '';
  const cp = [...name];
  if (cp.length >= 2) {
    const c0 = cp[0].codePointAt(0);
    if (c0 >= 0x1F1E6 && c0 <= 0x1F1FF) {
      return name.slice(cp[0].length + cp[1].length).trim();
    }
  }
  const m = name.match(/^[A-Z]{2}[\s,.\-_|]+/);
  if (m) return name.slice(m[0].length).trim();
  return name;
}

/* --- Ping rendering --- */
function pingHtml(ms) {
  if (ms === undefined) return '<span class="ping-val ping-unknown">--</span>';
  if (ms < 0) return '<span class="ping-val ping-bad">Timeout</span>';
  if (ms < 100) return `<span class="ping-val ping-good">${ms} ms</span>`;
  if (ms < 250) return `<span class="ping-val ping-medium">${ms} ms</span>`;
  return `<span class="ping-val ping-bad">${ms} ms</span>`;
}

/* --- Load groups --- */
async function loadGroups() {
  const data = await api('/api/groups', 'GET');
  const tabs = document.getElementById('tabs');
  let html = '';
  groupsData = data.groups;
  data.groups.forEach(g => {
    const cls = g.index === currentGroup ? 'tab active' : 'tab';
    html += `<div class="${cls}" onclick="selectGroup(${g.index})">
      ${esc(g.name)} <span class="count">${g.server_count}</span>
      <span class="del-btn" onclick="event.stopPropagation();editGroup(${g.index})" title="Edit">&#9998;</span>
      <span class="del-btn" onclick="event.stopPropagation();deleteGroup(${g.index})" title="Delete">&times;</span>
    </div>`;
  });
  html += `<div class="tab-add" onclick="showGroupModal()">+ Add</div>`;
  tabs.innerHTML = html;
  if (currentGroup < 0 && data.groups.length > 0) {
    currentGroup = data.active_group;
    // Don't recurse - just set and let refreshAll handle it
  }
}

async function selectGroup(idx) {
  currentGroup = idx;
  pingData = {};
  autoPinged = false;
  await loadGroups();
  await loadServers();
  pingAll();  // auto-ping on group switch
}

/* --- Load servers --- */
async function loadServers() {
  if (currentGroup < 0) {
    document.getElementById('serverBody').innerHTML = '';
    document.getElementById('emptyState').style.display = 'block';
    return;
  }
  const data = await api(`/api/servers?group=${currentGroup}`, 'GET');
  serverData = data.servers || [];
  activeIndex = data.active_index;
  renderServers();
}

function renderServers() {
  const body = document.getElementById('serverBody');
  const empty = document.getElementById('emptyState');
  if (serverData.length === 0) {
    body.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  // Build sortable list with original indices
  let items = serverData.map((s, i) => ({ s, i, ping: pingData[i] }));

  // Sort: active first, then by ping (ascending), timeout/unknown last
  const hasPings = Object.keys(pingData).length > 0;
  if (hasPings) {
    items.sort((a, b) => {
      if (a.i === activeIndex) return -1;
      if (b.i === activeIndex) return 1;
      const pa = a.ping === undefined ? 999999 : (a.ping < 0 ? 999998 : a.ping);
      const pb = b.ping === undefined ? 999999 : (b.ping < 0 ? 999998 : b.ping);
      return pa - pb;
    });
  }

  let html = '';
  items.forEach((item, row) => {
    const { s, i } = item;
    const isActive = i === activeIndex;
    const cls = isActive ? 'active-row' : '';
    const sec = s.params?.security || 'tls';
    const cc = extractCC(s.name);
    const name = stripFlag(s.name);
    const pHtml = pingHtml(pingData[i]);
    const btnLabel = isActive ? 'Active' : 'Connect';
    const btnCls = isActive ? 'btn btn-secondary btn-sm' : 'btn btn-primary btn-sm';
    const btnDis = isActive ? 'disabled' : '';

    html += `<tr class="${cls}">
      <td>${row + 1}</td>
      <td><span class="server-flag">${flagImg(cc)}</span><span class="server-name">${esc(name)}</span></td>
      <td>${esc(s.host)}</td>
      <td>${s.port}</td>
      <td>${esc(sec)}</td>
      <td>${pHtml}</td>
      <td><button class="${btnCls}" ${btnDis} onclick="switchServer(${i})">${btnLabel}</button></td>
    </tr>`;
  });
  body.innerHTML = html;

  const info = document.getElementById('toolbar-info');
  info.textContent = `${serverData.length} servers`;
}

/* --- Switch server --- */
async function switchServer(idx) {
  if (!confirm(`Switch to ${serverData[idx]?.name}?`)) return;
  document.getElementById('serverBody').classList.add('loading');
  const result = await api('/api/switch', 'POST', { group: currentGroup, server: idx });
  document.getElementById('serverBody').classList.remove('loading');
  if (result.ok) {
    autoPinged = false;  // re-ping after switch
    await refreshAll();
  } else {
    alert('Error: ' + result.message);
  }
}

/* --- Ping All --- */
async function pingAll() {
  if (currentGroup < 0) return;
  const btn = document.getElementById('btnPing');
  btn.disabled = true;
  btn.textContent = 'Pinging...';
  try {
    const result = await api('/api/ping', 'POST', { group: currentGroup });
    if (result.ok) {
      pingData = {};
      result.pings.forEach(p => { pingData[p.index] = p.ms; });
      renderServers();
    }
  } finally {
    btn.disabled = false;
    btn.textContent = 'Ping All';
  }
}

/* --- Fetch Subscription --- */
async function fetchSubscription() {
  const btn = document.getElementById('btnFetch');
  btn.disabled = true;
  btn.textContent = 'Fetching...';
  try {
    const result = await api('/api/group/fetch', 'POST', { group: currentGroup });
    if (result.ok) {
      pingData = {};
      await loadServers();
      pingAll();
    } else {
      alert('Error: ' + result.message);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = 'Update Subscription';
  }
}

/* --- Status + IP --- */
async function loadStatus() {
  try {
    statusData = await api('/api/status', 'GET');
    const srv = statusData.current_server;

    // Flag + name
    const cc = srv ? extractCC(srv.name) : '';
    const name = srv ? stripFlag(srv.name) : 'Not connected';
    document.getElementById('statusFlag').innerHTML = cc ? flagImg(cc, 36) : '--';
    document.getElementById('statusName').textContent = name;
    document.getElementById('statusHost').textContent = srv ? srv.host : '--';

    // Health details
    const mon = statusData.monitor || {};
    let dotCls = 'health-ok', textCls = 'health-text-ok', healthTxt = 'OK';
    if (mon.last_result === 'fail') { dotCls = 'health-fail'; textCls = 'health-text-fail'; healthTxt = 'FAIL'; }
    else if (mon.last_result === 'switched') { dotCls = 'health-warn'; textCls = 'health-text-warn'; healthTxt = 'Switched'; }
    else if (mon.last_result === 'no_server') { dotCls = 'health-fail'; textCls = 'health-text-fail'; healthTxt = 'No server'; }

    const failures = mon.consecutive_failures || 0;
    const lastCheck = mon.last_check ? new Date(mon.last_check).toLocaleTimeString() : '--';
    const lastSwitch = mon.last_switch ? new Date(mon.last_switch).toLocaleTimeString() : '--';

    document.getElementById('statusDetails').innerHTML =
      `<span>Health: <span class="health-dot ${dotCls}"></span> <span class="health-text ${textCls}">${healthTxt}</span></span>` +
      `<span>Failures: <b>${failures}</b></span>` +
      `<span>Last check: ${lastCheck}</span>` +
      `<span>Last switch: ${lastSwitch}</span>`;
  } catch(e) {}
}

async function loadMyIP() {
  try {
    const data = await api('/api/myip', 'GET');
    const el = document.getElementById('statusIPValue');
    el.textContent = data.ip || '...';
  } catch(e) {}
}

/* --- Group Modal (Add / Edit) --- */
function showGroupModal(idx) {
  editingGroupIdx = -1;
  document.getElementById('groupModalTitle').textContent = 'Add Subscription Group';
  document.getElementById('groupModalSubmit').textContent = 'Add';
  document.getElementById('groupModalName').value = '';
  document.getElementById('groupModalUrl').value = '';
  document.getElementById('groupModal').classList.add('show');
  document.getElementById('groupModalName').focus();
}
function editGroup(idx) {
  const g = groupsData.find(g => g.index === idx);
  if (!g) return;
  editingGroupIdx = idx;
  document.getElementById('groupModalTitle').textContent = 'Edit Subscription Group';
  document.getElementById('groupModalSubmit').textContent = 'Save';
  document.getElementById('groupModalName').value = g.name;
  document.getElementById('groupModalUrl').value = g.url;
  document.getElementById('groupModal').classList.add('show');
  document.getElementById('groupModalName').focus();
}
function closeGroupModal() {
  document.getElementById('groupModal').classList.remove('show');
}
async function submitGroup() {
  const name = document.getElementById('groupModalName').value.trim();
  const url = document.getElementById('groupModalUrl').value.trim();
  if (!name) { alert('Enter group name'); return; }
  let result;
  if (editingGroupIdx >= 0) {
    result = await api('/api/group/edit', 'POST', { group: editingGroupIdx, name, url });
  } else {
    result = await api('/api/group/add', 'POST', { name, url });
  }
  closeGroupModal();
  if (result.ok) { await refreshAll(); }
  else alert('Error: ' + result.message);
}
async function deleteGroup(idx) {
  if (!confirm('Delete this group?')) return;
  const result = await api('/api/group/delete', 'POST', { group: idx });
  if (result.ok) {
    if (currentGroup === idx) currentGroup = 0;
    await refreshAll();
  }
}

/* --- Settings --- */
function toggleSettings() {
  const panel = document.getElementById('settingsPanel');
  panel.classList.toggle('show');
  if (panel.classList.contains('show')) loadSettings();
}

function loadSettings() {
  const mon = statusData.monitor_settings || {};
  document.getElementById('setCheckUrl').value = mon.check_url || 'https://claude.ai';
  document.getElementById('setCheckInterval').value = mon.check_interval || 60;
  document.getElementById('setCheckTimeout').value = mon.check_timeout || 10;
  document.getElementById('setFailThreshold').value = mon.fail_threshold || 3;
  document.getElementById('setHydraAttempts').value = mon.hydra_restart_attempts || 2;
  document.getElementById('setExcludeCountries').value = (mon.exclude_countries || []).join(', ');
  document.getElementById('setEnabled').checked = mon.enabled !== false;
  document.getElementById('checkResult').textContent = '';
  // Services
  const svc = statusData.services || {};
  document.getElementById('setSvcXrayConfig').value = svc.xray_config_path || '/opt/etc/xray/config.json';
  document.getElementById('setSvcXrayInit').value = svc.xray_init_script || '/opt/etc/init.d/S24xray';
  document.getElementById('setSvcXrayPort').value = svc.xray_proxy_port || 12345;
  document.getElementById('setSvcSocksPort').value = svc.socks_port || 10808;
  document.getElementById('setSvcHydraInit').value = svc.hydra_init_script || '';
}

async function saveSettings() {
  const data = {
    check_url: document.getElementById('setCheckUrl').value.trim(),
    check_interval: parseInt(document.getElementById('setCheckInterval').value) || 60,
    check_timeout: parseInt(document.getElementById('setCheckTimeout').value) || 10,
    fail_threshold: parseInt(document.getElementById('setFailThreshold').value) || 3,
    hydra_restart_attempts: parseInt(document.getElementById('setHydraAttempts').value),
    exclude_countries: document.getElementById('setExcludeCountries').value.split(',').map(s => s.trim()).filter(Boolean),
    enabled: document.getElementById('setEnabled').checked,
    services: {
      xray_config_path: document.getElementById('setSvcXrayConfig').value.trim(),
      xray_init_script: document.getElementById('setSvcXrayInit').value.trim(),
      xray_proxy_port: parseInt(document.getElementById('setSvcXrayPort').value) || 12345,
      socks_port: parseInt(document.getElementById('setSvcSocksPort').value) || 10808,
      hydra_init_script: document.getElementById('setSvcHydraInit').value.trim(),
    },
  };
  const result = await api('/api/settings', 'POST', data);
  if (result.ok) {
    document.getElementById('checkResult').innerHTML = '<span class="check-ok">Saved!</span>';
    loadStatus();
  } else {
    document.getElementById('checkResult').innerHTML = `<span class="check-fail">Error: ${esc(result.message)}</span>`;
  }
}

async function manualCheck() {
  const btn = document.getElementById('btnCheck');
  const res = document.getElementById('checkResult');
  btn.disabled = true;
  btn.textContent = 'Checking...';
  res.textContent = '';
  try {
    const url = document.getElementById('setCheckUrl').value.trim() || undefined;
    const data = await api('/api/check', 'POST', { url });
    if (data.ok) {
      res.innerHTML = `<span class="check-ok">OK - HTTP ${esc(data.http_code)} (${esc(data.url)})</span>`;
    } else {
      res.innerHTML = `<span class="check-fail">FAIL - ${esc(data.message)}</span>`;
    }
  } catch(e) {
    res.innerHTML = `<span class="check-fail">Error: ${esc(String(e))}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Check Now';
  }
}

/* --- Helpers --- */
function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

async function refreshAll() {
  await Promise.all([loadGroups(), loadStatus()]);
  await loadServers();
  loadMyIP();
  if (!autoPinged && serverData.length > 0) {
    autoPinged = true;
    pingAll();
  }
}

// Init
refreshAll();
setInterval(() => { loadStatus(); loadMyIP(); }, 10000);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config())

    try:
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), VPNManagerHandler)
    except ImportError:
        from socketserver import ThreadingMixIn

        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True

        server = ThreadedHTTPServer((LISTEN_HOST, LISTEN_PORT), VPNManagerHandler)

    log.info("VPN Manager started on %s:%d", LISTEN_HOST, LISTEN_PORT)
    print(f"VPN Manager running at http://{LISTEN_HOST}:{LISTEN_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("VPN Manager stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
