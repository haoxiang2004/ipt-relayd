#!/bin/bash

# ==========================================
# ipt-relayd 专线中转一键脚本 (V2.0.0)
# 更新日志:
# 1. 升级至 V2.0，引入轻量级 Web 面板
# 2. 支持 Web 端口和登录密码修改
# ==========================================

# --- 基础配置 ---
sh_ver="2.0.0"
CONFIG_PATH="/etc/ipt-relayd/config.json"
PY_SCRIPT="/usr/local/bin/ipt-relayd.py"
SERVICE_FILE="/etc/systemd/system/ipt-relayd.service"
PANEL_CMD="/usr/local/bin/ipt-relayd"
REPO_URL="https://raw.githubusercontent.com/haoxiang2004/ipt-relayd/main/install.sh"

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
PLAIN="\033[0m"

# --- 权限与环境检测 ---

[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行！${PLAIN}" && exit 1

if [ "$0" != "$PANEL_CMD" ]; then
    curl -L "$REPO_URL" -o "$PANEL_CMD" 2>/dev/null
    chmod +x "$PANEL_CMD" 2>/dev/null
fi

init_env() {
    mkdir -p "/etc/ipt-relayd"
    if [ ! -f "$CONFIG_PATH" ]; then
        echo '{"global":{"check_interval":30},"web_port":8080,"web_password":"admin","endpoints":[]}' > "$CONFIG_PATH"
    fi
}

check_dependencies() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${YELLOW}正在安装 Python3...${PLAIN}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -yqq && apt-get install -yqq python3 || yum install -y python3
    fi
}

get_status() {
    if systemctl is-active --quiet ipt-relayd; then
        echo -e "${GREEN}▶ 运行中 (Running)${PLAIN}"
    else
        echo -e "${RED}■ 未启动 / 未安装 (Stopped)${PLAIN}"
    fi
}

# --- 核心逻辑 (智能双栈守护进程) ---

install_core() {
    echo -e "${YELLOW}>>> 部署核心转发引擎及 Web 面板...${PLAIN}"
    cat << 'EOF' > "$PY_SCRIPT"
#!/usr/bin/env python3
import json, time, socket, subprocess, signal, sys, logging, os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import base64
import urllib.parse

CONFIG_PATH = "/etc/ipt-relayd/config.json"
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
active_state = {}

def enable_ip_forwarding():
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass

def resolve_domain(domain):
    try:
        info = socket.getaddrinfo(domain, None)
        ip = info[0][4][0]
        v = 6 if ':' in ip else 4
        return ip, v
    except Exception: return None, None

def execute_iptables(action, lp, tip, tp, v):
    cmd = "ip6tables" if v == 6 else "iptables"
    dest = f"[{tip}]:{tp}" if v == 6 else f"{tip}:{tp}"
    
    cmds = [
        [cmd, "-t", "nat", action, "PREROUTING", "-p", "tcp", "--dport", str(lp), "-j", "DNAT", "--to-destination", dest],
        [cmd, "-t", "nat", action, "PREROUTING", "-p", "udp", "--dport", str(lp), "-j", "DNAT", "--to-destination", dest],
        [cmd, "-t", "nat", action, "POSTROUTING", "-p", "tcp", "-d", str(tip), "--dport", str(tp), "-j", "MASQUERADE"],
        [cmd, "-t", "nat", action, "POSTROUTING", "-p", "udp", "-d", str(tip), "--dport", str(tp), "-j", "MASQUERADE"]
    ]
    for c in cmds: subprocess.run(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# --- Web UI Setup ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ipt-relayd Web UI</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --surface-color: #1e293b;
            --primary-color: #3b82f6;
            --primary-hover: #2563eb;
            --danger-color: #ef4444;
            --danger-hover: #dc2626;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --radius-md: 12px;
            --radius-sm: 8px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem 1rem;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        .header h1 {
            font-size: 1.75rem;
            font-weight: 600;
            background: linear-gradient(135deg, #60a5fa, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .card {
            background-color: var(--surface-color);
            border-radius: var(--radius-md);
            border: 1px solid var(--border-color);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        .card-header {
            margin-bottom: 1rem;
            font-size: 1.25rem;
            font-weight: 500;
            color: var(--text-main);
        }

        /* Forms */
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .form-group { display: flex; flex-direction: column; gap: 0.5rem; }
        .form-group label { font-size: 0.875rem; color: var(--text-muted); }
        .form-group input {
            background-color: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 0.75rem 1rem;
            border-radius: var(--radius-sm);
            font-size: 1rem;
            transition: all 0.2s;
        }
        .form-group input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            font-weight: 500;
            color: white;
            background-color: var(--primary-color);
            border: none;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .btn:hover { background-color: var(--primary-hover); }
        .btn-danger { background-color: var(--danger-color); padding: 0.5rem 1rem; font-size: 0.875rem; }
        .btn-danger:hover { background-color: var(--danger-hover); }

        /* Tables */
        .table-responsive { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }
        th, td { padding: 1rem; border-bottom: 1px solid var(--border-color); }
        th { font-weight: 500; color: var(--text-muted); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background-color: rgba(255, 255, 255, 0.02); }

        /* Utilities */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            background-color: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.2);
        }

        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            padding: 1rem 1.5rem;
            background-color: #10b981;
            color: white;
            border-radius: var(--radius-sm);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            transform: translateY(150%);
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            z-index: 50;
        }
        .toast.show { transform: translateY(0); }
        .toast.error { background-color: var(--danger-color); }

        .empty-state {
            text-align: center;
            padding: 3rem 1rem;
            color: var(--text-muted);
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>ipt-relayd V2.0</h1>
            <div class="badge" id="ruleCount">加载中...</div>
        </header>

        <main>
            <!-- Add Rule Form -->
            <section class="card">
                <h2 class="card-header">添加转发规则</h2>
                <form id="addRuleForm">
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="rid">规则备注</label>
                            <input type="text" id="rid" required placeholder="例如: web-server-1">
                        </div>
                        <div class="form-group">
                            <label for="lp">本地监听端口</label>
                            <input type="number" id="lp" required min="1" max="65535" placeholder="8080">
                        </div>
                        <div class="form-group">
                            <label for="dom">落地IP/域名</label>
                            <input type="text" id="dom" required placeholder="8.8.8.8或example.com">
                        </div>
                        <div class="form-group">
                            <label for="tp">落地端口</label>
                            <input type="number" id="tp" required min="1" max="65535" placeholder="443">
                        </div>
                    </div>
                    <button type="submit" class="btn" id="addBtn">保存规则</button>
                </form>
            </section>

            <!-- Rules List -->
            <section class="card">
                <h2 class="card-header">当前转发列表</h2>
                <div class="table-responsive">
                    <table id="rulesTable">
                        <thead>
                            <tr>
                                <th>备注</th>
                                <th>映射流向</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="rulesBody">
                            <tr><td colspan="3" class="empty-state">正在加载中...</td></tr>
                        </tbody>
                    </table>
                </div>
            </section>
        </main>
    </div>

    <div id="toast" class="toast">操作成功</div>

    <script>
        const API_BASE = '/api';

        function showToast(msg, isError = false) {
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.className = `toast show ${isError ? 'error' : ''}`;
            setTimeout(() => t.className = 'toast', 3000);
        }

        async function fetchRules() {
            try {
                const res = await fetch(`${API_BASE}/config`);
                const data = await res.json();
                renderRules(data.endpoints || []);
            } catch (err) {
                showToast('加载配置失败', true);
            }
        }

        function renderRules(endpoints) {
            const tbody = document.getElementById('rulesBody');
            document.getElementById('ruleCount').textContent = `共 ${endpoints.length} 条规则`;
            
            if (endpoints.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="empty-state">暂无转发规则</td></tr>';
                return;
            }

            tbody.innerHTML = endpoints.map((e, index) => `
                <tr>
                    <td><strong>${e.id}</strong></td>
                    <td>
                        <div style="display:flex; align-items:center; gap:0.5rem;">
                            <span style="color:var(--text-muted)">本机:</span><span>${e.listen_port}</span>
                            <span style="color:var(--primary-color)">→</span>
                            <span style="color:var(--text-muted)">目标:</span><span>${e.remote_domain}:${e.remote_port}</span>
                        </div>
                    </td>
                    <td>
                        <button class="btn btn-danger" onclick="deleteRule(${index})">删除</button>
                    </td>
                </tr>
            `).join('');
        }

        document.getElementById('addRuleForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('addBtn');
            btn.textContent = '提交中...';
            btn.disabled = true;

            const payload = {
                id: document.getElementById('rid').value.trim(),
                listen_port: parseInt(document.getElementById('lp').value),
                remote_domain: document.getElementById('dom').value.trim(),
                remote_port: parseInt(document.getElementById('tp').value)
            };

            try {
                const res = await fetch(`${API_BASE}/add`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                const result = await res.json();
                if (res.ok) {
                    showToast('添加成功');
                    e.target.reset();
                    fetchRules();
                } else {
                    showToast(result.error || '添加失败', true);
                }
            } catch (err) {
                showToast('网络错误', true);
            } finally {
                btn.textContent = '保存规则';
                btn.disabled = false;
            }
        });

        async function deleteRule(index) {
            if (!confirm('确定要删除这条规则吗？')) return;
            
            try {
                const res = await fetch(`${API_BASE}/delete`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ index })
                });
                
                if (res.ok) {
                    showToast('删除成功');
                    fetchRules();
                } else {
                    showToast('删除失败', true);
                }
            } catch (err) {
                showToast('网络错误', true);
            }
        }

        // Init
        fetchRules();
    </script>
</body>
</html>
"""

class PanelHandler(BaseHTTPRequestHandler):
    def get_config(self):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except:
            return {"global": {"check_interval": 30}, "web_port":8080, "web_password":"admin", "endpoints": []}
            
    def save_config(self, data):
        try:
            with open(CONFIG_PATH, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except: return False

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="ipt-relayd Panel"')
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"error": "Unauthorized"}')

    def is_authenticated(self):
        conf = self.get_config()
        password = conf.get("web_password", "admin")
        auth_header = self.headers.get('Authorization')
        if not auth_header: return False
        try:
            auth_type, encoded = auth_header.split(' ', 1)
            if auth_type.lower() == 'basic':
                decoded = base64.b64decode(encoded).decode('utf-8')
                usr, pwd = decoded.split(':', 1)
                return pwd == password and usr == 'admin'
        except: pass
        return False

    def do_GET(self):
        if not self.is_authenticated():
            return self.do_AUTHHEAD()
            
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_CONTENT.encode('utf-8'))
        elif self.path == '/api/config':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.get_config()).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self.is_authenticated():
            return self.do_AUTHHEAD()
            
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
        
        try:
            data = json.loads(body)
        except:
            self.send_error(400, "Invalid JSON")
            return

        conf = self.get_config()

        if self.path == '/api/add':
            # Basic validation
            if not all(k in data for k in ("id", "listen_port", "remote_domain", "remote_port")):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Missing fields"}')
                return
                
            # Check port collision
            if any(e["listen_port"] == data["listen_port"] for e in conf.get("endpoints", [])):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Port already in use"}')
                return
                
            conf["endpoints"].append({
                "id": data["id"],
                "listen_port": int(data["listen_port"]),
                "remote_domain": data["remote_domain"],
                "remote_port": int(data["remote_port"])
            })
            self.save_config(conf)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"success": true}')
            
        elif self.path == '/api/delete':
            idx = data.get("index")
            exts = conf.get("endpoints", [])
            if idx is not None and 0 <= idx < len(exts):
                exts.pop(idx)
                conf["endpoints"] = exts
                self.save_config(conf)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"success": true}')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid index"}')
        else:
            self.send_response(404)
            self.end_headers()

def run_web_server():
    while True:
        try:
            if not os.path.exists(CONFIG_PATH):
                time.sleep(1)
                continue
            with open(CONFIG_PATH, "r") as f:
                port = json.load(f).get("web_port", 8080)
            
            logging.info(f"Starting Web Panel on port {port}")
            server = HTTPServer(('0.0.0.0', port), PanelHandler)
            server.serve_forever()
        except Exception as e:
            logging.error(f"Web server error: {e}")
            time.sleep(5)

def main():
    enable_ip_forwarding()
    signal.signal(signal.SIGTERM, lambda s,f: sys.exit(0))
    
    # Start web server in background
    web_thread = threading.Thread(target=run_web_server, daemon=True)
    web_thread.start()
    
    last_mtime, last_dns = 0, 0
    while True:
        try:
            if not os.path.exists(CONFIG_PATH): time.sleep(1); continue
            mtime = os.path.getmtime(CONFIG_PATH)
            now = time.time()
            if mtime != last_mtime or (now - last_dns >= 30):
                with open(CONFIG_PATH, "r") as f: data = json.load(f)
                endpoints = data.get("endpoints", [])
                curr_ids = [e["id"] for e in endpoints]
                
                for rid in list(active_state.keys()):
                    if rid not in curr_ids:
                        s = active_state[rid]
                        execute_iptables("-D", s['lp'], s['ip'], s['tp'], s['v'])
                        del active_state[rid]
                        
                for e in endpoints:
                    rid, lp, dom, tp = e["id"], e["listen_port"], e["remote_domain"], e["remote_port"]
                    ip, v = resolve_domain(dom)
                    if not ip: continue
                    
                    last = active_state.get(rid)
                    if not last or last['ip'] != ip or last['lp'] != lp or last['tp'] != tp or last['v'] != v:
                        if last: execute_iptables("-D", last['lp'], last['ip'], last['tp'], last['v'])
                        execute_iptables("-A", lp, ip, tp, v)
                        active_state[rid] = {"ip":ip, "lp":lp, "tp":tp, "v":v}
                        
                last_mtime, last_dns = mtime, now
        except Exception as e:
            pass
        time.sleep(1)

if __name__ == "__main__": main()
EOF
    chmod +x "$PY_SCRIPT"

    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=ipt-relayd Service
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 $PY_SCRIPT
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable ipt-relayd; systemctl restart ipt-relayd
    echo -e "${GREEN}✅ 核心组件安装/重置完毕！${PLAIN}"
}

# --- 校验函数 ---

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# --- 菜单功能 ---

add_forward() {
    echo -e "${YELLOW}>>> 添加转发规则 (连续错2次自动退回菜单)${PLAIN}"
    local err=0
    # 1. 备注
    read -p "1. 节点备注 (如 hinet-01): " rid
    [[ -z "$rid" ]] && return

    # 2. 本地端口
    while true; do
        read -p "2. 本机监听端口 (1-65535): " lp
        if validate_port "$lp"; then
            if ! python3 -c "import json; d=json.load(open('$CONFIG_PATH')); exit(1) if any(e['listen_port']==$lp for e in d['endpoints']) else exit(0)"; then
                echo -e "${RED}端口已被占用${PLAIN}"; ((err++))
            else break; fi
        else echo -e "${RED}端口格式错误${PLAIN}"; ((err++)); fi
        [[ $err -ge 2 ]] && return
    done

    # 3. 落地地址
    err=0
    while true; do
        read -p "3. 落地IP/域名 (支持IPv6): " dom
        [[ -z "$dom" ]] && { echo -e "${RED}不能为空${PLAIN}"; ((err++)); [[ $err -ge 2 ]] && return; continue; }

        echo -e "${CYAN}正在校验与解析...${PLAIN}"
        check_res=$(python3 -c "
import socket, sys
addr = '$dom'
try:
    socket.inet_pton(socket.AF_INET, addr)
    print('IP4_VALID')
    sys.exit(0)
except socket.error: pass

try:
    socket.inet_pton(socket.AF_INET6, addr)
    print('IP6_VALID')
    sys.exit(0)
except socket.error: pass

try:
    info = socket.getaddrinfo(addr, None)
    ip = info[0][4][0]
    if ':' in ip: print('DOMAIN_VALID_V6:' + ip)
    else: print('DOMAIN_VALID_V4:' + ip)
    sys.exit(0)
except socket.gaierror:
    sys.exit(1)
" 2>/dev/null)

        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ 错误: 无效的 IP 或 无法解析该域名！${PLAIN}"
            ((err++))
        else
            if [[ "$check_res" == "IP4_VALID" ]]; then
                echo -e "${GREEN}✅ 检测到合法 IPv4 地址: $dom${PLAIN}"
                break
            elif [[ "$check_res" == "IP6_VALID" ]]; then
                echo -e "${GREEN}✅ 检测到合法 IPv6 地址: $dom${PLAIN}"
                break
            else
                resolved_ip=${check_res#*:}
                if [[ "$check_res" == DOMAIN_VALID_V6* ]]; then
                    echo -e "${GREEN}✅ 域名解析成功 (IPv6): $resolved_ip${PLAIN}"
                else
                    echo -e "${GREEN}✅ 域名解析成功 (IPv4): $resolved_ip${PLAIN}"
                fi
                break
            fi
        fi
        [[ $err -ge 2 ]] && return
    done

    # 4. 落地端口
    err=0
    while true; do
        read -p "4. 落地端口 (1-65535): " tp
        validate_port "$tp" && break
        echo -e "${RED}端口格式错误${PLAIN}"; ((err++))
        [[ $err -ge 2 ]] && return
    done

    python3 -c "import json; f=open('$CONFIG_PATH','r+'); d=json.load(f); d['endpoints'].append({'id':'$rid','listen_port':int('$lp'),'remote_domain':'$dom','remote_port':int('$tp')}); f.seek(0); json.dump(d,f,indent=2); f.truncate()"
    echo -e "${GREEN}✅ 添加成功，底层规则已在后台智能双栈下发！${PLAIN}"
}

delete_forward() {
    echo -e "${YELLOW}>>> 删除单个转发规则${PLAIN}"
    python3 -c "import json; d=json.load(open('$CONFIG_PATH')); [print(f'{i+1}. {e[\"id\"]} ({e[\"listen_port\"]} -> {e[\"remote_domain\"]})') for i,e in enumerate(d['endpoints'])]" 2>/dev/null
    read -p "请输入要删除的序号 (0 取消): " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    python3 -c "import json; f=open('$CONFIG_PATH','r+'); d=json.load(f); d['endpoints'].pop(int('$idx')-1); f.seek(0); json.dump(d,f,indent=2); f.truncate()" 2>/dev/null
    echo -e "${GREEN}✅ 规则已安全移除！${PLAIN}"
}

clear_all_config() {
    echo -e "${YELLOW}>>> 危险操作：清空全部配置${PLAIN}"
    echo -e "${CYAN}提示：清空配置后，后台将自动拔除与之关联的所有 IPv4 和 IPv6 转发规则。${PLAIN}"
    read -p "确定要清空全部配置吗？(y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        python3 -c "import json; f=open('$CONFIG_PATH','r+'); d=json.load(f); d['endpoints']=[]; f.seek(0); json.dump(d,f,indent=2); f.truncate()" 2>/dev/null
        echo -e "${GREEN}✅ 配置已全部清空！后台守护进程将在 1 秒内安全执行拔除操作。${PLAIN}"
    else
        echo -e "${GREEN}操作已取消。${PLAIN}"
    fi
}

config_web_panel() {
    echo -e "${YELLOW}>>> Web 面板设置${PLAIN}"
    local port=$(python3 -c "import json; print(json.load(open('$CONFIG_PATH')).get('web_port', 8080))" 2>/dev/null)
    local pwd=$(python3 -c "import json; print(json.load(open('$CONFIG_PATH')).get('web_password', 'admin'))" 2>/dev/null)
    
    echo -e "当前 Web 端口: ${GREEN}${port}${PLAIN}"
    echo -e "当前 Web 密码: ${GREEN}${pwd}${PLAIN}"
    echo -e "Web 登录用户: ${GREEN}admin${PLAIN} (不可更改)\n"
    
    read -p "是否需要修改配置？(y/n) [默认 n]: " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        read -p "请输入新端口 (1-65535, 直接回车保持不变 ${port}): " new_port
        read -p "请输入新密码 (直接回车保持不变 ${pwd}): " new_pwd
        
        # 验证端口
        if [[ ! -z "$new_port" ]]; then
            if validate_port "$new_port"; then
                port=$new_port
            else
                echo -e "${RED}❌ 无效的端口号！${PLAIN}"
                return
            fi
        fi
        
        # 验证密码
        if [[ ! -z "$new_pwd" ]]; then
            pwd=$new_pwd
        fi
        
        python3 -c "import json; f=open('$CONFIG_PATH','r+'); d=json.load(f); d['web_port']=int('$port'); d['web_password']='$pwd'; f.seek(0); json.dump(d,f,indent=2); f.truncate()" 2>/dev/null
        echo -e "${GREEN}✅ Web 面板配置已更新！守护进程将在后台自动应用新端口。${PLAIN}"
    fi
}

list_rules() {
    echo -e "\n${CYAN}--- 当前配置列表 ---${PLAIN}"
    python3 -c "import json; d=json.load(open('$CONFIG_PATH')); [print(f'[{e[\"id\"]}] 本地 {e[\"listen_port\"]} -> 目标 {e[\"remote_domain\"]}:{e[\"remote_port\"]}') for e in d.get('endpoints', [])]" 2>/dev/null
    
    echo -e "\n${CYAN}--- 物理层 (IPv4) iptables ---${PLAIN}"
    iptables -t nat -nL PREROUTING --line-numbers | grep -E "DNAT|num"
    iptables -t nat -nL POSTROUTING --line-numbers | grep -E "MASQUERADE|num"
    
    if command -v ip6tables &> /dev/null; then
        echo -e "\n${CYAN}--- 物理层 (IPv6) ip6tables ---${PLAIN}"
        ip6tables -t nat -nL PREROUTING --line-numbers | grep -E "DNAT|num"
        ip6tables -t nat -nL POSTROUTING --line-numbers | grep -E "MASQUERADE|num"
    fi
    echo -e "${CYAN}--------------------------------------${PLAIN}"
}

view_logs() {
    echo -e "${YELLOW}提示: 正在查看实时日志。按 Ctrl+C 退出日志并返回主菜单。${PLAIN}"
    sleep 1
    trap 'echo -e "\n${GREEN}已退出日志查看。${PLAIN}"' INT
    journalctl -u ipt-relayd -n 30 -f
    trap - INT
}

show_menu() {
    clear
    echo -e "
${CYAN}################################################${PLAIN}
${CYAN}#             ipt-relayd (v${sh_ver})              #${PLAIN}
${CYAN}################################################${PLAIN}
 面板状态: $(get_status)
------------------------------------------------
 ${GREEN}1.${PLAIN} 安装 / 重置核心组件
 ${RED}2.${PLAIN} 彻底卸载 ipt-relayd
------------------------------------------------
 ${GREEN}3.${PLAIN} 添加转发规则
 ${GREEN}4.${PLAIN} 删除转发规则
 ${YELLOW}5.${PLAIN} 清空全部配置
 ${GREEN}6.${PLAIN} 查看当前配置
 ${GREEN}7.${PLAIN} Web 面板设置 (端口/密码)
------------------------------------------------
 ${GREEN}8.${PLAIN} 查看实时运行日志
 ${GREEN}9.${PLAIN} 更新面板脚本
 ${GREEN}0.${PLAIN} 退出管理面板
${CYAN}################################################${PLAIN}"
}

main() {
    check_dependencies; init_env
    [[ ! -t 0 ]] && exec < /dev/tty
    
    while true; do
        show_menu
        read -p "请输入数字选择 [0-9]: " opt
        case $opt in
            1) install_core ;;
            2) 
               read -p "确定要彻底卸载并清空规则吗？(y/n): " confirm
               if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                   systemctl stop ipt-relayd; systemctl disable ipt-relayd
                   rm -rf "$PY_SCRIPT" "$SERVICE_FILE" "$PANEL_CMD"
                   systemctl daemon-reload
                   echo -e "${GREEN}✅ 已彻底卸载！所有 iptables 规则已安全清理。${PLAIN}"
                   exit 0
               fi
               ;;
            3) add_forward ;;
            4) delete_forward ;;
            5) clear_all_config ;;
            6) list_rules ;;
            7) config_web_panel ;;
            8) view_logs ;;
            9) 
               echo -e "${YELLOW}>>> 正在从 GitHub 同步最新脚本...${PLAIN}"
               curl -L "$REPO_URL" -o "$PANEL_CMD" && chmod +x "$PANEL_CMD"
               echo -e "${GREEN}更新完毕！正在重启面板...${PLAIN}"
               sleep 1
               exec "$PANEL_CMD"
               ;;
            0) echo -e "${GREEN}已退出面板。随时输入 ipt-relayd 重新进入。${PLAIN}"; exit 0 ;;
            *) echo -e "${RED}无效的选择！${PLAIN}" ;;
        esac
        read -p "按回车键返回主菜单..."
    done
}

main