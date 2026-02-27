#!/bin/bash

# ==========================================
# ipt-relayd 专线中转一键脚本 (V1.9.1)
# 更新日志:
# 1. 极简菜单 Header，移除多余中文说明
# 2. 将全局下载命令 curl -sSL 替换为 curl -L 显示进度
# ==========================================

# --- 基础配置 ---
sh_ver="1.9.1"
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
        echo '{"global":{"check_interval":30},"endpoints":[]}' > "$CONFIG_PATH"
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
    echo -e "${YELLOW}>>> 部署核心转发引擎...${PLAIN}"
    cat << 'EOF' > "$PY_SCRIPT"
#!/usr/bin/env python3
import json, time, socket, subprocess, signal, sys, logging, os
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

def main():
    enable_ip_forwarding()
    signal.signal(signal.SIGTERM, lambda s,f: sys.exit(0))
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
        except Exception: pass
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

list_rules() {
    echo -e "\n${CYAN}--- 当前配置列表 ---${PLAIN}"
    python3 -c "import json; d=json.load(open('$CONFIG_PATH')); [print(f'[{e[\"id\"]}] 本地 {e[\"listen_port\"]} -> 目标 {e[\"remote_domain\"]}:{e[\"remote_port\"]}') for e in d['endpoints']]" 2>/dev/null
    
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
------------------------------------------------
 ${GREEN}7.${PLAIN} 查看实时运行日志
 ${GREEN}8.${PLAIN} 更新面板脚本
 ${GREEN}0.${PLAIN} 退出管理面板
${CYAN}################################################${PLAIN}"
}

main() {
    check_dependencies; init_env
    [[ ! -t 0 ]] && exec < /dev/tty
    
    while true; do
        show_menu
        read -p "请输入数字选择 [0-8]: " opt
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
            7) view_logs ;;
            8) 
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