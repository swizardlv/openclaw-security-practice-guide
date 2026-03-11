#!/usr/bin/env bash
# OpenClaw 极简安全实践指南 v2.8 - 每晚全面安全巡检脚本
# 覆盖 13 项核心指标；具备跨平台自适应与提权环境降权探测能力

# 1. 安全加固：强制严格权限
umask 077

# 2. 跨平台操作系统探测
OS_TYPE=$(uname -s)
if [ "$OS_TYPE" = "Darwin" ]; then
  CMD_STAT="stat -f %A"
  CMD_SHA256="shasum -a 256"
  CMD_SS="netstat -an | grep LISTEN"
  CMD_TOP="top -l 1"
else
  CMD_STAT="stat -c %a"
  CMD_SHA256="sha256sum"
  CMD_SS="ss -tunlp"
  CMD_TOP="top -b -n 1"
fi

# 跨平台超时封装
exec_timeout() {
  local t=$1
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$t" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$t" "$@"
  else
    "$@" # 兜底执行
  fi
}

# 3. 真实用户与家目录探测 (解决 sudo/cron 环境变量丢失)
if [ -n "$SUDO_USER" ]; then
  REAL_USER="$SUDO_USER"
  REAL_HOME=$(eval echo ~$REAL_USER)
else
  REAL_USER="$USER"
  REAL_HOME="$HOME"
fi

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

if [ -n "$REAL_HOME" ]; then
  # 注入 npm、yarn 本地全局目录
  export PATH="$REAL_HOME/.npm-global/bin:$REAL_HOME/.local/bin:$REAL_HOME/.yarn/bin:$PATH"
  # 注入 nvm 目录
  if [ -d "$REAL_HOME/.nvm/versions/node" ]; then
    NVM_BIN=$(ls -1d "$REAL_HOME"/.nvm/versions/node/*/bin 2>/dev/null | head -n 1)
    [ -n "$NVM_BIN" ] && export PATH="$NVM_BIN:$PATH"
  fi
  export OPENCLAW_STATE_DIR="${OPENCLAW_STATE_DIR:-$REAL_HOME/.openclaw}"
fi

OC="$OPENCLAW_STATE_DIR"

# 4. 报告目录安全设定
REPORT_DIR="/var/log/openclaw-audits"
if [ ! -d "$REPORT_DIR" ]; then
  mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="$OC/security-reports"
  mkdir -p "$REPORT_DIR"
fi

DATE_STR=$(date +%F)
REPORT_FILE="$REPORT_DIR/report-$DATE_STR-$$.txt"
SUMMARY="🛡️ OpenClaw 每日安全巡检简报 ($DATE_STR)\n\n"

> "$REPORT_FILE"
chmod 600 "$REPORT_FILE"
echo "=== OpenClaw Security Audit Detailed Report ($DATE_STR) ===" >> "$REPORT_FILE"

append_warn() {
  SUMMARY+="$1\n"
}

# --- 巡检开始 ---

# 1) OpenClaw 基础审计
echo "[1/13] OpenClaw 基础审计 (--deep)" >> "$REPORT_FILE"
if exec_timeout 300s openclaw security audit --deep >> "$REPORT_FILE" 2>&1; then
  SUMMARY+="1. 平台审计: ✅ 已执行原生扫描\n"
else
  append_warn "1. 平台审计: ⚠️ 执行超时或失败（详见详细报告）"
fi

# 2) 进程与网络
echo -e "\n[2/13] 监听端口与高资源进程" >> "$REPORT_FILE"
eval "$CMD_SS" >> "$REPORT_FILE" 2>/dev/null || true
eval "$CMD_TOP" | head -n 15 >> "$REPORT_FILE" 2>/dev/null || true
SUMMARY+="2. 进程网络: ✅ 已采集监听端口与进程快照\n"

# 3) 敏感目录变更
echo -e "\n[3/13] 敏感目录近 24h 变更文件数" >> "$REPORT_FILE"
MOD_FILES=$(find "$OC" /etc ~/.ssh ~/.gnupg /usr/local/bin -type f -mtime -1 2>/dev/null | wc -l | xargs)
echo "Total modified files: $MOD_FILES" >> "$REPORT_FILE"
SUMMARY+="3. 目录变更: ✅ $MOD_FILES 个文件 (位于 /etc/ 或 ~/.ssh 等)\n"

# 4) 系统定时任务
echo -e "\n[4/13] 系统级定时任务与 Systemd Timers" >> "$REPORT_FILE"
if [ "$OS_TYPE" = "Linux" ]; then
  ls -la /etc/cron.* /var/spool/cron/crontabs/ >> "$REPORT_FILE" 2>/dev/null || true
  systemctl list-timers --all >> "$REPORT_FILE" 2>/dev/null || true
else
  ls -la /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents >> "$REPORT_FILE" 2>/dev/null || true
fi
SUMMARY+="4. 系统 Cron: ✅ 已采集系统级定时任务信息\n"

# 5) OpenClaw 定时任务
echo -e "\n[5/13] OpenClaw Cron Jobs" >> "$REPORT_FILE"
if exec_timeout 60s openclaw cron list >> "$REPORT_FILE" 2>&1; then
  SUMMARY+="5. 本地 Cron: ✅ 已拉取内部任务列表\n"
else
  append_warn "5. 本地 Cron: ⚠️ 拉取失败（可能是 token/权限/超时问题）"
fi

# 6) 登录与 SSH 审计
echo -e "\n[6/13] 最近登录记录与 SSH 失败尝试" >> "$REPORT_FILE"
last -a -n 5 >> "$REPORT_FILE" 2>/dev/null || true
FAILED_SSH=0
if [ "$OS_TYPE" = "Linux" ] && command -v journalctl >/dev/null 2>&1; then
  FAILED_SSH=$(journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep -Ei "Failed|Invalid" | wc -l | xargs)
else
  for LOGF in /var/log/auth.log /var/log/secure /var/log/system.log; do
    if [ -f "$LOGF" ]; then
      FAILED_SSH=$(grep -Ei "sshd.*(Failed|Invalid)" "$LOGF" 2>/dev/null | tail -n 1000 | wc -l | xargs)
      break
    fi
  done
fi
echo "Failed SSH attempts (recent): $FAILED_SSH" >> "$REPORT_FILE"
SUMMARY+="6. SSH 安全: ✅ 近24h失败尝试 ${FAILED_SSH:-0} 次\n"

# 7) 关键文件完整性与权限
echo -e "\n[7/13] 关键配置文件权限与哈希基线" >> "$REPORT_FILE"
HASH_RES="MISSING_BASELINE"
if [ -f "$OC/.config-baseline.sha256" ]; then
  HASH_RES=$(cd "$OC" && eval "$CMD_SHA256" -c .config-baseline.sha256 2>&1 || true)
fi
echo "Hash Check: $HASH_RES" >> "$REPORT_FILE"
PERM_OC=$(eval "$CMD_STAT" "$OC/openclaw.json" 2>/dev/null || echo "MISSING")
PERM_PAIRED=$(eval "$CMD_STAT" "$OC/devices/paired.json" 2>/dev/null || echo "MISSING")
PERM_SSHD=$(eval "$CMD_STAT" /etc/ssh/sshd_config 2>/dev/null || echo "N/A")
PERM_AUTH_KEYS=$(eval "$CMD_STAT" "$REAL_HOME/.ssh/authorized_keys" 2>/dev/null || echo "N/A")
echo "Permissions: openclaw=$PERM_OC, paired=$PERM_PAIRED, sshd_config=$PERM_SSHD, authorized_keys=$PERM_AUTH_KEYS" >> "$REPORT_FILE"
if [[ "$HASH_RES" == *"OK"* ]] && [[ "$PERM_OC" == "600" ]]; then
  SUMMARY+="7. 配置基线: ✅ 哈希校验通过且权限合规\n"
else
  append_warn "7. 配置基线: ⚠️ 基线缺失/校验异常或权限不合规"
fi

# 8) 黄线操作交叉验证
echo -e "\n[8/13] 黄线操作对比 (sudo logs vs memory)" >> "$REPORT_FILE"
SUDO_COUNT=0
for LOGF in /var/log/auth.log /var/log/secure /var/log/system.log; do
  if [ -f "$LOGF" ]; then
    SUDO_COUNT=$(grep -Ei "sudo.*COMMAND" "$LOGF" 2>/dev/null | tail -n 2000 | wc -l | xargs)
    break
  fi
done
MEM_FILE="$OC/workspace/memory/$DATE_STR.md"
MEM_COUNT=$(grep -i "sudo" "$MEM_FILE" 2>/dev/null | wc -l | xargs)
echo "Sudo Logs(recent): ${SUDO_COUNT:-0}, Memory Logs(today): ${MEM_COUNT:-0}" >> "$REPORT_FILE"
SUMMARY+="8. 黄线审计: ✅ sudo记录=${SUDO_COUNT:-0}, memory记录=${MEM_COUNT:-0}\n"

# 9) 磁盘使用
echo -e "\n[9/13] 磁盘使用率与最近大文件" >> "$REPORT_FILE"
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}')
LARGE_FILES=$(find / -xdev -type d \( -name docker -o -name proc -o -name sys -o -name run \) -prune -o -type f -size +100M -mtime -1 -print 2>/dev/null | wc -l | xargs)
echo "Disk Usage: $DISK_USAGE, Large Files (>100M): $LARGE_FILES" >> "$REPORT_FILE"
SUMMARY+="9. 磁盘容量: ✅ 根分区占用 $DISK_USAGE, 新增 $LARGE_FILES 个大文件\n"

# 10) Gateway 环境变量 (Linux Only)
echo -e "\n[10/13] Gateway 环境变量泄露扫描" >> "$REPORT_FILE"
if [ "$OS_TYPE" = "Linux" ]; then
  GW_PID=$(pgrep -f "openclaw-gateway" | head -n 1 || true)
  if [ -n "$GW_PID" ] && [ -r "/proc/$GW_PID/environ" ]; then
    strings "/proc/$GW_PID/environ" | grep -iE 'SECRET|TOKEN|PASSWORD|KEY' | awk -F= '{print $1"=(Hidden)"}' >> "$REPORT_FILE" 2>/dev/null || true
    SUMMARY+="10. 环境变量: ✅ 已执行网关进程敏感变量名扫描\n"
  else
    append_warn "10. 环境变量: ⚠️ 未定位到 openclaw-gateway 进程"
  fi
else
  SUMMARY+="10. 环境变量: ✅ macOS 系统免于扫描 /proc\n"
fi

# 11) 明文凭证泄露扫描 (DLP)
echo -e "\n[11/13] 明文私钥/助记词泄露扫描 (DLP)" >> "$REPORT_FILE"
SCAN_ROOT="$OC/workspace"
DLP_HITS=0
if [ -d "$SCAN_ROOT" ]; then
  H1=$(exec_timeout 60s grep -RInE --exclude-dir=.git --exclude='*.png' --exclude='*.jpg' --exclude='*.jpeg' --exclude='*.gif' --exclude='*.webp' '\b0x[a-fA-F0-9]{64}\b' "$SCAN_ROOT" 2>/dev/null | wc -l | xargs)
  H2=$(exec_timeout 60s grep -RInE --exclude-dir=.git --exclude='*.png' --exclude='*.jpg' --exclude='*.jpeg' --exclude='*.gif' --exclude='*.webp' '\b([a-zA-Z]{3,12}[ \t]+){11,23}[a-zA-Z]{3,12}\b' "$SCAN_ROOT" 2>/dev/null | wc -l | xargs)
  DLP_HITS=$((${H1:-0} + ${H2:-0}))
fi
echo "DLP hits (heuristic): $DLP_HITS" >> "$REPORT_FILE"
if [ "$DLP_HITS" -gt 0 ]; then
  append_warn "11. 敏感凭证扫描: ⚠️ 检测到疑似明文敏感信息($DLP_HITS)，请人工复核"
else
  SUMMARY+="11. 敏感凭证扫描: ✅ 未发现明显私钥/助记词模式\n"
fi

# 12) Skill/MCP 完整性（基线diff）
echo -e "\n[12/13] Skill/MCP 完整性基线对比" >> "$REPORT_FILE"
SKILL_DIR="$OC/workspace/skills"
MCP_DIR="$OC/workspace/mcp"
HASH_DIR="$OC/security-baselines"
mkdir -p "$HASH_DIR" 2>/dev/null || true
CUR_HASH="$HASH_DIR/skill-mcp-current.sha256"
BASE_HASH="$HASH_DIR/skill-mcp-baseline.sha256"
> "$CUR_HASH"
for D in "$SKILL_DIR" "$MCP_DIR"; do
  if [ -d "$D" ]; then
    # 跨平台兼容的查找与哈希计算方式
    find "$D" -type f -exec eval "$CMD_SHA256" {} + 2>/dev/null | awk '{print $1, $2}' | sort >> "$CUR_HASH" || true
  fi
done
if [ -s "$CUR_HASH" ]; then
  if [ -f "$BASE_HASH" ]; then
    if diff -u "$BASE_HASH" "$CUR_HASH" >> "$REPORT_FILE" 2>&1; then
      SUMMARY+="12. Skill/MCP基线: ✅ 与上次基线一致\n"
    else
      append_warn "12. Skill/MCP基线: ⚠️ 检测到文件哈希变化（详见diff）"
    fi
  else
    cp "$CUR_HASH" "$BASE_HASH" 2>/dev/null || true
    SUMMARY+="12. Skill/MCP基线: ✅ 首次生成基线完成\n"
  fi
else
  SUMMARY+="12. Skill/MCP基线: ✅ 未发现skills/mcp目录文件\n"
fi

# 13) 大脑灾备自动同步
echo -e "\n[13/13] 大脑灾备 (Git Backup)" >> "$REPORT_FILE"
BACKUP_STATUS=""
if [ -d "$OC/.git" ]; then
  CURRENT_DIR=$(pwd)
  cd "$OC" || exit 1
  git add . >> "$REPORT_FILE" 2>&1 || true
  if git diff --cached --quiet; then
    echo "No staged changes" >> "$REPORT_FILE"
    BACKUP_STATUS="skip"
  else
    export GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=10"
    if git commit -m "🛡️ Nightly brain backup ($DATE_STR)" >> "$REPORT_FILE" 2>&1 && exec_timeout 30s git push origin main >> "$REPORT_FILE" 2>&1; then
      BACKUP_STATUS="ok"
    else
      BACKUP_STATUS="fail"
    fi
  fi
  cd "$CURRENT_DIR" || true
else
  BACKUP_STATUS="nogit"
fi

case "$BACKUP_STATUS" in
  ok)   SUMMARY+="13. 灾备备份: ✅ 已自动推送至远端仓库\n" ;;
  skip) SUMMARY+="13. 灾备备份: ✅ 无新变更，跳过推送\n" ;;
  nogit) append_warn "13. 灾备备份: ⚠️ 未初始化Git仓库，已跳过" ;;
  *)    append_warn "13. 灾备备份: ⚠️ 推送失败或超时（不影响本次巡检）" ;;
esac

echo -e "$SUMMARY\n📝 详细战报已保存本机: $REPORT_FILE"
exit 0
