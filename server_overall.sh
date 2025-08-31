#!/bin/bash
# AURORA Server Setup - Полная автоматическая настройка сервера
# Создано для Сириуса by Aurora
# Версия: 1.0

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Логирование
LOGFILE="/var/log/aurora-setup.log"
exec > >(tee -a "$LOGFILE")
exec 2>&1

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${WHITE}              AURORA Server Setup v1.0               ${CYAN}║${NC}"
echo -e "${CYAN}║${WHITE}          Полная настройка безопасности сервера      ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Проверка прав root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Этот скрипт должен запускаться с правами root!${NC}"
   exit 1
fi

# Функция логирования
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ОШИБКА] $1${NC}"
    exit 1
}

# Обновление системы
log "Обновление системы..."
apt update && apt upgrade -y

# Установка базовых пакетов
log "Установка базовых пакетов..."
apt install -y curl wget git vim htop tmux fail2ban ufw auditd clamav clamav-daemon nginx dnsmasq

# Настройка SSH
log "Настройка SSH безопасности..."
SSH_PORT=47291
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config << 'EOF'
Port 47291
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

systemctl restart sshd

# Настройка UFW
log "Настройка файервола..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Настройка Fail2Ban
log "Настройка Fail2Ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = 47291
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-noscript]
enabled = true
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
bantime = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# Настройка Audit
log "Настройка системы аудита..."
cat > /etc/audit/rules.d/audit.rules << 'EOF'
# Удаление всех предыдущих правил
-D

# Установка размера буфера
-b 8192

# Мониторинг SSH подключений
-w /var/log/auth.log -p wa -k ssh_auth
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Мониторинг изменений в системных файлах
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Мониторинг сетевых соединений
-a always,exit -F arch=b64 -S socket -S connect -S accept -k network_connections
-a always,exit -F arch=b32 -S socket -S connect -S accept -k network_connections

# Мониторинг выполнения команд
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution

# Мониторинг изменений файлов
-w /bin/ -p wa -k binaries
-w /sbin/ -p wa -k binaries
-w /usr/bin/ -p wa -k binaries
-w /usr/sbin/ -p wa -k binaries

# Блокировка изменений правил аудита
-e 2
EOF

systemctl enable auditd
systemctl restart auditd

# Настройка ClamAV
log "Настройка антивируса ClamAV..."
systemctl stop clamav-freshclam
freshclam
systemctl enable clamav-freshclam
systemctl start clamav-freshclam
systemctl enable clamav-daemon
systemctl start clamav-daemon

# Настройка автообновлений
log "Настройка автоматических обновлений..."
apt install -y unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades

# Установка скриптов
log "Установка пользовательских скриптов..."
SCRIPT_DIR="$(dirname "$0")"

# Копирование скриптов
cp "$SCRIPT_DIR/scripts/ssh-welcome-static" /usr/local/bin/
cp "$SCRIPT_DIR/scripts/optimize-io-scheduler" /usr/local/bin/
chmod +x /usr/local/bin/ssh-welcome-static
chmod +x /usr/local/bin/optimize-io-scheduler

# Настройка tmux
log "Настройка tmux..."
cp "$SCRIPT_DIR/configs/.tmux.conf" /root/
cp "$SCRIPT_DIR/configs/.tmux.conf" /etc/skel/

# Запуск оптимизации I/O
log "Оптимизация I/O планировщика..."
/usr/local/bin/optimize-io-scheduler

# Добавление в автозагрузку
echo '/usr/local/bin/optimize-io-scheduler' >> /etc/rc.local

# Настройка tmux сессии
log "Настройка tmux сессии..."
if ! tmux has-session -t main-root 2>/dev/null; then
    tmux new-session -d -s main-root -x 131 -y 24
    tmux rename-window -t main-root:0 'Welcome'
    tmux send-keys -t main-root:Welcome '/usr/local/bin/ssh-welcome-static' Enter
    tmux new-window -t main-root -n 'Monitor'
    tmux send-keys -t main-root:Monitor 'bashtop' Enter
fi

# Создание статуса сервера
cat > /tmp/server-status << 'EOF'
REBOOT_REQUIRED="false"
REBOOT_REASON=""
SETUP_COMPLETED="true"
SETUP_DATE="$(date)"
EOF

log "Настройка завершена!"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${WHITE}              НАСТРОЙКА ЗАВЕРШЕНА УСПЕШНО!           ${GREEN}║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} SSH порт изменен на: ${YELLOW}47291${NC}"
echo -e "${GREEN}║${NC} Fail2Ban настроен и активен"
echo -e "${GREEN}║${NC} UFW файервол настроен"
echo -e "${GREEN}║${NC} Audit логирование включено"
echo -e "${GREEN}║${NC} ClamAV антивирус установлен"
echo -e "${GREEN}║${NC} Автообновления настроены"
echo -e "${GREEN}║${NC} Tmux сессия создана"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${YELLOW} Подключение: ssh root@your_server -p 47291${NC}"
echo -e "${GREEN}║${YELLOW} Tmux сессия: tmux attach -t main-root${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${RED}ВАЖНО: Перезагрузите сервер для применения всех изменений!${NC}"
