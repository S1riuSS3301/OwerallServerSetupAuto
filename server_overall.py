#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AURORA Server Setup - Python версия
Полная автоматическая настройка сервера безопасности
Создано для Сириуса by Aurora
Версия: 1.0
"""

import os
import sys
import subprocess
import shutil
import time
from datetime import datetime
from pathlib import Path

# Цвета для вывода
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'

class AuroraServerSetup:
    def __init__(self):
        self.ssh_port = 47291
        self.logfile = "/var/log/aurora-setup.log"
        self.script_dir = Path(__file__).parent
        
    def log(self, message):
        """Логирование с временной меткой"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{Colors.GREEN}[{timestamp}] {message}{Colors.NC}")
        
    def error(self, message):
        """Вывод ошибки и выход"""
        print(f"{Colors.RED}[ОШИБКА] {message}{Colors.NC}")
        sys.exit(1)
        
    def run_command(self, command, check=True):
        """Выполнение команды с логированием"""
        try:
            result = subprocess.run(command, shell=True, check=check, 
                                  capture_output=True, text=True)
            return result
        except subprocess.CalledProcessError as e:
            self.error(f"Команда '{command}' завершилась с ошибкой: {e}")
            
    def check_root(self):
        """Проверка прав root"""
        if os.geteuid() != 0:
            self.error("Этот скрипт должен запускаться с правами root!")
            
    def show_banner(self):
        """Показать баннер"""
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.WHITE}              AURORA Server Setup v1.0               {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.WHITE}          Полная настройка безопасности сервера      {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
    def update_system(self):
        """Обновление системы"""
        self.log("Обновление системы...")
        self.run_command("apt update && apt upgrade -y")
        
    def install_packages(self):
        """Установка базовых пакетов"""
        self.log("Установка базовых пакетов...")
        packages = [
            "curl", "wget", "git", "vim", "htop", "tmux", "fail2ban", 
            "ufw", "auditd", "clamav", "clamav-daemon", "nginx", 
            "dnsmasq", "unattended-upgrades"
        ]
        self.run_command(f"apt install -y {' '.join(packages)}")
        
    def configure_ssh(self):
        """Настройка SSH"""
        self.log("Настройка SSH безопасности...")
        
        # Бэкап конфига
        shutil.copy("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.backup")
        
        # Копирование нашего конфига
        config_path = self.script_dir / "configs" / "sshd_config"
        if config_path.exists():
            shutil.copy(str(config_path), "/etc/ssh/sshd_config")
        
        self.run_command("systemctl restart sshd")
        
    def configure_firewall(self):
        """Настройка файервола"""
        self.log("Настройка файервола...")
        commands = [
            "ufw --force reset",
            "ufw default deny incoming",
            "ufw default allow outgoing",
            f"ufw allow {self.ssh_port}/tcp",
            "ufw allow 80/tcp",
            "ufw allow 443/tcp",
            "ufw --force enable"
        ]
        for cmd in commands:
            self.run_command(cmd)
            
    def configure_fail2ban(self):
        """Настройка Fail2Ban"""
        self.log("Настройка Fail2Ban...")
        
        fail2ban_config = f"""[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = {self.ssh_port}
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
"""
        
        with open("/etc/fail2ban/jail.local", "w") as f:
            f.write(fail2ban_config)
            
        self.run_command("systemctl enable fail2ban")
        self.run_command("systemctl restart fail2ban")
        
    def configure_audit(self):
        """Настройка системы аудита"""
        self.log("Настройка системы аудита...")
        
        # Копирование конфига аудита
        audit_config = self.script_dir / "configs" / "audit.rules"
        if audit_config.exists():
            shutil.copy(str(audit_config), "/etc/audit/rules.d/audit.rules")
            
        self.run_command("systemctl enable auditd")
        self.run_command("systemctl restart auditd")
        
    def configure_clamav(self):
        """Настройка ClamAV"""
        self.log("Настройка антивируса ClamAV...")
        
        self.run_command("systemctl stop clamav-freshclam")
        self.run_command("freshclam")
        self.run_command("systemctl enable clamav-freshclam")
        self.run_command("systemctl start clamav-freshclam")
        self.run_command("systemctl enable clamav-daemon")
        self.run_command("systemctl start clamav-daemon")
        
    def configure_auto_updates(self):
        """Настройка автообновлений"""
        self.log("Настройка автоматических обновлений...")
        
        unattended_config = """Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
"""
        
        with open("/etc/apt/apt.conf.d/50unattended-upgrades", "w") as f:
            f.write(unattended_config)
            
        auto_upgrades = '''APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
'''
        
        with open("/etc/apt/apt.conf.d/20auto-upgrades", "w") as f:
            f.write(auto_upgrades)
            
    def install_scripts(self):
        """Установка пользовательских скриптов"""
        self.log("Установка пользовательских скриптов...")
        
        scripts = ["ssh-welcome-static", "optimize-io-scheduler"]
        for script in scripts:
            src = self.script_dir / "scripts" / script
            dst = f"/usr/local/bin/{script}"
            if src.exists():
                shutil.copy(str(src), dst)
                os.chmod(dst, 0o755)
                
    def configure_tmux(self):
        """Настройка tmux"""
        self.log("Настройка tmux...")
        
        tmux_config = self.script_dir / "configs" / ".tmux.conf"
        if tmux_config.exists():
            shutil.copy(str(tmux_config), "/root/.tmux.conf")
            shutil.copy(str(tmux_config), "/etc/skel/.tmux.conf")
            
    def optimize_io(self):
        """Оптимизация I/O"""
        self.log("Оптимизация I/O планировщика...")
        self.run_command("/usr/local/bin/optimize-io-scheduler")
        
        # Добавление в автозагрузку
        with open("/etc/rc.local", "a") as f:
            f.write("/usr/local/bin/optimize-io-scheduler\n")
            
    def setup_tmux_session(self):
        """Настройка tmux сессии"""
        self.log("Настройка tmux сессии...")
        
        # Проверяем существование сессии
        result = self.run_command("tmux has-session -t main-root", check=False)
        if result.returncode != 0:
            commands = [
                "tmux new-session -d -s main-root -x 131 -y 24",
                "tmux rename-window -t main-root:0 'Welcome'",
                "tmux send-keys -t main-root:Welcome '/usr/local/bin/ssh-welcome-static' Enter",
                "tmux new-window -t main-root -n 'Monitor'",
                "tmux send-keys -t main-root:Monitor 'bashtop' Enter"
            ]
            for cmd in commands:
                self.run_command(cmd)
                
    def create_status_file(self):
        """Создание файла статуса"""
        status_content = f"""REBOOT_REQUIRED="false"
REBOOT_REASON=""
SETUP_COMPLETED="true"
SETUP_DATE="{datetime.now()}"
"""
        with open("/tmp/server-status", "w") as f:
            f.write(status_content)
            
    def show_completion(self):
        """Показать сообщение о завершении"""
        print()
        print(f"{Colors.GREEN}╔══════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.GREEN}║{Colors.WHITE}              НАСТРОЙКА ЗАВЕРШЕНА УСПЕШНО!           {Colors.GREEN}║{Colors.NC}")
        print(f"{Colors.GREEN}╠══════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.GREEN}║{Colors.NC} SSH порт изменен на: {Colors.YELLOW}{self.ssh_port}{Colors.NC}")
        print(f"{Colors.GREEN}║{Colors.NC} Fail2Ban настроен и активен")
        print(f"{Colors.GREEN}║{Colors.NC} UFW файервол настроен")
        print(f"{Colors.GREEN}║{Colors.NC} Audit логирование включено")
        print(f"{Colors.GREEN}║{Colors.NC} ClamAV антивирус установлен")
        print(f"{Colors.GREEN}║{Colors.NC} Автообновления настроены")
        print(f"{Colors.GREEN}║{Colors.NC} Tmux сессия создана")
        print(f"{Colors.GREEN}║{Colors.NC}")
        print(f"{Colors.GREEN}║{Colors.YELLOW} Подключение: ssh root@your_server -p {self.ssh_port}{Colors.NC}")
        print(f"{Colors.GREEN}║{Colors.YELLOW} Tmux сессия: tmux attach -t main-root{Colors.NC}")
        print(f"{Colors.GREEN}╚══════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        print(f"{Colors.RED}ВАЖНО: Перезагрузите сервер для применения всех изменений!{Colors.NC}")
        
    def run_setup(self):
        """Запуск полной настройки"""
        self.check_root()
        self.show_banner()
        
        steps = [
            self.update_system,
            self.install_packages,
            self.configure_ssh,
            self.configure_firewall,
            self.configure_fail2ban,
            self.configure_audit,
            self.configure_clamav,
            self.configure_auto_updates,
            self.install_scripts,
            self.configure_tmux,
            self.optimize_io,
            self.setup_tmux_session,
            self.create_status_file
        ]
        
        for step in steps:
            try:
                step()
            except Exception as e:
                self.error(f"Ошибка при выполнении {step.__name__}: {e}")
                
        self.log("Настройка завершена!")
        self.show_completion()

if __name__ == "__main__":
    setup = AuroraServerSetup()
    setup.run_setup()
