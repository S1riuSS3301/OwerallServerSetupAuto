# 🌟 AURORA Server Setup

**Полная автоматическая настройка безопасности сервера**  
*Создано для Сириуса by Aurora*

## 📋 Описание

AURORA Server Setup - это комплексное решение для автоматической настройки безопасности Linux серверов. Включает в себя все необходимые компоненты для создания защищенной и оптимизированной серверной среды.

## 🚀 Быстрый старт

### Автоматическая установка

```bash
# Скачать репозиторий
git clone https://github.com/your-username/aurora-server-setup.git
cd aurora-server-setup

# Запустить установку (Bash версия)
sudo ./server_overall.sh

# Или Python версия
sudo python3 server_overall.py
```

## 🛡️ Что включено

### Безопасность
- **SSH Hardening** - Изменение порта на 47291, отключение root login по паролю
- **Fail2Ban** - Защита от брутфорс атак
- **UFW Firewall** - Настройка базового файервола
- **Audit Logging** - Детальное логирование системных событий
- **ClamAV Antivirus** - Антивирусная защита с автообновлением

### Мониторинг и управление
- **Tmux Setup** - Настроенная сессия с мониторингом
- **Welcome Screen** - Информативный приветственный экран
- **System Status** - Отображение статуса всех сервисов
- **Auto Updates** - Автоматические обновления безопасности

### Оптимизация
- **I/O Scheduler** - Автоматическая оптимизация для HDD/SSD
- **DNS Caching** - Кэширование DNS запросов
- **Network Monitoring** - Мониторинг сетевых соединений

## 📁 Структура проекта

```
aurora-server-setup/
├── server_overall.sh          # Bash скрипт установки
├── server_overall.py          # Python скрипт установки
├── scripts/                   # Пользовательские скрипты
│   ├── ssh-welcome-static     # Приветственный экран
│   └── optimize-io-scheduler  # Оптимизация I/O
├── configs/                   # Конфигурационные файлы
│   ├── .tmux.conf            # Конфигурация tmux
│   ├── audit.rules           # Правила аудита
│   └── sshd_config           # Конфигурация SSH
└── docs/                     # Документация
    └── SECURITY.md           # Руководство по безопасности
```

## ⚙️ Детальная настройка

### SSH Configuration
- **Порт**: 47291 (вместо стандартного 22)
- **Аутентификация**: Только по ключам для production
- **Максимум попыток**: 3
- **Timeout**: 300 секунд

### Fail2Ban Rules
- **SSH**: 3 попытки, бан на 1 час
- **Nginx**: Защита от HTTP атак
- **Автоматическое разбанивание**: Через 1 час

### Audit Logging
- Мониторинг SSH подключений
- Отслеживание изменений системных файлов
- Логирование сетевых соединений
- Мониторинг выполнения команд

### Tmux Session
- **Сессия**: main-root
- **Окно 0**: Welcome (приветственный экран)
- **Окно 1**: Monitor (bashtop)
- **Автозапуск**: При создании новых окон

## 🔧 Управление

### Tmux команды
```bash
# Подключиться к сессии
tmux attach -t main-root

# Переключение между окнами
Ctrl+B затем 0  # Welcome экран
Ctrl+B затем 1  # Monitor
Ctrl+B затем c  # Создать новое окно (с welcome экраном)

# Отключиться (сессия продолжит работать)
Ctrl+B затем d
```

### Проверка статуса сервисов
```bash
# Статус всех сервисов
systemctl status fail2ban auditd clamav-freshclam nginx

# Логи безопасности
tail -f /var/log/auth.log
tail -f /var/log/fail2ban.log

# Audit логи
ausearch -k ssh_auth
ausearch -k network_connections
```

### Обновление конфигурации
```bash
# Перезагрузка tmux конфигурации
tmux source-file ~/.tmux.conf

# Обновление приветственного экрана
/usr/local/bin/ssh-welcome-static

# Оптимизация I/O
/usr/local/bin/optimize-io-scheduler
```

## 🔒 Безопасность

### Изменение SSH порта
После установки SSH будет доступен на порту **47291**:
```bash
ssh root@your_server -p 47291
```

### Fail2Ban статус
```bash
# Проверить статус
fail2ban-client status

# Проверить заблокированные IP
fail2ban-client status sshd

# Разблокировать IP
fail2ban-client set sshd unbanip IP_ADDRESS
```

### ClamAV сканирование
```bash
# Обновить базы вирусов
freshclam

# Сканировать систему
clamscan -r /home --bell -i

# Сканировать с удалением
clamscan -r /home --remove
```

## 📊 Мониторинг

### Системная информация
Приветственный экран показывает:
- Время работы сервера
- Использование CPU и RAM
- Свободное место на диске
- Статус всех сервисов безопасности
- Уведомления о необходимости перезагрузки

### Логи
```bash
# Основные логи
tail -f /var/log/aurora-setup.log    # Лог установки
tail -f /var/log/auth.log            # SSH подключения
tail -f /var/log/fail2ban.log        # Fail2Ban события
tail -f /var/log/audit/audit.log     # Audit события
```

## 🚨 Устранение неполадок

### SSH недоступен
1. Проверьте порт: `netstat -tlnp | grep 47291`
2. Проверьте файервол: `ufw status`
3. Проверьте SSH сервис: `systemctl status sshd`

### Fail2Ban не работает
1. Проверьте статус: `systemctl status fail2ban`
2. Проверьте конфигурацию: `fail2ban-client -d`
3. Перезапустите: `systemctl restart fail2ban`

### Tmux сессия недоступна
1. Список сессий: `tmux list-sessions`
2. Создать новую: `tmux new-session -s main-root`
3. Восстановить конфигурацию: `tmux source-file ~/.tmux.conf`

## 🔄 Обновления

### Автоматические обновления
Система настроена на автоматическое обновление пакетов безопасности. Проверить статус:
```bash
# Статус автообновлений
systemctl status unattended-upgrades

# Логи обновлений
tail -f /var/log/unattended-upgrades/unattended-upgrades.log
```

### Ручное обновление
```bash
# Обновить систему
apt update && apt upgrade -y

# Обновить базы ClamAV
freshclam

# Перезапустить сервисы
systemctl restart fail2ban auditd
```

## 📞 Поддержка

При возникновении проблем:
1. Проверьте логи в `/var/log/aurora-setup.log`
2. Убедитесь, что все сервисы запущены
3. Проверьте статус файервола и Fail2Ban
4. При необходимости создайте issue в репозитории

## 📄 Лицензия

MIT License - используйте свободно для личных и коммерческих проектов.

---

**AURORA Server Setup** - Ваш надежный помощник в настройке безопасного сервера! 🌟
