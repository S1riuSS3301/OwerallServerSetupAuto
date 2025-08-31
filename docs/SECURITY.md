# 🔒 Руководство по безопасности AURORA Server Setup

## 🛡️ Обзор безопасности

AURORA Server Setup реализует многоуровневую защиту сервера, включающую:

### Уровень 1: Сетевая безопасность
- **UFW Firewall** - Блокировка всех входящих соединений кроме разрешенных
- **Нестандартный SSH порт** - Порт 47291 вместо стандартного 22
- **Fail2Ban** - Автоматическая блокировка подозрительных IP

### Уровень 2: Аутентификация и доступ
- **SSH Hardening** - Отключение небезопасных методов аутентификации
- **Ограничение попыток входа** - Максимум 3 попытки
- **Timeout сессий** - Автоматическое отключение неактивных сессий

### Уровень 3: Мониторинг и аудит
- **Audit Daemon** - Детальное логирование всех системных событий
- **Сетевой мониторинг** - Отслеживание всех сетевых соединений
- **Мониторинг файлов** - Контроль изменений критических системных файлов

### Уровень 4: Защита от вредоносного ПО
- **ClamAV Antivirus** - Антивирусная защита с автообновлением баз
- **Автоматические обновления** - Установка критических обновлений безопасности

## 🔧 Детальная конфигурация

### SSH Configuration (/etc/ssh/sshd_config)
```bash
Port 47291                      # Нестандартный порт
PermitRootLogin yes            # Разрешен вход root (измените при необходимости)
PasswordAuthentication yes     # Аутентификация по паролю (отключите для production)
MaxAuthTries 3                 # Максимум 3 попытки входа
ClientAliveInterval 300        # Проверка активности клиента каждые 5 минут
ClientAliveCountMax 2          # Максимум 2 неактивных интервала
```

### Fail2Ban Rules (/etc/fail2ban/jail.local)
```ini
[sshd]
enabled = true
port = 47291
maxretry = 3                   # 3 неудачные попытки
bantime = 3600                 # Бан на 1 час
findtime = 600                 # Окно наблюдения 10 минут

[nginx-http-auth]
enabled = true
maxretry = 3
bantime = 3600

[nginx-noscript]
enabled = true
maxretry = 6
bantime = 3600
```

### UFW Firewall Rules
```bash
# Базовая политика
ufw default deny incoming      # Блокировать весь входящий трафик
ufw default allow outgoing     # Разрешить весь исходящий трафик

# Разрешенные порты
ufw allow 47291/tcp           # SSH
ufw allow 80/tcp              # HTTP
ufw allow 443/tcp             # HTTPS
```

### Audit Rules (/etc/audit/rules.d/audit.rules)
```bash
# SSH мониторинг
-w /var/log/auth.log -p wa -k ssh_auth
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Системные файлы
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Сетевые соединения
-a always,exit -F arch=b64 -S socket -S connect -S accept -k network_connections
-a always,exit -F arch=b32 -S socket -S connect -S accept -k network_connections

# Выполнение команд
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution
```

## 🚨 Мониторинг безопасности

### Проверка активных соединений
```bash
# Активные SSH соединения
who
w

# Сетевые соединения
netstat -tulnp
ss -tulnp

# Последние входы в систему
last
lastlog
```

### Анализ логов безопасности
```bash
# SSH попытки входа
grep "Failed password" /var/log/auth.log
grep "Accepted password" /var/log/auth.log

# Fail2Ban активность
tail -f /var/log/fail2ban.log
fail2ban-client status sshd

# Audit события
ausearch -k ssh_auth
ausearch -k network_connections
ausearch -k command_execution
```

### Мониторинг файловой системы
```bash
# Изменения в системных файлах
ausearch -k passwd_changes
ausearch -k group_changes
ausearch -k shadow_changes

# Мониторинг бинарных файлов
ausearch -k binaries

# Проверка целостности системы
aide --check
```

## 🔍 Обнаружение вторжений

### Признаки компрометации
1. **Необычная сетевая активность**
   ```bash
   netstat -i  # Проверка трафика интерфейсов
   iftop       # Мониторинг сетевого трафика в реальном времени
   ```

2. **Подозрительные процессы**
   ```bash
   ps aux | grep -v "^\[.*\]$"  # Процессы не в квадратных скобках
   top -c                        # Процессы с полными командными строками
   ```

3. **Неожиданные изменения файлов**
   ```bash
   find /etc -type f -mtime -1   # Файлы, измененные за последний день
   find /bin /sbin /usr/bin /usr/sbin -type f -mtime -1
   ```

### Реагирование на инциденты
1. **Немедленные действия**
   ```bash
   # Заблокировать подозрительный IP
   fail2ban-client set sshd banip SUSPICIOUS_IP
   
   # Или через UFW
   ufw deny from SUSPICIOUS_IP
   
   # Завершить подозрительные сессии
   pkill -KILL -u suspicious_user
   ```

2. **Анализ инцидента**
   ```bash
   # Собрать информацию о системе
   ps aux > /tmp/processes.txt
   netstat -tulnp > /tmp/connections.txt
   who > /tmp/users.txt
   
   # Архивировать логи
   tar -czf /tmp/security-logs-$(date +%Y%m%d).tar.gz /var/log/
   ```

## 🛠️ Регулярное обслуживание

### Еженедельные задачи
```bash
# Обновление системы
apt update && apt upgrade -y

# Обновление антивирусных баз
freshclam

# Проверка логов безопасности
grep "Failed password" /var/log/auth.log | tail -20
fail2ban-client status

# Сканирование на вирусы
clamscan -r /home --bell -i
```

### Ежемесячные задачи
```bash
# Полное сканирование системы
clamscan -r / --exclude-dir=/proc --exclude-dir=/sys --bell -i

# Анализ audit логов
aureport --summary
aureport --auth

# Проверка обновлений безопасности
apt list --upgradable | grep -i security

# Ротация логов
logrotate -f /etc/logrotate.conf
```

### Ежегодные задачи
```bash
# Смена SSH ключей
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key
systemctl restart sshd

# Аудит пользователей
cat /etc/passwd | grep -v nologin
last | head -20

# Проверка целостности системы
debsums -c
```

## 🚪 Восстановление доступа

### Если заблокирован SSH доступ
1. **Через консоль провайдера**
   ```bash
   # Проверить статус SSH
   systemctl status sshd
   
   # Проверить конфигурацию
   sshd -t
   
   # Восстановить стандартный порт временно
   sed -i 's/Port 47291/Port 22/' /etc/ssh/sshd_config
   systemctl restart sshd
   ufw allow 22/tcp
   ```

2. **Если заблокирован Fail2Ban**
   ```bash
   # Разблокировать свой IP
   fail2ban-client set sshd unbanip YOUR_IP
   
   # Или остановить Fail2Ban временно
   systemctl stop fail2ban
   ```

### Если забыт SSH порт
```bash
# Проверить активные порты SSH
netstat -tlnp | grep sshd
ss -tlnp | grep sshd

# Проверить конфигурацию
grep "^Port" /etc/ssh/sshd_config
```

## 📋 Чек-лист безопасности

### Ежедневно
- [ ] Проверить приветственный экран на наличие предупреждений
- [ ] Просмотреть последние записи в auth.log
- [ ] Проверить статус основных сервисов

### Еженедельно
- [ ] Обновить систему
- [ ] Проверить Fail2Ban логи
- [ ] Обновить антивирусные базы
- [ ] Просмотреть audit отчеты

### Ежемесячно
- [ ] Полное антивирусное сканирование
- [ ] Анализ сетевой активности
- [ ] Проверка обновлений безопасности
- [ ] Ротация и архивирование логов

### При подозрении на компрометацию
- [ ] Немедленно заблокировать подозрительные IP
- [ ] Собрать информацию о системе
- [ ] Архивировать логи
- [ ] Сменить пароли
- [ ] Проверить целостность системных файлов
- [ ] Полное сканирование на вредоносное ПО

---

**Помните**: Безопасность - это процесс, а не состояние. Регулярно обновляйте и мониторьте вашу систему!
