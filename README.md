# IPv6 Proxy Manager

Полноценный менеджер IPv6 прокси с автоматической ротацией подсетей и IP адресов. Поддерживает HTTP и SOCKS5 протоколы с веб-интерфейсом управления.

## 🚀 Возможности

- **Автоматическая ротация /64 подсетей** - каждые 24 часа из вашей /48 подсети
- **Ротация IP адресов** - настраиваемая ротация каждые N минут
- **HTTP и SOCKS5 прокси** - полноценная поддержка обоих протоколов
- **Три режима аутентификации**:
  - Единый логин/пароль для всех прокси
  - Уникальные случайные учетные данные
  - Без аутентификации
- **Веб-интерфейс** - удобное управление через браузер
- **REST API** - для интеграции с другими системами
- **Мониторинг в реальном времени** - статистика подключений

## 📋 Требования

- Linux сервер (Ubuntu/Debian или CentOS/RedHat)
- Python 3.8+
- IPv6 /48 подсеть от вашего провайдера
- Права root для настройки сети

## 🛠 Установка

### Автоматическая установка

```bash
wget https://raw.githubusercontent.com/your-repo/ipv6-proxy-manager/main/setup.sh
chmod +x setup.sh
sudo ./setup.sh
```

### Ручная установка

1. **Установите зависимости:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

2. **Создайте директорию проекта:**
```bash
sudo mkdir -p /opt/ipv6-proxy-manager
cd /opt/ipv6-proxy-manager
```

3. **Создайте виртуальное окружение:**
```bash
python3 -m venv venv
source venv/bin/activate
```

4. **Установите Python пакеты:**
```bash
pip install fastapi uvicorn pydantic
```

5. **Скопируйте файл `proxy_manager.py` в директорию проекта**

6. **Настройте IPv6:**
```bash
# Включите форвардинг
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

# Добавьте вашу /48 подсеть (замените на вашу)
ip -6 route add local 2a12:5940:e02e::/48 dev eth0
```

## 🚀 Запуск

### Через systemd (рекомендуется)

```bash
# Запуск
sudo systemctl start ipv6-proxy

# Автозапуск при загрузке
sudo systemctl enable ipv6-proxy

# Просмотр логов
sudo journalctl -u ipv6-proxy -f
```

### Ручной запуск

```bash
cd /opt/ipv6-proxy-manager
sudo ./start.sh
```

## 💻 Использование

### Веб-интерфейс

1. Откройте в браузере: `http://your-server-ip:8000`
2. Введите вашу IPv6 /48 подсеть (например: `2a12:5940:e02e`)
3. Настройте параметры:
   - Количество прокси (1-1000)
   - Протокол (HTTP или SOCKS5)
   - Время ротации IP (1-60 минут)
   - Режим аутентификации
4. Нажмите "Запустить прокси"
5. Скачайте список прокси

### API Endpoints

- `GET /` - Веб-интерфейс
- `POST /api/configure` - Настройка прокси
- `GET /api/proxies` - Список активных прокси
- `GET /api/export` - Экспорт списка прокси
- `GET /api/status` - Статус системы

### Пример конфигурации через API

```bash
curl -X POST http://localhost:8000/api/configure \
  -H "Content-Type: application/json" \
  -d '{
    "subnet_48": "2a12:5940:e02e",
    "proxy_count": 10,
    "protocol": "socks5",
    "rotation_minutes": 5,
    "auth_mode": "single",
    "username": "admin",
    "password": "secure_password"
  }'
```

## 📁 Формат выходного файла

### SOCKS5 с аутентификацией:
```
socks5://admin:secure_password@[2a12:5940:e02e:0000::a1b2c3d4]:10000
socks5://admin:secure_password@[2a12:5940:e02e:0000::e5f6g7h8]:10001
```

### HTTP без аутентификации:
```
http://[2a12:5940:e02e:0000::random1]:10000
http://[2a12:5940:e02e:0000::random2]:10001
```

## 🔧 Настройка клиентов

### curl
```bash
# SOCKS5
curl --proxy socks5://user:pass@[2a12:5940:e02e:0000::1]:10000 https://api.ipify.org

# HTTP
curl --proxy http://user:pass@[2a12:5940:e02e:0000::1]:10000 https://api.ipify.org
```

### Python requests
```python
import requests

# SOCKS5 (требуется requests[socks])
proxies = {
    'http': 'socks5://user:pass@[2a12:5940:e02e:0000::1]:10000',
    'https': 'socks5://user:pass@[2a12:5940:e02e:0000::1]:10000'
}

# HTTP
proxies = {
    'http': 'http://user:pass@[2a12:5940:e02e:0000::1]:10000',
    'https': 'http://user:pass@[2a12:5940:e02e:0000::1]:10000'
}

response = requests.get('https://api.ipify.org', proxies=proxies)
print(response.text)
```

### Chrome/Firefox

Используйте расширения типа FoxyProxy или SwitchyOmega с настройками:
- Protocol: SOCKS5 или HTTP
- Server: IPv6 адрес в квадратных скобках
- Port: соответствующий порт
- Username/Password: если настроена аутентификация

## 🛡 Безопасность

### Рекомендации:

1. **Используйте аутентификацию** - всегда включайте режим аутентификации для публичных серверов
2. **Настройте файрвол** - ограничьте доступ к портам прокси:
   ```bash
   # Разрешить только с определенных IP
   ufw allow from 1.2.3.4 to any port 10000:11000
   ```
3. **Используйте HTTPS** для веб-интерфейса в продакшене (настройте nginx reverse proxy)
4. **Регулярно обновляйте** систему и зависимости

## 🔍 Диагностика

### Проверка IPv6 конфигурации:
```bash
# Проверка адресов
ip -6 addr show

# Проверка маршрутов
ip -6 route show

# Проверка форвардинга
sysctl net.ipv6.conf.all.forwarding

# Тест подключения
curl --proxy socks5://[::1]:10000 https://api6.ipify.org
```

### Просмотр логов:
```bash
# Системные логи
sudo journalctl -u ipv6-proxy -f

# Логи в реальном времени
sudo tail -f /opt/ipv6-proxy-manager/proxy.log
```

### Частые проблемы:

**1. Ошибка "Cannot assign requested address"**
- Проверьте, что IPv6 подсеть правильно настроена
- Убедитесь, что используете правильный сетевой интерфейс

**2. Прокси не запускаются**
- Проверьте права доступа (нужен root)
- Убедитесь, что порты не заняты: `ss -tulpn | grep 10000`

**3. Клиенты не могут подключиться**
- Проверьте файрвол
- Убедитесь, что IPv6 работает на клиенте

## 📊 Мониторинг

### Встроенная статистика:
- Количество активных прокси
- Количество подключений на каждый прокси
- Время до следующей ротации
- История ротаций подсетей

### Интеграция с внешними системами:

API endpoint `/api/status` возвращает JSON с метриками:
```json
{
  "active_proxies": 10,
  "total_proxies": 10,
  "total_connections": 45,
  "current_subnet_index": 0,
  "last_subnet_rotation": "2024-01-15T10:00:00"
}
```

## 🔄 Обновление

```bash
cd /opt/ipv6-proxy-manager
git pull
source venv/bin/activate
pip install --upgrade -r requirements.txt
sudo systemctl restart ipv6-proxy
```

## 📝 Лицензия

MIT License

## 🤝 Поддержка

- Создайте issue в репозитории
- Telegram: @ipv6proxy_support
- Email: support@ipv6proxy.example.com

---

**Примечание**: Этот инструмент предназначен для легального использования. Убедитесь, что вы соблюдаете условия использования сервисов, к которым подключаетесь через прокси.