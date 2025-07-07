#!/bin/bash
# IPv6 Proxy Manager - Installation Script
# Автоматическая установка и настройка

PROJECT_DIR="/root/IPv6-proxy-manager"

set -e

echo "======================================"
echo "IPv6 Proxy Manager - Установка"
echo "======================================"

# Проверка прав root
if [[ $EUID -ne 0 ]]; then
   echo "❌ Этот скрипт должен быть запущен с правами root (sudo)"
   exit 1
fi

# Определение ОС
if [[ -f /etc/debian_version ]]; then
    OS="debian"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
else
    echo "❌ Неподдерживаемая ОС. Поддерживаются только Debian/Ubuntu и RedHat/CentOS"
    exit 1
fi

echo "✅ Обнаружена ОС: $OS"

# Установка зависимостей
echo "📦 Установка системных зависимостей..."

if [[ $OS == "debian" ]]; then
    apt-get update
    apt-get install -y python3 python3-pip python3-venv git net-tools iproute2
else
    yum install -y python3 python3-pip git net-tools iproute
fi

# Создание директории проекта

echo "📁 Создание директории проекта: $PROJECT_DIR"
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Создание виртуального окружения
echo "🐍 Создание виртуального окружения Python..."
python3 -m venv venv
source venv/bin/activate

# Установка Python зависимостей
echo "📦 Установка Python зависимостей..."
pip install --upgrade pip
pip install fastapi uvicorn pydantic

# Копирование файла прокси менеджера
echo "📄 Создание файла proxy_manager.py..."
cat > proxy_manager.py << 'EOF'
# Здесь должен быть код из артефакта ipv6_proxy_manager
# Для краткости не дублирую весь код
EOF

# Создание systemd сервиса
echo "⚙️ Создание systemd сервиса..."
cat > /etc/systemd/system/ipv6-proxy.service << EOF
[Unit]
Description=IPv6 Proxy Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/venv/bin"
ExecStart=$PROJECT_DIR/venv/bin/python proxy_manager.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Настройка IPv6
echo "🌐 Настройка IPv6..."

# Включение форвардинга IPv6
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.proxy_ndp=1" >> /etc/sysctl.conf
sysctl -p

# Функция для добавления IPv6 подсети
setup_ipv6_subnet() {
    local SUBNET=$1
    local INTERFACE=$2

    echo "➡️ Добавление IPv6 подсети $SUBNET на интерфейс $INTERFACE..."

    # Добавляем маршрут для всей подсети
    ip -6 route add local $SUBNET dev $INTERFACE 2>/dev/null || true

    # Добавляем первый адрес из подсети на интерфейс
    FIRST_IP="${SUBNET%::*}::1/48"
    ip -6 addr add $FIRST_IP dev $INTERFACE 2>/dev/null || true

    echo "✅ IPv6 подсеть настроена"
}

# Определение основного сетевого интерфейса
MAIN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "🔍 Основной сетевой интерфейс: $MAIN_INTERFACE"

# Запрос подсети у пользователя
echo ""
echo "======================================"
echo "Введите вашу IPv6 /48 подсеть"
echo "Формат: 2a12:5940:e02e (без ::/48)"
echo "======================================"
read -p "IPv6 подсеть: " USER_SUBNET

# Проверка формата
if [[ ! $USER_SUBNET =~ ^[0-9a-fA-F:]+$ ]]; then
    echo "❌ Неверный формат IPv6 подсети"
    exit 1
fi

# Настройка подсети
setup_ipv6_subnet "${USER_SUBNET}::/48" $MAIN_INTERFACE

# Создание скрипта для проверки
echo "📝 Создание вспомогательных скриптов..."

cat > $PROJECT_DIR/check_ipv6.sh << 'EOF'
#!/bin/bash
echo "=== IPv6 Configuration Check ==="
echo "Interfaces:"
ip -6 addr show
echo ""
echo "Routes:"
ip -6 route show
echo ""
echo "Forwarding:"
sysctl net.ipv6.conf.all.forwarding
echo ""
echo "Active connections:"
ss -6 -tulpn | grep -E "10[0-9]{3}"
EOF

chmod +x $PROJECT_DIR/check_ipv6.sh

# Создание скрипта быстрого запуска
cat > $PROJECT_DIR/start.sh << EOF
#!/bin/bash
cd $PROJECT_DIR
source venv/bin/activate
python proxy_manager.py
EOF

chmod +x $PROJECT_DIR/start.sh

# Настройка файрвола (если установлен)
if command -v ufw &> /dev/null; then
    echo "🔥 Настройка UFW файрвола..."
    ufw allow 8000/tcp comment "IPv6 Proxy Manager Web"
    ufw allow 10000:11000/tcp comment "IPv6 Proxy Ports"
fi

if command -v firewall-cmd &> /dev/null; then
    echo "🔥 Настройка FirewallD..."
    firewall-cmd --permanent --add-port=8000/tcp
    firewall-cmd --permanent --add-port=10000-11000/tcp
    firewall-cmd --reload
fi

# Финальные инструкции
echo ""
echo "======================================"
echo "✅ Установка завершена!"
echo "======================================"
echo ""
echo "📋 Важная информация:"
echo "- Веб-интерфейс: http://$(hostname -I | awk '{print $1}'):8000"
echo "- IPv6 подсеть: ${USER_SUBNET}::/48"
echo "- Директория: $PROJECT_DIR"
echo ""
echo "🚀 Команды управления:"
echo "- Запуск: systemctl start ipv6-proxy"
echo "- Остановка: systemctl stop ipv6-proxy"
echo "- Статус: systemctl status ipv6-proxy"
echo "- Автозапуск: systemctl enable ipv6-proxy"
echo "- Логи: journalctl -u ipv6-proxy -f"
echo ""
echo "🔧 Дополнительно:"
echo "- Проверка IPv6: $PROJECT_DIR/check_ipv6.sh"
echo "- Ручной запуск: $PROJECT_DIR/start.sh"
echo ""
echo "⚠️  ВАЖНО: Скопируйте полный код proxy_manager.py в файл"
echo "$PROJECT_DIR/proxy_manager.py перед запуском!"
echo ""
echo "======================================"