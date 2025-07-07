#!/usr/bin/env python3
"""
IPv6 Proxy Manager - полноценный менеджер IPv6 прокси с автоматической ротацией
Поддерживает HTTP/SOCKS5, ротацию подсетей и IP адресов
Автор: IPv6 Proxy Expert
"""

import asyncio
import ipaddress
import os
import random
import secrets
import socket
import struct
import time
import logging
import signal
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum
import json
import base64
from contextlib import closing

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
import uvicorn

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Конфигурационные модели
class ProxyProtocol(str, Enum):
    HTTP = "http"
    SOCKS5 = "socks5"


class AuthMode(str, Enum):
    SINGLE = "single"  # Один логин/пароль на все
    RANDOM = "random"  # Случайные для каждого
    NONE = "none"  # Без аутентификации


class ProxyConfig(BaseModel):
    subnet_48: str = Field(..., description="IPv6 /48 подсеть (например: 2a12:5940:e02e)")
    proxy_count: int = Field(10, ge=1, le=1000, description="Количество прокси")
    protocol: ProxyProtocol = Field(ProxyProtocol.SOCKS5, description="Протокол прокси")
    rotation_minutes: int = Field(5, ge=1, le=60, description="Ротация IP в минутах")
    auth_mode: AuthMode = Field(AuthMode.SINGLE, description="Режим аутентификации")
    username: Optional[str] = Field(None, description="Логин (для режима single)")
    password: Optional[str] = Field(None, description="Пароль (для режима single)")


class ProxyInfo(BaseModel):
    address: str
    port: int
    protocol: str
    username: Optional[str]
    password: Optional[str]
    last_rotation: datetime
    next_rotation: datetime
    active: bool
    connections: int


# SOCKS5 константы
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_USERPASS = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_GENERAL_ERROR = 0x01


# SOCKS5 Proxy Handler
class SOCKS5ProxyHandler:
    def __init__(self, proxy_id: int, manager):
        self.proxy_id = proxy_id
        self.manager = manager
        self.connections = 0

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обрабатывает клиентское соединение SOCKS5"""
        client_addr = writer.get_extra_info('peername')
        self.connections += 1

        try:
            # Аутентификация
            if not await self._handle_auth(reader, writer):
                return

            # Обработка команды подключения
            if not await self._handle_connect(reader, writer):
                return

            # Проксирование данных
            await self._relay_data(reader, writer)

        except Exception as e:
            logger.error(f"SOCKS5 error for client {client_addr}: {e}")
        finally:
            self.connections -= 1
            writer.close()
            await writer.wait_closed()

    async def _handle_auth(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """Обработка SOCKS5 аутентификации"""
        proxy_data = self.manager.proxies[self.proxy_id]

        # Читаем версию и количество методов
        data = await reader.read(2)
        if len(data) < 2 or data[0] != SOCKS5_VERSION:
            return False

        nmethods = data[1]
        methods = await reader.read(nmethods)

        if proxy_data['username'] is None:
            # Без аутентификации
            if SOCKS5_AUTH_NONE in methods:
                writer.write(bytes([SOCKS5_VERSION, SOCKS5_AUTH_NONE]))
                await writer.drain()
                return True
        else:
            # С аутентификацией
            if SOCKS5_AUTH_USERPASS in methods:
                writer.write(bytes([SOCKS5_VERSION, SOCKS5_AUTH_USERPASS]))
                await writer.drain()

                # Проверяем логин/пароль
                auth_version = await reader.read(1)
                if auth_version[0] != 0x01:
                    return False

                ulen = (await reader.read(1))[0]
                username = (await reader.read(ulen)).decode('ascii')
                plen = (await reader.read(1))[0]
                password = (await reader.read(plen)).decode('ascii')

                if username == proxy_data['username'] and password == proxy_data['password']:
                    writer.write(bytes([0x01, 0x00]))  # Success
                    await writer.drain()
                    return True
                else:
                    writer.write(bytes([0x01, 0x01]))  # Failure
                    await writer.drain()
                    return False

        # Нет подходящих методов
        writer.write(bytes([SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE]))
        await writer.drain()
        return False

    async def _handle_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """Обработка команды CONNECT"""
        # Читаем заголовок запроса
        data = await reader.read(4)
        if len(data) < 4 or data[0] != SOCKS5_VERSION:
            return False

        cmd = data[1]
        if cmd != SOCKS5_CMD_CONNECT:
            # Поддерживаем только CONNECT
            writer.write(bytes([SOCKS5_VERSION, 0x07, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            return False

        atyp = data[3]

        # Парсим адрес назначения
        if atyp == SOCKS5_ATYP_IPV4:
            addr = await reader.read(4)
            host = socket.inet_ntoa(addr)
        elif atyp == SOCKS5_ATYP_DOMAIN:
            addr_len = (await reader.read(1))[0]
            host = (await reader.read(addr_len)).decode('ascii')
        elif atyp == SOCKS5_ATYP_IPV6:
            addr = await reader.read(16)
            host = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            return False

        port_data = await reader.read(2)
        port = struct.unpack('!H', port_data)[0]

        # Сохраняем информацию о цели
        self.target_host = host
        self.target_port = port

        # Отправляем успешный ответ
        proxy_data = self.manager.proxies[self.proxy_id]
        bind_addr = socket.inet_pton(socket.AF_INET6, proxy_data['address'])
        response = bytes([SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV6])
        response += bind_addr + struct.pack('!H', proxy_data['port'])

        writer.write(response)
        await writer.drain()
        return True

    async def _relay_data(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        """Проксирует данные между клиентом и целевым сервером"""
        try:
            # Подключаемся к целевому серверу
            proxy_data = self.manager.proxies[self.proxy_id]

            # Создаем сокет с привязкой к IPv6 адресу
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind((proxy_data['address'], 0))
            sock.setblocking(False)

            # Подключаемся асинхронно
            loop = asyncio.get_event_loop()
            await loop.sock_connect(sock, (self.target_host, self.target_port))

            # Создаем reader/writer для целевого соединения
            target_reader, target_writer = await asyncio.open_connection(sock=sock)

            # Проксируем данные в обе стороны
            await asyncio.gather(
                self._copy_data(client_reader, target_writer, "client->target"),
                self._copy_data(target_reader, client_writer, "target->client"),
                return_exceptions=True
            )

        except Exception as e:
            logger.error(f"Relay error: {e}")
        finally:
            for writer in [client_writer, target_writer]:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass

    async def _copy_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
        """Копирует данные из reader в writer"""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.debug(f"Copy data error ({direction}): {e}")


# HTTP Proxy Handler
class HTTPProxyHandler:
    def __init__(self, proxy_id: int, manager):
        self.proxy_id = proxy_id
        self.manager = manager
        self.connections = 0

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обрабатывает HTTP прокси соединение"""
        client_addr = writer.get_extra_info('peername')
        self.connections += 1

        try:
            # Читаем HTTP запрос
            request_line = await reader.readline()
            if not request_line:
                return

            headers = {}
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    break
                if line:
                    key, value = line.decode('latin1').rstrip('\r\n').split(': ', 1)
                    headers[key.lower()] = value

            # Проверяем аутентификацию
            proxy_data = self.manager.proxies[self.proxy_id]
            if proxy_data['username']:
                auth_header = headers.get('proxy-authorization', '')
                if not self._check_auth(auth_header, proxy_data['username'], proxy_data['password']):
                    # Требуем аутентификацию
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n')
                    writer.write(b'Proxy-Authenticate: Basic realm="Proxy"\r\n')
                    writer.write(b'Connection: close\r\n\r\n')
                    await writer.drain()
                    return

            # Парсим метод и URL
            parts = request_line.decode('latin1').split()
            if len(parts) < 3:
                return

            method = parts[0]
            url = parts[1]

            if method == 'CONNECT':
                # HTTPS туннель
                await self._handle_connect(url, reader, writer)
            else:
                # HTTP запрос
                await self._handle_http(method, url, headers, reader, writer)

        except Exception as e:
            logger.error(f"HTTP proxy error for client {client_addr}: {e}")
        finally:
            self.connections -= 1
            writer.close()
            await writer.wait_closed()

    def _check_auth(self, auth_header: str, username: str, password: str) -> bool:
        """Проверяет Basic аутентификацию"""
        if not auth_header.startswith('Basic '):
            return False

        try:
            encoded = auth_header[6:]
            decoded = base64.b64decode(encoded).decode('ascii')
            user, passwd = decoded.split(':', 1)
            return user == username and passwd == password
        except:
            return False

    async def _handle_connect(self, url: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обрабатывает CONNECT запросы (HTTPS)"""
        try:
            # Парсим хост и порт
            if ':' in url:
                host, port = url.split(':', 1)
                port = int(port)
            else:
                host = url
                port = 443

            # Подключаемся к целевому серверу
            proxy_data = self.manager.proxies[self.proxy_id]

            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind((proxy_data['address'], 0))
            sock.setblocking(False)

            loop = asyncio.get_event_loop()
            await loop.sock_connect(sock, (host, port))

            target_reader, target_writer = await asyncio.open_connection(sock=sock)

            # Отправляем 200 OK
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            # Проксируем данные
            await asyncio.gather(
                self._copy_data(reader, target_writer),
                self._copy_data(target_reader, writer),
                return_exceptions=True
            )

        except Exception as e:
            logger.error(f"CONNECT error: {e}")
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            await writer.drain()

    async def _handle_http(self, method: str, url: str, headers: dict,
                           reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обрабатывает обычные HTTP запросы"""
        try:
            # Парсим URL
            if url.startswith('http://'):
                url = url[7:]

            if '/' in url:
                host, path = url.split('/', 1)
                path = '/' + path
            else:
                host = url
                path = '/'

            if ':' in host:
                host, port = host.split(':', 1)
                port = int(port)
            else:
                port = 80

            # Подключаемся к серверу
            proxy_data = self.manager.proxies[self.proxy_id]

            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind((proxy_data['address'], 0))
            sock.setblocking(False)

            loop = asyncio.get_event_loop()
            await loop.sock_connect(sock, (host, port))

            target_reader, target_writer = await asyncio.open_connection(sock=sock)

            # Пересобираем запрос
            request = f"{method} {path} HTTP/1.1\r\n"

            # Копируем заголовки, удаляя прокси-специфичные
            for key, value in headers.items():
                if key not in ['proxy-authorization', 'proxy-connection']:
                    request += f"{key}: {value}\r\n"

            request += "\r\n"

            target_writer.write(request.encode('latin1'))
            await target_writer.drain()

            # Копируем тело запроса если есть
            if 'content-length' in headers:
                length = int(headers['content-length'])
                body = await reader.read(length)
                target_writer.write(body)
                await target_writer.drain()

            # Проксируем ответ
            while True:
                data = await target_reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()

        except Exception as e:
            logger.error(f"HTTP error: {e}")
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            await writer.drain()

    async def _copy_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Копирует данные между соединениями"""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except:
            pass


# Основной класс управления прокси
class IPv6ProxyManager:
    def __init__(self):
        self.proxies: Dict[int, Dict] = {}
        self.config: Optional[ProxyConfig] = None
        self.base_port = 10000
        self.current_subnet_index = 0
        self.last_subnet_rotation = datetime.now()
        self.proxy_servers = {}
        self.rotation_tasks = {}
        self.handlers = {}

    def generate_ipv6_from_subnet(self, subnet_64: str) -> str:
        """Генерирует случайный IPv6 из /64 подсети"""
        network = ipaddress.IPv6Network(subnet_64)
        # Генерируем случайные 64 бита для хоста
        random_host = random.randint(1, 2 ** 64 - 1)
        ip = network.network_address + random_host
        return str(ip)

    def get_current_subnet_64(self) -> str:
        """Получает текущую /64 подсеть с учетом ротации"""
        if not self.config:
            raise ValueError("Конфигурация не установлена")

        # Проверяем, нужна ли ротация подсети
        if (datetime.now() - self.last_subnet_rotation).days >= 1:
            self.current_subnet_index += 1
            self.last_subnet_rotation = datetime.now()
            logger.info(f"Ротация подсети: индекс {self.current_subnet_index}")

        # Формируем /64 подсеть из /48
        base_48 = self.config.subnet_48.rstrip(':')
        subnet_64 = f"{base_48}:{self.current_subnet_index:04x}::/64"
        return subnet_64

    def generate_credentials(self, proxy_id: int) -> Tuple[Optional[str], Optional[str]]:
        """Генерирует учетные данные в зависимости от режима"""
        if self.config.auth_mode == AuthMode.NONE:
            return None, None
        elif self.config.auth_mode == AuthMode.SINGLE:
            return self.config.username, self.config.password
        else:  # RANDOM
            username = f"user_{proxy_id}_{secrets.token_hex(4)}"
            password = secrets.token_urlsafe(16)
            return username, password

    async def rotate_proxy_ip(self, proxy_id: int):
        """Ротация IP адреса для прокси"""
        while proxy_id in self.proxies:
            try:
                # Ждем время ротации
                await asyncio.sleep(self.config.rotation_minutes * 60)

                # Получаем новый IP
                subnet_64 = self.get_current_subnet_64()
                new_ip = self.generate_ipv6_from_subnet(subnet_64)

                # Обновляем данные
                self.proxies[proxy_id]['address'] = new_ip
                self.proxies[proxy_id]['last_rotation'] = datetime.now()
                self.proxies[proxy_id]['next_rotation'] = datetime.now() + timedelta(
                    minutes=self.config.rotation_minutes)

                logger.info(f"Ротация IP для прокси {proxy_id}: {new_ip}")

                # Перезапускаем сервер с новым IP
                await self._restart_proxy_server(proxy_id)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Ошибка ротации прокси {proxy_id}: {e}")
                await asyncio.sleep(5)

    async def _restart_proxy_server(self, proxy_id: int):
        """Перезапускает прокси сервер с новым IP"""
        # Останавливаем старый сервер
        if proxy_id in self.proxy_servers:
            server = self.proxy_servers[proxy_id]
            server.close()
            await server.wait_closed()

        # Запускаем новый
        await self._start_proxy_server(proxy_id)

    async def _start_proxy_server(self, proxy_id: int):
        """Запускает прокси сервер"""
        proxy_data = self.proxies[proxy_id]

        # Создаем обработчик
        if self.config.protocol == ProxyProtocol.SOCKS5:
            handler = SOCKS5ProxyHandler(proxy_id, self)
        else:
            handler = HTTPProxyHandler(proxy_id, self)

        self.handlers[proxy_id] = handler

        # Создаем сокет с привязкой к IPv6
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        try:
            sock.bind((proxy_data['address'], proxy_data['port']))
            sock.listen(128)
            sock.setblocking(False)

            # Запускаем сервер
            server = await asyncio.start_server(
                handler.handle_client,
                sock=sock
            )

            self.proxy_servers[proxy_id] = server
            logger.info(
                f"Запущен {self.config.protocol} прокси {proxy_id} на [{proxy_data['address']}]:{proxy_data['port']}")

        except Exception as e:
            logger.error(f"Ошибка запуска прокси {proxy_id}: {e}")
            sock.close()
            raise

    async def setup_proxies(self, config: ProxyConfig):
        """Настраивает и запускает прокси серверы"""
        self.config = config
        self.current_subnet_index = 0
        self.last_subnet_rotation = datetime.now()

        # Останавливаем старые прокси
        await self.stop_all_proxies()

        # Получаем текущую подсеть
        subnet_64 = self.get_current_subnet_64()

        # Создаем новые прокси
        for i in range(config.proxy_count):
            port = self.base_port + i
            username, password = self.generate_credentials(i)
            ip_address = self.generate_ipv6_from_subnet(subnet_64)

            self.proxies[i] = {
                'port': port,
                'protocol': config.protocol.value,
                'username': username,
                'password': password,
                'address': ip_address,
                'last_rotation': datetime.now(),
                'next_rotation': datetime.now() + timedelta(minutes=config.rotation_minutes),
                'active': False
            }

            try:
                # Запускаем прокси сервер
                await self._start_proxy_server(i)
                self.proxies[i]['active'] = True

                # Запускаем задачу ротации
                rotation_task = asyncio.create_task(self.rotate_proxy_ip(i))
                self.rotation_tasks[i] = rotation_task

            except Exception as e:
                logger.error(f"Не удалось запустить прокси {i}: {e}")
                self.proxies[i]['active'] = False

    async def stop_all_proxies(self):
        """Останавливает все прокси серверы"""
        # Отменяем задачи ротации
        for task in self.rotation_tasks.values():
            task.cancel()
        self.rotation_tasks.clear()

        # Закрываем серверы
        for server in self.proxy_servers.values():
            server.close()
            await server.wait_closed()
        self.proxy_servers.clear()

        # Очищаем данные
        self.proxies.clear()
        self.handlers.clear()

    def get_proxy_list(self) -> List[ProxyInfo]:
        """Возвращает список активных прокси"""
        result = []
        for proxy_id, data in self.proxies.items():
            connections = 0
            if proxy_id in self.handlers:
                connections = self.handlers[proxy_id].connections

            result.append(ProxyInfo(
                address=data['address'],
                port=data['port'],
                protocol=data['protocol'],
                username=data['username'],
                password=data['password'],
                last_rotation=data['last_rotation'],
                next_rotation=data['next_rotation'],
                active=data['active'],
                connections=connections
            ))
        return result

    def generate_proxy_file(self) -> str:
        """Генерирует файл со списком прокси"""
        lines = []
        for proxy in self.get_proxy_list():
            if not proxy.active:
                continue

            if proxy.protocol == "socks5":
                if proxy.username:
                    line = f"socks5://{proxy.username}:{proxy.password}@[{proxy.address}]:{proxy.port}"
                else:
                    line = f"socks5://[{proxy.address}]:{proxy.port}"
            else:  # HTTP
                if proxy.username:
                    line = f"http://{proxy.username}:{proxy.password}@[{proxy.address}]:{proxy.port}"
                else:
                    line = f"http://[{proxy.address}]:{proxy.port}"
            lines.append(line)
        return "\n".join(lines)


# Создаем FastAPI приложение
app = FastAPI(title="IPv6 Proxy Manager", version="2.0.0")
proxy_manager = IPv6ProxyManager()

# HTML интерфейс
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>IPv6 Proxy Manager</title>
    <meta charset="utf-8">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #0f0f0f;
            color: #e0e0e0;
        }
        .container {
            background: #1a1a1a;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
            border: 1px solid #333;
        }
        h1 {
            color: #4fc3f7;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4caf50;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .form-group {
            display: flex;
            flex-direction: column;
        }
        label {
            margin-bottom: 8px;
            font-weight: 600;
            color: #b0b0b0;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        input, select {
            padding: 12px 16px;
            border: 1px solid #333;
            border-radius: 8px;
            font-size: 16px;
            background: #252525;
            color: #e0e0e0;
            transition: all 0.3s;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #4fc3f7;
            background: #2a2a2a;
        }
        button {
            background: linear-gradient(135deg, #4fc3f7 0%, #2196f3 100%);
            color: white;
            border: none;
            padding: 14px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-right: 10px;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(79, 195, 247, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
        .button-secondary {
            background: linear-gradient(135deg, #66bb6a 0%, #4caf50 100%);
        }
        .proxy-list {
            margin-top: 30px;
            border: 1px solid #333;
            border-radius: 8px;
            background: #252525;
            overflow: hidden;
        }
        .proxy-header {
            background: #2a2a2a;
            padding: 15px 20px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .proxy-header h3 {
            margin: 0;
            color: #4fc3f7;
        }
        .proxy-stats {
            display: flex;
            gap: 20px;
            font-size: 14px;
            color: #b0b0b0;
        }
        .proxy-items {
            max-height: 600px;
            overflow-y: auto;
        }
        .proxy-item {
            padding: 15px 20px;
            border-bottom: 1px solid #333;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }
        .proxy-item:hover {
            background: #2a2a2a;
        }
        .proxy-address {
            flex: 1;
            color: #e0e0e0;
            word-break: break-all;
        }
        .proxy-meta {
            display: flex;
            gap: 20px;
            font-size: 12px;
            color: #888;
        }
        .status {
            margin-top: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            display: none;
            font-weight: 500;
        }
        .status.success {
            background: #1b5e20;
            color: #4caf50;
            border: 1px solid #2e7d32;
        }
        .status.error {
            background: #b71c1c;
            color: #ef5350;
            border: 1px solid #c62828;
        }
        .auth-fields {
            display: none;
            background: #2a2a2a;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .connection-active {
            color: #4caf50;
            font-weight: 600;
        }
        .connection-inactive {
            color: #f44336;
        }
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #1a1a1a;
        }
        ::-webkit-scrollbar-thumb {
            background: #444;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>
            <span class="status-indicator"></span>
            IPv6 Proxy Manager
        </h1>

        <form id="proxyForm">
            <div class="form-grid">
                <div class="form-group">
                    <label for="subnet_48">IPv6 /48 Подсеть</label>
                    <input type="text" id="subnet_48" name="subnet_48" 
                           placeholder="2a12:5940:e02e" required>
                </div>

                <div class="form-group">
                    <label for="proxy_count">Количество прокси</label>
                    <input type="number" id="proxy_count" name="proxy_count" 
                           min="1" max="1000" value="10" required>
                </div>

                <div class="form-group">
                    <label for="protocol">Протокол</label>
                    <select id="protocol" name="protocol">
                        <option value="socks5">SOCKS5</option>
                        <option value="http">HTTP</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="rotation_minutes">Ротация IP (минуты)</label>
                    <input type="number" id="rotation_minutes" name="rotation_minutes" 
                           min="1" max="60" value="5" required>
                </div>

                <div class="form-group">
                    <label for="auth_mode">Режим аутентификации</label>
                    <select id="auth_mode" name="auth_mode" onchange="toggleAuthFields()">
                        <option value="single">Единый логин/пароль</option>
                        <option value="random">Случайные логины/пароли</option>
                        <option value="none">Без аутентификации</option>
                    </select>
                </div>
            </div>

            <div class="auth-fields" id="authFields">
                <div class="form-grid">
                    <div class="form-group">
                        <label for="username">Логин</label>
                        <input type="text" id="username" name="username" placeholder="admin">
                    </div>

                    <div class="form-group">
                        <label for="password">Пароль</label>
                        <input type="password" id="password" name="password" placeholder="password">
                    </div>
                </div>
            </div>

            <div style="margin-top: 30px;">
                <button type="submit">Запустить прокси</button>
                <button type="button" onclick="downloadProxyList()" 
                        class="button-secondary">Скачать список прокси</button>
            </div>
        </form>

        <div id="status" class="status"></div>

        <div class="proxy-list" id="proxyList" style="display: none;">
            <div class="proxy-header">
                <h3>Активные прокси</h3>
                <div class="proxy-stats">
                    <span>Всего: <strong id="totalProxies">0</strong></span>
                    <span>Активных: <strong id="activeProxies">0</strong></span>
                    <span>Соединений: <strong id="totalConnections">0</strong></span>
                </div>
            </div>
            <div class="proxy-items" id="proxyItems"></div>
        </div>
    </div>

    <script>
        function toggleAuthFields() {
            const authMode = document.getElementById('auth_mode').value;
            const authFields = document.getElementById('authFields');
            authFields.style.display = authMode === 'single' ? 'block' : 'none';
        }

        async function submitForm(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);

            // Преобразуем числовые поля
            data.proxy_count = parseInt(data.proxy_count);
            data.rotation_minutes = parseInt(data.rotation_minutes);

            // Удаляем пустые поля аутентификации
            if (data.auth_mode !== 'single') {
                delete data.username;
                delete data.password;
            }

            showStatus('info', 'Настройка прокси серверов...');

            try {
                const response = await fetch('/api/configure', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if (response.ok) {
                    showStatus('success', result.message);
                    setTimeout(loadProxyList, 1000);
                } else {
                    showStatus('error', result.detail || 'Ошибка настройки');
                }
            } catch (error) {
                showStatus('error', 'Ошибка: ' + error.message);
            }
        }

        async function loadProxyList() {
            try {
                const response = await fetch('/api/proxies');
                const proxies = await response.json();

                const proxyItems = document.getElementById('proxyItems');
                proxyItems.innerHTML = '';

                let activeCount = 0;
                let totalConnections = 0;

                proxies.forEach(proxy => {
                    if (proxy.active) activeCount++;
                    totalConnections += proxy.connections;

                    const item = document.createElement('div');
                    item.className = 'proxy-item';

                    let address = `${proxy.protocol}://`;
                    if (proxy.username) {
                        address += `${proxy.username}:${proxy.password}@`;
                    }
                    address += `[${proxy.address}]:${proxy.port}`;

                    const statusClass = proxy.active ? 'connection-active' : 'connection-inactive';
                    const statusText = proxy.active ? 'Активен' : 'Неактивен';

                    item.innerHTML = `
                        <div class="proxy-address">${address}</div>
                        <div class="proxy-meta">
                            <span class="${statusClass}">${statusText}</span>
                            <span>Соединений: ${proxy.connections}</span>
                            <span>Ротация: ${new Date(proxy.next_rotation).toLocaleTimeString()}</span>
                        </div>
                    `;

                    proxyItems.appendChild(item);
                });

                // Обновляем статистику
                document.getElementById('totalProxies').textContent = proxies.length;
                document.getElementById('activeProxies').textContent = activeCount;
                document.getElementById('totalConnections').textContent = totalConnections;

                document.getElementById('proxyList').style.display = 'block';
            } catch (error) {
                console.error('Ошибка загрузки списка прокси:', error);
            }
        }

        async function downloadProxyList() {
            try {
                const response = await fetch('/api/export');

                if (!response.ok) {
                    showStatus('error', 'Нет активных прокси для экспорта');
                    return;
                }

                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `proxy_list_${new Date().toISOString().split('T')[0]}.txt`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                showStatus('success', 'Список прокси скачан');
            } catch (error) {
                showStatus('error', 'Ошибка скачивания: ' + error.message);
            }
        }

        function showStatus(type, message) {
            const status = document.getElementById('status');
            status.className = 'status ' + type;
            status.textContent = message;
            status.style.display = 'block';

            if (type !== 'info') {
                setTimeout(() => {
                    status.style.display = 'none';
                }, 5000);
            }
        }

        // Обработчик формы
        document.getElementById('proxyForm').addEventListener('submit', submitForm);

        // Инициализация
        toggleAuthFields();

        // Автообновление списка прокси
        setInterval(() => {
            if (document.getElementById('proxyList').style.display === 'block') {
                loadProxyList();
            }
        }, 5000);
    </script>
</body>
</html>
"""


# API endpoints
@app.get("/", response_class=HTMLResponse)
async def index():
    """Главная страница с веб-интерфейсом"""
    return HTML_TEMPLATE


@app.post("/api/configure")
async def configure_proxies(config: ProxyConfig):
    """Настройка и запуск прокси серверов"""
    try:
        # Валидация IPv6 подсети
        try:
            test_subnet = f"{config.subnet_48}:0000::/64"
            ipaddress.IPv6Network(test_subnet)
        except ValueError:
            raise HTTPException(400, "Неверный формат IPv6 подсети")

        # Запускаем прокси
        await proxy_manager.setup_proxies(config)

        # Считаем активные прокси
        active_count = sum(1 for p in proxy_manager.proxies.values() if p['active'])

        return {
            "success": True,
            "message": f"Запущено {active_count} из {config.proxy_count} прокси серверов"
        }
    except Exception as e:
        logger.error(f"Ошибка настройки прокси: {e}")
        raise HTTPException(500, str(e))


@app.get("/api/proxies")
async def get_proxies():
    """Получить список активных прокси"""
    return proxy_manager.get_proxy_list()


@app.get("/api/export", response_class=PlainTextResponse)
async def export_proxies():
    """Экспорт списка прокси в текстовый файл"""
    content = proxy_manager.generate_proxy_file()
    if not content:
        raise HTTPException(404, "Нет активных прокси для экспорта")

    return PlainTextResponse(
        content=content,
        headers={
            "Content-Disposition": f"attachment; filename=proxy_list_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        }
    )


@app.get("/api/status")
async def get_status():
    """Получить статус системы"""
    active_proxies = sum(1 for p in proxy_manager.proxies.values() if p['active'])
    total_connections = sum(h.connections for h in proxy_manager.handlers.values())

    return {
        "active_proxies": active_proxies,
        "total_proxies": len(proxy_manager.proxies),
        "total_connections": total_connections,
        "current_subnet_index": proxy_manager.current_subnet_index,
        "last_subnet_rotation": proxy_manager.last_subnet_rotation,
        "config": proxy_manager.config.dict() if proxy_manager.config else None
    }


# Graceful shutdown
async def shutdown_handler():
    """Обработчик остановки приложения"""
    logger.info("Остановка прокси серверов...")
    await proxy_manager.stop_all_proxies()
    logger.info("Все прокси серверы остановлены")


def signal_handler(sig, frame):
    """Обработчик сигналов"""
    logger.info(f"Получен сигнал {sig}, завершение работы...")
    asyncio.create_task(shutdown_handler())
    sys.exit(0)


# Настройка обработчиков сигналов
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    # Проверка прав
    if os.geteuid() != 0:
        print("⚠️  ВНИМАНИЕ: Для работы с IPv6 требуются права root!")
        print("Запустите: sudo python3 proxy_manager.py")
        sys.exit(1)

    print("🚀 IPv6 Proxy Manager v2.0")
    print("📡 Запуск на http://0.0.0.0:8000")
    print("⚡ Используйте Ctrl+C для остановки")

    # Запуск сервера
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )
