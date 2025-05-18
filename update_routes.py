#!/usr/bin/env python3
"""
OpenVPN Route Manager - скрипт для автоматического обновления маршрутов в конфигурации OpenVPN.
Обнаруживает новые IP-адреса для заданных доменов и добавляет их в конфигурацию сервера.
"""
import subprocess
import re
import os
import shutil
from collections import defaultdict
from datetime import datetime

# Конфигурационные константы
CONFIG_PATH = "/etc/openvpn/server/server.conf"
BACKUP_DIR = "/etc/openvpn/server/backups"
RESTART_COMMAND = "sudo systemctl restart openvpn-server@server"
DNS_SERVER = "1.1.1.1"  # Cloudflare DNS

# Маркеры блока маршрутов в конфиге
BEGIN_MARKER = "# BEGIN ROUTE BLOCK"
END_MARKER = "# END ROUTE BLOCK"

# Шаблон маршрута
ROUTE_TEMPLATE = 'push "route {ip} 255.255.255.255"  # {domains}'

# Список доменов для проверки
DOMAINS = [
    "nerdvm.racknerd.com",
    "racknerd.com",
    "",
    "",
    "",
    "",
    "",
]


def get_ipv4_addresses(domain):
    """Получение IPv4 адресов для домена через nslookup (Linux версия)"""
    if not domain:  # Пропускаем пустые домены
        return []

    try:
        result = subprocess.run(
            ["nslookup", domain, DNS_SERVER], capture_output=True, text=True, check=True
        )

        lines = result.stdout.splitlines()
        ip_list = []
        parse_addresses = False

        for line in lines:
            # Начинаем парсинг только после секции "Non-authoritative answer:"
            if "Non-authoritative answer:" in line:
                parse_addresses = True
                continue

            # Парсим только строки с "Address:" после секции ответа
            if parse_addresses and "Address:" in line:
                parts = line.split("Address:")
                if len(parts) > 1:
                    ip = parts[1].strip()
                    # Проверяем, что это действительно правильный IPv4
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                        ip_list.append(ip)

        return list(set(ip_list))  # Возвращаем уникальные IP
    except subprocess.CalledProcessError:
        print(f"[!] Ошибка получения IP для домена: {domain}")
        return []


def read_config_and_extract_routes():
    """Чтение конфига и извлечение существующих маршрутов и дополнительных строк"""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config_content = f.read()

        # Ищем блок маршрутов
        block_pattern = f"{BEGIN_MARKER}(.*?){END_MARKER}"
        match = re.search(block_pattern, config_content, re.DOTALL)

        if not match:
            print(
                "[!] Блок маршрутов не найден. Убедитесь, что в конфиге есть маркеры "
                f"{BEGIN_MARKER} и {END_MARKER}"
            )
            return {}, [], config_content

        route_block = match.group(1)
        existing_route_lines = []  # Сохраняем полные строки маршрутов
        existing_ip_map = {}  # Словарь IP -> полная строка маршрута
        non_route_lines = []  # Строки, не являющиеся маршрутами (dhcp-option и т.д.)

        # Обрабатываем блок маршрутов построчно
        for line in route_block.splitlines():
            line = line.strip()
            if not line:
                continue

            if 'push "route' in line:
                # Это строка маршрута
                ip_match = re.search(
                    r"route\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line
                )
                if ip_match:
                    ip = ip_match.group(1)
                    existing_ip_map[ip] = line
                    existing_route_lines.append(line)
            else:
                # Это не маршрут, сохраняем
                non_route_lines.append(line)

        return existing_ip_map, non_route_lines, config_content
    except (IOError, OSError) as e:
        print(f"[!] Ошибка при чтении конфига: {e}")
        return {}, [], ""
    except re.error as e:
        print(f"[!] Ошибка в регулярном выражении: {e}")
        return {}, [], ""


def backup_config():
    """Создание резервной копии конфига"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"server.conf.{timestamp}")

    try:
        shutil.copy2(CONFIG_PATH, backup_path)
        print(f"[✓] Создана резервная копия: {backup_path}")
        return True
    except (IOError, OSError) as e:
        print(f"[!] Ошибка при создании резервной копии: {e}")
        return False


def update_config(config_content, existing_ip_map, non_route_lines, ip_to_domains):
    """Обновление конфига с новыми маршрутами, сохраняя дополнительные строки"""
    # Создаем обновленный блок маршрутов
    new_routes_block = []
    new_routes_block.append(BEGIN_MARKER)

    # Сначала добавляем все не-маршрутные строки (dhcp-option и т.д.)
    for line in non_route_lines:
        new_routes_block.append(line)

    # Затем добавляем существующие маршруты, сохраняя их исходный формат
    existing_ips = set(existing_ip_map.keys())
    for ip in existing_ips:
        if ip in ip_to_domains:
            # Для IP, присутствующих в новых доменах, обновляем комментарий
            domains_str = " | ".join(ip_to_domains[ip])
            route_line = ROUTE_TEMPLATE.format(ip=ip, domains=domains_str)
        else:
            # Для IP, не присутствующих в новых доменах, сохраняем исходную строку
            route_line = existing_ip_map[ip]
        new_routes_block.append(route_line)

    # Затем добавляем новые маршруты
    for ip in ip_to_domains:
        if ip not in existing_ips:
            domains_str = " | ".join(ip_to_domains[ip])
            route_line = ROUTE_TEMPLATE.format(ip=ip, domains=domains_str)
            new_routes_block.append(route_line)

    new_routes_block.append(END_MARKER)
    new_block_content = "\n".join(new_routes_block)

    # Заменяем старый блок на новый
    block_pattern = f"{BEGIN_MARKER}.*?{END_MARKER}"
    updated_content = re.sub(
        block_pattern, new_block_content, config_content, flags=re.DOTALL
    )

    # Записываем обновленный конфиг
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(updated_content)
        print("[✓] Конфигурация обновлена")
        return True
    except (IOError, OSError) as e:
        print(f"[!] Ошибка при обновлении конфига: {e}")
        return False


def restart_openvpn():
    """Перезапуск OpenVPN"""
    try:
        print(f"[→] Выполнение команды: {RESTART_COMMAND}")
        result = subprocess.run(
            RESTART_COMMAND, shell=True, capture_output=True, text=True, check=False
        )

        if result.returncode == 0:
            print("[✓] OpenVPN успешно перезапущен")
            return True
        else:
            print(f"[!] Ошибка при перезапуске OpenVPN: {result.stderr}")
            return False
    except (subprocess.SubprocessError, OSError) as e:
        print(f"[!] Ошибка при выполнении команды перезапуска: {e}")
        return False


def main():
    """Основная функция, управляющая процессом обновления маршрутов OpenVPN"""
    print("[i] Запуск скрипта обновления маршрутов OpenVPN...")

    # Шаг 1: Чтение конфига и извлечение существующих маршрутов
    existing_ip_map, non_route_lines, config_content = read_config_and_extract_routes()
    print(f"[i] Найдено существующих маршрутов: {len(existing_ip_map)}")
    print(f"[i] Найдено дополнительных строк: {len(non_route_lines)}")

    # Шаг 2: Сбор новых IP для доменов
    print("[i] Сбор IP-адресов для доменов...")
    ip_to_domains = defaultdict(list)
    all_results = {}

    for domain in DOMAINS:
        if not domain:
            continue
        print(f"[→] Обработка домена: {domain}")
        ips = get_ipv4_addresses(domain)
        print(f"[i] Найдено IP-адресов: {ips}")
        all_results[domain] = ips

        # Группируем домены по IP
        for ip in ips:
            ip_to_domains[ip].append(domain)

    # Шаг 3: Определение новых маршрутов
    existing_ips = set(existing_ip_map.keys())
    new_ips = set(ip_to_domains.keys()) - existing_ips

    if not new_ips:
        print("[✓] Новых маршрутов не обнаружено. Конфигурация не изменена.")
        return

    print(f"[i] Обнаружено новых маршрутов: {len(new_ips)}")
    for ip in new_ips:
        domains_str = " | ".join(ip_to_domains[ip])
        print(f"[+] {ip} -> {domains_str}")

    # Шаг 4: Обновление конфига
    if backup_config():
        if update_config(
            config_content, existing_ip_map, non_route_lines, ip_to_domains
        ):
            # Шаг 5: Перезапуск OpenVPN
            restart_openvpn()
        else:
            print("[!] Обновление конфига не выполнено. OpenVPN не перезапущен.")
    else:
        print("[!] Резервное копирование не выполнено. Обновление конфига отменено.")


if __name__ == "__main__":
    main()
