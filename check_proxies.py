#!/usr/bin/env python3
"""
MTProto Proxy Checker
Парсит прокси из источников, проверяет доступность и определяет страну.
"""

import asyncio
import json
import re
import socket
import time
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError
from typing import Optional, Dict, List, Tuple

# Источники прокси
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/proxies.txt",
    "https://raw.githubusercontent.com/sakha1370/V2rayCollector/refs/heads/main/active_mtproto_proxies.txt",
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/white-list_mtproto",
]

# Файл результата
OUTPUT_FILE = "proxies.json"

# Таймауты
SOCKET_TIMEOUT = 3
HTTP_TIMEOUT = 10

# Максимальное количество одновременных проверок
MAX_CONCURRENT = 50

# ip-api.com /batch: до 100 IP за запрос, лимит 15 req/min без ключа
GEO_BATCH_SIZE = 100
GEO_BATCH_URL = "http://ip-api.com/batch?fields=status,country,countryCode,query"


def parse_proxy_line(line: str) -> Optional[Dict]:
    """
    Парсит строку с прокси и извлекает параметры.
    Поддерживает форматы:
    - tg://proxy?server=...&port=...&secret=...
    - https://t.me/proxy?server=...&port=...&secret=...
    - proxy:port:secret
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    # Извлекаем параметры из tg:// или https://t.me/proxy ссылок
    pattern = r'(?:tg://proxy|https://t\.me/proxy)[?&]server=([^&]+)&port=(\d+)&secret=([^&]+)'
    match = re.search(pattern, line)
    
    if match:
        server, port, secret = match.groups()
        return {
            'ip': server,
            'port': int(port),
            'secret': secret,
            'original': line
        }
    
    # Пробуем формат proxy:port:secret
    parts = line.split(':')
    if len(parts) >= 3:
        try:
            return {
                'ip': parts[0],
                'port': int(parts[1]),
                'secret': parts[2],
                'original': line
            }
        except ValueError:
            pass
    
    return None


def clean_proxy_url(proxy: Dict) -> str:
    """
    Очищает ссылку от рекламных параметров (channel, и т.д.)
    """
    return f"tg://proxy?server={proxy['ip']}&port={proxy['port']}&secret={proxy['secret']}"


async def check_proxy_ping(ip: str, port: int) -> Optional[float]:
    """
    Проверяет доступность прокси и измеряет пинг.
    Возвращает пинг в мс или None если недоступен.
    """
    loop = asyncio.get_event_loop()
    
    def try_connect() -> Optional[float]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            
            start = time.time()
            result = sock.connect_ex((ip, port))
            elapsed = (time.time() - start) * 1000  # конвертируем в мс
            
            sock.close()
            
            if result == 0:
                return round(elapsed, 2)
            return None
        except (socket.error, socket.timeout, OSError):
            return None

    return await loop.run_in_executor(None, try_connect)


def get_flag_emoji(country_code: str) -> str:
    """
    Конвертирует код страны (US, DE, etc.) в emoji флаг.
    """
    if len(country_code) != 2:
        return '🌐'

    # Unicode magic для флагов
    base = 0x1F1E6
    return chr(base + ord(country_code[0].upper()) - ord('A')) + \
           chr(base + ord(country_code[1].upper()) - ord('A'))


def fetch_geo_batch(ips: List[str]) -> Dict[str, Tuple[str, str]]:
    """
    Определяет страну для списка IP через ip-api.com/batch.
    Отправляет батчами по GEO_BATCH_SIZE штук.
    Возвращает словарь {ip: (страна, флаг)}.
    """
    results = {}

    for i in range(0, len(ips), GEO_BATCH_SIZE):
        batch = ips[i:i + GEO_BATCH_SIZE]
        body = json.dumps(batch).encode()

        try:
            req = Request(
                GEO_BATCH_URL,
                data=body,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                # Проверяем остаток лимита из заголовков
                x_rl = resp.headers.get('X-Rl', '1')
                x_ttl = resp.headers.get('X-Ttl', '0')

                data = json.loads(resp.read().decode())

                for entry in data:
                    ip = entry.get('query', '')
                    if entry.get('status') == 'success':
                        country = entry.get('country', 'Неизвестно')
                        code = entry.get('countryCode', '')
                        results[ip] = (country, get_flag_emoji(code) if code else '🌐')
                    else:
                        results[ip] = ('Неизвестно', '🌐')

                # Если лимит исчерпан — ждём сброса окна перед следующим батчем
                if x_rl == '0':
                    print(f"  ⏳ Лимит ip-api.com исчерпан, ждём {x_ttl}с...")
                    time.sleep(int(x_ttl) + 1)

        except Exception as e:
            print(f"  Ошибка geo-батча: {e}")
            # Помечаем все IP батча как неизвестные
            for ip in batch:
                results.setdefault(ip, ('Неизвестно', '🌐'))

    return results


async def fetch_source(url: str) -> str:
    """
    Загружает контент из источника.
    """
    try:
        loop = asyncio.get_event_loop()
        def _fetch():
            with urlopen(url, timeout=HTTP_TIMEOUT) as resp:
                return resp.read().decode('utf-8', errors='ignore')
        return await loop.run_in_executor(None, _fetch)
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return ""


async def check_proxy(proxy: Dict, semaphore: asyncio.Semaphore) -> Optional[Dict]:
    """
    Проверяет доступность прокси через ping.
    Возвращает прокси с пингом или None если недоступен.
    """
    async with semaphore:
        ping = await check_proxy_ping(proxy['ip'], proxy['port'])
        if ping is None:
            return None

        return {
            'ip': proxy['ip'],
            'port': proxy['port'],
            'secret': proxy['secret'],
            'ping': ping,
            'link': clean_proxy_url(proxy),
        }


async def main():
    print("🔍 Запуск проверки MTProto прокси...")
    print(f"Источники: {len(PROXY_SOURCES)}")

    # Загружаем все источники
    print("\n📥 Загрузка источников...")
    contents = await asyncio.gather(*[fetch_source(url) for url in PROXY_SOURCES])

    # Парсим все прокси
    print("\n📋 Парсинг прокси...")
    all_proxies = []
    seen = set()

    for content in contents:
        for line in content.split('\n'):
            proxy = parse_proxy_line(line)
            if proxy:
                # Уникальность по ip:port:secret
                key = f"{proxy['ip']}:{proxy['port']}:{proxy['secret']}"
                if key not in seen:
                    seen.add(key)
                    all_proxies.append(proxy)

    print(f"Найдено уникальных прокси: {len(all_proxies)}")

    # Проверяем доступность через ping
    print("\n✅ Проверка доступности...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    tasks = [check_proxy(p, semaphore) for p in all_proxies]
    results = await asyncio.gather(*tasks)

    working_proxies = [p for p in results if p is not None]
    print(f"Рабочих прокси: {len(working_proxies)}")

    # Определяем страну для всех рабочих прокси одним батч-запросом
    print("\n🌍 Определение стран (batch)...")
    loop = asyncio.get_event_loop()
    unique_ips = list({p['ip'] for p in working_proxies})
    geo_map = await loop.run_in_executor(None, fetch_geo_batch, unique_ips)

    # Подставляем гео в результаты
    for proxy in working_proxies:
        country, flag = geo_map.get(proxy['ip'], ('Неизвестно', '🌐'))
        proxy['country'] = country
        proxy['flag'] = flag

    # Сортируем по пингу
    working_proxies.sort(key=lambda x: x['ping'])

    print(f"\n✅ Рабочих прокси: {len(working_proxies)}")

    # Сохраняем результат
    output_data = {
        'last_update': int(time.time()),
        'proxies': working_proxies,
    }

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\n💾 Результат сохранён в {OUTPUT_FILE}")
    print(f"⏰ Время завершения: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return len(working_proxies)


if __name__ == "__main__":
    result = asyncio.run(main())
    exit(0 if result > 0 else 1)
