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

import aiohttp

# Источники прокси.
# Каждый источник — словарь с полями:
#   url       — адрес запроса (обязательно)
#   format    — формат ответа: 'text', 'json', 'html' (обязательно)
#   method    — HTTP-метод, по умолчанию GET
#   params    — query-параметры (?key=value)
#   headers   — заголовки запроса
#   data      — тело запроса (для POST)
#
# Для format='json' дополнительные поля:
#   json_path — ключ (или список ключей) для доступа к массиву прокси внутри ответа.
#               Например: 'proxies' или ['data', 'list'].
#               Если не указан — ожидается что корень ответа и есть массив.
#
# Для format='html' дополнительные поля:
#   html_pattern — регулярное выражение для извлечения прокси из HTML.
#                  Должно содержать именованные группы: (?P<server>...), (?P<port>...), (?P<secret>...)
#                  Если не указан — ищем tg:// и https://t.me/proxy ссылки в тексте страницы.
PROXY_SOURCES = [
    {
        'url': 'https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/proxies.txt',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/sakha1370/V2rayCollector/refs/heads/main/active_mtproto_proxies.txt',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/white-list_mtproto',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/SoliSpirit/mtproto/refs/heads/master/all_proxies.txt',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/refs/heads/main/proxy_list.txt',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/devho3ein/tg-proxy/refs/heads/main/proxys/All_Proxys.txt',
        'format': 'text',
    },
    {
        'url': 'https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt',
        'format': 'text',
    },
    {
        'url': 'https://mtpro.xyz/api/',
        'format': 'json',
        # json_path не указан — корень ответа и есть массив объектов
        'params': {'type': 'mtprotoS'},
        'headers': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0',
            'Accept': '*/*',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': 'https://mtpro.xyz/mtproto-ru',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        },
    },
    # Пример источника с вложенным JSON:
    # {
    #     'url': 'https://example.com/api/proxies',
    #     'format': 'json',
    #     'json_path': ['data', 'proxies'],  # resp['data']['proxies'] -> массив
    # },
    #
    # Пример HTML-источника со своим паттерном:
    # {
    #     'url': 'https://example.com/proxies',
    #     'format': 'html',
    #     'html_pattern': r'(?P<server>[\d.]+):(?P<port>\d+):(?P<secret>[a-fA-F0-9]+)',
    # },
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

# Возможные названия полей адреса/порта/секрета в JSON-объектах
_JSON_HOST_FIELDS   = ('host', 'server', 'ip', 'address', 'addr')
_JSON_PORT_FIELDS   = ('port',)
_JSON_SECRET_FIELDS = ('secret',)


# ---------------------------------------------------------------------------
# Парсеры по формату
# ---------------------------------------------------------------------------

def parse_proxy_line(line: str) -> Optional[Dict]:
    """
    Парсит одну строку и извлекает параметры прокси.
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
        port = int(port)
        if not 0 < port <= 65535:
            return None
        return {'ip': server, 'port': port, 'secret': secret, 'original': line}

    # Пробуем формат proxy:port:secret
    parts = line.split(':')
    if len(parts) >= 3:
        try:
            port = int(parts[1])
            if not 0 < port <= 65535:
                return None
            return {'ip': parts[0], 'port': port, 'secret': parts[2], 'original': line}
        except ValueError:
            pass

    return None


def parse_text(text: str) -> List[Dict]:
    """
    Построчный парсер для plain-text источников.
    """
    proxies = []
    for line in text.splitlines():
        proxy = parse_proxy_line(line)
        if proxy:
            proxies.append(proxy)
    return proxies


def _json_item_to_proxy(item: Dict) -> Optional[Dict]:
    """
    Извлекает прокси из одного JSON-объекта,
    перебирая известные варианты названий полей.
    """
    host   = next((item[f] for f in _JSON_HOST_FIELDS   if f in item), None)
    port   = next((item[f] for f in _JSON_PORT_FIELDS   if f in item), None)
    secret = next((item[f] for f in _JSON_SECRET_FIELDS if f in item), None)

    if host and port and secret:
        try:
            port = int(port)
            if not 0 < port <= 65535:
                return None
            return {
                'ip': str(host),
                'port': port,
                'secret': str(secret),
                'original': json.dumps(item),
            }
        except (ValueError, TypeError):
            pass

    return None


def parse_json(text: str, json_path: Optional[List[str]] = None) -> List[Dict]:
    """
    Парсер для JSON-источников.
    json_path — список ключей для спуска к массиву прокси внутри ответа,
    например ['data', 'proxies']. Если не указан — ожидается массив на верхнем уровне.
    """
    try:
        data = json.loads(text)

        # Спускаемся по json_path если указан
        if json_path:
            for key in json_path:
                data = data[key]

        if not isinstance(data, list):
            print(f"  Ожидался массив, получен {type(data).__name__}")
            return []

        proxies = []
        for item in data:
            if isinstance(item, dict):
                proxy = _json_item_to_proxy(item)
                if proxy:
                    proxies.append(proxy)
        return proxies

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"  Ошибка парсинга JSON: {e}")
        return []


def parse_html(text: str, html_pattern: Optional[str] = None) -> List[Dict]:
    """
    Парсер для HTML-источников.
    Если html_pattern указан — применяет его (нужны группы server/port/secret).
    Иначе ищет tg:// и https://t.me/proxy ссылки в тексте страницы.
    """
    proxies = []

    if html_pattern:
        # Пользовательский паттерн с именованными группами
        for match in re.finditer(html_pattern, text):
            try:
                groups = match.groupdict()
                proxies.append({
                    'ip': groups['server'],
                    'port': int(groups['port']),
                    'secret': groups['secret'],
                    'original': match.group(0),
                })
            except (KeyError, ValueError):
                pass
    else:
        # Ищем tg-ссылки прямо в HTML
        for line in text.splitlines():
            proxy = parse_proxy_line(line)
            if proxy:
                proxies.append(proxy)

    return proxies


def parse_source_response(text: str, source: Dict) -> List[Dict]:
    """
    Выбирает и вызывает нужный парсер на основе поля format источника.
    """
    fmt = source.get('format', 'text')

    if fmt == 'json':
        # json_path может быть строкой или списком строк
        path = source.get('json_path')
        if isinstance(path, str):
            path = [path]
        return parse_json(text, path)

    if fmt == 'html':
        return parse_html(text, source.get('html_pattern'))

    # По умолчанию — text
    return parse_text(text)


def clean_proxy_url(proxy: Dict) -> str:
    """
    Очищает ссылку от рекламных параметров (channel, и т.д.)
    """
    return f"tg://proxy?server={proxy['ip']}&port={proxy['port']}&secret={proxy['secret']}"


# ---------------------------------------------------------------------------
# Загрузка источников
# ---------------------------------------------------------------------------

async def fetch_source(session: aiohttp.ClientSession, source: Dict) -> List[Dict]:
    """
    Загружает один источник и возвращает список распарсенных прокси.
    Поддерживает произвольные method/params/headers/data через конфиг источника.
    """
    url = source['url']
    method = source.get('method', 'GET').upper()
    params = source.get('params')
    headers = source.get('headers')
    data = source.get('data')

    try:
        async with session.request(
            method, url,
            params=params,
            headers=headers,
            data=data,
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
        ) as resp:
            text = await resp.text(encoding='utf-8', errors='ignore')
            proxies = parse_source_response(text, source)
            print(f"  {url} — получено {len(proxies)} прокси")
            return proxies
    except Exception as e:
        print(f"  Ошибка загрузки {url}: {e}")
        return []


# ---------------------------------------------------------------------------
# Проверка доступности
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Гео-определение
# ---------------------------------------------------------------------------

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


def resolve_host(host: str) -> str:
    """
    Резолвит домен в IP-адрес. Если host уже является IP — возвращает как есть.
    """
    try:
        # getaddrinfo возвращает список кортежей, берём первый IPv4-адрес
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return infos[0][4][0]
    except socket.gaierror:
        return host


def fetch_geo_batch(hosts: List[str]) -> Dict[str, Tuple[str, str]]:
    """
    Определяет страну для списка IP/доменов через ip-api.com/batch.
    Домены предварительно резолвятся в IP.
    Отправляет батчами по GEO_BATCH_SIZE штук.
    Возвращает словарь {оригинальный host: (страна, флаг)}.
    """
    results = {}

    # Резолвим домены в IP, запоминаем маппинг host -> ip
    host_to_ip = {host: resolve_host(host) for host in hosts}

    # Инвертируем: ip -> список хостов (несколько доменов могут вести на один IP)
    ip_to_hosts: Dict[str, List[str]] = {}
    for host, ip in host_to_ip.items():
        ip_to_hosts.setdefault(ip, []).append(host)

    unique_ips = list(ip_to_hosts.keys())

    for i in range(0, len(unique_ips), GEO_BATCH_SIZE):
        batch = unique_ips[i:i + GEO_BATCH_SIZE]
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
                        geo = (country, get_flag_emoji(code) if code else '🌐')
                    else:
                        geo = ('Неизвестно', '🌐')

                    # Записываем результат для всех хостов, которые резолвятся в этот IP
                    for host in ip_to_hosts.get(ip, [ip]):
                        results[host] = geo

                # Если лимит исчерпан — ждём сброса окна перед следующим батчем
                if x_rl == '0':
                    print(f"  ⏳ Лимит ip-api.com исчерпан, ждём {x_ttl}с...")
                    time.sleep(int(x_ttl) + 1)

        except Exception as e:
            print(f"  Ошибка geo-батча: {e}")
            # Помечаем все хосты батча как неизвестные
            for ip in batch:
                for host in ip_to_hosts.get(ip, [ip]):
                    results.setdefault(host, ('Неизвестно', '🌐'))

    return results


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

async def main():
    print("🔍 Запуск проверки MTProto прокси...")
    print(f"Источники: {len(PROXY_SOURCES)}")

    # Загружаем все источники через единую aiohttp-сессию
    print("\n📥 Загрузка источников...")
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(session, src) for src in PROXY_SOURCES]
        results = await asyncio.gather(*tasks)

    # Дедуплицируем прокси по ip:port:secret
    print("\n📋 Дедупликация прокси...")
    all_proxies = []
    seen = set()

    for proxies in results:
        for proxy in proxies:
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
    checked = await asyncio.gather(*tasks)

    working_proxies = [p for p in checked if p is not None]
    print(f"Рабочих прокси: {len(working_proxies)}")

    # Определяем страну для всех рабочих прокси одним батч-запросом
    print("\n🌍 Определение стран (batch)...")
    loop = asyncio.get_event_loop()
    unique_hosts = list({p['ip'] for p in working_proxies})
    geo_map = await loop.run_in_executor(None, fetch_geo_batch, unique_hosts)

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
