from __future__ import annotations

from .models import ProxySource


OUTPUT_FILE = "proxies.json"

SOCKET_TIMEOUT = 3
HTTP_TIMEOUT = 10
MAX_CONCURRENT = 50

GEO_BATCH_SIZE = 100
GEO_BATCH_URL = "http://ip-api.com/batch?fields=status,country,countryCode,query"

JSON_HOST_FIELDS = ("host", "server", "ip", "address", "addr")
JSON_PORT_FIELDS = ("port",)
JSON_SECRET_FIELDS = ("secret",)

PROXY_SOURCES = [
    ProxySource(
        url="https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/proxies.txt",
        format="text",
    ),
    ProxySource(
        url="https://raw.githubusercontent.com/sakha1370/V2rayCollector/refs/heads/main/active_mtproto_proxies.txt",
        format="text",
    ),
    ProxySource(
        url="https://raw.githubusercontent.com/SoliSpirit/mtproto/refs/heads/master/all_proxies.txt",
        format="text",
    ),
    ProxySource(
        url="https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt",
        format="text",
    ),
    ProxySource(
        url="https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
        format="text",
    ),
    ProxySource(
        url="https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/refs/heads/main/proxy_list.txt",
        format="text",
    ),
    ProxySource(
        url="https://raw.githubusercontent.com/devho3ein/tg-proxy/refs/heads/main/proxys/All_Proxys.txt",
        format="text",
    ),
    ProxySource(
        url="https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
        format="text",
    ),
]
