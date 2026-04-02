from __future__ import annotations

import json
import re

from .config import JSON_HOST_FIELDS, JSON_PORT_FIELDS, JSON_SECRET_FIELDS
from .metadata import build_proxy_metadata
from .models import ProxyCandidate, ProxySource


PROXY_URL_PATTERN = re.compile(
    r"(?:tg://proxy|https://t\.me/proxy)[?&]server=([^&]+)&port=(\d+)&secret=([^&]+)"
)


def parse_proxy_line(line: str) -> ProxyCandidate | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = PROXY_URL_PATTERN.search(line)
    if match:
        ip, port, secret = match.groups()
        return build_candidate(ip, port, secret, line)

    parts = line.rsplit(":", 2)
    if len(parts) == 3:
        ip, port, secret = parts
        return build_candidate(ip, port, secret, line)

    return None


def parse_text(text: str) -> list[ProxyCandidate]:
    proxies: list[ProxyCandidate] = []
    for line in text.splitlines():
        proxy = parse_proxy_line(line)
        if proxy:
            proxies.append(proxy)
    return proxies


def parse_json(text: str, json_path: list[str] | None = None) -> list[ProxyCandidate]:
    try:
        data = json.loads(text)
        if json_path:
            for key in json_path:
                data = data[key]

        if not isinstance(data, list):
            print(f"  Expected list, got {type(data).__name__}")
            return []
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"  JSON parsing error: {exc}")
        return []

    proxies: list[ProxyCandidate] = []
    for item in data:
        if isinstance(item, dict):
            proxy = json_item_to_proxy(item)
            if proxy:
                proxies.append(proxy)
    return proxies


def parse_html(text: str, html_pattern: str | None = None) -> list[ProxyCandidate]:
    if not html_pattern:
        return parse_text(text)

    proxies: list[ProxyCandidate] = []
    for match in re.finditer(html_pattern, text):
        try:
            groups = match.groupdict()
            proxy = build_candidate(
                groups["server"],
                groups["port"],
                groups["secret"],
                match.group(0),
            )
            if proxy:
                proxies.append(proxy)
        except KeyError:
            continue
    return proxies


def parse_source_response(text: str, source: ProxySource) -> list[ProxyCandidate]:
    if source.format == "json":
        return parse_json(text, source.json_path)
    if source.format == "html":
        return parse_html(text, source.html_pattern)
    return parse_text(text)


def clean_proxy_url(proxy: ProxyCandidate | CheckedProxyLike) -> str:
    return f"tg://proxy?server={proxy.ip}&port={proxy.port}&secret={proxy.secret}"


def json_item_to_proxy(item: dict) -> ProxyCandidate | None:
    ip = next((item[field] for field in JSON_HOST_FIELDS if field in item), None)
    port = next((item[field] for field in JSON_PORT_FIELDS if field in item), None)
    secret = next((item[field] for field in JSON_SECRET_FIELDS if field in item), None)

    if ip is None or port is None or secret is None:
        return None

    return build_candidate(str(ip), port, str(secret), json.dumps(item))


def build_candidate(ip: str, port: str | int, secret: str, original: str) -> ProxyCandidate | None:
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return None

    if not ip or not secret or not 0 < port_number <= 65535:
        return None

    is_fake_tls, fake_tls_domain = build_proxy_metadata(secret)
    return ProxyCandidate(
        ip=ip,
        port=port_number,
        secret=secret,
        original=original,
        is_fake_tls=is_fake_tls,
        fake_tls_domain=fake_tls_domain,
    )


class CheckedProxyLike:
    ip: str
    port: int
    secret: str
