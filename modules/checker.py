from __future__ import annotations

import asyncio
import time

from .config import SOCKET_TIMEOUT
from .models import CheckedProxy, ProxyCandidate
from .parsers import clean_proxy_url


async def check_proxy_ping(ip: str, port: int) -> float | None:
    if not ip or not isinstance(ip, str) or len(ip) == 0:
        return None
    try:
        ip.encode('idna')
    except UnicodeError:
        return None

    try:
        start = time.time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=SOCKET_TIMEOUT,
        )
        elapsed = (time.time() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return round(elapsed, 2)
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError, UnicodeError, ValueError):
        return None


async def check_proxy(proxy: ProxyCandidate, semaphore: asyncio.Semaphore) -> CheckedProxy | None:
    async with semaphore:
        ping = await check_proxy_ping(proxy.ip, proxy.port)
        if ping is None:
            return None

        return CheckedProxy(
            ip=proxy.ip,
            port=proxy.port,
            secret=proxy.secret,
            ping=ping,
            link=clean_proxy_url(proxy),
            is_fake_tls=proxy.is_fake_tls,
            fake_tls_domain=proxy.fake_tls_domain,
        )
