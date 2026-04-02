from __future__ import annotations

import aiohttp

from .config import HTTP_TIMEOUT
from .models import ProxyCandidate, ProxySource
from .parsers import parse_source_response


async def fetch_source(session: aiohttp.ClientSession, source: ProxySource) -> list[ProxyCandidate]:
    try:
        async with session.request(
            source.method.upper(),
            source.url,
            params=source.params,
            headers=source.headers,
            data=source.data,
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
        ) as response:
            response.raise_for_status()
            text = await response.text(encoding="utf-8", errors="ignore")
            proxies = parse_source_response(text, source)
            print(f"  {source.url} -> received {len(proxies)} proxies")
            return proxies
    except Exception as exc:
        print(f"  Failed to fetch {source.url}: {exc}")
        return []
