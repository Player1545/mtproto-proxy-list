from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import aiohttp

from .checker import check_proxy
from .config import MAX_CONCURRENT, OUTPUT_FILE, PROXY_SOURCES
from .geo import fetch_geo_batch
from .models import CheckedProxy, ProxyCandidate
from .sources import fetch_source


async def run() -> int:
    print("Starting MTProto proxy check...")
    print(f"Sources: {len(PROXY_SOURCES)}")

    print("\nLoading sources...")
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*(fetch_source(session, source) for source in PROXY_SOURCES))

    all_proxies = deduplicate_candidates(results)
    print(f"\nUnique proxies found: {len(all_proxies)}")

    print("\nChecking availability...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    checked = await asyncio.gather(*(check_proxy(proxy, semaphore) for proxy in all_proxies))

    working_proxies = [proxy for proxy in checked if proxy is not None]
    print(f"Reachable proxies: {len(working_proxies)}")

    print("\nDetecting country (batch)...")
    unique_hosts = list({proxy.ip for proxy in working_proxies})
    async with aiohttp.ClientSession() as session:
        geo_map = await fetch_geo_batch(session, unique_hosts)

    enriched = attach_geo(working_proxies, geo_map)
    enriched.sort(key=lambda proxy: proxy.ping)

    output_data = build_output_payload(enriched)
    write_output(output_data, OUTPUT_FILE)

    print(f"\nSaved result to {OUTPUT_FILE}")
    return len(enriched)


def deduplicate_candidates(groups: list[list[ProxyCandidate]]) -> list[ProxyCandidate]:
    proxies: list[ProxyCandidate] = []
    seen: set[str] = set()

    for group in groups:
        for proxy in group:
            if proxy.dedupe_key in seen:
                continue
            seen.add(proxy.dedupe_key)
            proxies.append(proxy)

    return proxies


def attach_geo(
    proxies: list[CheckedProxy],
    geo_map: dict[str, tuple[str, str]],
) -> list[CheckedProxy]:
    enriched: list[CheckedProxy] = []
    for proxy in proxies:
        country, flag = geo_map.get(proxy.ip, ("Unknown", "🌐"))
        enriched.append(
            CheckedProxy(
                ip=proxy.ip,
                port=proxy.port,
                secret=proxy.secret,
                ping=proxy.ping,
                link=proxy.link,
                country=country,
                flag=flag,
                is_fake_tls=proxy.is_fake_tls,
                fake_tls_domain=proxy.fake_tls_domain,
            )
        )
    return enriched


def build_output_payload(proxies: list[CheckedProxy]) -> dict:
    return {
        "last_update": int(time.time()),
        "proxies": [proxy.as_dict() for proxy in proxies],
    }


def write_output(payload: dict, output_file: str) -> None:
    Path(output_file).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
