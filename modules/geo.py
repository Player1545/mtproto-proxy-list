from __future__ import annotations

import asyncio
import socket

import aiohttp

from .config import GEO_BATCH_SIZE, GEO_BATCH_URL, HTTP_TIMEOUT


def get_flag_emoji(country_code: str) -> str:
    if len(country_code) != 2:
        return "🌐"

    base = 0x1F1E6
    return (
        chr(base + ord(country_code[0].upper()) - ord("A"))
        + chr(base + ord(country_code[1].upper()) - ord("A"))
    )


async def resolve_host(host: str) -> str:
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        return infos[0][4][0]
    except socket.gaierror:
        return host


async def fetch_geo_batch(
    session: aiohttp.ClientSession,
    hosts: list[str],
) -> dict[str, tuple[str, str]]:
    results: dict[str, tuple[str, str]] = {}

    resolved = await asyncio.gather(*(resolve_host(host) for host in hosts))
    host_to_ip = dict(zip(hosts, resolved))

    ip_to_hosts: dict[str, list[str]] = {}
    for host, ip in host_to_ip.items():
        ip_to_hosts.setdefault(ip, []).append(host)

    unique_ips = list(ip_to_hosts.keys())
    for start in range(0, len(unique_ips), GEO_BATCH_SIZE):
        batch = unique_ips[start:start + GEO_BATCH_SIZE]

        try:
            async with session.post(
                GEO_BATCH_URL,
                json=batch,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
            ) as response:
                x_rl = response.headers.get("X-Rl", "1")
                x_ttl = response.headers.get("X-Ttl", "0")

                data = await response.json(content_type=None)
                for entry in data:
                    ip = entry.get("query", "")
                    if entry.get("status") == "success":
                        country = entry.get("country", "Unknown")
                        code = entry.get("countryCode", "")
                        geo = (country, get_flag_emoji(code) if code else "🌐")
                    else:
                        geo = ("Unknown", "🌐")

                    for host in ip_to_hosts.get(ip, [ip]):
                        results[host] = geo

                if x_rl == "0":
                    print(f"  ip-api rate limit reached, waiting {x_ttl}s...")
                    await asyncio.sleep(int(x_ttl) + 1)
        except Exception as exc:
            print(f"  Geo batch error: {exc}")
            for ip in batch:
                for host in ip_to_hosts.get(ip, [ip]):
                    results.setdefault(host, ("Unknown", "🌐"))

    return results
