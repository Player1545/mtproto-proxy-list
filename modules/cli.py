from __future__ import annotations

import asyncio

from .pipeline import run


async def async_main() -> int:
    return await run()


def main() -> int:
    return asyncio.run(async_main())
