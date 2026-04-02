from __future__ import annotations


def decode_fake_tls_domain(secret: str) -> str | None:
    if not secret.startswith("ee") or len(secret) <= 2:
        return None

    try:
        # Fake TLS secret format:
        # ee + 16-byte secret (32 hex chars) + optional hex-encoded domain
        payload = secret[34:]
        if not payload:
            return None

        chars: list[str] = []
        for index in range(0, len(payload) - 1, 2):
            value = int(payload[index:index + 2], 16)
            if value == 0:
                break
            if 32 <= value <= 126:
                chars.append(chr(value))

        domain = "".join(chars).strip().lower()
        return domain or None
    except ValueError:
        return None


def build_proxy_metadata(secret: str) -> tuple[bool, str | None]:
    domain = decode_fake_tls_domain(secret)
    return domain is not None, domain
