from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProxySource:
    url: str
    format: str = "text"
    method: str = "GET"
    params: dict | None = None
    headers: dict | None = None
    data: str | None = None
    json_path: list[str] | None = None
    html_pattern: str | None = None


@dataclass(frozen=True)
class ProxyCandidate:
    ip: str
    port: int
    secret: str
    original: str = ""
    is_fake_tls: bool = False
    fake_tls_domain: str | None = None

    @property
    def dedupe_key(self) -> str:
        return f"{self.ip}:{self.port}:{self.secret}"


@dataclass(frozen=True)
class CheckedProxy:
    ip: str
    port: int
    secret: str
    ping: float
    link: str
    country: str = "Unknown"
    flag: str = "Unknown"
    is_fake_tls: bool = False
    fake_tls_domain: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        payload = {
            "ip": self.ip,
            "port": self.port,
            "secret": self.secret,
            "ping": self.ping,
            "link": self.link,
            "country": self.country,
            "flag": self.flag,
        }
        if self.is_fake_tls:
            payload["is_fake_tls"] = True
        if self.fake_tls_domain:
            payload["fake_tls_domain"] = self.fake_tls_domain
        if self.metadata:
            payload.update(self.metadata)
        return payload
