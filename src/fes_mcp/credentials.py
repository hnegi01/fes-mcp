"""Per-session Sisense credentials.

A credential is (domain, token, ssl_verify) — enough to build a PySisense
client. Where it comes from varies by mode:
- dev/local: the server's env settings (one credential for everyone)
- oauth:     the login bridge stores one credential per authenticated user
- gateway:   a trusted upstream injects one per request (future)
"""

from __future__ import annotations

from dataclasses import dataclass

from .settings import Settings


@dataclass(frozen=True)
class SisenseCredential:
    domain: str
    token: str
    ssl_verify: bool = True

    def cache_key(self) -> tuple[str, str, bool]:
        return (self.domain, self.token, self.ssl_verify)


def credential_from_settings(settings: Settings) -> SisenseCredential | None:
    """Build the default (dev-mode) credential from env, if configured."""
    if not settings.sisense_domain or not settings.sisense_token:
        return None
    return SisenseCredential(
        domain=settings.sisense_domain,
        token=settings.sisense_token,
        ssl_verify=settings.sisense_ssl_verify,
    )
