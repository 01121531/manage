"""Server-side card secret resolver contract."""

from dataclasses import dataclass, field
from typing import Protocol

from platform.secrets import SecretResolver, SecretResolverUnavailable


_SECURITY_CODE_ALIASES = frozenset(
    {"cvv", "cvc", "cid", "security_code", "card_verification_value"}
)


class CardSecretUnavailable(RuntimeError):
    """The server cannot resolve the card secret reference."""


@dataclass(frozen=True)
class CardSecret:
    pan: str = field(repr=False)


class CardSecretResolver(Protocol):
    def resolve(self, secret_ref: str) -> CardSecret:
        """Return card details for a server-owned secret reference."""


class UnconfiguredCardSecretResolver:
    def resolve(self, secret_ref: str) -> CardSecret:
        raise CardSecretUnavailable("Card secret resolver is not configured")


class SecretCardSecretResolver:
    """Resolve a card PAN while rejecting all security-code material."""

    def __init__(self, secret_resolver: SecretResolver) -> None:
        self.secret_resolver = secret_resolver

    def resolve(self, secret_ref: str) -> CardSecret:
        try:
            value = self.secret_resolver.resolve(secret_ref)
        except SecretResolverUnavailable as error:
            raise CardSecretUnavailable(str(error)) from error
        if any(
            isinstance(key, str) and key.casefold() in _SECURITY_CODE_ALIASES
            for key in value
        ):
            raise CardSecretUnavailable("Card security codes are not supported")
        pan = value.get("pan") or value.get("card_number") or value.get("number")
        if not isinstance(pan, str) or not pan.strip():
            raise CardSecretUnavailable("Card PAN is missing")
        normalized_pan = pan.replace(" ", "").replace("-", "")
        if not normalized_pan.isdigit() or not 12 <= len(normalized_pan) <= 19:
            raise CardSecretUnavailable("Card PAN is invalid")
        return CardSecret(pan=normalized_pan)
