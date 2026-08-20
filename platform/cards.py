"""Server-side card secret resolver contract."""

from dataclasses import dataclass, field
from typing import Protocol

from platform.secrets import SecretResolver, SecretResolverUnavailable


class CardSecretUnavailable(RuntimeError):
    """The server cannot resolve the card secret reference."""


@dataclass(frozen=True)
class CardSecret:
    pan: str = field(repr=False)
    cvv: str = field(repr=False)


class CardSecretResolver(Protocol):
    def resolve(self, secret_ref: str) -> CardSecret:
        """Return card details for a server-owned secret reference."""


class UnconfiguredCardSecretResolver:
    def resolve(self, secret_ref: str) -> CardSecret:
        raise CardSecretUnavailable("Card secret resolver is not configured")


class SecretCardSecretResolver:
    """Resolve card PAN/CVV through the shared server-side secret resolver."""

    def __init__(self, secret_resolver: SecretResolver) -> None:
        self.secret_resolver = secret_resolver

    def resolve(self, secret_ref: str) -> CardSecret:
        try:
            value = self.secret_resolver.resolve(secret_ref)
        except SecretResolverUnavailable as error:
            raise CardSecretUnavailable(str(error)) from error
        pan = value.get("pan") or value.get("card_number") or value.get("number")
        cvv = value.get("cvv") or value.get("cvc") or value.get("security_code")
        if not isinstance(pan, str) or not pan.strip():
            raise CardSecretUnavailable("Card PAN is missing")
        if not isinstance(cvv, str) or not cvv.strip():
            raise CardSecretUnavailable("Card CVV is missing")
        normalized_pan = pan.replace(" ", "").replace("-", "")
        normalized_cvv = cvv.strip()
        if not normalized_pan.isdigit() or not 12 <= len(normalized_pan) <= 19:
            raise CardSecretUnavailable("Card PAN is invalid")
        if not normalized_cvv.isdigit() or not 3 <= len(normalized_cvv) <= 4:
            raise CardSecretUnavailable("Card CVV is invalid")
        return CardSecret(pan=normalized_pan, cvv=normalized_cvv)
