"""Encrypted storage format for enrichment provider credentials.

The admin can enter provider API keys from the Settings page. They are stored encrypted with
AES-256-GCM. The 32-byte data key is derived with HKDF-SHA256 from ``SETTINGS_ENCRYPTION_KEY``
(base64, at least 32 random bytes), so a database dump alone reveals nothing. The provider name
is bound to each ciphertext as associated data, so a row cannot be moved to another provider.

Nothing here ever puts a key, a master key or a plaintext into an exception message or a
``repr``: errors are constant strings raised ``from None``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, get_args

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

Provider = Literal[
    "abuseipdb",
    "greynoise",
    "maxmind",
    "nvd",
    "github",
    "abusech",
    "virustotal",
    "smtp",
]
PROVIDERS: tuple[str, ...] = get_args(Provider)

ENV_VAR = "SETTINGS_ENCRYPTION_KEY"
HKDF_INFO = b"suckerpot/provider-secrets/v1"
MIN_MASTER_BYTES = 32
MIN_DISTINCT_BYTES = 16  # rejects "AAAA…" and other low-entropy values
NONCE_BYTES = 12
MAX_KEY_LEN = 128
MIN_KEY_LEN = 16

_PRINTABLE = re.compile(r"^[\x21-\x7e]+$")  # printable ASCII, no space, no control character
_DIGITS = re.compile(r"^[0-9]{1,16}$")


class SecretError(Exception):
    """Encryption problem. The message is constant and never contains secret material."""


class ValidationError(ValueError):
    """The submitted credential has an invalid format (message safe to show to the admin)."""


@dataclass(frozen=True, slots=True)
class Credential:
    key: str = field(repr=False)
    account_id: str | None = None

    def __repr__(self) -> str:
        return "Credential(<redacted>)"


def last4(key: str) -> str:
    return key[-4:]


def validate_credential(provider: str, key: str, account_id: str | None) -> Credential:
    """Check the format of what the admin typed. Never echoes the value back."""
    if provider not in PROVIDERS:
        raise ValidationError("Unknown provider.")
    if not _PRINTABLE.match(key):
        raise ValidationError("The key may only contain printable ASCII characters, no spaces.")
    if not MIN_KEY_LEN <= len(key) <= MAX_KEY_LEN:
        raise ValidationError(f"The key must be {MIN_KEY_LEN} to {MAX_KEY_LEN} characters long.")
    if provider == "maxmind":
        if account_id is None or not _DIGITS.match(account_id):
            raise ValidationError("The MaxMind account ID must be 1 to 16 digits.")
        return Credential(key=key, account_id=account_id)
    if account_id:
        raise ValidationError("This provider has no account ID.")
    return Credential(key=key)


class SecretBox:
    """AES-256-GCM with a key derived from the master key."""

    def __init__(self, master: bytes) -> None:
        if len(master) < MIN_MASTER_BYTES:
            raise SecretError(f"{ENV_VAR} must decode to at least {MIN_MASTER_BYTES} bytes")
        if len(set(master)) < MIN_DISTINCT_BYTES:
            raise SecretError(f"{ENV_VAR} is too predictable (use openssl rand -base64 32)")
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(
            master
        )
        self._aes = AESGCM(derived)

    def __repr__(self) -> str:
        return "SecretBox(<redacted>)"

    def encrypt(self, provider: str, credential: Credential) -> tuple[bytes, bytes]:
        """Return ``(ciphertext, nonce)``."""
        payload = json.dumps({"k": credential.key, "a": credential.account_id}).encode()
        nonce = os.urandom(NONCE_BYTES)
        return self._aes.encrypt(nonce, payload, provider.encode()), nonce

    def decrypt(self, provider: str, ciphertext: bytes, nonce: bytes) -> Credential:
        try:
            payload = self._aes.decrypt(nonce, ciphertext, provider.encode())
            data = json.loads(payload)
            key, account = data["k"], data["a"]
            if not isinstance(key, str) or not (account is None or isinstance(account, str)):
                raise TypeError
        except InvalidTag, ValueError, KeyError, TypeError:
            raise SecretError("cannot decrypt the stored key") from None
        return Credential(key=key, account_id=account)


def box_from_env(env: Mapping[str, str] | None = None) -> SecretBox | None:
    """The box for ``SETTINGS_ENCRYPTION_KEY``, or None when it is unset.

    A value that is set but unusable raises ``SecretError`` (fail loudly rather than silently
    disabling the feature).
    """
    e = os.environ if env is None else env
    raw = e.get(ENV_VAR, "").strip()
    if not raw:
        return None
    try:
        master = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    except binascii.Error, ValueError:
        raise SecretError(f"{ENV_VAR} must be base64 (openssl rand -base64 32)") from None
    for name, value in e.items():
        if (
            name != ENV_VAR
            and value.strip() == raw
            and (name.endswith("_PASSWORD") or name == "SESSION_SECRET")
        ):
            raise SecretError(f"{ENV_VAR} must differ from {name}")
    return SecretBox(master)
