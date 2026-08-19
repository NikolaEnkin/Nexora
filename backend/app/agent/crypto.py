"""Application-boundary encryption for checkpoint payloads.

Checkpoint channel values contain raw user message content, so they are sealed
before they reach PostgreSQL (`ARCH-014`, packet §9). Key material is reached only
through `CheckpointCipherPort`, never inline, so a managed key service can replace
the local provider without touching a single call site.

Thread, tenant and checkpoint identity are bound in as additional authenticated
data. That is what makes a stolen ciphertext useless in another thread or another
tenant: AES-GCM authentication fails and the read is refused rather than
returning someone else's state.
"""

import os
from base64 import b64decode
from binascii import Error as BinasciiError
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.agent.errors import RuntimeInternalError
from app.config import CHECKPOINT_KEY_BYTES, LOCAL_CHECKPOINT_KEY, Settings

NONCE_BYTES = 12
LOCAL_KEY_ID = "local-fake-v1"


@dataclass(frozen=True, slots=True)
class SealedPayload:
    """Ciphertext plus the metadata needed to open it again."""

    key_id: str
    nonce: bytes
    ciphertext: bytes


class NonceSource(Protocol):
    def next_nonce(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class UrandomNonceSource:
    def next_nonce(self) -> bytes:
        return os.urandom(NONCE_BYTES)


class CheckpointCipherPort(Protocol):
    """The only way runtime code reaches key material."""

    @property
    def key_id(self) -> str: ...

    def seal(self, plaintext: bytes, *, aad: bytes) -> SealedPayload: ...

    def open(self, payload: SealedPayload, *, aad: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class AesGcmCheckpointCipher:
    """AES-256-GCM over a key supplied by configuration.

    Deterministic tests need reproducible ciphertext, so the nonce source is
    injectable. Production callers use the default, which is `os.urandom` by way
    of `cryptography`.
    """

    _key: bytes
    _key_id: str
    _nonce_source: NonceSource

    @property
    def key_id(self) -> str:
        return self._key_id

    @classmethod
    def from_settings(
        cls, settings: Settings, *, nonce_source: NonceSource | None = None
    ) -> "AesGcmCheckpointCipher":
        raw = settings.checkpoint_encryption_key.get_secret_value()
        if settings.environment == "production" and raw == LOCAL_CHECKPOINT_KEY:
            raise ValueError("production checkpoint encryption key must be replaced")
        try:
            key = b64decode(raw, validate=True)
        except BinasciiError as error:
            raise ValueError("checkpoint encryption key must be valid base64") from error
        if len(key) != CHECKPOINT_KEY_BYTES:
            raise ValueError(
                f"checkpoint encryption key must decode to exactly {CHECKPOINT_KEY_BYTES} bytes"
            )
        key_id = LOCAL_KEY_ID if raw == LOCAL_CHECKPOINT_KEY else "configured-v1"
        return cls(_key=key, _key_id=key_id, _nonce_source=nonce_source or UrandomNonceSource())

    def seal(self, plaintext: bytes, *, aad: bytes) -> SealedPayload:
        nonce = self._nonce_source.next_nonce()
        if len(nonce) != NONCE_BYTES:
            raise ValueError(f"AES-GCM nonce must be exactly {NONCE_BYTES} bytes")
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, aad)
        return SealedPayload(key_id=self._key_id, nonce=nonce, ciphertext=ciphertext)

    def open(self, payload: SealedPayload, *, aad: bytes) -> bytes:
        if payload.key_id != self._key_id:
            raise RuntimeInternalError
        try:
            return AESGCM(self._key).decrypt(payload.nonce, payload.ciphertext, aad)
        except InvalidTag as error:
            # A tag failure means the ciphertext, the key, or the bound identity is
            # wrong. Never distinguish those cases to a caller: an attacker replaying
            # another tenant's row must learn nothing beyond "refused".
            raise RuntimeInternalError from error


def checkpoint_aad(
    *, tenant_id: str, actor_id: str, thread_id: str, checkpoint_ns: str, checkpoint_id: str
) -> bytes:
    """Bind a sealed payload to exactly one tenant, actor, thread and checkpoint."""
    return "|".join(
        ("nexora-checkpoint-v1", tenant_id, actor_id, thread_id, checkpoint_ns, checkpoint_id)
    ).encode()


def event_aad(
    *, tenant_id: str, actor_id: str, operation_id: str, sequence: int, event_type: str
) -> bytes:
    """Bind a sealed event payload to exactly one operation slot and type."""
    return "|".join(
        ("nexora-event-v1", tenant_id, actor_id, operation_id, str(sequence), event_type)
    ).encode()


def write_aad(
    *,
    tenant_id: str,
    actor_id: str,
    thread_id: str,
    checkpoint_ns: str,
    checkpoint_id: str,
    task_id: str,
    idx: int,
) -> bytes:
    """Bind a sealed pending write to exactly one task slot."""
    return "|".join(
        (
            "nexora-write-v1",
            tenant_id,
            actor_id,
            thread_id,
            checkpoint_ns,
            checkpoint_id,
            task_id,
            str(idx),
        )
    ).encode()
