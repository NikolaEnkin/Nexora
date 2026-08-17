import json
from pathlib import Path

import pytest

from app.contracts import (
    ActorContext,
    AuditEvent,
    AuthorizationDecision,
    DomainEvent,
    ErrorEnvelope,
    IdempotencyRecord,
    parse_v1,
)
from app.errors import ContractVersionUnsupported

MODELS = {
    "ActorContext": ActorContext,
    "AuthorizationDecision": AuthorizationDecision,
    "DomainEvent": DomainEvent,
    "AuditEvent": AuditEvent,
    "IdempotencyRecord": IdempotencyRecord,
    "ErrorEnvelope": ErrorEnvelope,
}


@pytest.mark.contract
def test_v1_roundtrip_and_unknown_major_rejection() -> None:
    fixture = json.loads(Path("backend/tests/fixtures/contracts/foundation-v1.json").read_text())
    for name, payload in fixture["contracts"].items():
        model = MODELS[name]
        parsed = parse_v1(model, payload)
        assert parsed.model_dump(mode="json") == payload
        unsupported = {**payload, "version": "2"}
        with pytest.raises(ContractVersionUnsupported) as captured:
            parse_v1(model, unsupported)
        assert captured.value.code == "CONTRACT_VERSION_UNSUPPORTED"
