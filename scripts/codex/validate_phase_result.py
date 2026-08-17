import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PHASE_01_COMMANDS = {
    "git status --short",
    "git diff --check",
    "docker compose -f infra/compose.yaml config",
    "make bootstrap",
    "make db-migrate-check",
    "make lint",
    "make format-check",
    "make typecheck",
    "make test-unit",
    "make test-contract",
    "make test-security",
    "make phase PHASE=01",
}
PHASE_01_EVIDENCE = {
    f"artifacts/validation/phase-01/{name}"
    for name in {
        "REVIEW.md",
        "codex-result.json",
        "changed-files.txt",
        "code-attempts.md",
        "phase-review.log",
        "automated-tests.log",
        "migration-check.log",
        "contract-tests.log",
        "security-tests.log",
        "reviewer.md",
        "test-audit.md",
        "security-review.md",
        "human-uat.md",
    }
}
PHASE_01_UAT = {"P01-UAT-01", "P01-UAT-02", "P01-UAT-03"}


def validate_semantics(result: dict[str, Any], root: Path = Path(".")) -> None:
    phase = str(result["phase"])
    manifest = (root / "tests/manifest.yaml").read_text()
    required_test_ids = set(
        re.findall(rf'(?m)^  - id: (P{phase}-[0-9]{{3}})\n    phase: "{phase}"', manifest)
    )
    reported_tests = {str(item["id"]) for item in result["tests"]}
    if reported_tests != required_test_ids or len(result["tests"]) != len(required_test_ids):
        raise ValueError("phase result test set differs from the manifest")
    if phase == "01":
        reported_commands = {str(item["command"]) for item in result["commands"]}
        if reported_commands != PHASE_01_COMMANDS or len(result["commands"]) != len(
            PHASE_01_COMMANDS
        ):
            raise ValueError("phase result command set differs from the Phase-01 packet")
        uat_ids = set(result["human_uat"]["required_ids"])
        if uat_ids != PHASE_01_UAT or len(result["human_uat"]["required_ids"]) != 3:
            raise ValueError("Phase-01 human UAT IDs must be exactly P01-UAT-01..03")
    if result["status"] == "READY_FOR_HUMAN_REVIEW":
        for field in ("baseline_commit", "commit"):
            value = result[field]
            if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{40}", value) is None:
                raise ValueError(f"ready result requires a full {field}")
        if not result["changed_files"]:
            raise ValueError("ready result requires a non-empty changed-file inventory")
        evidence_paths = {str(item["path"]) for item in result["evidence"]}
        if phase == "01" and (
            evidence_paths != PHASE_01_EVIDENCE or len(result["evidence"]) != len(PHASE_01_EVIDENCE)
        ):
            raise ValueError("Phase-01 evidence inventory must match the exact packet set")
        for item in result["evidence"]:
            evidence_path = root / str(item["path"])
            if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
                raise ValueError(f"missing or empty evidence: {evidence_path}")
            expected_hash = item.get("sha256")
            if expected_hash is not None:
                actual_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
                if actual_hash != expected_hash:
                    raise ValueError(f"evidence hash mismatch: {evidence_path}")
        if phase == "01":
            sentinel_payload = json.loads(
                (root / "backend/tests/fixtures/security/fake-secret.json").read_text()
            )
            sentinel = str(sentinel_payload["secret"]).encode()
            for relative_path in evidence_paths:
                if sentinel in (root / relative_path).read_bytes():
                    raise ValueError(f"secret sentinel found in evidence: {relative_path}")
        for collection in (result["commands"], result["tests"], result["review_attempts"]):
            for item in collection:
                relative_path = str(item["evidence_path"])
                if relative_path not in evidence_paths:
                    raise ValueError(f"evidence reference is not declared: {relative_path}")
                evidence_path = root / relative_path
                if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
                    raise ValueError(f"referenced evidence is missing: {evidence_path}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_phase_result.py <result.json>")
    schema = json.loads(Path("schemas/phase-result.schema.json").read_text())
    result = json.loads(Path(sys.argv[1]).read_text())
    Draft202012Validator(schema).validate(result)
    validate_semantics(result)
    print(f"phase-result-valid: {sys.argv[1]}")


if __name__ == "__main__":
    main()
