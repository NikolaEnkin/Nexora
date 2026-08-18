import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from scripts.codex.validate_phase_result import validate_semantics


@pytest.mark.contract
def test_ready_result_validates_and_agent_pass_is_rejected() -> None:
    schema = json.loads(Path("schemas/phase-result.schema.json").read_text())
    fixture = json.loads(Path("backend/tests/fixtures/execution/phase-results.json").read_text())
    validator = Draft202012Validator(schema)
    validator.validate(fixture["ready"])
    errors = list(validator.iter_errors(fixture["agent_pass"]))
    assert errors
    assert any("PASS" in error.message for error in errors)
    assert fixture["ready"]["human_uat"]["status"] == "PENDING"
    with pytest.raises(ValueError, match="test set differs"):
        validate_semantics(fixture["ready"])


@pytest.mark.contract
def test_complete_ready_result_passes_semantics_and_missing_evidence_fails(
    tmp_path: Path,
) -> None:
    (tmp_path / "tests").mkdir()
    shutil.copyfile("tests/manifest.yaml", tmp_path / "tests/manifest.yaml")
    fixture_dir = tmp_path / "backend/tests/fixtures/security"
    fixture_dir.mkdir(parents=True)
    shutil.copyfile(
        "backend/tests/fixtures/security/fake-secret.json",
        fixture_dir / "fake-secret.json",
    )
    evidence_dir = tmp_path / "artifacts/validation/phase-01"
    evidence_dir.mkdir(parents=True)
    required_names = {
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
    for name in required_names:
        (evidence_dir / name).write_text("fixed evidence\n")
    commands = [
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
    ]
    result = {
        "schema_version": "1.0.0",
        "phase": "01",
        "status": "READY_FOR_HUMAN_REVIEW",
        "branch": "phase/01-foundations",
        "baseline_commit": "a" * 40,
        "commit": "b" * 40,
        "changed_files": [
            {"path": "Makefile", "change": "created", "allowlist_category": "MAY_CREATE"}
        ],
        "commands": [
            {
                "command": command,
                "attempt": 1,
                "exit_code": 0,
                "evidence_path": "artifacts/validation/phase-01/phase-review.log",
            }
            for command in commands
        ],
        "tests": [
            {
                "id": f"P01-{number:03d}",
                "result": "PASSED",
                "evidence_path": "artifacts/validation/phase-01/automated-tests.log",
                "negative_side_effect_count": 0,
            }
            for number in range(1, 9)
        ],
        "review_attempts": [
            {
                "attempt": 1,
                "result": "PASSED",
                "evidence_path": "artifacts/validation/phase-01/phase-review.log",
                "fix_summary": "fixed",
            }
        ],
        "findings": [],
        "blockers": [],
        "evidence": [
            {
                "path": f"artifacts/validation/phase-01/{name}",
                "purpose": "contract fixture",
            }
            for name in sorted(required_names)
        ],
        "human_uat": {
            "required_ids": ["P01-UAT-01", "P01-UAT-02", "P01-UAT-03"],
            "status": "PENDING",
            "reviewer": "Nikola",
        },
        "known_limitations": [],
    }
    schema = json.loads(Path("schemas/phase-result.schema.json").read_text())
    Draft202012Validator(schema).validate(result)
    validate_semantics(result, tmp_path)
    (evidence_dir / "security-review.md").unlink()
    with pytest.raises(ValueError, match="missing"):
        validate_semantics(result, tmp_path)
