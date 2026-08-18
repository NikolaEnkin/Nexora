from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

EVIDENCE = Path("artifacts/validation/phase-01")


@dataclass(frozen=True, slots=True)
class ValidationCommand:
    arguments: tuple[str, ...]
    logs: tuple[str, ...]

    @property
    def display(self) -> str:
        return " ".join(self.arguments)


COMMANDS = (
    ValidationCommand(("git", "status", "--short"), ("phase-review.log",)),
    ValidationCommand(("git", "diff", "--check"), ("phase-review.log",)),
    ValidationCommand(
        ("docker", "compose", "-f", "infra/compose.yaml", "config"),
        ("phase-review.log",),
    ),
    ValidationCommand(("make", "bootstrap"), ("phase-review.log",)),
    ValidationCommand(("make", "lint"), ("phase-review.log",)),
    ValidationCommand(("make", "format-check"), ("phase-review.log",)),
    ValidationCommand(("make", "typecheck"), ("phase-review.log",)),
    ValidationCommand(("make", "db-migrate-check"), ("migration-check.log",)),
    ValidationCommand(("make", "test-unit"), ("automated-tests.log",)),
    ValidationCommand(("make", "test-contract"), ("contract-tests.log",)),
    ValidationCommand(("make", "test-security"), ("security-tests.log",)),
    ValidationCommand(("make", "phase", "PHASE=01"), ("automated-tests.log", "phase-review.log")),
)


def append_log(name: str, command: ValidationCommand, exit_code: int, output: str) -> None:
    path = EVIDENCE / name
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n$ {command.display}\n")
        handle.write(output)
        if output and not output.endswith("\n"):
            handle.write("\n")
        handle.write(f"[exit_code={exit_code}]\n")


def main() -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for name in {
        "phase-review.log",
        "migration-check.log",
        "automated-tests.log",
        "contract-tests.log",
        "security-tests.log",
    }:
        (EVIDENCE / name).write_text(
            "Phase 01 machine validation — 2026-08-17 — fake/local data only\n",
            encoding="utf-8",
        )

    failed = False
    environment = {
        **os.environ,
        "NEXORA_ENVIRONMENT": "test",
        "NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK": "true",
    }
    for command in COMMANDS:
        print(f"$ {command.display}", flush=True)
        completed = subprocess.run(  # noqa: S603
            command.arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )
        print(completed.stdout, end="")
        for log in command.logs:
            append_log(log, command, completed.returncode, completed.stdout)
        failed = failed or completed.returncode != 0
    if failed:
        raise SystemExit(1)
    print("phase-01-validation: all required commands passed")


if __name__ == "__main__":
    main()
