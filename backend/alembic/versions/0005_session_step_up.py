"""Record when a session last proved a second factor.

Revision ID: 0005_session_step_up
Revises: 0004_business_domain
Create Date: 2026-08-21

`ADR-004` §4 with Amendment 2, signed 2026-08-21. Its own revision rather than a
column inside `0004`, because a session column has no business in a migration
named `business_domain`.

**Why on the session and not on the user.** If step-up lived on `users`, proving a
factor on a laptop would silently make every other session of that person — and
any stolen one — count as recently verified. On the session, each one proves
itself.

**Why a timestamp and not a flag.** `ADR-004` §4 gives the proof a five-minute
life. A boolean cannot expire. `ActorContext.assurance` is derived per request as
`step_up` iff `now - step_up_at < 5 minutes`, exactly as approval expiry is derived
against the server clock rather than trusted from input.

`NULL` means never, which resolves to `standard`. That is the fail-closed default
and the value every session starts with.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_session_step_up"
down_revision: str | None = "0004_business_domain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ADR-004 §4 Amendment 2. `sms` and `email` are absent by decision, not oversight:
# the amendment rejects both at every level, because SIM swap and mailbox
# compromise are the same attack as the account compromise being defended against.
STEP_UP_FACTORS = ("webauthn", "totp")


def upgrade() -> None:
    op.add_column(
        "auth_sessions", sa.Column("step_up_at", sa.DateTime(timezone=True), nullable=True)
    )
    # Kept for audit: which factor actually satisfied the challenge. Amendment 2
    # requires WebAuthn for OWNER and DEPUTY, and a claim of compliance that
    # cannot be checked afterwards is not compliance.
    op.add_column("auth_sessions", sa.Column("step_up_factor", sa.String(20), nullable=True))
    op.create_check_constraint(
        "ck_auth_sessions_step_up_factor",
        "auth_sessions",
        "step_up_factor IS NULL OR step_up_factor IN " + str(STEP_UP_FACTORS),
    )
    op.create_check_constraint(
        "ck_auth_sessions_step_up_pair",
        "auth_sessions",
        "(step_up_at IS NULL) = (step_up_factor IS NULL)",
    )

    # The Phase-01 trigger enumerates what a runtime session may not change, and
    # `step_up_at` was not in that list, so it was unconstrained. Two rules matter:
    # it may only move forward, and it may never point into the future — otherwise
    # a compromised runtime could simply extend its own window.
    op.execute(
        """CREATE OR REPLACE FUNCTION protect_session_step_up() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.step_up_at IS NULL THEN
            RETURN NEW;
          END IF;
          IF NEW.step_up_at > CURRENT_TIMESTAMP + interval '1 minute' THEN
            RAISE EXCEPTION 'step-up cannot be dated into the future'
              USING ERRCODE = '42501';
          END IF;
          IF TG_OP = 'UPDATE' AND OLD.step_up_at IS NOT NULL
             AND NEW.step_up_at < OLD.step_up_at THEN
            RAISE EXCEPTION 'step-up time cannot move backwards'
              USING ERRCODE = '42501';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_auth_sessions_protect_step_up
        BEFORE INSERT OR UPDATE ON auth_sessions
        FOR EACH ROW EXECUTE FUNCTION protect_session_step_up()"""
    )
    op.execute("REVOKE ALL ON FUNCTION protect_session_step_up() FROM PUBLIC")


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_auth_sessions_protect_step_up ON auth_sessions")
    op.execute("DROP FUNCTION protect_session_step_up() CASCADE")
    op.drop_constraint("ck_auth_sessions_step_up_pair", "auth_sessions", type_="check")
    op.drop_constraint("ck_auth_sessions_step_up_factor", "auth_sessions", type_="check")
    op.drop_column("auth_sessions", "step_up_factor")
    op.drop_column("auth_sessions", "step_up_at")
