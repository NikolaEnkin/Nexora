"""An application-owned LangGraph checkpoint saver over Alembic-managed storage.

See `docs/adr/ADR-003-agent-checkpoint-storage.md` for why the upstream
`PostgresSaver` is not used: it has no isolated-schema support in Python, creates
its tables outside Alembic, and carries no tenant column or row-level security.

Two properties matter most here.

Identity is bound at construction, not read from graph config. The saver holds the
trusted `ActorContext`, so a `RunnableConfig` naming another tenant or actor is
not merely rejected — it cannot be expressed. Row-level security is the second
barrier behind that.

Payloads are sealed before they reach PostgreSQL, with tenant, actor, thread,
namespace and checkpoint identity bound in as additional authenticated data. A
row lifted into another thread fails authentication rather than decoding.
"""

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_id,
)
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.agent.crypto import CheckpointCipherPort, SealedPayload, checkpoint_aad, write_aad
from app.agent.errors import CheckpointConflict
from app.agent.state import STATE_SCHEMA_VERSION, AgentState
from app.contracts import ActorContext
from app.db import set_request_context

DEFAULT_NAMESPACE = ""

_NEXT_SEQ = text(
    """SELECT COALESCE(max(checkpoint_seq), -1) + 1 FROM nexora_agent.agent_checkpoints
    WHERE thread_id = :thread_id AND checkpoint_ns = :checkpoint_ns"""
)
_INSERT_CHECKPOINT = text(
    """INSERT INTO nexora_agent.agent_checkpoints (
        thread_id, checkpoint_ns, checkpoint_id, tenant_id, actor_id,
        parent_checkpoint_id, checkpoint_seq, state_schema_version, key_id,
        checkpoint_type, checkpoint_nonce, checkpoint_ciphertext,
        metadata_type, metadata_nonce, metadata_ciphertext, created_at
    ) VALUES (
        :thread_id, :checkpoint_ns, :checkpoint_id, :tenant_id, :actor_id,
        :parent_checkpoint_id, :checkpoint_seq, :state_schema_version, :key_id,
        :checkpoint_type, :checkpoint_nonce, :checkpoint_ciphertext,
        :metadata_type, :metadata_nonce, :metadata_ciphertext, :now
    )"""
)
_SELECT_LATEST = text(
    """SELECT thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, checkpoint_seq,
              state_schema_version, key_id, checkpoint_type, checkpoint_nonce,
              checkpoint_ciphertext, metadata_type, metadata_nonce, metadata_ciphertext
    FROM nexora_agent.agent_checkpoints
    WHERE thread_id = :thread_id AND checkpoint_ns = :checkpoint_ns
    ORDER BY checkpoint_seq DESC LIMIT 1"""
)
_SELECT_ONE = text(
    """SELECT thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, checkpoint_seq,
              state_schema_version, key_id, checkpoint_type, checkpoint_nonce,
              checkpoint_ciphertext, metadata_type, metadata_nonce, metadata_ciphertext
    FROM nexora_agent.agent_checkpoints
    WHERE thread_id = :thread_id AND checkpoint_ns = :checkpoint_ns
      AND checkpoint_id = :checkpoint_id"""
)
_SELECT_HISTORY = text(
    """SELECT thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, checkpoint_seq,
              state_schema_version, key_id, checkpoint_type, checkpoint_nonce,
              checkpoint_ciphertext, metadata_type, metadata_nonce, metadata_ciphertext
    FROM nexora_agent.agent_checkpoints
    WHERE thread_id = :thread_id AND checkpoint_ns = :checkpoint_ns
      AND (CAST(:before_seq AS bigint) IS NULL OR checkpoint_seq < CAST(:before_seq AS bigint))
    ORDER BY checkpoint_seq DESC"""
)
_UPSERT_WRITE = text(
    """INSERT INTO nexora_agent.agent_checkpoint_writes (
        thread_id, checkpoint_ns, checkpoint_id, task_id, idx, tenant_id, actor_id,
        channel, task_path, key_id, value_type, value_nonce, value_ciphertext, created_at
    ) VALUES (
        :thread_id, :checkpoint_ns, :checkpoint_id, :task_id, :idx, :tenant_id, :actor_id,
        :channel, :task_path, :key_id, :value_type, :value_nonce, :value_ciphertext, :now
    ) ON CONFLICT (thread_id, checkpoint_ns, checkpoint_id, task_id, idx)
    DO UPDATE SET channel = EXCLUDED.channel, task_path = EXCLUDED.task_path,
                  key_id = EXCLUDED.key_id, value_type = EXCLUDED.value_type,
                  value_nonce = EXCLUDED.value_nonce,
                  value_ciphertext = EXCLUDED.value_ciphertext"""
)
_SELECT_WRITES = text(
    """SELECT task_id, channel, key_id, value_type, value_nonce, value_ciphertext
    FROM nexora_agent.agent_checkpoint_writes
    WHERE thread_id = :thread_id AND checkpoint_ns = :checkpoint_ns
      AND checkpoint_id = :checkpoint_id
    ORDER BY task_id, idx"""
)


def _thread_id(config: RunnableConfig) -> str:
    configurable = config.get("configurable") or {}
    thread_id = configurable.get("thread_id")
    if not isinstance(thread_id, str) or not thread_id:
        raise ValueError("checkpoint config requires a thread_id")
    return thread_id


def _namespace(config: RunnableConfig) -> str:
    configurable = config.get("configurable") or {}
    namespace = configurable.get("checkpoint_ns", DEFAULT_NAMESPACE)
    return namespace if isinstance(namespace, str) else DEFAULT_NAMESPACE


@dataclass
class PostgresCheckpointSaver(BaseCheckpointSaver[int]):
    """Durable, tenant-scoped, encrypted checkpoints.

    `actor` is supplied by the trusted Phase-01 authentication boundary and is the
    only source of tenant and actor identity. Nothing in `RunnableConfig` can
    override it.
    """

    sessions: sessionmaker[Session]
    cipher: CheckpointCipherPort
    actor: ActorContext
    clock: Any

    def __post_init__(self) -> None:
        # Pass the serializer explicitly: the base initializer resolves
        # `serde or self.serde`, so leaving it unset would yield None.
        BaseCheckpointSaver.__init__(self, serde=JsonPlusSerializer())

    # -- helpers ---------------------------------------------------------

    def _seal_checkpoint(
        self, thread_id: str, namespace: str, checkpoint_id: str, payload: object
    ) -> tuple[str, SealedPayload]:
        type_tag, blob = self.serde.dumps_typed(payload)
        sealed = self.cipher.seal(
            blob,
            aad=checkpoint_aad(
                tenant_id=str(self.actor.tenant_id),
                actor_id=str(self.actor.actor_id),
                thread_id=thread_id,
                checkpoint_ns=namespace,
                checkpoint_id=checkpoint_id,
            ),
        )
        return type_tag, sealed

    def _open_checkpoint(
        self,
        thread_id: str,
        namespace: str,
        checkpoint_id: str,
        type_tag: str,
        nonce: bytes,
        ciphertext: bytes,
        key_id: str,
    ) -> Any:
        blob = self.cipher.open(
            SealedPayload(key_id=key_id, nonce=bytes(nonce), ciphertext=bytes(ciphertext)),
            aad=checkpoint_aad(
                tenant_id=str(self.actor.tenant_id),
                actor_id=str(self.actor.actor_id),
                thread_id=thread_id,
                checkpoint_ns=namespace,
                checkpoint_id=checkpoint_id,
            ),
        )
        return self.serde.loads_typed((type_tag, blob))

    def _config_for(self, thread_id: str, namespace: str, checkpoint_id: str) -> RunnableConfig:
        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": namespace,
                "checkpoint_id": checkpoint_id,
            }
        }

    def _load_writes(
        self, session: Session, thread_id: str, namespace: str, checkpoint_id: str
    ) -> list[tuple[str, str, Any]]:
        rows = session.execute(
            _SELECT_WRITES,
            {
                "thread_id": thread_id,
                "checkpoint_ns": namespace,
                "checkpoint_id": checkpoint_id,
            },
        ).mappings()
        writes: list[tuple[str, str, Any]] = []
        for row in rows:
            blob = self.cipher.open(
                SealedPayload(
                    key_id=row["key_id"],
                    nonce=bytes(row["value_nonce"]),
                    ciphertext=bytes(row["value_ciphertext"]),
                ),
                aad=write_aad(
                    tenant_id=str(self.actor.tenant_id),
                    actor_id=str(self.actor.actor_id),
                    thread_id=thread_id,
                    checkpoint_ns=namespace,
                    checkpoint_id=checkpoint_id,
                    task_id=row["task_id"],
                    idx=row["idx"],
                ),
            )
            writes.append(
                (row["task_id"], row["channel"], self.serde.loads_typed((row["value_type"], blob)))
            )
        return writes

    def _tuple_from_row(self, session: Session, row: Any) -> CheckpointTuple:
        thread_id = row["thread_id"]
        namespace = row["checkpoint_ns"]
        checkpoint_id = row["checkpoint_id"]
        checkpoint = self._open_checkpoint(
            thread_id,
            namespace,
            checkpoint_id,
            row["checkpoint_type"],
            row["checkpoint_nonce"],
            row["checkpoint_ciphertext"],
            row["key_id"],
        )
        metadata = self._open_checkpoint(
            thread_id,
            namespace,
            checkpoint_id,
            row["metadata_type"],
            row["metadata_nonce"],
            row["metadata_ciphertext"],
            row["key_id"],
        )
        parent = row["parent_checkpoint_id"]
        return CheckpointTuple(
            config=self._config_for(thread_id, namespace, checkpoint_id),
            checkpoint=checkpoint,
            metadata=metadata,
            parent_config=(
                None if parent is None else self._config_for(thread_id, namespace, parent)
            ),
            pending_writes=self._load_writes(session, thread_id, namespace, checkpoint_id),
        )

    # -- BaseCheckpointSaver ---------------------------------------------

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        thread_id = _thread_id(config)
        namespace = _namespace(config)
        checkpoint_id = checkpoint["id"]
        parent = get_checkpoint_id(config)

        checkpoint_type, sealed_checkpoint = self._seal_checkpoint(
            thread_id, namespace, checkpoint_id, checkpoint
        )
        metadata_type, sealed_metadata = self._seal_checkpoint(
            thread_id, namespace, checkpoint_id, dict(metadata)
        )

        try:
            with self.sessions() as session, session.begin():
                set_request_context(session, self.actor.tenant_id, self.actor.actor_id)
                next_seq = session.execute(
                    _NEXT_SEQ, {"thread_id": thread_id, "checkpoint_ns": namespace}
                ).scalar_one()
                session.execute(
                    _INSERT_CHECKPOINT,
                    {
                        "thread_id": thread_id,
                        "checkpoint_ns": namespace,
                        "checkpoint_id": checkpoint_id,
                        "tenant_id": self.actor.tenant_id,
                        "actor_id": self.actor.actor_id,
                        "parent_checkpoint_id": parent,
                        "checkpoint_seq": next_seq,
                        "state_schema_version": STATE_SCHEMA_VERSION,
                        "key_id": self.cipher.key_id,
                        "checkpoint_type": checkpoint_type,
                        "checkpoint_nonce": sealed_checkpoint.nonce,
                        "checkpoint_ciphertext": sealed_checkpoint.ciphertext,
                        "metadata_type": metadata_type,
                        "metadata_nonce": sealed_metadata.nonce,
                        "metadata_ciphertext": sealed_metadata.ciphertext,
                        "now": self.clock(),
                    },
                )
        except IntegrityError as error:
            # A concurrent writer already claimed this sequence. The latest durable
            # checkpoint is never overwritten; the caller must reload and retry.
            raise CheckpointConflict from error

        return self._config_for(thread_id, namespace, checkpoint_id)

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        thread_id = _thread_id(config)
        namespace = _namespace(config)
        checkpoint_id = get_checkpoint_id(config)
        if checkpoint_id is None:
            raise ValueError("pending writes require a checkpoint_id")

        with self.sessions() as session, session.begin():
            set_request_context(session, self.actor.tenant_id, self.actor.actor_id)
            for index, (channel, value) in enumerate(writes):
                idx = WRITES_IDX_MAP.get(channel, index)
                type_tag, blob = self.serde.dumps_typed(value)
                sealed = self.cipher.seal(
                    blob,
                    aad=write_aad(
                        tenant_id=str(self.actor.tenant_id),
                        actor_id=str(self.actor.actor_id),
                        thread_id=thread_id,
                        checkpoint_ns=namespace,
                        checkpoint_id=checkpoint_id,
                        task_id=task_id,
                        idx=idx,
                    ),
                )
                session.execute(
                    _UPSERT_WRITE,
                    {
                        "thread_id": thread_id,
                        "checkpoint_ns": namespace,
                        "checkpoint_id": checkpoint_id,
                        "task_id": task_id,
                        "idx": idx,
                        "tenant_id": self.actor.tenant_id,
                        "actor_id": self.actor.actor_id,
                        "channel": channel,
                        "task_path": task_path,
                        "key_id": self.cipher.key_id,
                        "value_type": type_tag,
                        "value_nonce": sealed.nonce,
                        "value_ciphertext": sealed.ciphertext,
                        "now": self.clock(),
                    },
                )

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = _thread_id(config)
        namespace = _namespace(config)
        checkpoint_id = get_checkpoint_id(config)

        with self.sessions() as session, session.begin():
            set_request_context(session, self.actor.tenant_id, self.actor.actor_id)
            if checkpoint_id is None:
                row = (
                    session.execute(
                        _SELECT_LATEST,
                        {"thread_id": thread_id, "checkpoint_ns": namespace},
                    )
                    .mappings()
                    .one_or_none()
                )
            else:
                row = (
                    session.execute(
                        _SELECT_ONE,
                        {
                            "thread_id": thread_id,
                            "checkpoint_ns": namespace,
                            "checkpoint_id": checkpoint_id,
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None:
                return None
            return self._tuple_from_row(session, row)

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        if config is None:
            raise ValueError("checkpoint listing requires a thread-scoped config")
        thread_id = _thread_id(config)
        namespace = _namespace(config)

        before_seq: int | None = None
        with self.sessions() as session, session.begin():
            set_request_context(session, self.actor.tenant_id, self.actor.actor_id)
            if before is not None:
                before_id = get_checkpoint_id(before)
                if before_id is not None:
                    boundary = (
                        session.execute(
                            _SELECT_ONE,
                            {
                                "thread_id": thread_id,
                                "checkpoint_ns": namespace,
                                "checkpoint_id": before_id,
                            },
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if boundary is not None:
                        before_seq = boundary["checkpoint_seq"]

            rows = list(
                session.execute(
                    _SELECT_HISTORY,
                    {
                        "thread_id": thread_id,
                        "checkpoint_ns": namespace,
                        "before_seq": before_seq,
                    },
                ).mappings()
            )
            if limit is not None:
                rows = rows[:limit]
            results = [self._tuple_from_row(session, row) for row in rows]
        yield from results

    def get_next_version(self, current: int | None, channel: None = None) -> int:
        return 1 if current is None else current + 1


def latest_checkpoint_seq(
    sessions: sessionmaker[Session], actor: ActorContext, thread_id: str
) -> int | None:
    """Durable sequence for a thread, or None when nothing has been checkpointed."""
    with sessions() as session, session.begin():
        set_request_context(session, actor.tenant_id, actor.actor_id)
        row = (
            session.execute(
                _SELECT_LATEST, {"thread_id": thread_id, "checkpoint_ns": DEFAULT_NAMESPACE}
            )
            .mappings()
            .one_or_none()
        )
    return None if row is None else int(row["checkpoint_seq"])


def agent_state_from_checkpoint(checkpoint: Checkpoint) -> AgentState:
    """Recover `AgentState v1` from a LangGraph checkpoint.

    `channel_values` also carries LangGraph's own bookkeeping channels (branch
    routing markers and similar), which are execution plumbing rather than part of
    the contract. Only the declared `AgentState` fields are taken, so the result is
    exactly a v1 state and nothing else.
    """
    values = checkpoint["channel_values"]
    declared = {key: values[key] for key in AgentState.model_fields if key in values}
    return AgentState.model_validate(declared)


def utc_clock() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)
