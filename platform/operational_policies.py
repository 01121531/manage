"""Deterministic runtime selection for governed mail and card policies."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from platform.config import Settings
from platform.models import OperationalPolicyDeployment, OperationalPolicyVersion
from platform.schemas import CardSelectionRule


PolicyDomain = Literal["mail", "card"]


@dataclass(frozen=True)
class MailRuntimePolicy:
    version: str
    session_ttl_seconds: int
    code_ttl_seconds: int
    poll_interval_seconds: int


@dataclass(frozen=True)
class CardRuntimePolicy:
    version: str
    lease_ttl_seconds: int
    reveal_ttl_seconds: int
    allocation_order: str
    selection_rules: tuple[CardSelectionRule, ...]

    def rule_for(self, task_type: str) -> CardSelectionRule | None:
        return next(
            (rule for rule in self.selection_rules if rule.task_type == task_type),
            None,
        )


DEFAULT_CARD_SELECTION_RULE = CardSelectionRule(
    task_type="card_checkout",
    pool_key="legacy-unclassified",
    region="legacy-unclassified",
    brands=[],
    minimum_validity_days=0,
    allocation_order="oldest_available",
)


def canonical_card_selection_rule(rule: CardSelectionRule) -> str:
    return json.dumps(rule.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def parse_card_selection_rule(value: str) -> CardSelectionRule | None:
    try:
        return CardSelectionRule.model_validate(json.loads(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _selection_rules(value: str | None) -> tuple[CardSelectionRule, ...] | None:
    try:
        payload = json.loads(value) if value is not None else None
        if not isinstance(payload, list) or not payload:
            return None
        rules = tuple(CardSelectionRule.model_validate(item) for item in payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if len({rule.task_type for rule in rules}) != len(rules):
        return None
    return rules


def default_mail_policy(settings: Settings) -> MailRuntimePolicy:
    return MailRuntimePolicy(
        version="settings-default",
        session_ttl_seconds=settings.mail_session_ttl_seconds,
        code_ttl_seconds=settings.mail_code_ttl_seconds,
        poll_interval_seconds=settings.mail_poll_interval_seconds,
    )


def default_card_policy(settings: Settings) -> CardRuntimePolicy:
    return CardRuntimePolicy(
        version="settings-default",
        lease_ttl_seconds=settings.card_lease_ttl_seconds,
        reveal_ttl_seconds=settings.card_reveal_ttl_seconds,
        allocation_order="oldest_available",
        selection_rules=(DEFAULT_CARD_SELECTION_RULE,),
    )


def _selected_record(
    db: Session, *, tenant_id: str, domain: PolicyDomain, subject_id: str
) -> OperationalPolicyVersion | None:
    deployment = db.scalar(
        select(OperationalPolicyDeployment).where(
            OperationalPolicyDeployment.tenant_id == tenant_id,
            OperationalPolicyDeployment.domain == domain,
        )
    )
    if deployment is None:
        return None
    active = db.get(OperationalPolicyVersion, deployment.active_policy_id)
    if active is None or active.tenant_id != tenant_id or active.domain != domain:
        return None
    if deployment.rollout_percent >= 100 or deployment.previous_policy_id is None:
        return active
    previous = db.get(OperationalPolicyVersion, deployment.previous_policy_id)
    if previous is None or previous.tenant_id != tenant_id or previous.domain != domain:
        return active
    bucket = int.from_bytes(
        hashlib.sha256(f"{tenant_id}:{subject_id}".encode("utf-8")).digest()[:4],
        "big",
    ) % 100
    return active if bucket < deployment.rollout_percent else previous


def select_mail_policy(
    db: Session, *, tenant_id: str, task_id: str, settings: Settings
) -> MailRuntimePolicy:
    record = _selected_record(
        db, tenant_id=tenant_id, domain="mail", subject_id=task_id
    )
    if record is None:
        return default_mail_policy(settings)
    if (
        record.session_ttl_seconds is None
        or record.code_ttl_seconds is None
        or record.poll_interval_seconds is None
    ):
        return default_mail_policy(settings)
    return MailRuntimePolicy(
        version=record.version,
        session_ttl_seconds=record.session_ttl_seconds,
        code_ttl_seconds=record.code_ttl_seconds,
        poll_interval_seconds=record.poll_interval_seconds,
    )


def select_card_policy(
    db: Session, *, tenant_id: str, task_id: str, settings: Settings
) -> CardRuntimePolicy:
    record = _selected_record(
        db, tenant_id=tenant_id, domain="card", subject_id=task_id
    )
    if record is None:
        return default_card_policy(settings)
    rules = _selection_rules(record.selection_rules_json)
    if (
        record.lease_ttl_seconds is None
        or record.reveal_ttl_seconds is None
        or record.allocation_order != "oldest_available"
        or rules is None
    ):
        return CardRuntimePolicy(
            version=record.version,
            lease_ttl_seconds=settings.card_lease_ttl_seconds,
            reveal_ttl_seconds=settings.card_reveal_ttl_seconds,
            allocation_order="oldest_available",
            selection_rules=(),
        )
    return CardRuntimePolicy(
        version=record.version,
        lease_ttl_seconds=record.lease_ttl_seconds,
        reveal_ttl_seconds=record.reveal_ttl_seconds,
        allocation_order=record.allocation_order,
        selection_rules=rules,
    )
