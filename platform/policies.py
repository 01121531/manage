"""Upload policy selection and worker-side snapshot resolution."""

from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from platform.models import UploadJob, UploadPolicyDeployment, UploadPolicyVersion
from platform.uploads import Sub2Policy


def policy_from_record(record: UploadPolicyVersion) -> Sub2Policy:
    return Sub2Policy(
        version=record.version,
        proxy_ref=record.proxy_ref,
        group_id=record.group_id,
        concurrency=record.concurrency,
        credential_ref=record.credential_ref,
    )


def select_policy_for_task(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
    fallback: Sub2Policy,
    allow_fallback: bool = True,
) -> Sub2Policy | None:
    """Select the deployed policy deterministically for a tenant task."""

    def fallback_or_none() -> Sub2Policy | None:
        return fallback if allow_fallback else None

    def is_deployed(record: UploadPolicyVersion | None) -> bool:
        return bool(
            record is not None
            and record.tenant_id == tenant_id
            and record.status == "active"
            and record.approved_by is not None
            and record.approved_at is not None
        )

    deployment = db.scalar(
        select(UploadPolicyDeployment).where(
            UploadPolicyDeployment.tenant_id == tenant_id
        )
    )
    if deployment is None:
        return fallback_or_none()
    active = db.get(UploadPolicyVersion, deployment.active_policy_id)
    if not is_deployed(active):
        return fallback_or_none()
    assert active is not None
    if deployment.rollout_percent >= 100 or deployment.previous_policy_id is None:
        return policy_from_record(active)
    previous = db.get(UploadPolicyVersion, deployment.previous_policy_id)
    if not is_deployed(previous):
        return fallback_or_none()
    assert previous is not None
    bucket = int.from_bytes(
        hashlib.sha256(f"{tenant_id}:{task_id}".encode("utf-8")).digest()[:4],
        "big",
    ) % 100
    return policy_from_record(active if bucket < deployment.rollout_percent else previous)


def resolve_policy_for_job(
    db: Session,
    *,
    job: UploadJob,
    fallback: Sub2Policy,
    allow_fallback: bool = True,
) -> Sub2Policy | None:
    """Resolve the immutable policy recorded on a queued upload job."""

    record = db.scalar(
        select(UploadPolicyVersion).where(
            UploadPolicyVersion.tenant_id == job.tenant_id,
            UploadPolicyVersion.version == job.policy_version,
        )
    )
    if (
        record is not None
        and record.status in {"active", "retired"}
        and record.approved_by is not None
        and record.approved_at is not None
    ):
        return policy_from_record(record)
    if allow_fallback and fallback.version == job.policy_version:
        return fallback
    return None
