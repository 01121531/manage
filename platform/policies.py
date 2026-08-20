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
) -> Sub2Policy:
    """Select the deployed policy deterministically for a tenant task."""

    deployment = db.scalar(
        select(UploadPolicyDeployment).where(
            UploadPolicyDeployment.tenant_id == tenant_id
        )
    )
    if deployment is None:
        return fallback
    active = db.get(UploadPolicyVersion, deployment.active_policy_id)
    if active is None or active.tenant_id != tenant_id:
        return fallback
    if deployment.rollout_percent >= 100 or deployment.previous_policy_id is None:
        return policy_from_record(active)
    previous = db.get(UploadPolicyVersion, deployment.previous_policy_id)
    if previous is None or previous.tenant_id != tenant_id:
        return policy_from_record(active)
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
) -> Sub2Policy | None:
    """Resolve the immutable policy recorded on a queued upload job."""

    record = db.scalar(
        select(UploadPolicyVersion).where(
            UploadPolicyVersion.tenant_id == job.tenant_id,
            UploadPolicyVersion.version == job.policy_version,
        )
    )
    if record is not None:
        return policy_from_record(record)
    if fallback.version == job.policy_version:
        return fallback
    return None
