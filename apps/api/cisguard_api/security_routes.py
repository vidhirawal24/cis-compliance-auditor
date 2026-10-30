from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib
import hmac
import secrets
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from cisguard_contracts.v1.models import ApprovalCreate
from cisguard_contracts.v1.security_extensions import InviteBody, AcceptBody, MemberUpdate, ReferenceBody
from .database import tenant_session
from .db_models import OrganizationMember, AuditEvent, CredentialReference, Approval, RemediationPlan
from .security import MATRIX, TokenVerifier, require_permission, require_independent_approver
from .settings import get_settings
from .pagination import encode_cursor, decode_cursor

router = APIRouter(prefix="/api/v1")


@lru_cache
def verifier():
    return TokenVerifier(get_settings())


def identity(request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    key = get_settings().cursor_signing_key.get_secret_value()
    if not key:
        raise HTTPException(503, "Rate limit configuration unavailable")
    address = request.client.host if request.client else "unknown"
    bucket = hmac.new(key.encode(), address.encode(), hashlib.sha256).hexdigest()
    with tenant_session(UUID(int=0), UUID(int=0)) as db:
        allowed = db.scalar(text("SELECT cisguard.consume_rate(:b)"), {"b": bucket})
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded")
    return verifier().verify(auth[7:])


def context(db, who):
    db.execute(
        text("SELECT set_config('app.aal',:a,true),set_config('app.email',:e,true)"),
        {"a": who.aal, "e": who.email or ""},
    )


def member(db, who, org, permission, privileged=False):
    context(db, who)
    row = db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.org_id == org,
            OrganizationMember.user_id == who.user_id,
            OrganizationMember.active.is_(True),
        )
    )
    if not row:
        raise HTTPException(403, "Organization membership required")
    require_permission(row.role, permission, who.aal, privileged=privileged)
    return row


def envelope(request, data):
    return {"schema_version": "1.0.0", "data": data, "meta": {"request_id": request.state.request_id}}


def audit(db, request, who, org, event, resource):
    db.add(
        AuditEvent(
            org_id=org,
            actor_id=who.user_id,
            request_id=UUID(request.state.request_id),
            event_type=event,
            resource_id=resource,
            details={},
        )
    )


@router.get("/me")
@router.get("/auth/session")
def me(request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        row = member(db, who, x_org_id, "session.read")
        audit(db, request, who, x_org_id, "auth.session.validated", who.user_id)
        return envelope(
            request,
            {
                "user_id": str(who.user_id),
                "org_id": str(x_org_id),
                "roles": [row.role],
                "aal": who.aal,
                "expires_at": datetime.fromtimestamp(who.expires, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            },
        )


@router.get("/me/permissions")
def permissions(request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        row = member(db, who, x_org_id, "session.read")
        return envelope(
            request,
            {
                "role": row.role,
                "permissions": MATRIX["roles"][row.role],
                "mfa_required": row.role in MATRIX["mfa_roles"],
            },
        )


@router.get("/me/mfa")
def mfa_status(request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        row = db.scalar(
            select(OrganizationMember).where(
                OrganizationMember.org_id == x_org_id,
                OrganizationMember.user_id == who.user_id,
                OrganizationMember.active.is_(True),
            )
        )
        if not row:
            raise HTTPException(403, "Organization membership required")
        return envelope(
            request,
            {"enrolled": who.mfa_enrolled, "aal": who.aal, "required": row.role in MATRIX["mfa_roles"]},
        )


@router.get("/organizations/{org_id}/members")
def members(
    org_id: UUID, request: Request, x_org_id: UUID = Header(), limit: int = 50, cursor: str | None = None
):
    if org_id != x_org_id or not 1 <= limit <= 100:
        raise HTTPException(403, "Invalid organization scope or limit")
    who = identity(request)
    with tenant_session(who.user_id, org_id) as db:
        member(db, who, org_id, "tenant.admin")
        key = get_settings().cursor_signing_key.get_secret_value()
        query = select(OrganizationMember).where(OrganizationMember.org_id == org_id)
        if cursor:
            query = query.where(OrganizationMember.id > decode_cursor(cursor, org_id, key))
        rows = db.scalars(query.order_by(OrganizationMember.id).limit(limit + 1)).all()
        next_cursor = encode_cursor(org_id, rows[limit - 1].id, key) if len(rows) > limit else None
        rows = rows[:limit]
        return envelope(
            request,
            {
                "items": [
                    {"user_id": str(r.user_id), "org_id": str(r.org_id), "role": r.role, "active": r.active}
                    for r in rows
                ],
                "next_cursor": next_cursor,
            },
        )


@router.patch("/organizations/{org_id}/members/{user_id}")
def update_member(
    org_id: UUID, user_id: UUID, body: MemberUpdate, request: Request, x_org_id: UUID = Header()
):
    if org_id != x_org_id:
        raise HTTPException(403, "Organization scope mismatch")
    who = identity(request)
    if who.user_id == user_id:
        raise HTTPException(403, "Self role changes are forbidden")
    with tenant_session(who.user_id, org_id) as db:
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:o,0))"), {"o": str(org_id)})
        member(db, who, org_id, "tenant.admin", True)
        row = db.scalar(
            select(OrganizationMember).where(
                OrganizationMember.org_id == org_id, OrganizationMember.user_id == user_id
            )
        )
        if not row:
            raise HTTPException(404, "Member not found")
        row.role, row.active = body.role.value, body.active
        audit(db, request, who, org_id, "membership.updated", row.id)
        return envelope(request, {"user_id": str(user_id), "role": row.role, "active": row.active})


@router.post("/organizations/{org_id}/invitations", status_code=201)
def invite(org_id: UUID, body: InviteBody, request: Request, x_org_id: UUID = Header()):
    if org_id != x_org_id:
        raise HTTPException(403, "Organization scope mismatch")
    who = identity(request)
    invite_id, token = uuid4(), secrets.token_urlsafe(48)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    with tenant_session(who.user_id, org_id) as db:
        member(db, who, org_id, "tenant.admin", True)
        db.execute(
            text(
                "INSERT INTO cisguard.invitations(id,org_id,email,role,token_hash,invited_by,expires_at) VALUES(:i,:o,:e,:r,:h,:u,:x)"
            ),
            {
                "i": invite_id,
                "o": org_id,
                "e": body.email,
                "r": body.role.value,
                "h": hashlib.sha256(token.encode()).hexdigest(),
                "u": who.user_id,
                "x": expires,
            },
        )
        audit(db, request, who, org_id, "invitation.created", invite_id)
    return envelope(
        request,
        {
            "invitation_id": str(invite_id),
            "token": token,
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "delivery": "MANUAL",
        },
    )


@router.post("/invitations/{invitation_id}/accept")
def accept(invitation_id: UUID, body: AcceptBody, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    if not who.email:
        raise HTTPException(403, "Verified email required")
    try:
        with tenant_session(who.user_id, x_org_id) as db:
            context(db, who)
            db.execute(
                text("SELECT cisguard.accept_invitation(:i,:h,:m)"),
                {"i": invitation_id, "h": hashlib.sha256(body.token.encode()).hexdigest(), "m": uuid4()},
            )
            audit(db, request, who, x_org_id, "invitation.accepted", invitation_id)
    except IntegrityError:
        raise HTTPException(409, "Membership already exists") from None
    return envelope(request, {"org_id": str(x_org_id), "accepted": True})


@router.post("/credential-references", status_code=201)
def reference(body: ReferenceBody, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    ref_id = uuid4()
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "tenant.admin", True)
        db.add(
            CredentialReference(
                id=ref_id,
                org_id=x_org_id,
                label=body.label,
                vault_reference=f"device-secrets/data/{x_org_id}/{ref_id}",
            )
        )
        audit(db, request, who, x_org_id, "credential_reference.created", ref_id)
    return envelope(
        request,
        {"credential_reference_id": str(ref_id), "label": body.label, "provisioning": "REQUIRED_IN_OPENBAO"},
    )


@router.post("/approvals", status_code=201)
def approve(body: ApprovalCreate, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    expires = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    if not now < expires <= now + timedelta(hours=24):
        raise HTTPException(422, "Approval expiration must be within 24 hours")
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "change.approve", True)
        plan = db.scalar(
            select(RemediationPlan).where(
                RemediationPlan.org_id == x_org_id, RemediationPlan.id == body.plan_id
            )
        )
        if not plan:
            raise HTTPException(404, "Plan not found")
        require_independent_approver(who.user_id, plan.author_id, plan.author_id)
        if plan.plan_sha256 != body.plan_sha256:
            raise HTTPException(409, "Plan changed; review the current plan")
        if body.decision == "APPROVED" and plan.outcome != "FEASIBLE":
            raise HTTPException(409, "Only feasible plans may be approved")
        approval_id = uuid4()
        db.add(
            Approval(
                id=approval_id,
                org_id=x_org_id,
                plan_id=plan.id,
                plan_sha256=plan.plan_sha256,
                approver_id=who.user_id,
                plan_author_id=plan.author_id,
                decision=body.decision,
                reason=body.reason,
                expires_at=expires,
            )
        )
        audit(
            db,
            request,
            who,
            x_org_id,
            "approval.granted" if body.decision == "APPROVED" else "approval.rejected",
            approval_id,
        )
    return envelope(
        request,
        {
            "schema_version": "1.0.0",
            "org_id": str(x_org_id),
            "approval_id": str(approval_id),
            "approver_id": str(who.user_id),
            "decided_at": now.isoformat().replace("+00:00", "Z"),
            **body.model_dump(mode="json"),
        },
    )
