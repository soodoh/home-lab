#!/usr/bin/env python3

"""Guarded one-time Authentik provider service-account bootstrap.

Run this file only through `ak shell --no-imports` inside the production
Authentik server container. The create operation emits the new token exactly
once on a dedicated marker line; the caller must capture it without logging.
"""

import hashlib
import json
import os

from django.contrib.auth.models import Permission
from django.db import transaction
from django.utils.dateparse import parse_datetime
from guardian.models import RoleModelPermission

from authentik.core.models import Token, User
from authentik.rbac.models import Role


USERNAME = "home-lab-opentofu"
ROLE_NAME = "home-lab-opentofu-application-manager"
TOKEN_IDENTIFIER = "home-lab-opentofu-provider-2026-08"
TOKEN_EXPIRES_AT = "2026-11-12T00:00:00Z"
CONFIRMATION = "create-reviewed-home-lab-opentofu-service-account"
PERMISSIONS = (
    ("authentik_core", "application", "view_application"),
    ("authentik_core", "application", "change_application"),
    ("authentik_core", "provider", "view_provider"),
    ("authentik_core", "provider", "change_provider"),
    ("authentik_providers_proxy", "proxyprovider", "view_proxyprovider"),
    ("authentik_providers_proxy", "proxyprovider", "change_proxyprovider"),
)

REQUEST = {
    "format": "home-lab-authentik-service-account-bootstrap-v1",
    "username": USERNAME,
    "role": ROLE_NAME,
    "tokenIdentifier": TOKEN_IDENTIFIER,
    "tokenExpiresAt": TOKEN_EXPIRES_AT,
    "permissions": [".".join(value) for value in PERMISSIONS],
}
REQUEST_SHA256 = hashlib.sha256(
    (json.dumps(REQUEST, separators=(",", ":"), sort_keys=True) + "\n").encode()
).hexdigest()


def inventory() -> dict[str, object]:
    user = User.objects.filter(username=USERNAME).first()
    role = Role.objects.filter(name=ROLE_NAME).first()
    token = Token.objects.filter(identifier=TOKEN_IDENTIFIER).first()
    assigned_permissions: list[str] = []
    role_assigned = False
    if role is not None:
        assigned_permissions = sorted(
            f"{item.content_type.app_label}.{item.content_type.model}.{item.permission.codename}"
            for item in RoleModelPermission.objects.filter(role=role)
            .select_related("content_type", "permission")
        )
    if user is not None and role is not None:
        role_assigned = user.roles.filter(pk=role.pk).exists()
    return {
        "request": REQUEST,
        "requestSha256": REQUEST_SHA256,
        "userExists": user is not None,
        "userType": None if user is None else user.type,
        "userActive": None if user is None else user.is_active,
        "roleExists": role is not None,
        "roleAssigned": role_assigned,
        "assignedPermissions": assigned_permissions,
        "tokenExists": token is not None,
        "tokenExpiring": None if token is None else token.expiring,
        "tokenExpiresAt": None if token is None or token.expires is None else token.expires.isoformat(),
    }


def emit_status(status: str) -> None:
    value = inventory()
    value["status"] = status
    print("__HOME_LAB_AUTHENTIK_STATUS__" + json.dumps(value, separators=(",", ":"), sort_keys=True))


def create() -> None:
    if os.environ.get("HOME_LAB_AUTHENTIK_BOOTSTRAP_CONFIRMATION") != CONFIRMATION:
        raise SystemExit("authentik bootstrap confirmation is absent or invalid")
    if os.environ.get("HOME_LAB_AUTHENTIK_BOOTSTRAP_REQUEST_SHA256") != REQUEST_SHA256:
        raise SystemExit("authentik bootstrap request hash is absent or invalid")
    before = inventory()
    if before["userExists"] or before["roleExists"] or before["tokenExists"]:
        raise SystemExit("authentik bootstrap refuses pre-existing service-account objects")

    expires = parse_datetime(TOKEN_EXPIRES_AT)
    if expires is None:
        raise SystemExit("authentik bootstrap token expiry is invalid")

    with transaction.atomic():
        user = User.objects.create(
            username=USERNAME,
            name="Home Lab OpenTofu",
            type="service_account",
            is_active=True,
        )
        role = Role.objects.create(name=ROLE_NAME)
        user.roles.add(role)
        for app_label, model, codename in PERMISSIONS:
            permission = Permission.objects.select_related("content_type").get(
                content_type__app_label=app_label,
                content_type__model=model,
                codename=codename,
            )
            RoleModelPermission.objects.create(
                role=role,
                content_type=permission.content_type,
                permission=permission,
            )
        token = Token.objects.create(
            identifier=TOKEN_IDENTIFIER,
            intent="api",
            user=user,
            description="OpenTofu provider token; rotate out-of-band before expiry",
            expiring=True,
            expires=expires,
        )

    emit_status("created")
    print("__HOME_LAB_AUTHENTIK_TOKEN__" + token.key)


operation = os.environ.get("HOME_LAB_AUTHENTIK_BOOTSTRAP_OPERATION", "inspect")
if operation == "inspect":
    emit_status("inspected")
elif operation == "create":
    create()
else:
    raise SystemExit("authentik bootstrap operation must be inspect or create")
