#!/usr/bin/env python3

"""Guarded one-time bootstrap for separate Authentik plan and apply identities.

Run only through ``ak shell --no-imports`` inside the production Authentik
server container. The create operation emits each token once on a dedicated
marker line; callers must capture those lines without logging command output.
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


CONFIRMATION = "create-reviewed-home-lab-opentofu-authentik-identities"
TOKEN_EXPIRES_AT = os.environ.get("HOME_LAB_AUTHENTIK_BOOTSTRAP_TOKEN_EXPIRES_AT", "")
MODELS = (
    ("authentik_blueprints", "blueprintinstance"),
    ("authentik_core", "application"),
    ("authentik_core", "propertymapping"),
    ("authentik_core", "provider"),
    ("authentik_flows", "flow"),
    ("authentik_flows", "flowstagebinding"),
    ("authentik_flows", "stage"),
    ("authentik_policies", "policybinding"),
    ("authentik_providers_oauth2", "oauth2provider"),
    ("authentik_providers_oauth2", "scopemapping"),
    ("authentik_providers_proxy", "proxyprovider"),
    ("authentik_stages_authenticator_validate", "authenticatorvalidatestage"),
)
ACCOUNTS = {
    "plan": {
        "username": "home-lab-opentofu-plan",
        "name": "Home Lab OpenTofu Plan",
        "role": "home-lab-opentofu-authentik-plan",
        "tokenIdentifier": "home-lab-opentofu-authentik-plan",
        "actions": ("view",),
    },
    "apply": {
        "username": "home-lab-opentofu-apply",
        "name": "Home Lab OpenTofu Apply",
        "role": "home-lab-opentofu-authentik-apply",
        "tokenIdentifier": "home-lab-opentofu-authentik-apply",
        "actions": ("view", "add", "change"),
    },
}


def permissions_for(account: dict[str, object]) -> tuple[tuple[str, str, str], ...]:
    actions = account["actions"]
    if not isinstance(actions, tuple):
        raise SystemExit("authentik bootstrap account actions are invalid")
    return tuple(
        (app_label, model, f"{action}_{model}")
        for app_label, model in MODELS
        for action in actions
    )


REQUEST = {
    "format": "home-lab-authentik-service-account-bootstrap-v2",
    "tokenExpiresAt": TOKEN_EXPIRES_AT,
    "accounts": {
        capability: {
            "username": account["username"],
            "role": account["role"],
            "tokenIdentifier": account["tokenIdentifier"],
            "permissions": [".".join(value) for value in permissions_for(account)],
        }
        for capability, account in ACCOUNTS.items()
    },
}
REQUEST_SHA256 = hashlib.sha256(
    (json.dumps(REQUEST, separators=(",", ":"), sort_keys=True) + "\n").encode()
).hexdigest()


def account_inventory(account: dict[str, object]) -> dict[str, object]:
    username = account["username"]
    role_name = account["role"]
    token_identifier = account["tokenIdentifier"]
    user = User.objects.filter(username=username).first()
    role = Role.objects.filter(name=role_name).first()
    token = Token.objects.filter(identifier=token_identifier).first()
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


def inventory() -> dict[str, object]:
    return {
        "request": REQUEST,
        "requestSha256": REQUEST_SHA256,
        "accounts": {
            capability: account_inventory(account)
            for capability, account in ACCOUNTS.items()
        },
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
    expires = parse_datetime(TOKEN_EXPIRES_AT)
    if expires is None:
        raise SystemExit("HOME_LAB_AUTHENTIK_BOOTSTRAP_TOKEN_EXPIRES_AT must be an ISO-8601 timestamp")

    before = inventory()
    if any(
        state[flag]
        for state in before["accounts"].values()
        for flag in ("userExists", "roleExists", "tokenExists")
    ):
        raise SystemExit("authentik bootstrap refuses pre-existing service-account objects")

    created_tokens: dict[str, Token] = {}
    with transaction.atomic():
        for capability, account in ACCOUNTS.items():
            user = User.objects.create(
                username=account["username"],
                name=account["name"],
                type="service_account",
                is_active=True,
            )
            role = Role.objects.create(name=account["role"])
            user.roles.add(role)
            for app_label, model, codename in permissions_for(account):
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
            created_tokens[capability] = Token.objects.create(
                identifier=account["tokenIdentifier"],
                intent="api",
                user=user,
                description=f"Home Lab OpenTofu {capability} token; rotate before expiry",
                expiring=True,
                expires=expires,
            )

    emit_status("created")
    for capability, token in created_tokens.items():
        print(f"__HOME_LAB_AUTHENTIK_{capability.upper()}_TOKEN__{token.key}")


operation = os.environ.get("HOME_LAB_AUTHENTIK_BOOTSTRAP_OPERATION", "inspect")
if operation == "inspect":
    emit_status("inspected")
elif operation == "create":
    create()
else:
    raise SystemExit("authentik bootstrap operation must be inspect or create")
