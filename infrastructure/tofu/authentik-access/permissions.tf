locals {
  roles = {
    apply   = "home-lab-opentofu-authentik-apply"
    refresh = "home-lab-opentofu-managed-group-read"
  }

  controller_users = {
    plan = {
      username = "home-lab-opentofu-plan"
      name     = "Home Lab OpenTofu Plan"
      path     = "users"
      roles    = ["refresh"]
    }
    apply = {
      username = "home-lab-opentofu-apply"
      name     = "Home Lab OpenTofu Apply"
      path     = "users"
      roles    = ["apply", "refresh"]
    }
  }

  # Global application lifecycle grants and read permissions needed for shared
  # references. Creation of the scoped models below also needs a global grant.
  global_permissions = {
    apply = [
      "authentik_core.add_application",
      "authentik_core.change_application",
      "authentik_core.delete_application",
      "authentik_rbac.edit_system_settings",
    ]
    refresh = [
      "authentik_core.view_application",
      "authentik_core.view_user",
      "authentik_flows.view_flow",
      "authentik_flows.view_stage",
      "authentik_providers_oauth2.view_scopemapping",
      "authentik_rbac.view_system_settings",
      "authentik_stages_password.view_passwordstage",
      "authentik_stages_user_login.view_userloginstage",
    ]
  }

  # Keys are Authentik app_label.model identifiers. For lifecycle models, give
  # the creator add globally, then use native Initial Permissions so that both
  # roles can work with the object immediately, without an owner run.
  models = {
    "authentik_core.group" = {
      collections = ["groups"]
      create      = true
      apply_extra = ["add_user_to_group", "remove_user_from_group"]
    }
    "authentik_crypto.certificatekeypair" = {
      collections   = ["certificates", "signingCertificates"]
      create        = true
      refresh_extra = ["view_certificatekeypair_certificate", "view_certificatekeypair_key"]
    }
    "authentik_providers_oauth2.oauth2provider" = {
      collections   = ["oauthProviders"]
      create        = true
      refresh_extra = ["change_oauth2provider"] # Required to read the client secret.
    }
    "authentik_providers_proxy.proxyprovider" = {
      collections = ["proxyProviders"]
      create      = true
    }
    "authentik_providers_ldap.ldapprovider" = {
      collections = ["ldapProviders"]
      create      = true
    }
    "authentik_providers_oauth2.scopemapping" = {
      collections = ["scopeMappings"]
      create      = true
    }
    "authentik_policies.policybinding" = {
      collections = ["applicationPolicyBindings", "serviceApplicationBindings"]
      create      = true
    }
    "authentik_outposts.outpost" = {
      collections = ["outposts"]
      create      = true
    }
    "authentik_flows.flow" = {
      collections = ["customFlows"]
      create      = true
    }
    "authentik_flows.flowstagebinding" = {
      collections = ["flowStageBindings"]
      create      = true
    }
    "authentik_stages_authenticator_validate.authenticatorvalidatestage" = {
      collections = ["authenticatorValidateStages"]
      create      = true
    }
    "authentik_stages_identification.identificationstage" = {
      collections = ["identificationStages"]
      create      = true
    }
    "authentik_stages_authenticator_webauthn.authenticatorwebauthnstage" = {
      collections = ["webauthnStages"]
      create      = true
    }
    "authentik_stages_invitation.invitationstage" = {
      collections = ["invitationStages"]
      create      = true
    }
    "authentik_stages_prompt.prompt" = {
      collections = ["promptFields"]
      create      = true
    }
    "authentik_stages_prompt.promptstage" = {
      collections = ["promptStages"]
      create      = true
    }
    "authentik_stages_user_write.userwritestage" = {
      collections = ["userWriteStages"]
      create      = true
    }
    "authentik_stages_user_login.userloginstage" = {
      collections = ["userLoginStages"]
      create      = true
    }
    "authentik_policies_password.passwordpolicy" = {
      collections = ["passwordPolicies"]
      create      = true
    }
    "authentik_brands.brand" = {
      collections = ["brands"]
      apply_extra = ["change_brand"]
    }
    # Never grant broad user writes, role linkage/assignment or blueprint writes.
    "authentik_core.user" = {
      collections = ["serviceAccounts"]
      apply_extra = ["change_user", "reset_user_password"]
    }
    "authentik_rbac.role" = {
      collections = ["rbacRoles"]
    }
  }
}
