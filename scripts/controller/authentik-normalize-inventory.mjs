#!/usr/bin/env node

import { createHash } from "node:crypto";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { load } from "js-yaml";

const [apiPath, graphPath, failureResultsPath, blueprintPath, desiredPath, secretsPath, capturedAt] = process.argv.slice(2);
if (!apiPath || !graphPath || !failureResultsPath || !blueprintPath || !desiredPath || !secretsPath || !capturedAt) {
  console.error("usage: authentik-normalize-inventory.js API_JSON GRAPH_JSON FAILURE_RESULTS_JSON BLUEPRINT_YAML DESIRED_JSON SECRETS_JSON CAPTURED_AT");
  process.exit(64);
}

const api = JSON.parse(readFileSync(apiPath, "utf8"));
const graph = JSON.parse(readFileSync(graphPath, "utf8"));
const failureResults = JSON.parse(readFileSync(failureResultsPath, "utf8"));
const blueprint = load(readFileSync(blueprintPath, "utf8"));
const oauthIds = new Set(["15", "16", "21", "37", "47", "49"]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sortObject(value) {
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)));
}


function deepCanonical(value) {
  if (Array.isArray(value)) return value.map(deepCanonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, deepCanonical(value[key])]));
  }
  return value;
}

function hash(value) {
  return createHash("sha256").update(`${JSON.stringify(deepCanonical(value))}\n`).digest("hex");
}

assert(api.counts.applications === 25, "expected 25 applications");
assert(api.counts.providers === 25, "expected 25 total providers");
assert(api.counts.proxyProviders === 19, "expected 19 proxy providers");
assert(api.counts.oauthProviders === 6, "expected 6 direct OAuth2 providers");
assert(new Set(api.oauthProviders.map((item) => String(item.pk))).size === 6, "OAuth2 provider IDs must be unique");
assert(api.oauthProviders.every((item) => oauthIds.has(String(item.pk))), "unexpected OAuth2 provider ID");
assert(oauthIds.size === api.oauthProviders.length, "an expected OAuth2 provider is absent");

const proxyIds = new Set(api.proxyProviders.map((item) => String(item.pk)));
const applications = sortObject(Object.fromEntries(api.applications.map((item) => {
  const providerId = String(item.provider);
  assert(proxyIds.has(providerId) || oauthIds.has(providerId), `application ${item.slug} references an unmanaged provider`);
  return [item.slug, {
    backchannel_provider_ids: item.backchannel_providers,
    group: item.group,
    meta_description: item.meta_description,
    meta_hide: item.meta_hide,
    meta_icon: item.meta_icon,
    meta_launch_url: item.meta_launch_url,
    meta_publisher: item.meta_publisher,
    name: item.name,
    open_in_new_tab: item.open_in_new_tab,
    policy_engine_mode: item.policy_engine_mode,
    provider_id: item.provider,
    provider_type: proxyIds.has(providerId) ? "proxy" : "oauth2",
    slug: item.slug,
    uuid: item.pk,
  }];
})));

const proxyProviders = sortObject(Object.fromEntries(api.proxyProviders.map((item) => [String(item.pk), {
  access_token_validity: item.access_token_validity,
  authentication_flow: item.authentication_flow,
  authorization_flow: item.authorization_flow,
  basic_auth_enabled: item.basic_auth_enabled,
  basic_auth_password_attribute: item.basic_auth_password_attribute,
  basic_auth_user_attribute: item.basic_auth_user_attribute,
  cookie_domain: item.cookie_domain,
  external_host: item.external_host,
  intercept_header_auth: item.intercept_header_auth,
  internal_host: item.internal_host,
  internal_host_ssl_validation: item.internal_host_ssl_validation,
  invalidation_flow: item.invalidation_flow,
  jwt_federation_providers: item.jwt_federation_providers,
  jwt_federation_sources: item.jwt_federation_sources,
  mode: item.mode,
  name: item.name,
  pk: item.pk,
  property_mappings: item.property_mappings,
  refresh_token_validity: item.refresh_token_validity,
  skip_path_regex: item.skip_path_regex,
}])));

const oauthProviders = sortObject(Object.fromEntries(api.oauthProviders.map((item) => [String(item.pk), {
  access_code_validity: item.access_code_validity,
  access_token_validity: item.access_token_validity,
  allowed_redirect_uris: item.redirect_uris.map(({ matching_mode, redirect_uri_type, url }) => ({ matching_mode, redirect_uri_type, url })),
  authentication_flow: item.authentication_flow,
  authorization_flow: item.authorization_flow,
  client_id: item.client_id,
  client_type: item.client_type,
  encryption_key: item.encryption_key,
  grant_types: item.grant_types,
  include_claims_in_id_token: item.include_claims_in_id_token,
  invalidation_flow: item.invalidation_flow,
  issuer_mode: item.issuer_mode,
  jwt_federation_providers: item.jwt_federation_providers,
  jwt_federation_sources: item.jwt_federation_sources,
  logout_method: item.logout_method,
  logout_uri: item.logout_uri,
  name: item.name,
  pk: item.pk,
  property_mappings: item.property_mappings,
  refresh_token_threshold: item.refresh_token_threshold,
  refresh_token_validity: item.refresh_token_validity,
  signing_key: item.signing_key,
  sub_mode: item.sub_mode,
}])));

const entries = blueprint.entries ?? [];
const customFlowEntries = entries.filter((entry) => entry.model === "authentik_flows.flow" && entry.attrs?.slug === "passwordless-authentication-flow");
const customStageEntries = entries.filter((entry) => entry.model === "authentik_stages_authenticator_validate.authenticatorvalidatestage" && entry.attrs?.name === "Passwordless WebAuthn");
const customScopeEntries = entries.filter((entry) => entry.model === "authentik_providers_oauth2.scopemapping" && entry.attrs?.managed == null);
assert(customFlowEntries.length === 1, "expected one passwordless custom flow");
assert(customStageEntries.length === 1, "expected one passwordless custom stage");
assert(customScopeEntries.length === 1 && customScopeEntries[0].attrs.name === "Vaultwarden Email Scope", "unexpected unmanaged scope mapping");
assert(graph.flows.filter((item) => !item.slug.startsWith("default-") && item.slug !== "initial-setup").length === 1, "unexpected custom flow");
assert(graph.stages.filter((item) => !item.name.startsWith("default-") && !item.name.startsWith("stage-default-")).length === 1, "unexpected custom stage");
assert(graph.policies.every((item) => item.name.startsWith("default-")), "unexpected custom policy");
assert(graph.certificates.filter((item) => item.managed == null).length === 1 && graph.certificates.find((item) => item.managed == null)?.name === "authentik Self-signed Certificate", "unexpected unmanaged certificate");

const flowEntry = customFlowEntries[0];
const stageEntry = customStageEntries[0];
const scopeEntry = customScopeEntries[0];
const customFlows = {
  "passwordless-authentication": {
    pk: flowEntry.identifiers.pk,
    ...flowEntry.attrs,
  },
};
const authenticatorValidateStages = {
  "passwordless-webauthn": {
    pk: stageEntry.identifiers.pk,
    ...stageEntry.attrs,
  },
};
const scopeMappings = {
  "vaultwarden-email": {
    pk: scopeEntry.identifiers.pk,
    description: scopeEntry.attrs.description,
    expression: scopeEntry.attrs.expression,
    name: scopeEntry.attrs.name,
    scope_name: scopeEntry.attrs.scope_name,
  },
};

const customFlowId = flowEntry.identifiers.pk;
const customStageId = stageEntry.identifiers.pk;
const defaultLoginStage = graph.stages.find((item) => item.name === "default-authentication-login");
assert(defaultLoginStage, "default authentication login stage is absent");
const selectedFlowBindings = graph.flowStageBindings.filter((item) => item.target === customFlowId);
assert(selectedFlowBindings.length === 2, "expected two passwordless flow bindings");
const flowStageBindings = sortObject(Object.fromEntries(selectedFlowBindings.map((item) => {
  let stage_ref;
  if (item.stage === customStageId) stage_ref = "passwordless-webauthn";
  else if (item.stage === defaultLoginStage.pk) stage_ref = "default-authentication-login";
  else throw new Error("passwordless flow references an unexpected stage");
  return [item.pk, {
    evaluate_on_plan: item.evaluate_on_plan,
    invalid_response_action: item.invalid_response_action,
    order: item.order,
    pk: item.pk,
    policy_engine_mode: item.policy_engine_mode,
    re_evaluate_policies: item.re_evaluate_policies,
    stage_ref,
  }];
})));

const applicationIds = new Map(Object.values(applications).map((item) => [item.uuid, item.slug]));
const selectedPolicyBindings = graph.policyBindings.filter((item) => applicationIds.has(item.target));
assert(selectedPolicyBindings.length === 30, "expected 30 application access bindings");
const applicationPolicyBindings = sortObject(Object.fromEntries(selectedPolicyBindings.map((item) => [item.pk, {
  application_slug: applicationIds.get(item.target),
  enabled: item.enabled,
  failure_result: failureResults[item.pk],
  group: item.group,
  negate: item.negate,
  order: item.order,
  pk: item.pk,
  policy: item.policy,
  timeout: item.timeout,
  user: item.user == null ? null : Number(item.user),
}])));
assert(Object.values(applicationPolicyBindings).every((item) => item.group != null || item.user != null || item.policy != null), "empty application policy binding");

const desired = {
  $schema: "./desired.schema.json",
  applications,
  applicationPolicyBindings,
  authenticatorValidateStages,
  customBlueprints: {},
  customFlows,
  flowStageBindings,
  oauthProviders,
  proxyProviders,
  schemaVersion: 2,
  scopeMappings,
  sourceInventory: {
    applicationPolicyBindingsSha256: hash(applicationPolicyBindings),
    applicationsSha256: hash(applications),
    capturedAt,
    complete: true,
    customConfigurationSha256: hash({ authenticatorValidateStages, customFlows, flowStageBindings, scopeMappings }),
    oauthProvidersSha256: hash(oauthProviders),
    proxyProvidersSha256: hash(proxyProviders),
  },
};
const serializedDesired = `${JSON.stringify(deepCanonical(desired), null, 2)}\n`;
assert(!serializedDesired.includes("client_secret"), "client secret leaked into desired state");
writeFileSync(desiredPath, serializedDesired, { mode: 0o600 });
chmodSync(desiredPath, 0o600);

const secrets = {
  schemaVersion: 1,
  oauthProviders: sortObject(Object.fromEntries(api.oauthProviders.map((item) => {
    assert(typeof item.client_secret === "string" && item.client_secret.length > 0, `OAuth2 provider ${item.pk} has no client secret`);
    return [String(item.pk), { client_secret: item.client_secret }];
  }))),
};
writeFileSync(secretsPath, `${JSON.stringify(deepCanonical(secrets), null, 2)}\n`, { mode: 0o600 });
chmodSync(secretsPath, 0o600);
