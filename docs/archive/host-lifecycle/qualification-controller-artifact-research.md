# Research: qualification-controller artifact candidates

> Deferred artifact research; not an operational retirement prerequisite. See the [current operational plan](../../host-lifecycle-completion-plan.md) and [archive index](README.md). Historical failures and evidence limits below remain unchanged.

## Summary
This note carries forward artifact **candidates, not approved or verified downloads**, from preserved failed-run metadata. It is not a complete authoritative-controller environment, proof of native compatibility, or migration completion. Only the specifically authorized local records and repository sources were read during this recovery; no external metadata was independently re-fetched or authenticated.

## Recovery provenance
- Original researcher run `af137031-dcff-4387-ab39-a551a0125d15` failed with `Request was aborted`; its root cause remains unknown. Queued steering request `4e1c335b-0ebb-47ca-bbae-aff21704fd82` was never delivered (zero delivered). The original run remains **failed**, despite preserving a metadata report; it created no repository note.
- Authorized inputs were `failed-run-research-handoff.md`, `blocked.json`, and `same-protocol-retry-approval.json` in `/Users/pauldiloreto/.local/state/home-lab-source-integration/pve-amd64-route-feasibility-3491395-01/artifact-research-abort-01/`. The records identify preserved report SHA-256 `3a5a89f614cef361921331de492a11a33fd02fbb3da1e6d50f3b3acd40de685b`; this recovery did not recompute it.
- The approval records one fresh native researcher attempt, same protocol—not a resumed failed process or an execution-mode fallback—with authoritative output set to this repository note. This note supersedes the handoff's output-routing statements, not its failed-run history.
- Repository context supplied by the task/records: `main`, HEAD `34913959852acf683196bc62eeacded48b543ce4`, with preexisting dirty reviewed documentation/Docker changes and two untracked observer candidates. These were not changed or independently re-inventoried.
- **Evidence distinction:** repository requirements below are directly read local source evidence (high confidence about source text). External release, date, digest, signature-guidance and error claims below are attributed exclusively to the preserved handoff, not newly verified observations. Suitability assessments are interpretation, not demonstrated compatibility.

## Preserved repository contract
Direct sources: [controller wheel lock](../../../controller/requirements-ansible-controller.lock), [collection requirements](../../../ansible/collections/requirements.yml), [package.json](../../../package.json), and [qualification versions.tf](../../../infrastructure/tofu/debian-lifecycle-qualification/versions.tf).

Preserve ansible-core **2.21.2**, community.general **13.2.0**, Bun **1.2.4**, bpg/proxmox **= 0.111.1**, and OpenTofu **>= 1.11.0, < 2.0.0**. No installed versions are inferred. The wheel lock declares Ubuntu 24.04 x86_64 and CPython 3.13; its exact dependency URLs/hashes are reproduced below, not regenerated or download-verified:

```text
ansible-core @ https://files.pythonhosted.org/packages/f3/0c/c3f6f78d0e28123bec95a7d1a0caf8042c51042ce71db2816a290448863b/ansible_core-2.21.2-py3-none-any.whl#sha256=c7d696c717da03109a32a569a5fe57925812a86734344eab775cba169bf57cf8
cffi @ https://files.pythonhosted.org/packages/6f/08/f2e7d62c460faae0926f2d6e423694aa409ced3bc1fe2927a0a6e5f05416/cffi-2.1.0-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl#sha256=799416bae98336e400981ff6e532d67d5c709cfb30afb79865a1315f94b0e224
cryptography @ https://files.pythonhosted.org/packages/d9/41/029086c34d91052fc3b88bcc8056f709a7c915c7a23b235a54eb800b1c97/cryptography-50.0.0-cp311-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl#sha256=06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7
jinja2 @ https://files.pythonhosted.org/packages/62/a1/3d680cbfd5f4b8f15abc1d571870c5fc3e594bb582bc3b64ea099db13e56/jinja2-3.1.6-py3-none-any.whl#sha256=85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67
markupsafe @ https://files.pythonhosted.org/packages/a9/21/9b05698b46f218fc0e118e1f8168395c65c8a2c750ae2bab54fc4bd4e0e8/markupsafe-3.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl#sha256=ccfcd093f13f0f0b7fdd0f198b90053bf7b2f02a3927a30e63f3ccc9df56b676
packaging @ https://files.pythonhosted.org/packages/df/b2/87e62e8c3e2f4b32e5fe99e0b86d576da1312593b39f47d8ceef365e95ed/packaging-26.2-py3-none-any.whl#sha256=5fc45236b9446107ff2415ce77c807cee2862cb6fac22b8a73826d0693b0980e
pycparser @ https://files.pythonhosted.org/packages/0c/c3/44f3fbbfa403ea2a7c779186dc20772604442dde72947e7d01069cbe98e3/pycparser-3.0-py3-none-any.whl#sha256=b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992
pyyaml @ https://files.pythonhosted.org/packages/74/27/e5b8f34d02d9995b80abcef563ea1f8b56d20134d8f4e5e81733b1feceb2/pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl#sha256=0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6
resolvelib @ https://files.pythonhosted.org/packages/e2/23/c941a0d0353681ca138489983c4309e0f5095dfd902e1357004f2357ddf2/resolvelib-1.2.1-py3-none-any.whl#sha256=fb06b66c8da04172d9e72a21d7d06186d8919e32ae5ab5cdf5b9d920be805ac2
```

## Candidate metadata table
All external entries and primary URLs in this table are carried forward from the preserved handoff. “Published SHA-256” means a value reported there as upstream metadata, **not authentication or a hash of an artifact downloaded by this recovery**. Publication dates are reported upstream dates, not a local clock assertion. Version/build-scoped URLs are not guaranteed immutable or retained; the handoff reports both GitHub release records had `"immutable":false`.

| Component | Exact candidate / architecture | Primary artifact URL (not downloaded) | Reported published SHA-256 | Preserved metadata citation and limits |
|---|---|---|---|---|
| Ubuntu controller disk | Ubuntu 24.04 LTS, release-20260826; amd64 | [ubuntu-24.04-server-cloudimg-amd64.img](https://cloud-images.ubuntu.com/releases/noble/release-20260826/ubuntu-24.04-server-cloudimg-amd64.img) | `d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30` | [Dated listing](https://cloud-images.ubuntu.com/releases/noble/release-20260826/): image 2026-08-26 20:31; [SHA256SUMS](https://cloud-images.ubuntu.com/releases/noble/release-20260826/SHA256SUMS) listed 20:32. Companion SHA256SUMS.gpg unverified. |
| CPython SOURCE | 3.13.15; architecture-neutral source, intended Linux x86_64 build | [Python-3.13.15.tar.xz](https://www.python.org/ftp/python/3.13.15/Python-3.13.15.tar.xz) | `1e66a7945a48390ee4c2a4268a0e4185884059a13c4aab6d148aa208deea4a76` | [Release page](https://www.python.org/downloads/release/python-31315/), Aug. 5, 2026; source checksum, .sigstore, .asc and SPDX links. **Not an installed or ready-made Ubuntu runtime.** |
| OpenTofu provisioner | 1.11.1; darwin_arm64 | [tofu_1.11.1_darwin_arm64.zip](https://github.com/opentofu/opentofu/releases/download/v1.11.1/tofu_1.11.1_darwin_arm64.zip) | `1ad4f7affb6947a36f03142c655c5d84bb5bd0bf5a350d3c84519dfd6acd6697` | [Release API](https://api.github.com/repos/opentofu/opentofu/releases/tags/v1.11.1), asset 326980936; published 2025-12-10T17:45:29Z, draft/prerelease false. GitHub asset digest only; manifest fetch failed. |
| OpenTofu controller | 1.11.1; linux_amd64 | [tofu_1.11.1_linux_amd64.zip](https://github.com/opentofu/opentofu/releases/download/v1.11.1/tofu_1.11.1_linux_amd64.zip) | `bbfaf9baff1e5baf2775a4a9e7ba9e3c0152841f29f4ee7cf4610feb48f2db1c` | [Same API](https://api.github.com/repos/opentofu/opentofu/releases/tags/v1.11.1), asset 326980930; same date. Candidate satisfies repository range; not a latest-release or advisory-clearance claim. |
| Bun | Preserved 1.2.4; linux x64 baseline candidate | [bun-linux-x64-baseline.zip](https://github.com/oven-sh/bun/releases/download/bun-v1.2.4/bun-linux-x64-baseline.zip) | **Missing:** API `"digest":null` | [Release API](https://api.github.com/repos/oven-sh/bun/releases/tags/bun-v1.2.4), asset 232705940; published 2025-02-26T10:17:09Z, asset created 09:43:45Z. Historical CPU/platform and trusted checksum provenance unresolved. |
| Node tooling runtime | 24.20.0 Krypton LTS; linux x64 | [node-v24.20.0-linux-x64.tar.xz](https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.xz) | `2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2` | [Release post](https://nodejs.org/en/blog/release/v24.20.0), 2026-08-26, reported signed checksum text. [Manifest location](https://nodejs.org/dist/v24.20.0/SHASUMS256.txt.asc); digest came from post, not separately authenticated. |

## Findings
1. **Claim:** Ubuntu is a disk candidate, not qualification evidence. **Sources:** preserved [release listing](https://cloud-images.ubuntu.com/releases/noble/release-20260826/), [daily listing](https://cloud-images.ubuntu.com/noble/20260826/), and [daily checksum manifest](https://cloud-images.ubuntu.com/noble/20260826/SHA256SUMS). **Support:** preserved metadata; interpretation. **Confidence:** medium, unverified in recovery. The handoff reports the daily `noble-server-cloudimg-amd64.img` is labelled `QCow2 UEFI/GPT Bootable disk image` and has the same published hash as the release disk. Linking that to QEMU/PVE suitability is researcher inference; no disk inspection, import or firmware test occurred. This Ubuntu candidate does **not** replace the existing Debian guest image pin.
2. **Claim:** CPython source introduces a separate build/bootstrap obligation. **Sources:** preserved [release](https://www.python.org/downloads/release/python-31315/) and [build guidance](https://devguide.python.org/getting-started/setup-building/). **Support:** interpretation from preserved source metadata and local wheel tags. **Confidence:** high that source is not an installed runtime; native build feasibility unresolved. Preserve normal GIL-enabled CPython 3.13 (`cp313`, not `cp313t`). The handoff identifies C toolchain/build-essential, make, pkg-config, OpenSSL, zlib, libffi, bzip2, xz and SQLite development inputs, and reports Ubuntu 24.04 lacks libmpdec-dev with bundled library use permitted. Exact versions, full dependency closure, configure options, ensurepip/venv policy and module tests remain unresolved; a rolling guide is not a pinned 3.13 build recipe.
3. **Claim:** Node has a source-proven controller requirement, not just optional commit tooling relevance. **Sources:** [reconcile script](../../../scripts/reconcile-infrastructure#L79), [package.json](../../../package.json); preserved [commitlint registry record](https://registry.npmjs.org/@commitlint/cli/21.2.1) and [Node release](https://nodejs.org/en/blog/release/v24.20.0). **Support:** direct local evidence for required command; interpretation for candidate fit. **Confidence:** high for source requirement; medium for metadata-based engine fit, untested overall. The handoff reports commitlint 21.2.1 requires Node `>=22.12.0`; 24.20.0 satisfies that floor. package.json requests `^21.2.1`, not an exact resolved CLI. Node is not an Ansible-core dependency, but the validation lane explicitly requires it. Bun cannot be assumed to replace Node; no package-lock or transitive compatibility validation occurred.

## Additional required controller tools
Direct inspection confirms [scripts/reconcile-infrastructure:79](../../../scripts/reconcile-infrastructure#L79) checks these commands for `validate`:

```text
tofu node jq python3 shellcheck ansible-lint ansible-playbook docker git go
```

The focused source also confirms actual use of **ShellCheck at line 206**, **ansible-lint at line 224**, and **Docker Compose at line 229** (`docker compose config --no-interpolate --quiet`), as well as Ansible playbook syntax checks. These are the source facts omitted by the undelivered steering request.

The candidate table and existing core wheel lock are **not a COMPLETE authoritative-controller environment**. The lock does not lock ansible-lint, Go, Docker/Compose, ShellCheck, jq, Git, OS packages, or verifier/build tools. Command presence is not sufficient version, functionality or compatibility validation; Docker alone does not establish availability of its Compose subcommand. No recursive research or new pins for these prerequisites were undertaken. Exact OS package resolution, verifier/build dependency approval and native validation require separate approvals. The focused reads are not an exhaustive dependency audit of every downstream validation script.

## Unresolved verification
- **No signatures authenticated.** Preserved [Canonical guidance](https://documentation.ubuntu.com/public-images/public-images-how-to/verify-image-checksum/) describes authenticating SHA256SUMS.gpg then comparing image checksums, with expected UEC key fingerprint `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`. This is a reported documented key, not an observed valid signature on this build.
- Preserved [OpenTofu guidance](https://opentofu.org/docs/intro/install/standalone/) describes checksums plus Cosign `.pem`/`.sig` verification; expected identity `https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/v1.11`, issuer `https://token.actions.githubusercontent.com`. Cosign bootstrap remains unapproved; listed `.gpgsig` assets are not verified signatures.
- Preserved [Python Sigstore guidance](https://www.python.org/downloads/metadata/sigstore/) identifies 3.13 signer `thomas@python.org`, issuer `https://accounts.google.com`. Neither bundle nor .asc was verified. Preserved [Node versioned README](https://raw.githubusercontent.com/nodejs/node/v24.20.0/README.md) describes SHASUMS256.txt.asc, release-key keyring, gpgv and checksum comparison. Keyring pin/review and all verifier/trust bootstrap remain outstanding; mutable HEAD is not an approved immutable input.
- Bun's published SHA256/SHA512, historical CPU requirements, signature provenance and archive authentication remain missing. No digest was invented, inferred or calculated.
- Exact signed Ubuntu package/build plans, native Node/Bun compatibility, CPython build results, wheel retrieval verification, collection/provider artifact authentication, resource fit, and advisory/maintenance review remain unresolved. OpenTofu 1.11.1 is a stable candidate, not a statement of newest or secure status.
- Controller **2 GiB** and fresh Debian fixture **4 GiB** are source-plan/task budgets only, not measured capacity or proven build feasibility. VM9901 is **proposed, not reserved**. VM9900's failed first boot remains **failed**. The prior eight GETs are consumed; prior fixture/PVE grants cannot be reused. No new operational authority is conferred; bounded ADR0003 migration scope is unchanged, without reporting automation or universal observers.

### Preserved bounded errors and validation limitation
These are original-run records, not requests or failures newly generated by this recovery:

| Original request/check | Preserved result |
|---|---|
| [OpenTofu checksum manifest](https://github.com/opentofu/opentofu/releases/download/v1.11.1/tofu_1.11.1_SHA256SUMS) | `Error - Unsupported content type: application/octet-stream` through fetch_content. No raw-mode/execution workaround was attempted. Manifest body remains unresolved; API digests do not authenticate it. |
| [Canonical former guidance URL 1](https://documentation.ubuntu.com/public-cloud/all-clouds/how-to/verify-cloud-image/) and [URL 2](https://documentation.ubuntu.com/public-cloud/all-clouds/how-to/verify-ubuntu-images/) | Each returned `Error - HTTP 404: Not Found`; one bounded discovery search located the public-images guidance cited above. |
| [Node verify URL](https://nodejs.org/en/download/verify) | `Error - HTTP 404: Not Found`; versioned README supplied guidance instead. |
| Original automated source_check | `unclear`, confidence `0.30`: `Passages mention the claim's terms but contain no clear support or contradiction markers.` The combined claim was not validated automatically; the original report relied on fetched first-party passages/API fields. Recovery performed no source_check or independent external validation. |

## Contradictions
No conflicting artifact hash was reported in the preserved handoff; this is not a new contradiction search. The preserved [rolling Bun installation guide](https://bun.sh/docs/installation) described baseline assets as aliases of one x64 binary, while historical 1.2.4 API metadata listed distinct baseline/ordinary assets with different sizes. Current advice must not be projected onto 1.2.4; baseline remains only a conservative candidate.

The handoff records Python 3.13.12 discovery was superseded by 3.13.15 in one bounded update; this recovery made no version change. Its characterization of Node as conditional tooling is qualified here by directly checked validation source requiring Node. Failed-run statements about writing only a managed handoff describe that earlier run, not this repository-note recovery.

## Sources
- **Kept, directly read:** authorized preservation/approval records and five repository inputs cited above — provenance, unchanged pins, and actual controller prerequisites.
- **Kept, preserved citations only:** Canonical dated listings/manifests and verification guidance; Python release/build/Sigstore pages; OpenTofu release API/standalone guidance; Bun 1.2.4 API; Node release/versioned README and commitlint publisher metadata — exact candidate metadata and unresolved trust/build obligations. None re-fetched here.
- **Deprioritized in original handoff:** mutable Ubuntu aliases, Node generic download page, latest-release lists, superseded Python 3.13.12 and unrelated Ubuntu hits. Rolling Bun documentation retained only to flag historical applicability. No third-party article serves as pin authority.

## Next steps
Separate owner approval must precede further work: review these candidates, resolve Bun provenance and the authenticated OpenTofu manifest, then approve complete package/verifier/build dependency plans and capacity/native qualification. Downloads, signature/digest checks, installation, host/PVE actions and migration qualification require their own explicit grants; this note authorizes none.

## Not performed
No web_search, fetch_content, source_check, get_search_content, new network request, artifact download, command, install, package operation, credential access, host/PVE/SSH access, delegation, staging, commit, push, native validation or migration action occurred in this recovery. No arbitrary private state/receipt discovery was performed. No preexisting repository files, locks, plans, failed-run records or observer candidates were changed. The sole output of that recovery was the new `docs/qualification-controller-artifact-research.md` note (subsequently moved to this archive), not merely a managed handoff.

---

## BEGIN bounded public-metadata follow-up — metadata-followup-01

### Summary and stage provenance
**Bun 1.2.4 Linux x64 BASELINE now has a directly observed vendor-published SHA-256 in a commit-pinned formula. OpenTofu 1.11.1 checksum-manifest text remains unavailable through the authorized tool.** Neither result authenticates an archive or signature, approves a variant, or establishes native compatibility.

The historical body above is retained as the record of failed researcher `af137031-dcff-4387-ab39-a551a0125d15` and successful source-only recovery `4cae89a0` (recovery identifier supplied by this follow-up task). Its no-network statements apply to that OLD recovery, **not this network-enabled follow-up**. Earlier external metadata remains carried-forward/unverified except for the specific newly observed source text below. No historical failed run is reclassified.

Before network research, this follow-up read the existing note and `/Users/pauldiloreto/.local/state/home-lab-source-integration/pve-amd64-route-feasibility-3491395-01/metadata-followup-01/approval.json`. That approval records `2026-09-10T19:37:23.099728+00:00`, answer `Resolve metadata gaps (Recommended)`, and prior-note SHA-256 `a95997074aeed05149c5e74244f123b9493efbe4bf1eac10a8032dcad304a8c3`. The digest and parent's sibling `note-before.md` freeze are recorded provenance, not independently recomputed or read here. Repository branch/HEAD remain task-supplied, not rechecked.

### Findings
1. **Claim: the vendor's pinned formula publishes the exact baseline zip hash. Sources:** [raw formula](https://raw.githubusercontent.com/oven-sh/homebrew-bun/9510da3431c51aeaa0da85d91896ded94a942e0f/Formula/bun%401.2.4.rb), [commit](https://github.com/oven-sh/homebrew-bun/commit/9510da3431c51aeaa0da85d91896ded94a942e0f). **Support:** direct evidence. **Confidence:** high for the published filename/hash association; artifact authenticity remains unestablished.

   Owning repository: `oven-sh/homebrew-bun`; immutable commit identifier: `9510da3431c51aeaa0da85d91896ded94a942e0f`; actual discovered path: `Formula/bun@1.2.4.rb`. The fetched formula declares `version "1.2.4"`. Exact Linux branch passage:

   ```ruby
   elsif OS.linux?
     if Hardware::CPU.arm?
       url "https://github.com/oven-sh/bun/releases/download/bun-v#{version}/bun-linux-aarch64.zip"
       sha256 "694a1b39ad3560f3fc7c8e0ac42df277d7ac4f28fe373646104000ddff9ae85c" # bun-linux-aarch64.zip
     elsif Hardware::CPU.avx2?
       url "https://github.com/oven-sh/bun/releases/download/bun-v#{version}/bun-linux-x64.zip"
       sha256 "8adcbd74cf1af07dc3607ebee32bfe5a53353b1aef9515963781183d5c401586" # bun-linux-x64.zip
     else
       url "https://github.com/oven-sh/bun/releases/download/bun-v#{version}/bun-linux-x64-baseline.zip"
       sha256 "e03eb2559a61af0cfb7acf3e59272d55613ef14078f156f7b22512456caa0f8b" # bun-linux-x64-baseline.zip
     end
   ```

   Thus the formula's version interpolation identifies the existing candidate URL `https://github.com/oven-sh/bun/releases/download/bun-v1.2.4/bun-linux-x64-baseline.zip`, with published SHA-256 **`e03eb2559a61af0cfb7acf3e59272d55613ef14078f156f7b22512456caa0f8b`**. Interpolating the declared version is source interpretation, not an archive download. The ordinary `bun-linux-x64.zip` hash `8adcbd74cf1af07dc3607ebee32bfe5a53353b1aef9515963781183d5c401586` is a **DIFFERENT candidate**, not a baseline checksum or approved substitution. The arm/aarch64 branch is separate; no Linux musl filename occurs in this fetched formula, and no musl hash or compatibility is inferred. The CPU branching is historical formula evidence only—not a complete CPU minimum specification, CPU detection on the intended controller, or a variant decision.

   The [path-scoped commit API](https://api.github.com/repos/oven-sh/homebrew-bun/commits?path=Formula%2Fbun%401.2.4.rb&per_page=1) reports message `Release bun-v1.2.4` and author/committer date `2025-02-26T10:19:02Z`. Its GitHub `verification.verified:true` / `reason:"valid"` is only an API assertion about that commit; no signature verification was performed here and it does not authenticate a release archive. This bounded one-entry history lookup is not a full history audit.

2. **Claim: the authorized raw-mode OpenTofu manifest attempt failed without yielding checksum lines. Source:** exact [vendor manifest URL](https://github.com/opentofu/opentofu/releases/download/v1.11.1/tofu_1.11.1_SHA256SUMS). **Support:** directly observed tool outcome, not retrieved manifest evidence. **Confidence:** high about the failed attempt; manifest contents unknown.

   Exactly one new `fetch_content` call with `mode:"raw"` targeted that exact URL. Exact returned error:

   ```text
   Error: Unsupported content type in raw mode: application/octet-stream
   ```

   No manifest body or line for either requested filename was returned. Therefore no text/API comparison can be made:

   | Requested manifest filename | Preserved API digest, NOT re-fetched | Newly observed manifest line | Comparison |
   |---|---|---|---|
   | `tofu_1.11.1_darwin_arm64.zip` | `1ad4f7affb6947a36f03142c655c5d84bb5bd0bf5a350d3c84519dfd6acd6697` | Unavailable | Not possible |
   | `tofu_1.11.1_linux_amd64.zip` | `bbfaf9baff1e5baf2775a4a9e7ba9e3c0152841f29f4ee7cf4610feb48f2db1c` | Unavailable | Not possible |

   This is additional stage-specific evidence alongside, not a replacement for, the old readable-mode `Error - Unsupported content type: application/octet-stream`. No retry, CLI/HTTP-code workaround, installer, alternate execution mode or verifier bootstrap followed. Even matching text would not authenticate a signature or downloaded archive.

### Bounded request ledger and validation limits
This follow-up used **two targeted search queries in one `web_search` call**, `workflow:"none"`, `includeContent:false`; **five metadata fetch attempts** with `fetch_content`, all raw mode; and one `get_search_content` lookup of already fetched listing content. No additional network fetch was requested by that stored-content lookup. The remaining allowance was not used.

Search queries (discovery only, not hash authority):
- `site:github.com/oven-sh/homebrew-bun "1.2.4"`
- `site:github.com/oven-sh "bun-v1.2.4" "baseline" "sha256"`

| Fetch | Exact primary metadata URL | Observed outcome / purpose |
|---|---|---|
| 1 | https://github.com/opentofu/opentofu/releases/download/v1.11.1/tofu_1.11.1_SHA256SUMS | Raw-mode error quoted above; no text. |
| 2 | https://api.github.com/repos/oven-sh/homebrew-bun/contents/ | JSON listing discovered `Formula` directory; mutable discovery source only. |
| 3 | https://api.github.com/repos/oven-sh/homebrew-bun/contents/Formula?ref=main | JSON listing discovered `Formula/bun@1.2.4.rb`, blob identifier `1848885cd5716f80b5712b43ec4c4a5214cecd49`. Inline output was truncated; stored-content lookup for `bun@1.2.4.rb` retrieved the matching entry. Blob identifier is NOT an artifact SHA-256. |
| 4 | https://api.github.com/repos/oven-sh/homebrew-bun/commits?path=Formula%2Fbun%401.2.4.rb&per_page=1 | JSON supplied the exact commit above for the discovered formula path. |
| 5 | https://raw.githubusercontent.com/oven-sh/homebrew-bun/9510da3431c51aeaa0da85d91896ded94a942e0f/Formula/bun%401.2.4.rb | Full raw formula text returned; baseline and ordinary hashes read directly. |

No automated `source_check` was run in this follow-up: the two allowed search queries were already consumed, and that tool performs additional searches. Validation is limited to direct inspection of the fetched primary formula/API text; no automated corroboration, independent cryptographic verification, or signature/authenticity claim is made.

### Contradictions
- The preserved Bun release-API `digest:null` for asset `232705940` is not proof that no publisher hash exists elsewhere. The newly fetched vendor formula supplies one for the exact baseline filename without contradicting that nullable API field; the release API itself was not re-fetched.
- The newly fetched historical formula explicitly gives different ordinary/baseline URLs and SHA-256 values and branches on AVX2. This reinforces the existing warning against projecting rolling alias guidance onto 1.2.4. The rolling guide remains preserved/unverified, not newly fetched evidence.
- No conflicting baseline hash was found in the fetched primary sources. This was not an exhaustive search.

### Sources kept and rejected/deprioritized
- **Kept:** the five owning-primary metadata URLs in the ledger. The commit-pinned raw formula is the decisive new checksum provenance; mutable directory listings were discovery only. OpenTofu's URL establishes the attempted source, not manifest contents.
- **Rejected as hash authority:** search-returned Chocolatey Bun 1.2.4 metadata (third party and Windows baseline, not Linux), NewReleases (secondary release mirror), unrelated GitHub issues/repositories and the general releases listing. None was separately fetched or used to establish a checksum. Search failure to surface the formula did not establish its absence.

### Retained gaps and stop boundary
**Concrete remaining metadata gap:** the OpenTofu 1.11.1 text manifest and its two requested lines could not be retrieved; their agreement with the carried-forward API digests is unknown. Bun's baseline *published checksum provenance* is now specifically evidenced by the pinned vendor formula, but its archive digest has not been calculated or verified, and signature provenance/authentication remains unestablished. No version or variant was changed or approved.

All signature checks, downloaded-artifact checks, full dependencies/native compatibility, resource fit, VM IDs/reservations, and operational approval remain unestablished. Controller/fixture budgets are not measurements; VM9901 remains proposed, not reserved; VM9900's failed lineage remains unchanged. No new PVE/fixture grant exists, and no earlier grant was reused. No archives/images/binaries, commands, installers, credentials, host/PVE/SSH operations, delegation, Git publication, execution-mode fallback, or tool/version bumps occurred. Only this complete note was written; no source/lock/evidence file elsewhere was changed.

**Next step:** owner review of this partial metadata result and retained OpenTofu gap; any further retrieval or verification requires separate approval. This bounded follow-up stops here, without a general supply-chain expansion.

## END bounded public-metadata follow-up — metadata-followup-01
