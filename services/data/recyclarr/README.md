# Recyclarr configuration

Compose mounts `configs/` and `includes/` read-only from Git. Native state,
resource checkouts and settings remain in `/srv/home-lab-state/recyclarr-data`;
API keys come from the separate `/config/secrets.yml` credential mount.
Recyclarr remains the sole writer of Arr quality profiles and custom formats.
Restic and the `media` recovery group include these live configuration directories
under `/srv/docker-compose/current/services/data/recyclarr`, plus native settings.

The local includes deliberately retain the existing named profiles, quality
ordering and score sets. They are native Recyclarr configuration, not downloaded
include-template IDs or guide-backed profiles: adopting guide-backed profiles
would also change Radarr language selection and enable additional format groups.
Upstream include provenance is recorded in each file; their MIT license is here.
Custom-format definitions and their default scores still follow TRaSH Guides.
Review the complete `recyclarr sync --preview` before approving a normal sync.

Sonarr's two profiles share one instance-wide `series` quality definition. An
anime profile does not have independent size limits. Radarr-4K keeps its
4K-only grouped quality cutoff; the unrelated `Unused` profile is not managed.

URLs retain native `!env_var` references, and API keys retain native `!secret`
references. Configuration changes require reviewed deployment; editing the
shadowed appdata `configs` or `includes` directories is not convergence.
