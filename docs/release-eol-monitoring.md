# Release and EOL monitoring

The credential-free release monitor reads only the fixed API endpoints declared in `infrastructure/contract/home-lab.yml`:

- Debian: <https://endoflife.date/api/v1/products/debian/>
- Proxmox VE: <https://endoflife.date/api/v1/products/proxmox-ve/>

`scripts/controller/release-eol-report.js` bounds each response to 1 MiB, refuses redirects, wrong products, missing cycles, future or older-than-seven-day source generation, invalid dates, unmaintained releases, and required unknown EOL dates. It compares Debian cycle and point release directly with the contract and compares the PVE release with the exact committed `pve-manager` package version.

The report is canonical JSON validated by `infrastructure/maintenance/release-eol-report.schema.json`. It always contains `automatic_apply: false`; it has no host, Ansible deploy, OpenTofu apply, package, or secret capability. A warning or healthy report is information only. A blocking report fails the command, but neither result authorizes mutation.

The pinned, read-only `.github/workflows/release-eol-report.yml` runs weekly and on manual dispatch. It installs locked validation dependencies with scripts disabled, runs hostile fixtures, fetches the report, and uploads it for 14 days. Workflow permissions are `contents: read`, and every external action is pinned to a full commit.

At the 2026-09-03 qualification observation:

- Debian 13 (Trixie) was maintained; current/latest was 13.6, Debian Security Support ends 2028-08-09, and LTS ends 2030-06-30.
- Proxmox VE 9 was maintained; current `pve-manager` was 9.2.11 and latest release line was 9.2. The source did not publish an EOL date, so the report correctly returned warning `proxmox-eol-unknown` rather than inferring a date.

The live report had no blockers and made no production connection or mutation.
