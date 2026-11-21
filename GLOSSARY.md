# Home-lab deployment

Deployment distinguishes the application source chosen for a run from the
independently approved controller that carries it out.

## Language

**Selected application source**:
The reviewed application configuration and encrypted credential authorities
chosen for one deployment.

**Acquired owner identity**:
The identity of production ownership established by a successful acquisition or
explicitly approved adoption, not proof of backup admission or convergence.

**Installed controller**:
The separately approved deployment implementation and its dependencies,
independent of the selected application source.

**Wolf image-update lifecycle**:
The admitted change of Wolf's persisted application image references, complete
only when its writer is healthy and the changed configuration is verified.

**Managed publication**:
Replacement of deployment-owned application configuration and credentials,
including refreshing the running consumers affected by those replacements.

## Backup

**Local capture**:
One recovery set assembled for the local Restic repository. Replica
reconciliation is separate from the local capture.

**Ready capture**:
A local capture whose durable manifest binds its staged data and exact snapshot
sources to the reviewed policy, artifact and any acquired owner identity.
A retry reuses those snapshot sources and rereads explicitly live paths.

**Restic capture plan**:
The reviewed source selections and writer pause set for one fresh capture,
checked against the declared Compose inventory. It describes what to capture,
not what a completed backup has proved.

**Restic snapshot evidence**:
The recorded format, completion, and copy lineage of a Restic snapshot. It
identifies what the repository holds, not whether that snapshot is sufficient
for the current deployment or recovery.

**Owner-bound backup admission**:
A current-run decision that backup protection is sufficient under an acquired
owner identity. A successful strict operation sets a post-change capture cutoff
before releasing that owner, even if the operation reports no changes.

**Replica-safe expiry**:
Removal of retained daily backup history after the exact copy of each eligible
capture has been identified in both replica destinations. Copies are removed only
after their local source snapshot is gone.

**Full-v2 capture archive**:
The recovery representation of a local capture: files organized by their original paths,
explicit database and native exports, and a manifest. It can be staged without
the installed controller or the original snapshot sources.
