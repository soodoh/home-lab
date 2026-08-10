# Proxmox local artifact cleanup

This is a one-time, console-backed maintenance operation. It removes stale local media only after VM 100 proves that the RX 7900 XTX works without a custom ROM. It is not a steady-state deletion allowlist.

## 1. Capture immutable before evidence

On the Proxmox host, check out the reviewed commit and capture the current VM configuration, every local ISO/template, both known ROM paths, file sizes, SHA-256 values, and configuration references:

```sh
cd /root/home-lab
scripts/inventory-proxmox-local-artifacts \
  --output /root/proxmox-artifacts-before-$(date -u +%Y%m%dT%H%M%SZ)
```

Copy the resulting mode-`0700` directory to the protected maintenance record. Do not commit firmware or media bytes. Review `artifacts.tsv` and retain the evidence until after the change and its rollback window.

## 2. Apply only the VM detach plan

Keep local console access available. From the trusted local controller:

```sh
scripts/local-controller plan steady
scripts/local-controller apply steady
```

The reviewed Proxmox plan may remove only these artifact dependencies from VM 100:

- replace `ide2: local:iso/archlinux-2025.04.01-x86_64.iso` with the declared empty drive `ide2: none,media=cdrom`;
- remove `ide2` from the boot order; and
- remove `rom_file = vbios_7900xtx.bin` from `hostpci1`.

Reject replacement, recreation, disk, PCI mapping, or unrelated VM changes. The normal plan policy permits removal of a non-empty custom `hostpci` ROM value but continues to reject other protected `hostpci` changes.

Do not delete any file yet. Confirm the live configuration no longer contains the dependencies:

```sh
qm config 100 | grep -E '^(boot|hostpci1|ide2):'
```

Expected results are a boot order without `ide2`, `ide2: none,media=cdrom`, and `hostpci1` without `romfile=`.

## 3. Prove passthrough without a custom ROM

Cold-boot the Proxmox host. BIOS `3881` or later must retain the reviewed iGPU-primary, CSM, IOMMU, and PCIe settings. After VM 100 starts, verify inside the Arch guest that `amdgpu` owns the passed-through RX 7900 XTX, runtime power-down is disabled for the dedicated headless GPU, and the render node exists:

```sh
lspci -nnk | grep -A3 -i 'VGA\|Display'
cat /sys/module/amdgpu/parameters/runpm
cat /sys/bus/pci/devices/0000:02:00.0/power/runtime_status
ls -l /dev/dri
```

Expected power values are `0` and `active`. The HDMI dummy plug is not a managed dependency. Start a real Wolf session and prove hardware rendering/encoding end to end. A container health check alone is insufficient.

Then perform a second VM lifecycle test from the Proxmox console:

```sh
qm shutdown 100 --timeout 120
qm start 100
```

Repeat the guest checks and Wolf session. Inspect both host boots for VFIO, ROM, BAR, and reset faults:

```sh
journalctl -b -1 -k | grep -Ei 'vfio|rom|bar|reset' || true
journalctl -b -k | grep -Ei 'vfio|rom|bar|reset' || true
```

If the proof fails, retain all artifacts and restore the last known-good configuration. Do not download an approximate third-party ROM or silently reintroduce an HDMI dummy plug as a recovery dependency.

## 4. Review exact purge targets

After successful proof, capture a second inventory. Confirm that each selected media volume reports `references=none`. The expected stale ISO volume IDs are:

- `local:iso/archlinux-2025.04.01-x86_64.iso`
- `local:iso/virtio-win.iso`
- `local:iso/Win11_24H2_English_x64.iso`

Select the exact Ubuntu 23.10 and Debian 13.6 `local:vztmpl/...` IDs from the reviewed `local-media.json`; do not infer or wildcard their filenames.

Assign only the five reviewed volume IDs and display them before deletion:

```sh
arch_iso='local:iso/archlinux-2025.04.01-x86_64.iso'
virtio_iso='local:iso/virtio-win.iso'
windows_iso='local:iso/Win11_24H2_English_x64.iso'
ubuntu_template='<exact-reviewed-local:vztmpl-volume-id>'
debian_template='<exact-reviewed-local:vztmpl-volume-id>'

printf '%s\n' "$arch_iso" "$virtio_iso" "$windows_iso" \
  "$ubuntu_template" "$debian_template"
```

Stop if any identifier differs from the evidence or appears in a VM/container configuration.

## 5. Purge and verify

Delete only the reviewed Proxmox volumes, then the two unreferenced ROM files:

```sh
for volume in "$arch_iso" "$virtio_iso" "$windows_iso" \
  "$ubuntu_template" "$debian_template"; do
  pvesm free "$volume"
done

rm -- /usr/share/kvm/vbios_7900xtx.bin /usr/share/kvm/vbios_raphael.bin
```

Capture a final inventory into a new directory. Verify:

- both ROM entries report `missing`;
- the five purged volume IDs are absent from `local-media.json`;
- VM 100 retains only the declared empty `ide2: none,media=cdrom` and has no `romfile=` configuration;
- the guest passes the GPU and Wolf checks; and
- a steady infrastructure plan is a no-op.

Preserve the before, proof, and after evidence in the protected maintenance record. Future unknown local media is audit drift and requires a new review; steady convergence must not delete it automatically.
