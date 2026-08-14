{
  description = "Pinned Proxmox controller tooling and inert VM 100 NixOS scaffold";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, disko, sops-nix }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      nixosConfigurations.vm-100 = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          disko.nixosModules.disko
          sops-nix.nixosModules.sops
          ./hosts/vm-100
        ];
      };

      nixosConfigurations.vm-100-candidate = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          disko.nixosModules.disko
          sops-nix.nixosModules.sops
          ./hosts/vm-100
          ({ lib, ... }: {
            disabledModules = [
              ./hosts/vm-100/networking.nix
              ./hosts/vm-100/storage.nix
              ./hosts/vm-100/secrets.nix
            ];
            homeLab.vm100.rootDiskDevice = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2";
            disko.rootMountPoint = "/mnt/vm-100-candidate";
            system.switch.enable = lib.mkForce true;
            networking.useDHCP = false;
            networking.useNetworkd = true;
            systemd.network.enable = true;
            systemd.network.networks."20-vm-100-qualification" = {
              matchConfig.Name = "ens18";
              networkConfig.DHCP = "ipv4";
            };
          })
        ];
      };

      lib.vm-100-scaffold =
        builtins.fromJSON (builtins.readFile ./vm-100/projection.json);
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          coralDriver = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
            vm-100-coral-driver = pkgs.callPackage ./packages/coral-driver {
              kernel = pkgs.linuxPackages.kernel;
            };
          };
          candidatePackages = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
            vm-100-compose-artifact = self.nixosConfigurations.vm-100-candidate.config.homeLab.vm100.composeArtifact;

            vm-100-compose-qualification =
              let
                candidatePkgs = self.nixosConfigurations.vm-100-candidate.pkgs;
                config = self.nixosConfigurations.vm-100-candidate.config;
                artifact = config.homeLab.vm100.composeArtifact;
                probeImage = "redis:8.2-m01-alpine@sha256:73785dd3f61435fbea1a14bafd2c6509f9df112f50953e09eb31c94717c77e76";
              in candidatePkgs.writeShellApplication {
                name = "vm-100-compose-qualification";
                runtimeInputs = [ candidatePkgs.coreutils candidatePkgs.docker candidatePkgs.docker-compose candidatePkgs.python3 ];
                text = ''
                  work=$(${candidatePkgs.coreutils}/bin/mktemp -d)
                  trap '${candidatePkgs.coreutils}/bin/rm -rf "$work"' EXIT
                  ${candidatePkgs.python3}/bin/python3 - ${artifact}/secrets/production.env.keys "$work/qualification.env" <<'PY'
                  import pathlib, sys
                  keys = pathlib.Path(sys.argv[1]).read_text().splitlines()
                  path = pathlib.Path(sys.argv[2])
                  values = {}
                  for key in keys:
                      value = "qualification"
                      if key == "INTERNAL_HOST_IP": value = "127.0.0.1"
                      elif key == "TZ": value = "UTC"
                      elif key == "DOMAIN": value = "example.invalid"
                      elif key.endswith(("__PORT", "__TIMEOUT")): value = "25"
                      elif key.endswith(("__USE_SSL", "__USE_TLS")): value = "false"
                      elif key.endswith(("_URL", "_BASE_URL", "_AUTHORITY")): value = "http://127.0.0.1"
                      elif key.endswith("_PATH") or key in {"GAMES_PATH", "HASS_PATH", "MEDIA_PATH", "VUETORRENT_PATH"}: value = f"/tmp/vm-100-compose-qualification/{key.lower()}"
                      elif key == "RESOLVER_ADDRESS": value = "127.0.0.1"
                      elif key == "SERVER_COUNTRIES": value = "US"
                      values[key] = value
                  path.write_text("".join(f"{key}={values[key]}\\n" for key in keys))
                  path.chmod(0o600)
                  PY
                  ${candidatePkgs.docker}/bin/docker version --format '{{.Server.Version}}' > "$work/docker-version"
                  ${candidatePkgs.docker-compose}/bin/docker-compose \
                    --project-directory ${artifact} \
                    --env-file "$work/qualification.env" \
                    config --format json > "$work/model.json"
                  ${candidatePkgs.python3}/bin/python3 - "$work/model.json" ${candidatePkgs.lib.escapeShellArg probeImage} <<'PY'
                  import json, pathlib, sys
                  model = json.loads(pathlib.Path(sys.argv[1]).read_text())
                  services = model.get("services")
                  if not isinstance(services, dict) or len(services) != 41:
                      raise SystemExit("Compose service inventory differs")
                  images = [service.get("image") for service in services.values()]
                  if any(not isinstance(image, str) or "@sha256:" not in image for image in images):
                      raise SystemExit("Compose image pinning differs")
                  if sys.argv[2] not in images:
                      raise SystemExit("Compose probe image differs")
                  PY
                  ${candidatePkgs.docker}/bin/docker pull ${candidatePkgs.lib.escapeShellArg probeImage} >/dev/null
                  ${candidatePkgs.docker}/bin/docker run --rm --network none --read-only --cap-drop ALL \
                    ${candidatePkgs.lib.escapeShellArg probeImage} redis-server --version > "$work/probe"
                  printf 'vm-100-compose-qualification=passed services=41 artifact=%s\n' \
                    "$(${candidatePkgs.coreutils}/bin/cat ${artifact}/.artifact-sha256)"
                '';
              };

            vm-100-candidate-update =
              let
                candidatePkgs = self.nixosConfigurations.vm-100-candidate.pkgs;
                config = self.nixosConfigurations.vm-100-candidate.config;
                guard = candidatePkgs.writeShellApplication {
                  name = "vm-100-candidate-update-guard";
                  runtimeInputs = [ candidatePkgs.util-linux ];
                  text = ''
                    exec ${candidatePkgs.python3}/bin/python3 ${./scripts/vm-100-candidate-update-guard.py} "$@"
                  '';
                };
              in candidatePkgs.writeShellApplication {
                name = "vm-100-candidate-update";
                runtimeInputs = [ guard candidatePkgs.coreutils candidatePkgs.findutils candidatePkgs.jq candidatePkgs.util-linux ];
                text = ''
                  if [[ $# -ne 2 || $1 != --request ]]; then
                    echo "usage: vm-100-candidate-update --request REQUEST" >&2
                    exit 64
                  fi
                  approval=$(vm-100-candidate-update-guard "$2")
                  expected=$(${candidatePkgs.jq}/bin/jq -er '.expectedCurrentSystem' <<<"$approval")
                  targetSystem=$(${candidatePkgs.jq}/bin/jq -er '.targetSystem' <<<"$approval")
                  [[ $targetSystem == ${config.system.build.toplevel} ]]
                  target=/mnt/vm-100-candidate
                  [[ -d $target && ! -L $target ]]
                  [[ -z $(${candidatePkgs.findutils}/bin/find "$target" -mindepth 1 -maxdepth 1 -print -quit) ]]
                  ${candidatePkgs.util-linux}/bin/mount /dev/disk/by-partlabel/disk-vm100-root-root "$target"
                  ${candidatePkgs.coreutils}/bin/mkdir -p "$target/boot"
                  ${candidatePkgs.util-linux}/bin/mount /dev/disk/by-partlabel/disk-vm100-root-ESP "$target/boot"
                  cleanup() {
                    ${candidatePkgs.util-linux}/bin/umount "$target/boot" || true
                    ${candidatePkgs.util-linux}/bin/umount "$target" || true
                  }
                  trap cleanup EXIT
                  [[ $(${candidatePkgs.coreutils}/bin/readlink -f "$target/nix/var/nix/profiles/system") == "$expected" ]]
                  ${config.system.build.nixos-install}/bin/nixos-install \
                    --root "$target" \
                    --system ${config.system.build.toplevel} \
                    --no-channel-copy \
                    --no-root-password
                  [[ $(${candidatePkgs.coreutils}/bin/readlink -f "$target/nix/var/nix/profiles/system") == "$targetSystem" ]]
                  ${candidatePkgs.coreutils}/bin/sync
                  cleanup
                  trap - EXIT
                  printf 'vm-100-candidate-update=completed previous=%s target=%s\n' "$expected" "$targetSystem"
                '';
              };

            vm-100-candidate-install =
              let
                candidatePkgs = self.nixosConfigurations.vm-100-candidate.pkgs;
                config = self.nixosConfigurations.vm-100-candidate.config;
                guard = candidatePkgs.writeShellApplication {
                  name = "vm-100-candidate-install-guard";
                  runtimeInputs = [ candidatePkgs.util-linux ];
                  text = ''
                    exec ${candidatePkgs.python3}/bin/python3 ${./scripts/vm-100-candidate-install-guard.py} "$@"
                  '';
                };
              in candidatePkgs.writeShellApplication {
                name = "vm-100-candidate-install";
                runtimeInputs = [ guard candidatePkgs.coreutils candidatePkgs.findutils candidatePkgs.util-linux ];
                text = ''
                  if [[ $# -ne 2 || $1 != --request ]]; then
                    echo "usage: vm-100-candidate-install --request REQUEST" >&2
                    exit 64
                  fi
                  request=$2
                  approval=$(vm-100-candidate-install-guard "$request")
                  device=$(${candidatePkgs.jq}/bin/jq -er '.device' <<<"$approval")
                  mode=$(${candidatePkgs.jq}/bin/jq -er '.mode' <<<"$approval")
                  target=/mnt/vm-100-candidate
                  if [[ $mode == inspect ]]; then
                    printf 'vm-100-candidate-install=inspection-passed device=%s\n' "$device"
                    exit 0
                  fi
                  [[ $mode == install ]]
                  [[ -d $target && ! -L $target ]]
                  [[ -z $(${candidatePkgs.findutils}/bin/find "$target" -mindepth 1 -maxdepth 1 -print -quit) ]]
                  [[ ''${VM100_CANDIDATE_INSTALL_CONFIRMED:-} == install-reviewed-qualification-candidate ]]
                  ${config.system.build.diskoScript}
                  ${config.system.build.nixos-install}/bin/nixos-install \
                    --root "$target" \
                    --system ${config.system.build.toplevel} \
                    --no-channel-copy \
                    --no-root-password
                  ${candidatePkgs.util-linux}/bin/findmnt -n --target "$target" >/dev/null
                  printf 'vm-100-candidate-install=completed device=%s\n' "$device"
                '';
              };
          };
          bundle = pkgs.runCommand "home-lab-proxmox-host-bundle-v1" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            python3 ${./proxmox}/bundle.py build \
              --projection ${./proxmox/projection.json} \
              --package-manifest ${./proxmox/package-manifest.json} \
              --flake-lock ${./flake.lock} \
              --output "$out/bundle" \
              --hash-output "$out/bundle.sha256"
          '';
          hostPlan = pkgs.writeShellApplication {
            name = "proxmox-host";
            runtimeInputs = [ pkgs.git pkgs.openssh pkgs.python3 ]
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.netcat-openbsd ];
            text = ''
              # Linux gets pinned netcat above; the trusted Darwin controller uses /usr/bin/nc.
              PROXMOX_HOST_FIXED_BUNDLE=${bundle}/bundle \
              PROXMOX_HOST_FIXED_BUNDLE_HASH=${bundle}/bundle.sha256 \
              PROXMOX_HOST_FIXED_SOURCE_ROOT=${./.} \
                exec python3 ${./proxmox}/planner.py "$@"
            '';
          };
        in {
          default = bundle;
          proxmox-host-bundle = bundle;
          proxmox-host-plan = hostPlan;
        } // coralDriver // candidatePackages);


      apps = forAllSystems (system: {
        proxmox-host = {
          type = "app";
          program = "${self.packages.${system}.proxmox-host-plan}/bin/proxmox-host";
          meta.description = "Create, privately prepare, and guardedly apply exact deterministic Proxmox host plans";
        };
      } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
        vm-100-candidate-install = {
          type = "app";
          program = "${self.packages.x86_64-linux.vm-100-candidate-install}/bin/vm-100-candidate-install";
          meta.description = "Guard and install the exact VM 100 candidate NixOS generation";
        };
        vm-100-candidate-update = {
          type = "app";
          program = "${self.packages.x86_64-linux.vm-100-candidate-update}/bin/vm-100-candidate-update";
          meta.description = "Guard and update the exact installed VM 100 qualification generation";
        };
        vm-100-compose-qualification = {
          type = "app";
          program = "${self.packages.x86_64-linux.vm-100-compose-qualification}/bin/vm-100-compose-qualification";
          meta.description = "Qualify isolated dockerd and the exact secret-free Compose artifact";
        };
      });

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          bundle = self.packages.${system}.proxmox-host-bundle;
        in {
          proxmox-host-bundle = pkgs.runCommand "check-home-lab-proxmox-host-bundle-v1" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            python3 ${./proxmox}/bundle.py verify \
              --bundle ${bundle}/bundle \
              --hash-file ${bundle}/bundle.sha256
            touch "$out"
          '';
        } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vm-100-candidate-disko =
            let
              config = self.nixosConfigurations.vm-100-candidate.config;
            in pkgs.runCommand "check-vm-100-candidate-disko" { } ''
              test "${config.homeLab.vm100.rootDiskDevice}" = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"
              test "${config.disko.rootMountPoint}" = "/mnt/vm-100-candidate"
              test -x ${config.system.build.diskoScript}
              test -x ${config.system.build.toplevel}/bin/switch-to-configuration
              test "${if config.fileSystems ? "/mnt/games" then "present" else "absent"}" = absent
              test "${if config.fileSystems ? "/mnt/storage" then "present" else "absent"}" = absent
              test "${if config.sops.secrets == { } then "empty" else "configured"}" = empty
              test "${config.systemd.network.networks."20-vm-100-qualification".networkConfig.DHCP}" = ipv4
              test "${if config.virtualisation.docker.enable then "enabled" else "disabled"}" = enabled
              test "$(cat ${config.homeLab.vm100.composeArtifact}/.artifact-sha256)" = "$(cat ${./compose-artifact.sha256})"
              test -x ${self.packages.x86_64-linux.vm-100-compose-qualification}/bin/vm-100-compose-qualification
              test -x ${self.packages.x86_64-linux.vm-100-candidate-install}/bin/vm-100-candidate-install
              test -x ${self.packages.x86_64-linux.vm-100-candidate-update}/bin/vm-100-candidate-update
              touch "$out"
            '';
        });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          default = pkgs.mkShell {
            packages = [ pkgs.bun pkgs.nodejs pkgs.python3 pkgs.shellcheck ];
          };
        });
    };
}
