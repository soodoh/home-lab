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
      vm100Projection = builtins.fromJSON (builtins.readFile ./vm-100/projection.json);
      biosBootModule = { lib, ... }: {
        # VM 100 firmware is protected as SeaBIOS. Selecting the exact Disko
        # root device creates one GRUB mirroredBoot entry using its EF02 area.
        homeLab.vm100.rootDiskDevice = lib.mkDefault "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2";
        boot.loader.grub.efiSupport = lib.mkForce false;
        boot.loader.grub.efiInstallAsRemovable = lib.mkForce false;
      };
      mkVm100 = { projection ? vm100Projection, extraModules ? [ ] }:
        nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          specialArgs.vm100Projection = projection;
          modules = [
            disko.nixosModules.disko
            sops-nix.nixosModules.sops
            ./hosts/vm-100
          ] ++ nixpkgs.lib.optional
            (projection.deploymentAuthority != "arch")
            biosBootModule
          ++ extraModules;
        };
      authorityConfig = authority: activation:
        (mkVm100 {
          projection = vm100Projection // {
            deploymentAuthority = authority;
            nixosActivationEnabled = activation;
          };
        }).config;
      authorityConfigs = {
        arch = authorityConfig "arch" false;
        migration = authorityConfig "migration-in-progress" false;
        nixos = authorityConfig "nixos" true;
      };
      authorityEvaluation = {
        arch = {
          switchEnabled = authorityConfigs.arch.system.switch.enable;
          dockerEnabled = authorityConfigs.arch.virtualisation.docker.enable;
        };
        migration = {
          switchEnabled = authorityConfigs.migration.system.switch.enable;
          dockerEnabled = authorityConfigs.migration.virtualisation.docker.enable;
          gamesOptions = authorityConfigs.migration.fileSystems."/mnt/games".options;
          sharedOptions = authorityConfigs.migration.fileSystems."/mnt/storage".options;
          dockerCondition = authorityConfigs.migration.systemd.services.docker.unitConfig.ConditionPathExists;
          socketCondition = authorityConfigs.migration.systemd.sockets.docker.unitConfig.ConditionPathExists;
          writeEnableRequires = authorityConfigs.migration.systemd.services.vm-100-migration-write-enable.requires;
        };
        nixos = {
          switchEnabled = authorityConfigs.nixos.system.switch.enable;
          dockerEnabled = authorityConfigs.nixos.virtualisation.docker.enable;
          gamesOptions = authorityConfigs.nixos.fileSystems."/mnt/games".options;
          sharedOptions = authorityConfigs.nixos.fileSystems."/mnt/storage".options;
          dockerConditioned = authorityConfigs.nixos.systemd.services.docker.unitConfig ? ConditionPathExists;
        };
      };
    in {
      nixosConfigurations.vm-100 = mkVm100 { };

      nixosConfigurations.vm-100-candidate = mkVm100 {
        extraModules = [
          biosBootModule
          ({ lib, ... }: {
            disabledModules = [
              ./hosts/vm-100/networking.nix
              ./hosts/vm-100/storage.nix
              ./hosts/vm-100/secrets.nix
            ];
            homeLab.vm100.rootDiskDevice = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2";
            disko.rootMountPoint = "/mnt/vm-100-candidate";
            system.switch.enable = lib.mkForce true;
            virtualisation.docker.enable = lib.mkForce true;
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
      lib.vm-100-authority-evaluation = authorityEvaluation;
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          coralDriver = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
            vm-100-coral-driver = pkgs.callPackage ./packages/coral-driver {
              kernel = pkgs.linuxPackages.kernel;
            };
          };
          candidatePackages = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
            # Exact pinned bootstrap closure used only to initialize an empty,
            # bounded Arch-side tmpfs store for signed inspection imports.
            vm-100-ephemeral-nix-bootstrap = pkgs.nix;

            vm-100-compose-artifact = self.nixosConfigurations.vm-100-candidate.config.homeLab.vm100.composeArtifact;

            vm-100-compose-qualification = self.nixosConfigurations.vm-100-candidate.config.homeLab.vm100.composeQualification;

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
                  runtimeInputs = [ candidatePkgs.psmisc candidatePkgs.util-linux ];
                  text = ''
                    exec ${candidatePkgs.python3}/bin/python3 ${./scripts/vm-100-candidate-install-guard.py} "$@"
                  '';
                };
              in candidatePkgs.writeShellApplication {
                name = "vm-100-candidate-install";
                runtimeInputs = [ guard candidatePkgs.coreutils candidatePkgs.findutils candidatePkgs.util-linux ];
                text = ''
                  if [[ $# -ne 6 || $1 != --request || $3 != --protected-disk-input || $5 != --inspection-handoff ]]; then
                    echo "usage: vm-100-candidate-install --request REQUEST --protected-disk-input INPUT --inspection-handoff HANDOFF" >&2
                    exit 64
                  fi
                  request=$2
                  protectedDiskInput=$4
                  inspectionHandoff=$6
                  approval=$(vm-100-candidate-install-guard --request "$request" --protected-disk-input "$protectedDiskInput" --inspection-handoff "$inspectionHandoff")
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
          migrationPackages = pkgs.lib.optionalAttrs
            (system == "x86_64-linux" && vm100Projection.deploymentAuthority == "migration-in-progress") {
              vm-100-migration-verify = self.nixosConfigurations.vm-100.config.homeLab.vm100.migrationVerify;
              vm-100-migration-write-commit = self.nixosConfigurations.vm-100.config.homeLab.vm100.migrationWriteCommit;
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
        } // coralDriver // candidatePackages // migrationPackages);


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
      } // nixpkgs.lib.optionalAttrs
        (system == "x86_64-linux" && vm100Projection.deploymentAuthority == "migration-in-progress") {
          vm-100-migration-verify = {
            type = "app";
            program = "${self.packages.x86_64-linux.vm-100-migration-verify}/bin/vm-100-migration-verify";
            meta.description = "Verify VM 100 migration boot and reused storage without mutation";
          };
          vm-100-migration-write-commit = {
            type = "app";
            program = "${self.packages.x86_64-linux.vm-100-migration-write-commit}/bin/vm-100-migration-write-commit";
            meta.description = "Enter the guarded persistent VM 100 migration write-commit target";
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
          vm-100-ephemeral-nix-cli =
            let bootstrapNix = self.packages.x86_64-linux.vm-100-ephemeral-nix-bootstrap;
            in pkgs.runCommand "check-vm-100-ephemeral-nix-cli" { nativeBuildInputs = [ pkgs.gnugrep pkgs.man ]; } ''
              export MANPATH=${bootstrapNix.man}/share/man
              test "$(${bootstrapNix}/bin/nix --version)" = "nix (Nix) 2.34.8"
              test -x ${bootstrapNix}/bin/nix
              test -x ${bootstrapNix}/bin/nix-store
              ${bootstrapNix}/bin/nix path-info --help | grep -F -- "--json-format"
              ${bootstrapNix}/bin/nix path-info --help | grep -F -- "--sigs"
              ${bootstrapNix}/bin/nix store verify --help | grep -F -- "--quiet"
              ${bootstrapNix}/bin/nix store verify --help | grep -F -- "--sigs-needed"
              ${bootstrapNix}/bin/nix-store --help | grep -F -- "--import"
              ! ${bootstrapNix}/bin/nix-store --help | grep -F -- "--require-signature"
              ! ${bootstrapNix}/bin/nix-store --help | grep -F -- "--signatures"
              touch "$out"
            '';

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
              test -x ${self.packages.x86_64-linux.vm-100-ephemeral-nix-bootstrap}/bin/nix
              test -x ${self.packages.x86_64-linux.vm-100-ephemeral-nix-bootstrap}/bin/nix-store
              test -x ${self.packages.x86_64-linux.vm-100-candidate-install}/bin/vm-100-candidate-install
              test -x ${self.packages.x86_64-linux.vm-100-candidate-update}/bin/vm-100-candidate-update
              touch "$out"
            '';

          vm-100-authority-and-migration =
            let
              archConfig = authorityConfigs.arch;
              migrationConfig = authorityConfigs.migration;
              nixosConfig = authorityConfigs.nixos;
              marker = "/var/lib/home-lab/vm-100-write-commit.json";
            in pkgs.runCommand "check-vm-100-authority-and-migration" { } ''
              test "${if archConfig.system.switch.enable then "true" else "false"}" = false
              test "${if archConfig.virtualisation.docker.enable then "true" else "false"}" = false
              test "${if migrationConfig.system.switch.enable then "true" else "false"}" = false
              test "${if migrationConfig.virtualisation.docker.enable then "true" else "false"}" = true
              test "${if nixosConfig.system.switch.enable then "true" else "false"}" = true
              test "${if nixosConfig.virtualisation.docker.enable then "true" else "false"}" = true
              test "${pkgs.lib.concatStringsSep "," migrationConfig.fileSystems."/mnt/games".options}" = noatime,ro
              test "${pkgs.lib.concatStringsSep "," migrationConfig.fileSystems."/mnt/storage".options}" = defaults,ro
              test "${migrationConfig.systemd.services.docker.unitConfig.ConditionPathExists}" = ${marker}
              test "${migrationConfig.systemd.sockets.docker.unitConfig.ConditionPathExists}" = ${marker}
              test "${if nixosConfig.systemd.services.docker.unitConfig ? ConditionPathExists then "present" else "absent"}" = absent
              test "${pkgs.lib.concatStringsSep "," migrationConfig.systemd.services.vm-100-migration-write-enable.requires}" = vm-100-write-commit.service
              test -x ${migrationConfig.homeLab.vm100.migrationVerify}/bin/vm-100-migration-verify
              test -x ${migrationConfig.homeLab.vm100.migrationWriteCommit}/bin/vm-100-migration-write-commit
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
