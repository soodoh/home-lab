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
          {
            homeLab.vm100.rootDiskDevice = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_QUAL-NIXOS-128G";
            disko.rootMountPoint = "/mnt/vm-100-candidate";
          }
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
          candidateInstaller = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
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
                    exec ${config.system.build.diskoScript}/bin/disko --dry-run
                  fi
                  [[ $mode == install ]]
                  [[ -d $target && ! -L $target ]]
                  [[ -z $(${candidatePkgs.findutils}/bin/find "$target" -mindepth 1 -maxdepth 1 -print -quit) ]]
                  [[ ''${VM100_CANDIDATE_INSTALL_CONFIRMED:-} == install-reviewed-qualification-candidate ]]
                  ${config.system.build.diskoScript}/bin/disko
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
        } // coralDriver // candidateInstaller);


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
              test "${config.homeLab.vm100.rootDiskDevice}" = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_QUAL-NIXOS-128G"
              test "${config.disko.rootMountPoint}" = "/mnt/vm-100-candidate"
              test -x ${config.system.build.diskoScript}/bin/disko
              test -x ${self.packages.x86_64-linux.vm-100-candidate-install}/bin/vm-100-candidate-install
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
