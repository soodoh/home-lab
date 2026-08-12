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
        } // coralDriver);

      apps = forAllSystems (system: {
        proxmox-host = {
          type = "app";
          program = "${self.packages.${system}.proxmox-host-plan}/bin/proxmox-host";
          meta.description = "Create, privately prepare, and guardedly apply exact deterministic Proxmox host plans";
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
        });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          default = pkgs.mkShell {
            packages = [ pkgs.bun pkgs.nodejs pkgs.python3 pkgs.shellcheck ];
          };
        });
    };
}
