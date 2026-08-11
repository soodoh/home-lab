{
  description = "Pinned controller tooling and deterministic Proxmox host foundation bundle";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          bundle = pkgs.runCommand "home-lab-proxmox-host-bundle-v1" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            python3 ${./proxmox/bundle.py} build \
              --projection ${./proxmox/projection.json} \
              --package-manifest ${./proxmox/package-manifest.json} \
              --flake-lock ${./flake.lock} \
              --output "$out/bundle" \
              --hash-output "$out/bundle.sha256"
          '';
        in {
          default = bundle;
          proxmox-host-bundle = bundle;
        });

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          bundle = self.packages.${system}.proxmox-host-bundle;
        in {
          proxmox-host-bundle = pkgs.runCommand "check-home-lab-proxmox-host-bundle-v1" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            python3 ${./proxmox/bundle.py} verify \
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
