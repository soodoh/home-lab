{ config, lib, pkgs, ... }:
let
  artifactHash = lib.removeSuffix "\n" (builtins.readFile ../../compose-artifact.sha256);
  artifact = pkgs.runCommand "vm-100-compose-artifact-${artifactHash}" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    cp -R --no-preserve=mode ${../../compose-artifact} "$out"
    chmod -R u+w "$out"
    actual=$(python3 "$out/scripts/compose-artifact.py" --root "$out" --no-git hash)
    test "$actual" = ${lib.escapeShellArg artifactHash}
    printf '%s\n' ${lib.escapeShellArg artifactHash} > "$out/.artifact-sha256"
  '';
in
{
  options.homeLab.vm100.composeArtifact = lib.mkOption {
    type = lib.types.package;
    readOnly = true;
    internal = true;
  };

  config = {
    homeLab.vm100.composeArtifact = artifact;

    virtualisation.docker = {
      enable = true;
      autoPrune.enable = false;
      daemon.settings = {
        live-restore = true;
        log-driver = "local";
      };
    };

    environment.systemPackages = [ pkgs.docker-compose ];
    environment.etc."home-lab/compose-artifact".source = artifact;
    environment.etc."home-lab/compose-artifact.sha256".text = "${artifactHash}\n";

    assertions = [
      {
        assertion = builtins.match "^[0-9a-f]{64}$" artifactHash != null;
        message = "VM 100 Compose artifact hash must be a lowercase SHA-256 digest";
      }
      {
        assertion = !config.virtualisation.docker.autoPrune.enable;
        message = "VM 100 Docker must not enable unrestricted automatic pruning";
      }
    ];
  };
}
