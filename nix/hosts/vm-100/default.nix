{ lib, vm100Projection ? builtins.fromJSON (builtins.readFile ../../vm-100/projection.json), ... }:
let
  projection = vm100Projection;
  validAuthorityRelation =
    (projection.deploymentAuthority == "arch" && !projection.nixosActivationEnabled) ||
    (projection.deploymentAuthority == "migration-in-progress" && !projection.nixosActivationEnabled) ||
    (projection.deploymentAuthority == "nixos" && projection.nixosActivationEnabled);
in
{
  imports = [
    ./base.nix
    ./access.nix
    ./networking.nix
    ./storage.nix
    ./hardware.nix
    ./disko.nix
    ./secrets.nix
    ./compose.nix
    ./migration.nix
    ../../modules/coral.nix
  ];

  nixpkgs.hostPlatform = projection.system;
  networking.hostName = projection.hostName;
  system.stateVersion = projection.stateVersion;
  system.switch.enable = projection.nixosActivationEnabled;

  boot.loader.grub = {
    enable = true;
    device = "nodev";
    efiSupport = true;
    efiInstallAsRemovable = true;
  };
  boot.loader.systemd-boot.enable = false;
  boot.loader.efi.canTouchEfiVariables = false;

  assertions = [
    {
      assertion = projection.vmid == 100;
      message = "VM 100 scaffold identity differs";
    }
    {
      assertion = validAuthorityRelation;
      message = "VM 100 deployment authority must have the exact NixOS activation relation";
    }
  ];

  fileSystems."/" = lib.mkDefault {
    device = "none";
    fsType = "tmpfs";
    options = [ "size=1G" "mode=0755" ];
  };

  system.forbiddenDependenciesRegexes = [
    (lib.escapeRegex "infrastructure/contract/home-lab.yml")
    (lib.escapeRegex "secrets/production.sops.env")
  ];
}
