{ lib, ... }:
let
  projection = builtins.fromJSON (builtins.readFile ../../vm-100/projection.json);
in
{
  imports = [
    ./base.nix
    ./access.nix
    ./disko.nix
    ./secrets.nix
  ];

  nixpkgs.hostPlatform = projection.system;
  networking.hostName = projection.hostName;
  system.stateVersion = projection.stateVersion;
  system.switch.enable = false;

  assertions = [
    {
      assertion = projection.vmid == 100;
      message = "VM 100 scaffold identity differs";
    }
    {
      assertion = projection.deploymentAuthority == "arch" && !projection.nixosActivationEnabled;
      message = "VM 100 NixOS scaffold must remain inert while Arch owns the guest";
    }
  ];

  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = false;
  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
    options = [ "size=1G" "mode=0755" ];
  };

  system.forbiddenDependenciesRegexes = [
    (lib.escapeRegex "infrastructure/contract/home-lab.yml")
    (lib.escapeRegex "secrets/production.sops.env")
  ];
}
