{ config, lib, pkgs, ... }:
let
  coralDriver = config.boot.kernelPackages.callPackage ../packages/coral-driver { };
in
{
  users.groups.apex = { };
  users.users.docker.extraGroups = [ "apex" ];

  boot.extraModulePackages = [ coralDriver ];
  boot.kernelModules = [ "gasket" "apex" ];

  services.udev.extraRules = ''
    SUBSYSTEM=="apex", KERNEL=="apex_0", GROUP="apex", MODE="0660"
  '';

  environment.etc."home-lab/coral-build-metadata".source =
    "${coralDriver}/share/home-lab-coral/build-metadata";

  assertions = [
    {
      assertion = builtins.elem "apex" config.users.users.docker.extraGroups;
      message = "VM 100 workload user requires the Coral device group";
    }
    {
      assertion = lib.hasInfix "KERNEL==\"apex_0\"" config.services.udev.extraRules;
      message = "VM 100 Coral udev rule must select apex_0";
    }
  ];
}
