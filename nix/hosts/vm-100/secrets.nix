{ config, lib, ... }:
{
  # The sops-nix module seam is pinned without ciphertext, recipients, key
  # paths, generated identities, secret declarations, or materialization.
  assertions = [
    {
      assertion = config.sops.secrets == { } && config.sops.templates == { };
      message = "VM 100 scaffold must not declare runtime secrets or templates";
    }
  ];
  sops.secrets = lib.mkDefault { };
  sops.templates = lib.mkDefault { };
  sops.age.generateKey = false;
  sops.age.sshKeyPaths = [ ];
}
