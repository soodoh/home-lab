{ config, lib, pkgs, ... }:
let
  canonicalSecret = "compose-production-env-canonical";
  canonicalPath = "/run/home-lab/compose/production.env.canonical";
  runtimePath = "/run/home-lab/compose/production.env";
  restoreDotenvLayout = ../../scripts/restore-dotenv-layout.py;
in
{
  sops = {
    defaultSopsFile = ../../secrets/production.sops.env;
    defaultSopsFormat = "dotenv";
    validateSopsFiles = true;
    useSystemdActivation = true;
    age = {
      keyFile = "/var/lib/sops-nix/age/keys.txt";
      generateKey = false;
      sshKeyPaths = [ ];
    };
    secrets.${canonicalSecret} = {
      key = "";
      format = "dotenv";
      owner = "root";
      group = "root";
      mode = "0400";
      path = canonicalPath;
      restartUnits = [ "restore-compose-production-env.service" ];
    };
  };

  systemd.tmpfiles.settings."10-home-lab-compose-secrets" = {
    "/run/home-lab".d = { mode = "0755"; user = "root"; group = "root"; };
    "/run/home-lab/compose".d = { mode = "0700"; user = "root"; group = "root"; };
    "/var/lib/sops-nix".d = { mode = "0700"; user = "root"; group = "root"; };
    "/var/lib/sops-nix/age".d = { mode = "0700"; user = "root"; group = "root"; };
  };

  environment.etc."home-lab/production-env-keys".source = ../../secrets/production.env.keys;
  environment.etc."home-lab/production-env-layout.json".source = ../../secrets/production.env.layout.json;

  systemd.services.restore-compose-production-env = {
    description = "Restore exact Compose production dotenv layout";
    wantedBy = [ "multi-user.target" ];
    before = [ "docker.service" ];
    requiredBy = [ "docker.service" ];
    after = [ "sops-install-secrets.service" ];
    requires = [ "sops-install-secrets.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "root";
      Group = "root";
      UMask = "0077";
    };
    script = ''
      set -euo pipefail
      ${config.systemd.package}/bin/systemctl is-active --quiet sops-install-secrets.service
      target=${lib.escapeShellArg runtimePath}
      ${config.systemd.package}/bin/systemd-tmpfiles --create --prefix=/run/home-lab/compose
      ${pkgs.coreutils}/bin/rm -f -- "$target"
      ${pkgs.python3}/bin/python3 ${restoreDotenvLayout} \
        ${lib.escapeShellArg canonicalPath} \
        /etc/home-lab/production-env-layout.json \
        "$target"
      ${pkgs.coreutils}/bin/chown root:root "$target"
      ${pkgs.coreutils}/bin/chmod 0400 "$target"
    '';
  };

  assertions = [
    {
      assertion = config.sops.age.keyFile == "/var/lib/sops-nix/age/keys.txt" && !config.sops.age.generateKey;
      message = "VM 100 SOPS identity must be explicitly installed outside the Nix store";
    }
    {
      assertion = config.sops.secrets.${canonicalSecret}.path == canonicalPath &&
        config.sops.secrets.${canonicalSecret}.owner == "root" &&
        config.sops.secrets.${canonicalSecret}.group == "root" &&
        config.sops.secrets.${canonicalSecret}.mode == "0400";
      message = "VM 100 canonical Compose environment metadata differs";
    }
    {
      assertion = lib.hasPrefix "/run/" config.sops.secrets.${canonicalSecret}.path &&
        lib.hasPrefix "/run/" runtimePath;
      message = "VM 100 decrypted runtime material must remain outside persistent storage and the Nix store";
    }
  ];
}
