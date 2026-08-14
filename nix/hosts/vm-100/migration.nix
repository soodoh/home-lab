{ config, lib, pkgs, vm100Projection ? builtins.fromJSON (builtins.readFile ../../vm-100/projection.json), ... }:
let
  isMigration = vm100Projection.deploymentAuthority == "migration-in-progress";
  storage = vm100Projection.storage;
  artifactHash = lib.removeSuffix "\n" (builtins.readFile ../../compose-artifact.sha256);
  marker = "/var/lib/home-lab/vm-100-write-commit.json";
  guard = pkgs.writeShellApplication {
    name = "vm-100-migration-guard";
    runtimeInputs = [ pkgs.util-linux pkgs.systemd ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${../../scripts/vm-100-migration-guard.py} \
        "$@" \
        --expected-artifact ${lib.escapeShellArg artifactHash} \
        --games-uuid ${lib.escapeShellArg storage.games.filesystemUuid} \
        --games-filesystem ${lib.escapeShellArg storage.games.filesystem} \
        --shared-source ${lib.escapeShellArg storage.shared.source} \
        --shared-filesystem ${lib.escapeShellArg storage.shared.filesystem}
    '';
  };
  verify = pkgs.writeShellApplication {
    name = "vm-100-migration-verify";
    runtimeInputs = [ guard ];
    text = ''
      if [[ $# -ne 0 ]]; then
        echo "usage: vm-100-migration-verify" >&2
        exit 64
      fi
      exec vm-100-migration-guard verify-only
    '';
  };
  writeCommit = pkgs.writeShellApplication {
    name = "vm-100-migration-write-commit";
    runtimeInputs = [ pkgs.systemd ];
    text = ''
      if [[ $# -ne 0 ]]; then
        echo "usage: vm-100-migration-write-commit" >&2
        exit 64
      fi
      exec systemctl start vm-100-write-commit.target
    '';
  };
in
{
  options.homeLab.vm100 = {
    writeCommitMarker = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      internal = true;
      default = marker;
    };
    migrationVerify = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      readOnly = true;
      internal = true;
      default = if isMigration then verify else null;
    };
    migrationWriteCommit = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      readOnly = true;
      internal = true;
      default = if isMigration then writeCommit else null;
    };
  };

  config = lib.mkIf isMigration {
    environment.systemPackages = [ verify writeCommit ];

    systemd.tmpfiles.settings."10-vm-100-migration"."/var/lib/home-lab".d = {
      mode = "0700";
      user = "root";
      group = "root";
    };

    systemd.services.docker = {
      requires = [ "vm-100-migration-write-enable.service" ];
      after = [ "vm-100-migration-write-enable.service" ];
      unitConfig.ConditionPathExists = marker;
    };
    systemd.sockets.docker = {
      requires = [ "vm-100-migration-write-enable.service" ];
      after = [ "vm-100-migration-write-enable.service" ];
      unitConfig.ConditionPathExists = marker;
    };

    systemd.services.vm-100-write-commit = {
      description = "Validate and persist the guarded VM 100 migration write commit";
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        Group = "root";
        UMask = "0077";
        ExecStart = "${guard}/bin/vm-100-migration-guard commit";
      };
    };

    systemd.services.vm-100-migration-write-enable = {
      description = "Enable reused VM 100 storage after the persistent write commit";
      requires = [ "vm-100-write-commit.service" ];
      after = [ "local-fs.target" "remote-fs.target" "vm-100-write-commit.service" ];
      before = [ "docker.service" "docker.socket" ];
      wantedBy = [ "multi-user.target" ];
      unitConfig.ConditionPathExists = marker;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        User = "root";
        Group = "root";
        ExecStart = "${guard}/bin/vm-100-migration-guard enable-writes";
      };
    };

    systemd.targets.vm-100-write-commit = {
      description = "Guarded VM 100 migration write commit";
      requires = [ "vm-100-write-commit.service" "docker.service" "docker.socket" ];
      after = [ "vm-100-write-commit.service" "vm-100-migration-write-enable.service" "docker.service" "docker.socket" ];
    };

    assertions = [
      {
        assertion = config.systemd.services.docker.unitConfig.ConditionPathExists == marker &&
          config.systemd.sockets.docker.unitConfig.ConditionPathExists == marker;
        message = "VM 100 migration must inhibit both Docker service and socket before write commit";
      }
      {
        assertion = config.homeLab.vm100.migrationVerify != null &&
          config.homeLab.vm100.migrationWriteCommit != null;
        message = "VM 100 migration must expose explicit verify-only and guarded write-commit seams";
      }
    ];
  };
}
