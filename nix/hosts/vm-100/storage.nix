{ config, lib, vm100Projection ? builtins.fromJSON (builtins.readFile ../../vm-100/projection.json), ... }:
let
  projection = vm100Projection;
  storage = projection.storage;
  migrationMountOptions = lib.optionals (projection.deploymentAuthority == "migration-in-progress") [ "ro" ];
in
{
  boot.supportedFilesystems = [ "nfs" ];

  fileSystems.${storage.games.mountpoint} = {
    device = "/dev/disk/by-uuid/${storage.games.filesystemUuid}";
    fsType = storage.games.filesystem;
    options = storage.games.options ++ migrationMountOptions;
    neededForBoot = false;
  };

  fileSystems.${storage.shared.mountpoint} = {
    device = storage.shared.source;
    fsType = storage.shared.filesystem;
    options = storage.shared.options ++ migrationMountOptions;
    neededForBoot = false;
  };

  systemd.tmpfiles.settings."10-vm-100-storage" = {
    ${storage.games.mountpoint}.d = {
      mode = "0755";
      user = "root";
      group = "root";
    };
    ${storage.shared.mountpoint}.d = {
      mode = "0755";
      user = "root";
      group = "root";
    };
  };

  assertions = [
    {
      assertion = config.fileSystems.${storage.games.mountpoint}.device == "/dev/disk/by-uuid/${storage.games.filesystemUuid}";
      message = "VM 100 games mount must select the existing filesystem by UUID";
    }
    {
      assertion = config.fileSystems.${storage.shared.mountpoint}.device == storage.shared.source;
      message = "VM 100 shared storage must retain the qualified NFS source";
    }
    {
      assertion = projection.deploymentAuthority != "migration-in-progress" ||
        (lib.elem "ro" config.fileSystems.${storage.games.mountpoint}.options &&
          lib.elem "ro" config.fileSystems.${storage.shared.mountpoint}.options);
      message = "VM 100 reused games and NFS mounts must be read-only during migration";
    }
  ];
}
