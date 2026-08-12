{ config, ... }:
let
  projection = builtins.fromJSON (builtins.readFile ../../vm-100/projection.json);
  storage = projection.storage;
in
{
  boot.supportedFilesystems = [ "nfs" ];

  fileSystems.${storage.games.mountpoint} = {
    device = "/dev/disk/by-uuid/${storage.games.filesystemUuid}";
    fsType = storage.games.filesystem;
    options = storage.games.options;
    neededForBoot = false;
  };

  fileSystems.${storage.shared.mountpoint} = {
    device = storage.shared.source;
    fsType = storage.shared.filesystem;
    options = storage.shared.options;
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
  ];
}
