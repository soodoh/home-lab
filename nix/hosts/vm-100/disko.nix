{ config, lib, ... }:
let
  cfg = config.homeLab.vm100;
in
{
  options.homeLab.vm100.rootDiskDevice = lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    default = null;
    description = "Stable whole-disk by-id path selected only by a guarded installer.";
  };

  config = lib.mkIf (cfg.rootDiskDevice != null) {
    disko.devices.disk.vm100-root = {
      type = "disk";
      device = cfg.rootDiskDevice;
      content = {
        type = "gpt";
        partitions = {
          bios = {
            priority = 1;
            size = "1M";
            type = "EF02";
          };
          ESP = {
            priority = 2;
            size = "512M";
            type = "EF00";
            content = {
              type = "filesystem";
              format = "vfat";
              mountpoint = "/boot";
              mountOptions = [ "umask=0077" ];
            };
          };
          root = {
            priority = 3;
            size = "100%";
            content = {
              type = "filesystem";
              format = "ext4";
              mountpoint = "/";
              mountOptions = [ "noatime" ];
            };
          };
        };
      };
    };
  };
}
