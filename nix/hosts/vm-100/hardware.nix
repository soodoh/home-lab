{ config, lib, ... }:
let
  projection = builtins.fromJSON (builtins.readFile ../../vm-100/projection.json);
  hardware = projection.hardware;
  serialVendor = builtins.elemAt (lib.splitString ":" hardware.serial.vendor_device) 0;
  serialProduct = builtins.elemAt (lib.splitString ":" hardware.serial.vendor_device) 1;
in
{
  boot.kernelModules = hardware.kernelModules ++ [ "tun" ];
  boot.extraModprobeConfig = ''
    options amdgpu runpm=${if hardware.gpu.runtimePowerManagement then "1" else "0"}
  '';

  hardware.graphics.enable = true;
  hardware.bluetooth = {
    enable = true;
    powerOnBoot = true;
  };
  services.qemuGuest.enable = hardware.qemuGuestAgent;

  boot.kernel.sysctl = hardware.sysctls;
  services.udev.extraRules = ''
    KERNEL=="uinput", GROUP="${hardware.input.group}", MODE="${hardware.input.mode}"
    KERNEL=="uhid", GROUP="${hardware.input.group}", MODE="${hardware.input.mode}"
    SUBSYSTEM=="tty", ATTRS{idVendor}=="${serialVendor}", ATTRS{idProduct}=="${serialProduct}", GROUP="${hardware.serial.group}", MODE="${hardware.serial.mode}"
  '';

  assertions = [
    {
      assertion = hardware.kernelModules == [ "uhid" "uinput" ];
      message = "VM 100 input kernel modules differ from the qualified hardware inventory";
    }
    {
      assertion = hardware.tun.path == "/dev/net/tun" && builtins.elem "tun" config.boot.kernelModules;
      message = "VM 100 TUN device support must remain kernel-backed at /dev/net/tun";
    }
    {
      assertion = !hardware.gpu.runtimePowerManagement && lib.hasInfix "amdgpu runpm=0" config.boot.extraModprobeConfig;
      message = "VM 100 dedicated GPU runtime power management must remain disabled";
    }
    {
      assertion = hardware.serial.protected_symlinks == [ "/dev/zigbee" "/dev/zwave" ];
      message = "VM 100 protected serial symlink scope differs";
    }
  ];
}
