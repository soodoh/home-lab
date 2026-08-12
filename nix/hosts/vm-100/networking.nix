{ lib, ... }:
let
  projection = builtins.fromJSON (builtins.readFile ../../vm-100/projection.json);
  network = projection.networking;
  addressParts = lib.splitString "/" network.ipv4;
in
{
  networking.useDHCP = false;
  networking.useNetworkd = true;
  networking.nameservers = network.dns;

  systemd.network.enable = true;
  systemd.network.networks."20-vm-100" = {
    matchConfig = {
      Name = network.interface;
      MACAddress = network.matchMac;
    };
    address = [ network.ipv4 ];
    routes = [
      {
        Destination = "0.0.0.0/0";
        Gateway = network.gateway;
      }
    ];
    networkConfig = {
      DHCP = network.dhcp;
      DNS = network.dns;
      IPv6AcceptRA = false;
      LinkLocalAddressing = "no";
    };
  };

  assertions = [
    {
      assertion = builtins.length addressParts == 2 && builtins.elemAt addressParts 1 == "24";
      message = "VM 100 static IPv4 projection must retain the qualified /24 prefix";
    }
    {
      assertion = !network.dhcp;
      message = "VM 100 production networking must not enable DHCP";
    }
  ];
}
