{ config, lib, pkgs, ... }:
let
  projection = builtins.fromJSON (builtins.readFile ../../vm-100/projection.json);
  identity = projection.workloadIdentity;
  access = projection.access;
  workloadShell = {
    "/bin/bash" = pkgs.bashInteractive;
  }.${identity.shell};
in
{
  users.groups.${identity.primaryGroup}.gid = lib.mkForce identity.gid;
  # This acknowledges NixOS's lockout assertion while all accounts remain explicitly locked.
  users.allowNoPasswordLogin = true;
  users.users.root.hashedPassword = "!";
  users.users.${identity.user} = {
    isNormalUser = true;
    uid = identity.uid;
    group = identity.primaryGroup;
    extraGroups = identity.supplementaryGroups;
    home = identity.home;
    createHome = true;
    homeMode = "0700";
    shell = workloadShell;
    hashedPassword = "!";
    openssh.authorizedKeys.keys = [ ];
  };

  services.openssh = {
    enable = access.opensshEnabled;
    openFirewall = false;
    settings = {
      PasswordAuthentication = access.passwordAuthentication;
      KbdInteractiveAuthentication = access.keyboardInteractiveAuthentication;
      PermitRootLogin = if access.permitRootLogin then "yes" else "no";
      AllowTcpForwarding = access.allowTcpForwarding;
      X11Forwarding = access.x11Forwarding;
      PermitTunnel = false;
      GatewayPorts = "no";
      AllowAgentForwarding = false;
      AuthenticationMethods = "publickey";
      AllowUsers = [ identity.user ];
    };
  };

  security.sudo.extraRules = [ ];

  assertions = [
    {
      assertion = identity.user == identity.primaryGroup && identity.uid == identity.gid;
      message = "VM 100 workload UID/GID identity must remain numerically stable";
    }
    {
      assertion = access.authorizedLoginKeys == builtins.length config.users.users.${identity.user}.openssh.authorizedKeys.keys;
      message = "VM 100 console-only access must not authorize an SSH login key";
    }
    {
      assertion = !(builtins.hasAttr "nix-plan" config.users.users) &&
        !(builtins.hasAttr "nix-copy" config.users.users) &&
        !(builtins.hasAttr "nix-apply" config.users.users);
      message = "VM deployment identities require separately reviewed forced-command transports";
    }
    {
      assertion = !(builtins.elem identity.user (lib.concatMap (rule: rule.users) config.security.sudo.extraRules));
      message = "VM 100 workload account must not receive a sudo rule";
    }
    {
      assertion = lib.hasPrefix "/nix/store/" config.users.users.${identity.user}.shell;
      message = "VM 100 workload shell must resolve from the pinned NixOS generation";
    }
  ];
}
