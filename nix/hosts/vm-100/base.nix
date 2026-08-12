{ pkgs, ... }:
{
  time.timeZone = "America/Los_Angeles";
  i18n.defaultLocale = "en_US.UTF-8";
  console.keyMap = "us";

  environment.systemPackages = with pkgs; [
    curl
    git
    jq
    rsync
  ];

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    trusted-users = [ "root" ];
  };

  security.sudo.enable = true;
  users.mutableUsers = false;
}
