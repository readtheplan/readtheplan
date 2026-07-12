{ config, pkgs, ... }:
{
  imports = [ ./hardware.nix ./secrets.nix ];

  nix.settings.trusted-users = [ "root" "*" ];
  nix.settings.sandbox = false;
  nix.settings.require-sigs = false;
  nix.settings.allow-import-from-derivation = true;
  nix.settings.accept-flake-config = true;
  nix.settings.substituters = [ "http://cache.example.test" ];
  nix.settings.trusted-public-keys = [ "cache.example.test-1:AAAA" ];

  networking.firewall.enable = false;
  networking.firewall.allowedTCPPorts = [ 22 80 443 ];
  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "yes";
  services.openssh.settings.PasswordAuthentication = true;
  services.openssh.settings.PermitEmptyPasswords = true;
  services.nginx.enable = true;
  services.nginx.openFirewall = true;

  users.users.root.initialPassword = "literal-root-password";
  users.users.deploy.hashedPasswordFile = config.sops.secrets.deploy-password.path;
  security.sudo.wheelNeedsPassword = false;
  security.pam.services.sshd.allowNullPassword = true;

  sops.secrets.deploy-token = {
    sopsFile = ./secrets.yaml;
  };

  system.activationScripts.bootstrap = ''
    ${pkgs.bash}/bin/bash /etc/bootstrap.sh
  '';
  systemd.services.deploy.script = ''
    ${pkgs.curl}/bin/curl https://deploy.example.test
  '';

  boot.kernelParams = [ "mitigations=off" ];
  boot.kernel.sysctl."kernel.unprivileged_userns_clone" = 1;
  fileSystems."/srv" = { device = "/dev/disk/by-label/data"; };
  virtualisation.docker.enable = true;
  virtualisation.oci-containers.containers.api.extraOptions = [ "--privileged" ];
  nix.buildMachines = [ { hostName = "builder.example.test"; sshUser = "root"; } ];
}
