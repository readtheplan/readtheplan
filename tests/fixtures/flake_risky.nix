{
  description = "risky infrastructure flake";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.ops.url = "http://deploy:literal-token@git.example.test/ops.git";
  inputs.ops.inputs.nixpkgs.follows = "nixpkgs";

  nixConfig.extra-substituters = [ "http://cache.example.test" ];
  nixConfig.trusted-public-keys = [ "cache.example.test-1:AAAA" ];

  outputs = { self, nixpkgs, ops }:
    let
      ambient = builtins.getEnv "DEPLOY_ENV";
      unpinned = builtins.fetchTarball {
        url = "https://example.test/release.tar.gz";
      };
      builder = nixpkgs.legacyPackages.x86_64-linux.runCommand "deploy" { } ''
        cp ${unpinned} $out
      '';
    in {
      overlays.default = final: prev: { deployment = builder; };
    };
}
