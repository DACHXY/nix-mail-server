{
  description = "Mail server flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    {
      nixosModules = rec {
        mail-server = import ./nixosModule;
        default = mail-server;
      };

      overlay = import ./overlays;
    };
}
