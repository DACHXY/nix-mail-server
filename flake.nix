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
    }@inputs:
    let
      system = "x86_64-linux";
    in
    {
      nixosModules = rec {
        mail-server = import ./nixosModule;
        default = mail-server;
      };

      overlay = import ./overlays;

      packages.${system}.dovecot =
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlay ];
          };
        in
        pkgs.dovecot;
    };
}
