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
        mail-server = import ./nixosModule { inherit self system; };
        default = mail-server;
      };

      packages.${system}.dovecot =
        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        pkgs.dovecot_2_4;
    };
}
