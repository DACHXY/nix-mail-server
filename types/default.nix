{ lib }:
let
  inherit (lib) types mkOption;
in
{
  clientType =
    with types;
    submodule (
      { name, ... }:
      {
        freeformType = attrsOf (
          nullOr (oneOf [
            str
            int
            bool
            (attrsOf path)
            (listOf (oneOf [
              str
              int
              bool
            ]))
          ])
        );

        options = {
          name = mkOption {
            type = str;
            default = name;
            description = ''
              client name for client.
            '';
          };

          clientId = mkOption {
            type = str;
            default = name;
            description = ''
              clientId for client.
            '';
          };

          protocol = mkOption {
            type = str;
            default = "openid-connect";
            description = ''
              Protocol for client.
            '';
          };

          publicClient = mkOption {
            type = bool;
            default = false;
            description = ''
              Is public client.
            '';
          };

          clientSecret = {
            owner = mkOption {
              type = str;
              default = "root";
              description = "Owner for client secret";
            };
            group = mkOption {
              type = str;
              default = "root";
              description = "Group for client secret";
            };
            mode = mkOption {
              type = str;
              default = "600";
              example = "660";
              description = "Mode for client secret";
            };
            path = mkOption {
              type = path;
              default = "/run/keycloak-client-secrets/${name}";
              description = ''
                client secret saving path.
              '';
            };
          };
        };
      }
    );
}
