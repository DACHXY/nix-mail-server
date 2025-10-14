{
  config,
  lib,
  pkgs,
  ...
}:
let
  exTypes = import ../types { inherit lib; };
  inherit (lib)
    mkIf
    types
    mkOption
    literalExpression
    ;
  cfg = config.services.keycloak;
in
{
  options.services.keycloak = {
    adminAccountFile = mkOption {
      type = with types; nullOr path;
      default = null;
      description = "Leave this to `null` to use `admin` and `initialAdminPassword`, useful for initialization.";
      example = literalExpression ''
        pkgs.writeText "admin-env" ''\'''\'
          ADMIN_USERNAME=admin
          ADMIN_PASSWORD=passwd
        ''\'''\';
      '';
    };
    ensureClients = mkOption {
      type = types.attrsOf exTypes.clientType;
      default = { };
      description = ''
        Ensure clients and get secret.
      '';
    };
  };

  config = mkIf cfg.enable {
    systemd.services.keycloak = {
      serviceConfig = {
        RuntimeDirectory = [ "keycloak-client-secrets:0711" ];
      };
    };
    systemd.services.keycloak-ensure-clients =
      mkIf (builtins.length (builtins.attrNames cfg.ensureClients) > 0)
        (
          let
            script = import ../scripts/keycloak_gen_client.nix { inherit pkgs lib cfg; };
          in
          {
            requiredBy = [ "keycloak.service" ];
            serviceConfig = {
              Type = "oneshot";
              ExecStart = "${lib.getExe script}";
              EnvironmentFile = mkIf (cfg.adminAccountFile != null) [
                cfg.adminAccountFile
              ];
            };
          }
        );
  };
}
