{
  config,
  lib,
  ...
}:
with lib;
let
  mkSecretOption =
    {
      name,
      description ? null,
      example ? null,
    }:
    mkOption {
      type = with types; path;
      description = if description == null then "Secret file for ${name}" else description;
      example = if example == null then "/run/secrets/${name}" else example;
    };
in
{
  options.mail-server = {
    enable = mkEnableOption "mail-server";

    configureNginx = mkEnableOption "Enable auto configuration of nginx proxy and acme" // {
      default = false;
    };

    hostname = mkOption {
      type = types.str;
      default = "mx1";
    };

    caFile = mkOption {
      type = types.path;
      default = config.security.pki.caBundle;
      description = ''
        Extra CA certification to trust;
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        This option results in following configuration:

        networking.firewall.allowedTCPPorts = [
          25  # SMTP
          465 # SMTPS
          587 # STARTTLS
          143 # IMAP STARTTLS
          993 # IMAPS
          110 # POP3 STARTTLS
          995 # POP3S
        ];
      '';
    };

    rootAlias = mkOption {
      type = with types; uniq str;
      default = "";
      description = "Root alias";
      example = ''
        <your username>
      '';
    };

    virtual = mkOption {
      type = lib.types.lines;
      default = "";
      description = ''
        Entries for the virtual alias map, cf. man-page {manpage}`virtual(5)`.
      '';
    };

    extraAliases = mkOption {
      type = with types; str;
      default = "";
      description = "Extra aliases";
      example = ''
        something: root
        gender: root
      '';
    };

    mailDir = mkOption {
      type = with types; uniq str;
      description = "Path to store local mails";
      default = "~/Maildir";
      example = "~/Maildir";
    };

    virtualMailDir = mkOption {
      type = with types; path;
      description = "Path to store virtual mails";
      default = "/var/mail/vhosts";
      example = "/var/mail/vmails";
    };

    uid = mkOption {
      type = with types; int;
      default = 5000;
      description = "UID for \"vmail\"";
    };

    gid = mkOption {
      type = with types; int;
      default = 5000;
      description = "GID for \"vmail\"";
    };

    domain = mkOption {
      type = with types; uniq str;
      default = config.networking.fqdn;
      description = "Domain name used for mail server";
    };

    origin = mkOption {
      type = with types; uniq str;
      default = "";
      description = "Origin to use in outgoing e-mail. Leave blank to use hostname.";
    };

    destination = mkOption {
      type = with types; listOf str;
      default = [ ];
      description = "Postfix destination";
    };

    networks = mkOption {
      type = with types; listOf str;
      default = [ ];
      description = "Postfix networks";
    };

    relayhosts = mkOption {
      type = with types; listOf str;
      default = [ ];
      description = "Postfix relay hosts";
    };

    keycloak = {
      enable = mkEnableOption "Keycloak" // {
        default = true;
      };

      hostname = mkOption {
        type = types.str;
        default = "keycloak";
      };

      dbSecretFile = mkSecretOption {
        name = "keycloakDBSecret";
        description = "DB password for keycloak";
      };

      username = mkOption {
        type = with types; uniq str;
        default = "keycloak";
        description = "Keycloak username";
      };
    };

    dovecot = {
      extraConfig = mkOption {
        type = types.lines;
        default = "";
        example = ''
          userdb static {
            fields {
              uid = 4040
              gid = 4040
              home = /var/mail/vhost/%{user | domain}/%{user | username}
            }
          }
        '';
      };
    };

    ldap = {
      enable = mkEnableOption "openldap" // {
        default = true;
      };

      hostname = mkOption {
        type = types.str;
        default = "ldap";
      };

      filter = mkOption {
        type = types.str;
        default = "(&(objectClass=inetOrgPerson)(uid=%{user | username}))";
        example = "(&(objectClass=unixAccount)(cn=%{user}))";
        description = "`ldap_filter` for dovecot passdb";
      };

      extraAuthConf = mkOption {
        type = types.lines;
        default = "";
        example = ''
          auth_username_format = %{user | lower}
          fields {
            user = %{ldap:mail}
            password = %{ldap:userPassword}
          }
        '';
        description = "Extra configuration for dovecot passdb";
      };

      secretFile = mkSecretOption {
        name = "openldapSecret";
        description = ''
          openldap `cn=admin,dc=<your>,dc=<domain>` password, 
        '';
      };

      webSecretFile = mkSecretOption {
        name = "phpLdapAdminSecret";
        description = ''Value from `php -r 'echo "APP_KEY=base64:".base64_encode(random_bytes(32))."\n";'`'';
        example = literalExpression ''
          pkgs.writeText "phpLdapAdminSecret" ''\'''\'
            APP_KEY=base64:HVQLeatagcQizES7SzEx7hDioAJpB0AX1Pfg032eatE=
          ''\'''\'
        '';
      };
    };

    rspamd = {
      enable = mkEnableOption "Rspamd and trainer" // {
        default = true;
      };

      hostname = mkOption {
        type = types.str;
        default = "rspamd";
      };

      port = mkOption {
        type = with types; int;
        default = 11334;
        description = "Port for rspamd webUI";
      };

      secretFile = mkSecretOption {
        name = "rspamdSecret";
        description = "Generate with `rspamadm pw`";
        example = literalExpression ''
          pkgs.writeText "rspamdSecret" ''\'''\'
            password=$2$tbazk58jkj8qi16s6fkji9xg8nizrpp5$zkpneyqy5fzrjrxo45ia1n8r9z56hsqb4r73iko9p8j3a1am1okb
          ''\'''\'
        '';
      };

      trainerSecretFile = mkSecretOption {
        name = "trainerSecret";
        description = "password for `spam@<your-domain>` imap account";
        example = literalExpression ''
          pkgs.writeText "rspamdTrainerSecret" ''\'''\'
            PASSWORD=YOUR_PASSWORD
          ''\'''\'
        '';
      };
    };

    postsrsd = {
      enable = mkEnableOption "postsrsd" // {
        default = true;
      };
    };
  };

  imports = [
    ./dovecot.nix
    ./server.nix
  ];
}
