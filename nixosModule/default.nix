{
  config,
  lib,
  options,
  ...
}:
with lib;
let
  helper = import ../helper { inherit lib; };
  inherit (helper) getOlcSuffix;
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

  ldapOU =
    with types;
    submodule {
      options = {
        ou = mkOption {
          type = str;
          example = "machine";
          description = "Organization Unit";
        };
        desc = mkOption {
          type = str;
          default = "";
          example = "All machine accounts";
          description = "Description for ou.";
        };
        dn = mkOption {
          type = nullOr str;
          default = null;
          description = ''
            `dn` for ldap. If this is null, 
            default value `ou=''\${ou},''\${olcSuffix}` will be set.
          '';
        };
        olcSuffix = mkOption {
          type = str;
          default = getOlcSuffix config.mail-server.domain;
          description = "olcSuffix for ldap.";
          example = "dc=your,dc=domain";
        };
      };
    };

  ldapUser =
    with types;
    submodule {
      options = {
        uid = mkOption {
          type = str;
          description = "`uid` for ldap";
          example = "user1";
        };

        ou = mkOption {
          type = str;
          default = "people";
          description = "`ou` for ldap";
          example = "group";
        };

        dn = mkOption {
          type = nullOr str;
          default = null;
          description = ''
            `dn` for ldap. If this is null, 
            default value `uid=''\${uid},ou=''\${ou},''\${olcSuffix}` will be set.
          '';
        };

        objectClass = mkOption {
          type = listOf str;
          default = [
            "inetOrgPerson"
            "inetMailRoutingObject"
          ];
          description = "`objectClass` for ldap.";
        };

        passwordFile = mkOption {
          type = nullOr path;
          default = null;
          description = ''
            `userPassword` for ldap. If this is null,
            `userPassword` will not be set.
          '';
        };

        mail = mkOption {
          type = nullOr str;
          default = null;
          description = ''
            Mail address for this user. If this is null,
            `''\${uid}@''\${domain}` will be set.
          '';
        };

        mailRoutingAddress = mkOption {
          type = nullOr str;
          default = null;
          description = ''
            mailRoutingAddress for this user. If this is null,
            `''\${uid}@''\${domain}` will be set.
          '';
        };

        extraAttrs = mkOption {
          type = attrsOf str;
          default = { };
          description = "extra attributes for ldap.";
          example = {
            cn = "UserName name";
            sn = "UserName";
          };
        };

        olcSuffix = mkOption {
          type = str;
          default = getOlcSuffix config.mail-server.domain;
          description = "olcSuffic for ldap.";
          example = "dc=your,dc=domain";
        };
      };
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

    webmail = {
      enable = (mkEnableOption "Enable RoundCube webmail") // {
        default = false;
      };
      hostname = mkOption {
        type = types.str;
        default = "${config.mail-server.hostname}.${config.mail-server.domain}";
        description = ''
          Hostname for webmail.
        '';
        example = "mail.your.domain";
      };
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        This option results in following configuration:

        networking.firewall.allowedTCPPorts = [
          80 # HTTP
          443 # HTTPS
          25 # SMTP
          465 # SMTPS
          587 # SMTP STARTTLS
          143 # IMAP STARTTLS
          993 # IMAPS
          110 # POP3 STARTTLS
          995 # POP3S
          389 # LDAP
          636 # LDAPS
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
      default = config.networking.domain;
      description = "Domain name used for mail server";
    };

    extraDomains = mkOption {
      type = with types; listOf str;
      default = [ ];
      description = "Extra domain names used for mail server";
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

    relayDomains = mkOption {
      type = with types; listOf str;
      default = [ ];
      description = "Postfix relay domains";
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

      adminAccountFile = options.services.keycloak.adminAccountFile;

      ensureClients = mkOption {
        type = options.services.keycloak.ensureClients.type;
        default = {
          dovecot = {
            clientSecret = {
              owner = "dovecot";
              group = "dovecot";
            };
          };
          roundcube = {
            clientSecret = {
              owner = "roundcube";
              group = "roundcube";
            };
            rootUrl = "https://${config.services.roundcube.hostName}";
            baseUrl = "https://${config.services.roundcube.hostName}";
            redirectUris = [ "/*" ];
          };
        };
        description = options.services.keycloak.ensureClients.description;
      };

      extraConf = mkOption {
        type = with types; attrs;
        default = { };
        example = literalExpression ''
          {
            initialAdminPassword = "temp-secret-password";
          }
        '';
        description = "Extra keycloak settings";
      };
    };

    dovecot = {
      oauth = {
        enable = (mkEnableOption ''Enable OAuth2 authentication for dovecot.'') // {
          default = false;
        };
      };
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

      olcAccess = mkOption {
        type = with types; listOf lines;
        default = [
          ''
            {0}to attrs=userPassword
                by peername="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage 
                by dn.exact="cn=admin,${getOlcSuffix config.mail-server.domain}" manage
                by self write
                by anonymous auth
                by * none
          ''
          ''
            {1}to *
                by peername="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage 
                by dn.exact="cn=admin,${getOlcSuffix config.mail-server.domain}" manage
                by self read
                by anonymous auth
                by * none
          ''
        ];
        description = "OlcAccess rule for ldap.";
        example = literalExpression ''
          [
          ''\'''\'
            {0}to attrs=userPassword
                by dn.exact="cn=admin,${ldapDomain}" read
                by dn.exact="cn=admin,${ldapDomain}" write 
                by self write
                by anonymous auth
                by * none
          ''\'''\'
          ''\'''\'
              {1}to *
                  by dn.exact="cn=admin,${ldapDomain}" write
                  by * read
          ''\'''\'
          ]
        '';
      };

      ensureOUs = mkOption {
        type = with types; listOf ldapOU;
        default = [
          {
            ou = "people";
            desc = "All user accounts";
          }
          {
            ou = "groups";
            desc = "All user groups";
          }
        ];
        description = "Ensure organizationalUnit created.";
      };

      ensureUsers = mkOption {
        type = with types; listOf ldapUser;
        default = [
          {
            uid = "spam";
            ou = "people";
            passwordFile = "${config.mail-server.rspamd.secretFile}";
            extraAttrs = {
              cn = "Spam Rspamd";
              sn = "Rspamd";
            };
          }
        ];
        description = ''
          Ensure service accounts: `uid=$name,ou=service,<olcSuffix>`
        '';
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
    ./keycloak.nix
    ./server.nix
  ];
}
