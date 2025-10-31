{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  helper = import ../helper { inherit lib; };
  inherit (helper) mkLdapUser getOlcSuffix mkLdapOU;

  cfg = config.mail-server;
  dcList = strings.splitString "." cfg.domain;
  oauthURI =
    if cfg.configureNginx then
      "https://${cfg.keycloak.hostname}.${cfg.domain}"
    else
      "http://localhost:${toString config.services.keycloak.settings.http-port}";
  ldapDomain = getOlcSuffix cfg.domain;

  dovecotSecretPath = "/run/dovecot";
  ldapAuthConf = "${dovecotSecretPath}/dovecot-auth-ldap.conf.ext";
  ldapAuthBaseConf = pkgs.writeText "dovecot-ldap.conf.ext" ''
    ldap_auth_dn = cn=admin,${ldapDomain}
    ldap_auth_dn_password = "$LDAP_PASSWORD"
    ldap_uris = ldap://localhost
    ldap_base = ${ldapDomain}

    passdb ldap {
      ldap_bind = no
      ldap_filter = ${cfg.ldap.filter} 
      use_worker = yes 
      ${cfg.ldap.extraAuthConf}
    }

    userdb ldap {
      use_worker = yes
      ldap_connection_group = different-connection-group
      filter = (|(mailRoutingAddress=%{user})(mail=%{user}))
      fields {
        uid = ${toString cfg.uid}
        gid = ${toString cfg.gid}
        user = %{ldap:mailRoutingAddress}
        mail_driver = maildir
        home = /var/mail/%{user | domain}/%{user | username}
        mail_path = /var/mail/%{user | domain}/%{user | username}/Maildir
      }
    }
  '';

  oauth2AuthConf = "${dovecotSecretPath}/dovecot-auth-oauth2.conf.ext";
  oauth2AuthBaseConf = pkgs.writeText "dovecot-oauth.conf.ext" ''
    oauth2 {
      openid_configuration_url = ${oauthURI}/realms/master/.well-known/openid-configuration
      introspection_url = ${oauthURI}/realms/master/protocol/openid-connect/userinfo
      introspection_mode = auth
      send_auth_headers = yes
      username_attribute = email
      client_id = ${config.services.keycloak.ensureClients.dovecot.clientId}
      client_secret = $CLIENT_SECRET 
    }

    passdb oauth2 {
    }
  '';

  dovecotDomain = config.services.postfix.settings.main.myhostname;

  rspamdSecretPath = "/run/rspamd/rspamd-controller-password.inc";
in
{
  config = mkIf cfg.enable {
    security.acme.certs = mkIf cfg.configureNginx {
      "${config.services.postfix.settings.main.myhostname}" = {
        extraDomainNames = [
          "${cfg.domain}"
        ]
        ++ cfg.extraDomains;

        postRun = ''
          systemctl restart postfix.service
          systemctl restart dovecot.service
        '';
      };
      "${cfg.ldap.hostname}.${cfg.domain}" = {
        postRun = ''
          systemctl restart openldap.service
        '';
      };
    };

    # ===== opendkim ===== #
    services.opendkim = {
      enable = true;
      settings = {
        UMask = "0007";
      };
      domains = "csl:${cfg.domain}";
      selector = "${cfg.hostname}";
    };

    # ===== Postfix ===== #
    systemd.services.postfix = mkIf cfg.configureNginx {
      wants = [
        "acme-finished-${config.services.postfix.settings.main.myhostname}.target"
      ];
      serviceConfig.LoadCredential =
        let
          certDir =
            config.security.acme.certs."${config.services.postfix.settings.main.myhostname}".directory;
        in
        [
          "cert.pem:${certDir}/cert.pem"
          "key.pem:${certDir}/key.pem"
        ];
    };

    services.postfix = {
      enable = true;
      virtual = cfg.virtual;
      enableSubmission = true; # 587
      enableSubmissions = true; # 465
      enableSmtp = true;

      submissionsOptions = {
        milter_macro_daemon_name = "ORIGINATING";
        smtpd_client_restrictions = "permit_sasl_authenticated,reject";
        smtpd_sasl_auth_enable = "yes";
        smtpd_sasl_type = "dovecot";
        smtpd_sasl_path = "private/auth";
        smtpd_tls_protocols = "TLSv1.3";
        smtpd_tls_mandatory_protocols = "TLSv1.3";
      };

      submissionOptions = {
        milter_macro_daemon_name = "ORIGINATING";
        smtpd_client_restrictions = "permit_sasl_authenticated,reject";
        smtpd_sasl_auth_enable = "yes";
        smtpd_sasl_type = "dovecot";
        smtpd_sasl_path = "private/auth";
        smtpd_tls_security_level = "encrypt";
        smtpd_tls_protocols = "TLSv1.3";
        smtpd_tls_mandatory_protocols = "TLSv1.3";
      };

      settings.main =
        let
          credsDir = "/run/credentials/postfix.service";
          certDir = "${credsDir}/cert.pem";
          keyDir = "${credsDir}/key.pem";
        in
        (optionalAttrs cfg.configureNginx {
          smtp_tls_security_level = "may";
          smtp_tls_chain_files = [
            keyDir
            certDir
          ];

          smtpd_tls_chain_files = [
            keyDir
            certDir
          ];
        })
        // {
          myhostname = "${cfg.hostname}.${cfg.domain}";
          mynetworks = cfg.networks;
          mydestination = cfg.destination;
          myorigin = if cfg.origin == "" then cfg.domain else cfg.origin;
          relayhost = cfg.relayhosts;
          relay_domains = cfg.relayDomains;
          smtpd_client_restrictions = "permit_mynetworks, permit_sasl_authenticated, reject";
          smtpd_relay_restrictions = "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject";

          virtual_uid_maps = [
            "static:${toString cfg.uid}"
          ];
          virtual_gid_maps = [
            "static:${toString cfg.gid}"
          ];

          virtual_mailbox_domains = [ cfg.domain ];
          virtual_transport = "lmtp:unix:private/dovecot-lmtp";
          tls_random_source = "dev:/dev/urandom";
          home_mailbox = "/var/spool/mail/%d/%n";
        }
        // optionalAttrs config.services.opendkim.enable (
          let
            opendkimSocket = strings.removePrefix "local:" config.services.opendkim.socket;
          in
          {
            smtpd_milters = [ "unix:${opendkimSocket}" ];
            non_smtpd_milters = [ "unix:${opendkimSocket}" ];
            milter_default_action = "accept";
          }
        );

      rootAlias = cfg.rootAlias;
      postmasterAlias = "root";
      extraAliases = ''
        mailer-daemon: postmaster
        nobody: root
        hostmaster: root
        usenet: root
        news: root
        webmaster: root
        www: root
        ftp: root
        abuse: root
        noc: root
        security: root
      ''
      + cfg.extraAliases;
    };

    systemd.services.rspamd = mkIf config.services.rspamd.enable {
      path = [
        pkgs.rspamd
        pkgs.coreutils
      ];
      serviceConfig = {
        ExecStartPre = [
          "${pkgs.writeShellScript "generate-rspamd-passwordfile" ''
            RSPAMD_PASSWORD_HASH=$(rspamadm pw --password $(cat ${cfg.rspamd.secretFile}))
            echo "enable_password = \"$RSPAMD_PASSWORD_HASH\";" > ${rspamdSecretPath} 
            chmod 770 "${rspamdSecretPath}" 
          ''}"
        ];
      };
    };

    services.rspamd = {
      enable = true;
      postfix.enable = true;
      locals = {
        "redis.conf".text = ''
          servers = "${config.services.redis.servers.rspamd.unixSocket}";
        '';
        "classifier-bayes.conf".text = ''
          backend = "redis";
          autolearn = true;
        '';
        "dkim_signing.conf".text = ''
          enabled = false;
        '';
        "milter_headers.conf".text = ''
          enabled = true;
          extended_spam_headers = true;
          skip_local = false;
          use = ["x-spamd-bar", "x-spam-level", "x-spam-status", "authentication-results", "x-spamd-result"];
          authenticated_headers = ["authentication-results"];
        '';
      };
      workers = {
        normal = {
          type = "normal";
          includes = [ "$CONFDIR/worker-normal.inc" ];
          bindSockets = [
            {
              socket = "/run/rspamd/rspamd.sock";
              mode = "0660";
              owner = "${config.services.rspamd.user}";
              group = "${config.services.rspamd.group}";
            }
          ];
        };
        controller = {
          type = "controller";
          includes = [
            "$CONFDIR/worker-controller.inc"
          ];
          extraConfig = ''
            .include(try=true; priority=1,duplicate=merge) "${rspamdSecretPath}"
          '';
          bindSockets = [ "127.0.0.1:${toString cfg.rspamd.port}" ];
        };
      };
      overrides."whitelist.conf".text = ''
        whiltelist_from {
          ${cfg.domain} = true;
        }
      '';
    };

    services.redis.servers.rspamd = {
      enable = true;
      port = 0;
      user = config.services.rspamd.user;
    };

    # ===== rspamd trainer ===== #
    services.rspamd-trainer = {
      enable = true;
      settings = {
        HOST = cfg.domain;
        USERNAME = "spam@${cfg.domain}";
        INBOXPREFIX = "INBOX.";
      };
      secrets = [
        cfg.rspamd.trainerSecretFile
      ];
    };

    systemd.services.rspamd-trainer = lib.mkIf config.services.rspamd-trainer.enable {
      after = [
        "postfix.service"
        "dovecot.service"
        "rspamd-trainer-pre.service"
      ];
      requires = [ "rspamd-trainer-pre.service" ];
    };

    # ===== Create Mailbox for rspamd trainer ===== #
    systemd.services.rspamd-trainer-pre = lib.mkIf config.services.rspamd-trainer.enable {
      serviceConfig = {
        ExecStart =
          let
            script = pkgs.writeShellScript "rspamd-trainer-pre.sh" ''
              set -euo pipefail

              username=${config.services.rspamd-trainer.settings.USERNAME}
              domain="${cfg.domain}"
              mailbox_list=("report_spam" "report_ham" "report_spam_reply")
              for mailbox in ''\${mailbox_list[@]}; do
                echo "Creating $mailbox..."
                ${pkgs.dovecot}/bin/doveadm mailbox create -u "$username@$domain" "INBOX.$mailbox" 2>/dev/null || true
              done
            '';
          in
          "${pkgs.bash}/bin/bash ${script}";
        Type = "oneshot";
      };
    };

    # ===== Dovecot ===== #
    systemd.services.dovecot = {
      wants = if cfg.configureNginx then [ "acme-finished-${dovecotDomain}.target" ] else [ ];
      requires = if cfg.dovecot.oauth.enable then [ "keycloak-ensure-clients.service" ] else [ ];
      after = mkIf cfg.webmail.enable [ "keycloak-ensure-clients.service" ];
      serviceConfig = {
        RuntimeDirectory = [ "dovecot" ];
        RuntimeDirectoryMode = "0700";
        ExecStartPre =
          (optional cfg.dovecot.oauth.enable [
            ''${pkgs.bash}/bin/bash -c "CLIENT_SECRET=\"$(cat /run/credentials/dovecot.service/clientSecret)\" ${pkgs.gettext.out}/bin/envsubst < ${oauth2AuthBaseConf} > ${oauth2AuthConf}"''
            ''${pkgs.busybox.out}/bin/chown ${config.services.dovecot.user}:${config.services.dovecot.group} ${oauth2AuthConf}''
            ''${pkgs.busybox.out}/bin/chmod 660 ${oauth2AuthConf}''
          ])
          ++ [
            ''${pkgs.bash}/bin/bash -c "LDAP_PASSWORD=\"$(cat ${cfg.ldap.secretFile})\" ${pkgs.gettext.out}/bin/envsubst < ${ldapAuthBaseConf} > ${ldapAuthConf}"''
            ''${pkgs.busybox.out}/bin/chown ${config.services.dovecot.user}:${config.services.dovecot.group} ${ldapAuthConf}''
            ''${pkgs.busybox.out}/bin/chmod 660 ${ldapAuthConf}''
          ];
        LoadCredential = mkIf cfg.configureNginx (
          let
            certDir = config.security.acme.certs."${dovecotDomain}".directory;
          in
          [
            "cert.pem:${certDir}/cert.pem"
            "key.pem:${certDir}/key.pem"
            "clientSecret:${config.services.keycloak.ensureClients.dovecot.clientSecret.path}"
          ]
        );
      };
    };

    services.dovecot =
      let
        credsDir = "/run/credentials/dovecot.service";
        certDir = "${credsDir}/cert.pem";
        keyDir = "${credsDir}/key.pem";
      in
      (optionalAttrs cfg.configureNginx {
        sslServerKey = keyDir;
        sslServerCert = certDir;
      })
      // {
        enable = true;
        enablePAM = false;
        enableImap = true;
        enablePop3 = true;
        enableLmtp = true;
        enableHealthCheck = true;
        mailLocation = "/var/spool/mail/%{user | domain}/%{user | username}";
        mailUser = "vmail";
        mailGroup = "vmail";

        mailboxes = {
          Junk = {
            specialUse = "Junk";
            auto = "subscribe";
          };
          Drafts = {
            specialUse = "Drafts";
            auto = "subscribe";
          };
          Archive = {
            specialUse = "Archive";
            auto = "subscribe";
          };
          Sent = {
            specialUse = "Sent";
            auto = "subscribe";
          };
        };

        extraConfig = ''
          # authentication debug logging
          log_path = /dev/stderr
          log_debug = (category=auth-client) OR (category=auth) OR (event=auth_client_passdb_lookup_started)
          auth_verbose = yes

          auth_mechanisms = plain login ${optionalString cfg.dovecot.oauth.enable "oauthbearer xoauth2"}

          ${optionalString cfg.configureNginx ''
            ssl = required
          ''}

          service auth {
            unix_listener ${config.services.postfix.settings.main.queue_directory}/private/auth {
              mode = 0660
              user = ${config.services.postfix.user}
              group = ${config.services.postfix.group}
              type = postfix
            }
          }

          service lmtp {
            unix_listener ${config.services.postfix.settings.main.queue_directory}/private/dovecot-lmtp {
              mode = 0660
              user = ${config.services.postfix.user}
              group = ${config.services.postfix.group}
              type = postfix
            }
          }


          lda_mailbox_autosubscribe = yes
          lda_mailbox_autocreate = yes

          !include ${ldapAuthConf}
          ${optionalString cfg.dovecot.oauth.enable "!include ${oauth2AuthConf}"}

          ${cfg.dovecot.extraConfig}
        '';
      };

    systemd.services.dovecot-healthcheck = mkIf config.services.dovecot.enableHealthCheck (
      let
        pythonServer =
          pkgs.writeScript "dovecot-healthcheck"
            # python
            ''
              #!${pkgs.python3}/bin/python3
              import socket
              from http.server import BaseHTTPRequestHandler, HTTPServer

              DOVECOT_HOST = '127.0.0.1'
              DOVECOT_PORT = ${toString config.services.dovecot.healthCheckPort}

              class HealthCheckHandler(BaseHTTPRequestHandler):
                  def do_GET(self):
                      if self.path != '/ping':
                          self.send_response(404)
                          self.end_headers()
                          return
                      try:
                          with socket.create_connection((DOVECOT_HOST, DOVECOT_PORT), timeout=5) as sock:
                              sock.sendall(b"PING\n")
                              data = sock.recv(1024).strip()
                      except Exception as e:
                          self.send_response(500)
                          self.end_headers()
                          self.wfile.write(b"Error connecting to healthcheck service")
                          return

                      if data == b"PONG":
                          self.send_response(200)
                          self.send_header("Content-Type", "text/plain")
                          self.end_headers()
                          self.wfile.write(b"PONG")
                      else:
                          self.send_response(500)
                          self.end_headers()
                          self.wfile.write(b"Unexpected response")

              if __name__ == '__main__':
                  server = HTTPServer(('0.0.0.0', 5002), HealthCheckHandler)
                  print("HTTP healthcheck proxy running on port 5002")
                  server.serve_forever()
            '';
      in
      {
        requires = [ "dovecot.service" ];
        wantedBy = [ "multi-user.target" ];
        after = [ "dovecot.service" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = pythonServer;
        };
      }
    );

    # ===== Firewall ===== #
    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [
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

    services.postgresql = {
      enable = true;
    };

    # ===== OAuth keycloak ===== #
    systemd.services.keycloak = {
      after = [ "openldap.service" ];
      requires = [ "openldap.service" ];
    };

    services.keycloak = (
      {
        inherit (cfg.keycloak) adminAccountFile ensureClients;
        enable = true;

        database = {
          type = "postgresql";
          name = "keycloak";
          createLocally = true;
          passwordFile = cfg.keycloak.dbSecretFile;
        };

        settings = {
          hostname = "${cfg.keycloak.hostname}.${cfg.domain}";
          proxy-headers = "xforwarded";
          http-port = 38080;
          http-enabled = true;
          health-enabled = true;
          http-management-port = 38081;
          truststore-paths = cfg.caFile;
        };
      }
      // cfg.keycloak.extraConf
    );

    systemd.services.keycloak-ensure-clients-post = mkIf cfg.webmail.enable {
      wantedBy = [ "keycloak-ensure-clients.service" ];
      after = [ "keycloak-ensure-clients.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.writeShellScript "keycloak-ensure-clients-post" ''
          ${optionalString cfg.webmail.enable "${pkgs.systemd}/bin/systemctl restart phpfpm-roundcube.service"}
        ''}";
      };
    };

    # ==== LDAP ===== #
    systemd.services.openldap-pre = mkIf config.services.openldap.enable {
      before = [ "openldap.service" ];
      requiredBy = [ "openldap.service" ];
      serviceConfig = {
        User = "openldap";
        ExecStart = ''${pkgs.bash}/bin/bash -c '${config.services.openldap.package}/bin/slappasswd -T ${cfg.ldap.secretFile} > /var/lib/openldap/olcPasswd' '';
        ExecStartPost = [
          "${pkgs.busybox.out}/bin/chmod 700 /var/lib/openldap/olcPasswd"
        ];
        Type = "oneshot";
        StateDirectory = [
          "openldap"
        ];
        StateDirectoryMode = "700";
      };
    };

    systemd.services.openldap-ensure-service-users = mkIf config.services.openldap.enable (
      let
        firstDC = elemAt dcList 0;
        baseLdif = pkgs.writeText "openldap-base.ldif" ''
          dn: ${ldapDomain} 
          objectClass: dcObject
          objectClass: organization
          dc: ${firstDC} 
          o: ${firstDC} Organization

          ${concatStringsSep "\n" (map (u: mkLdapOU u) cfg.ldap.ensureOUs)}

          ${concatStringsSep "\n" (map (u: mkLdapUser u) cfg.ldap.ensureUsers)}
        '';
      in
      {
        after = [ "openldap.service" ];
        wantedBy = [ "openldap.service" ];
        path = [
          config.services.openldap.package
          pkgs.gawk
        ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.writeShellScript "ldap-ensure-services-users" ''
            URI="ldap://localhost:389"
            BIND_DN="cn=admin,${ldapDomain}"
            PASSWORD="$(cat ${cfg.ldap.secretFile})"
            LDIF="${baseLdif}"

            grep "^dn" "$LDIF" | cut -d' ' -f2- | while read -r DN; do
              echo "Checking: $DN"
              if ldapsearch -x -D "$BIND_DN" -w "$PASSWORD" -b "$DN" "(objectClass=*)" >/dev/null; then
                echo "$DN Exist, skip."
              else
                echo "$DN Not exist, creating..."
                awk -v dn="$DN" '
                  BEGIN {found=0}
                  /^dn:[[:space:]]*/ {
                      if(found) exit
                      if($0 ~ "^dn:[[:space:]]*"dn) {found=1; print; next}
                  }
                  found && !/^$/ {print}
                  found && /^$/ {exit}
                ' "$LDIF" | \
                while IFS= read -r line; do
                  if [[ $line =~ ^userPassword:[[:space:]]*/ ]]; then
                    secret_file="$(echo "$line" | sed 's/^userPassword:[[:space:]]*//; s/[[:space:]]*$//')"
                    if [[ -f "$secret_file" ]]; then
                      echo "userPassword: $(slappasswd -h "{SSHA}" -s "$(cat "$secret_file")" 2>/dev/null)"
                    else
                      echo "$line"
                    fi
                  else
                    echo "$line"
                  fi
                done | ldapadd -x -D "$BIND_DN" -w "$PASSWORD"
              fi
            done
          ''}";
        };
      }
    );

    systemd.services.openldap = {
      wants = [ "acme-finished-${cfg.ldap.hostname}.${cfg.domain}.target" ];
      serviceConfig.LoadCredential =
        let
          certDir = config.security.acme.certs."${cfg.ldap.hostname}.${cfg.domain}".directory;
        in
        [
          "full.pem:${certDir}/full.pem"
          "cert.pem:${certDir}/cert.pem"
          "key.pem:${certDir}/key.pem"
        ];
    };

    services.openldap =
      let
        credsDir = "/run/credentials/openldap.service";
        caDir = "${credsDir}/full.pem";
        certDir = "${credsDir}/cert.pem";
        keyDir = "${credsDir}/key.pem";
      in
      {
        enable = true;

        urlList = (
          [
            "ldap:///"
            "ldapi:///"
          ]
          ++ (optionals cfg.configureNginx [ "ldaps:///" ])
        );
        settings = {
          attrs = {
            olcLogLevel = "conns config";

            olcTLSCACertificateFile = caDir;
            olcTLSCertificateFile = certDir;
            olcTLSCertificateKeyFile = keyDir;
            olcTLSCipherSuite = "HIGH:MEDIUM:+3DES:+RC4:+aNULL";
            olcTLSCRLCheck = "none";
            olcTLSVerifyClient = "never";
            olcTLSProtocolMin = "3.1";
          };

          children = {
            "cn=schema".includes = [
              "${pkgs.openldap}/etc/schema/core.ldif"
              "${pkgs.openldap}/etc/schema/cosine.ldif"
              "${pkgs.openldap}/etc/schema/inetorgperson.ldif"
              "${../schema/inetMailRoutingObject.ldif}"
            ];

            "olcDatabase={1}mdb" = {
              attrs = {
                objectClass = [
                  "olcDatabaseConfig"
                  "olcMdbConfig"
                ];

                olcDatabase = "{1}mdb";
                olcDbDirectory = "/var/lib/openldap/data";

                olcSuffix = ldapDomain;

                olcRootDN = "cn=admin,${ldapDomain}";
                olcRootPW.path = "/var/lib/openldap/olcPasswd";

                olcAccess = cfg.ldap.olcAccess;
              };

              children = {
                "olcOverlay={2}ppolicy".attrs = {
                  objectClass = [
                    "olcOverlayConfig"
                    "olcPPolicyConfig"
                    "top"
                  ];
                  olcOverlay = "{2}ppolicy";
                  olcPPolicyHashCleartext = "TRUE";
                };

                "olcOverlay={3}memberof".attrs = {
                  objectClass = [
                    "olcOverlayConfig"
                    "olcMemberOf"
                    "top"
                  ];
                  olcOverlay = "{3}memberof";
                  olcMemberOfRefInt = "TRUE";
                  olcMemberOfDangling = "ignore";
                  olcMemberOfGroupOC = "groupOfNames";
                  olcMemberOfMemberAD = "member";
                  olcMemberOfMemberOfAD = "memberOf";
                };

                "olcOverlay={4}refint".attrs = {
                  objectClass = [
                    "olcOverlayConfig"
                    "olcRefintConfig"
                    "top"
                  ];
                  olcOverlay = "{4}refint";
                  olcRefintAttribute = "memberof member manager owner";
                };
              };
            };
          };
        };
      };

    # ==== postsrsd ==== #
    services.postsrsd = {
      enable = true;
      configurePostfix = true;
      settings = {
        srs-domain = cfg.domain;
        domains = [ cfg.domain ];
      };
    };

    virtualisation = {
      docker = {
        enable = true;
        rootless = {
          enable = true;
          setSocketVariable = true;
        };
      };
      oci-containers = {
        backend = "docker";
        containers = {
          phpLDAPadmin = {
            extraOptions = [ "--network=host" ];
            image = "phpldapadmin/phpldapadmin";
            environment = {
              APP_URL = "https://ldap.${cfg.domain}";
              APP_DEBUG = "true";
              ASSET_URL = "https://ldap.${cfg.domain}";
              APP_TIMEZONE = "Asia/Taipei";
              LDAP_HOST = "127.0.0.1";
              SERVER_NAME = ":8080";
              LDAP_LOGIN_OBJECTCLASS = "inetOrgPerson";
              LDAP_BASE_DN = "${ldapDomain}";
              LDAP_LOGIN_ATTR = "dn";
              LDAP_LOGIN_ATTR_DESC = "Username";
              LDAP_ALERT_ROOTDN = "true";
            };
            environmentFiles = [
              cfg.ldap.webSecretFile
            ];
          };
        };
      };
    };

    # ===== Virtual Mail User ===== #
    users.groups.vmail = {
      gid = cfg.gid;
    };

    users.users.vmail = {
      uid = cfg.uid;
      group = "vmail";
    };

    users.groups."${config.services.opendkim.group}" = {
      members = [ config.services.postfix.user ];
    };

    systemd.services.phpfpm-roundcube = {
      after = [ "keycloak-ensure-clients.service" ];
      requires = [ "keycloak-ensure-clients.service" ];
      serviceConfig = {
        RuntimeDirectory = [ "roundcube" ];
        ExecStartPre = [
          ''${pkgs.bash}/bin/bash -c "cat ${config.services.keycloak.ensureClients.roundcube.clientSecret.path} > /run/roundcube/clientSecret"''
          ''${pkgs.coreutils}/bin/chown roundcube:roundcube /run/roundcube/clientSecret''
          ''${pkgs.coreutils}/bin/chmod 600 /run/roundcube/clientSecret''
        ];
      };
    };

    services.roundcube = mkIf cfg.webmail.enable {
      enable = true;
      configureNginx = cfg.configureNginx;
      hostName = "${cfg.webmail.hostname}";
      extraConfig =
        let
          enableTLS = cfg.configureNginx;
          prefix = if enableTLS then "tls://" else "";
        in
        ''
          $config['oauth_client_id'] = '${config.services.keycloak.ensureClients.roundcube.clientId}';
          $config['oauth_client_secret'] = trim(file_get_contents('/run/roundcube/clientSecret'));
          $config['oauth_provider'] = 'generic';
          $config['oauth_provider_name'] = 'Keycloak';
          $config['oauth_auth_uri'] = '${oauthURI}/realms/master/protocol/openid-connect/auth';
          $config['oauth_token_uri'] = '${oauthURI}/realms/master/protocol/openid-connect/token';
          $config['oauth_identity_uri'] = '${oauthURI}/realms/master/protocol/openid-connect/userinfo';
          $config['oauth_scope'] = 'openid email';
          $config['oauth_debug'] = true;
          $config['oauuth_identity_fields'] = ['email'];
          $config['oauth_login_redirect'] = true;

          $config['imap_host'] = '${prefix}${cfg.hostname}.${cfg.domain}';
          $config['smtp_server'] = '${prefix}${cfg.hostname}.${cfg.domain}';
          $config['username_domain'] = [
            '${cfg.hostname}.${cfg.domain}' => '${cfg.domain}'
          ];
        '';
    };

    services.nginx = mkIf cfg.configureNginx {
      enable = mkDefault true;
      recommendedGzipSettings = mkDefault true;
      recommendedOptimisation = mkDefault true;
      recommendedTlsSettings = mkDefault true;
      recommendedProxySettings = mkDefault true;

      virtualHosts = {
        "${config.services.postfix.settings.main.myhostname}" = {
          enableACME = true;
          forceSSL = true;
          locations."/dovecot/ping".proxyPass = "http://localhost:${toString 5002}/ping";
        };
        "${cfg.ldap.hostname}.${cfg.domain}" = {
          enableACME = true;
          forceSSL = true;
          locations."/" = {
            extraConfig = ''
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_pass http://localhost:${toString 8080}/;
            '';
          };
        };
        "${cfg.rspamd.hostname}.${cfg.domain}" = mkIf config.services.rspamd.enable {
          enableACME = true;
          forceSSL = true;
          locations."/".proxyPass = "http://localhost:${toString cfg.rspamd.port}/";
        };
        "${config.services.keycloak.settings.hostname}" = mkIf config.services.keycloak.enable {
          enableACME = true;
          forceSSL = true;
          locations."/".proxyPass =
            "http://localhost:${toString config.services.keycloak.settings.http-port}";
          locations."/health".proxyPass =
            "http://localhost:${toString config.services.keycloak.settings.http-management-port}/health";
        };
      };
    };
  };
}
