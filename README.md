# Nix Mail Server

This is a mail server module for NixOS with flake support.

## Features

- [x] Keycloak (OAuth)
- [x] Dovecot (OAuth & LDAP) + Postfix
- [x] Rspamd
- [x] Postsrsd
- [x] Roundcube (Webmail with OAuth)
- [x] ACME Support
- [x] OAuth (openid connection) automatically configure clients

> Sadly, you still need to configure `LDAP User Federation` manually.

## Installation

Install

```nix
# flake.nix
{
inputs = {
    mail-server = {
        url = "github:dachxy/nix-mail-server";
    };
};

outputs = { self, mail-server, ...}@inputs: {
    # other configurations ...
    nixosConfigurations."<your-device>" = nixpkgs.lib.nixosSystem {
        modules = [
            mail-server.nixosModules.default
            {
                nixpkgs.overlays = [ mail-server.overlay ];
            }
        ];
    };
};
}
```

Example

```nix
let
    # You can change this to your unix username,
    username = "admin"; 
    domain = "your.domain";
in
{
  mail-server = {
    enable = true;
    configureNginx = true;
    hostname = "mx1";
    domain = domain;
    extraDomains = [
        "mail.${domain}"
    ];
    rootAlias = "${username}";
    relayhosts = [ "[mx1.some.host]:587" ];
    networks = [
        "127.0.0.0/8"
        "10.0.0.0/24"
    ];
    virtual = ''
        admin@${domain} ${username}@${domain}
        postmaster@${domain} ${username}@${domain}
    '';
    openFirewall = true;
    keycloak = {
        dbSecretFile = "${pkgs.writeText "test" ''123''}";

        # ==== Option 1 ===== #
        # Leave `adminAccountFile` empty to use default temp admin account
        # to initialize clients configuration. Instead, requires `initialAdminPassword`.
        extraConf = {
            initialAdminPassword = "temp-secret";
        };

        # ==== Option 2 ===== #
        # Usually when temp admin is deleted, 
        # use a env file to supply new realm manager credentials.
        adminAccountFile = "${pkgs.writeText "test" ''
            ADMIN_USERNAME=admin
            ADMIN_PASSWORD=passwd
        ''}";
    };
    ldap = {
        filter = "(&(objectClass=inetOrgPerson)(objectClass=mailRoutingObject)(uid=%{user | username}))";
        extraAuthConf = ''
            auth_username_format = %{user | lower}
            fields {
                user = %{ldap:mail}
                password = %{ldap:userPassword}
            }
        '';

        # keep this screts in production
        secretFile = "${pkgs.writeText "olcRootPW" "YourPassword"}";

        # keep this screts in production
        # Generate with `nix shell nixpkgs#php -c php -r "echo 'base64:'.base64_encode(random_bytes(32)).\"\n\";"`
        webSecretFile = "${pkgs.writeText "test" ''
            APP_KEY=base64:HVQLeatagcQizES7SzEx7hDioAJpB0AX1Pfg032eatE=
        ''}";
    };
    rspamd = {
        # keep this screts in production
        secretFile = "${pkgs.writeText "test" ''
            test123
        ''}";

        # keep this screts in production
        trainerSecretFile = "${pkgs.writeText "test" ''
            PASSWORD=123
        ''}";
    };
    dovecot.oauth.enable = true;
  };
};
```

## Initial Configuration

### Keycloak

To init keycloak, you need to go to
[http://localhost:38080](http://localhost:38080) to configure temporary
bootstrap admin credential. See
[Offical Doc](https://www.keycloak.org/server/bootstrap-admin-recovery).

## Usage

### LDAP

Three way to connect to LDAP:

- `ldap:///localhost:389`
- `ldapi:///`
- `ldaps://<your-ldap-fqdn>` (require `configureNginx = true`)

Default admin dn: `cn=admin,<your-olcSuffix>`

> olcSuffix is generated base on your domain, e.g. `your.domain` ->
> `dc=your,dc=domain`

Default OU

- `ou=people,<your-olcSuffix>`
- `ou=groups,<your-olcSuffix>`

Default Users

- `uid=spam,ou=people,<your-olcSuffix>` (account for `rspamd`)

You can use the following configuration to ensure users and OUs.

> NOTE: Users and OUs will not be deleted automatically if the attribute once
> created.

`user`

```nix
mail-server.ldap.ensureUsers = [
  {
    uid = "example";
    # defualt: people
    ou = "people"; 
    # default (if null): uid=${uid},ou=${ou},${olcSuffix}
    dn = null; 
    # default (if null): ${uid}@${domain}
    mail = "example@<your-domain>"; 

    # default ["inetOrgPerson" "inetMailRoutingObject"]
    objectClass = ["inetOrgPerson" "inetMailRoutingObject"]; 

    # The password will be hashed to meet ppolicy.
    passwordFile = "${pkgs.writeText "testpassword" ''
      test123
    ''}"; 

    extraAttrs = {
      cn = "Example HAHA";
      sn = "HAHA";
    };
  }
];
```

`ou`

```nix
mail-server.ldap.ensureOUs= [
  {
    ou = "newOU";
    desc = "New OU for something";
  }
];
```

### WebMail (Roundcube) && OAuth

Require enabling oauth for dovecot:

```nix
{
    webmail = {
      enable = true;
      hostname = "mail.${domain}";
    };

    # Enable oauth for dovecot also
    dovecot.oauth = {
        enable = true;
    };
}
```

Keycloak settings:

```nix
{
    keycloak = {
        dbSecretFile = "${pkgs.writeText "test" ''123''}";

        # ==== Option 1 ===== #
        # Leave `adminAccountFile` empty to use default temp admin account
        # to initialize clients configuration. Instead, requires `initialAdminPassword`.
        extraConf = {
            initialAdminPassword = "temp-secret";
        };

        # ==== Option 2 ===== #
        # Usually when temp admin is deleted, 
        # use a env file to supply new realm manager credentials.
        adminAccountFile = "${pkgs.writeText "test" ''
            ADMIN_USERNAME=admin
            ADMIN_PASSWORD=passwd
        ''}";

        # This is the defalut settings for clients.
        # client will be automatically created through keycloak restful api.
        # client secret will be automatically set for dovecot and roundcube, too.
        ensureClients = {
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
    };
}
```
