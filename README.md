# Nix Mail Server

This is a mail server module for NixOS with flake support.

## Installation

Install

```nix
# flake.nix

inputs = {
    mail-server = {
        url = "github:dachxy/nix-mail-server";
    };
}

outputs = { self, mail-server, ...}@inputs: {
    ...
    nixosConfigurations."<your-device>" = nixpkgs.lib.nixosSystem {
        modules = [
            mail-server.nixosModules.default
            {
                nixpkgs.overlays = [ mail-server.overlay ];
            }
        ];
    };
}
```

Example

```nix
  mail-server = {
    enable = true;
    configureNginx = true;
    hostname = "mx1";
    domain = "your.domain";
    rootAlias = "${username}";
    relayhosts = [ "[mx1.some.host]:587" ];
    networks = [
      "127.0.0.0/8"
      "10.0.0.0/24"
    ];
    virtual = ''
      admin@your.domain ${username}@your.domain
      postmaster@your.domain ${username}@your.domain
    '';
    openFirewall = true;
    keycloak = {
      dbSecretFile = "${pkgs.writeText "test" ''123''}";
    };
    ldap = {
      filter = "(cn=%{user | username})";
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
    ou = "people"; # defualt: people
    dn = null; # default (if null): uid=${uid},ou=${ou},${olcSuffix}
    mail = "example@<your-domain>"; # default (if null): ${uid}@${domain}
    objectClass = ["inetOrgPerson" "inetMailRoutingObject"]; # default ["inetOrgPerson" "inetMailRoutingObject"]
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
