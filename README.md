# Nix Mail Server

This is a mail server module for NixOS with flake support.

## Usage

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
    mailDir = "Maildir";
    virtualMailDir = "/var/mail/vhosts";
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
        password=$2$4rrjqef1uu6n5fex6dduatndhfnj5qu1$znea6jd8i9bkear5y5gusdz318tk11srza6enubdbds9e3jesn8y
      ''}";

      # keep this screts in production
      trainerSecretFile = "${pkgs.writeText "test" ''
        PASSWORD=123
      ''}";
    };
  };
```
