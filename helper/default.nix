{
  lib,
}:
let
  inherit (lib)
    optionalString
    concatStringsSep
    splitString
    removePrefix
    ;
  inherit (builtins) attrValues mapAttrs;
  olcSuffix2Domain =
    suffix: concatStringsSep "." (map (x: removePrefix "dc=" x) (splitString "," suffix));
in
{
  mkLdapUser =
    {
      uid,
      ou,
      dn,
      mail,
      mailRoutingAddress,
      objectClass,
      passwordFile,
      extraAttrs,
      olcSuffix,
    }:
    ''
      dn: ${if dn == null then "uid=${uid},ou=${ou},${olcSuffix}" else dn}
      ${concatStringsSep "\n" (map (o: "objectClass: ${o}") objectClass)}
      uid: ${uid}
      mail: ${if mail == null then "${uid}@${olcSuffix2Domain olcSuffix}" else mail}
      mailRoutingAddress: ${
        if mailRoutingAddress == null then "${uid}@${olcSuffix2Domain olcSuffix}" else mailRoutingAddress
      }
      ${optionalString (passwordFile != null) "userPassword: ${passwordFile}"}
      ${concatStringsSep "\n" (attrValues (mapAttrs (name: value: "${name}: ${value}") extraAttrs))}
    '';

  mkLdapOU =
    {
      ou,
      desc,
      dn,
      olcSuffix,
    }:
    ''
      dn: ${if dn == null then "ou=${ou},${olcSuffix}" else dn}
      objectClass: organizationalUnit
      ou: ${ou} 
      description: ${desc}
    '';

  getOlcSuffix = domain: concatStringsSep "," (map (dc: "dc=${dc}") (splitString "." domain));
}
