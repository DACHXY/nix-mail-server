{
  pkgs,
  lib,
  cfg,
}:
let
  helper = import ../helper { inherit lib; };
  inherit (lib) mapAttrsToList;
  inherit (helper) mkOAuthClient;

  admClientId = "admin-cli";
  defaultAdmPassword = if cfg.initialAdminPassword != null then cfg.initialAdminPassword else "";
  defaultAdmUsername = "admin";
  host = "http://localhost:${toString cfg.settings.http-port}";
  realm = "master";
  clientData = builtins.toJSON (mapAttrsToList (name: value: mkOAuthClient value) cfg.ensureClients);
in
pkgs.writers.writePython3Bin "ensure-clients"
  { libraries = with pkgs.python3Packages; [ requests ]; }
  ''
    # flake8: noqa

    import pwd
    import grp
    import time
    import requests
    import os
    import json
    from pathlib import Path
    import sys
    from typing import TypeAlias, cast

    Client: TypeAlias = dict[str, str | bool | list[str]]

    MAX_RETRIES = 10
    TIMEOUT_SECONDS = 5
    WAIT_TIME = 5
    HOST = "${host}"
    REALM = "${realm}"
    BASE_URL = f"{HOST}/admin/realms/{REALM}"
    CLIENT_ID = "${admClientId}"
    DATA_LIST = json.loads('${clientData}') 

    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "${defaultAdmUsername}")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "${defaultAdmPassword}")

    def wait_for_service(url: str, max_retries: int, timeout: int, wait_time: int = 10) -> bool:
        for attempt in range(0, max_retries):
            try:
                print(f"attempt times: {attempt + 1}/{max_retries} [timeout: {timeout}s]")
                res = requests.get(url, timeout=timeout)
                if 200 <= res.status_code < 500:
                    return True
            except requests.exceptions.Timeout:
                print("Timeout.")
            except requests.exceptions.ConnectionError:
                print("Connection error.")
            except Exception as e:
                print("Unknown error: ", e)
            
            if attempt < max_retries:
                time.sleep(wait_time)

        print("Service not started, exiting...")
        return False


    def get_token() -> str | None:
        headers = {
            "content-type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
        }

        res = requests.post(
            f"{HOST}/realms/{REALM}/protocol/openid-connect/token",
            data=data,
            headers=headers,
        )

        data = cast(Client, res.json())
        token: str | None = cast(str | None, data.get("access_token"))

        return token


    def req(
        url: str, token: str, json: Client | None = None, method: str = "GET"
    ) -> requests.Response:
        headers = {"authorization": f"bearer {token}", "content-type": "application/json"}
        return requests.request(method=method, url=url, json=json, headers=headers)


    def get_client_uuid(client_id: str, all_clients: list[Client]) -> str | None:
        for client in all_clients:
            if client.get("clientId") == client_id:
                return str(client.get("id"))
        return None


    def get_client_secret(client_id: str, all_clients: list[Client]) -> str | None:
        for client in all_clients:
            if client.get("clientId") == client_id:
                return cast(str | None, client.get("secret"))
        return None


    def create_client(token: str, client_data: Client) -> None:
        payload = client_data.copy()
        payload.pop("clientSecret", None)

        res = req(f"{BASE_URL}/clients", method="post", token=token, json=payload)
        res.raise_for_status()
        return None


    def update_client(client_uuid: str, token: str, client_data: Client) -> None:
        payload = client_data.copy()
        payload.pop("clientSecret", None)

        res = req(
            f"{BASE_URL}/clients/{client_uuid}",
            method="put",
            token=token,
            json=payload,
        )
        res.raise_for_status()
        return None


    def get_all_clients(token: str) -> list[Client]:
        res = req(f"{BASE_URL}/clients", token=token)
        return cast(list[Client], res.json())


    def handle_client(client: Client, token: str, all_clients: list[Client]) -> None:
        client_id = cast(str, client.get("clientId"))
        uuid = get_client_uuid(client_id, all_clients)

        if uuid is None:
            print("Client not found, creating...")
            create_client(token, client)
            print(f"{client_id} created.")
            return None

        print("Client exist, updating...")
        update_client(uuid, token, client)


    def main():
        token = get_token()
        if token is None:
            print("Token get failed.")
            sys.exit(1)

        all_clients = get_all_clients(token)

        for client in DATA_LIST:
            handle_client(client, token, all_clients)

        # refresh all clients
        print("Saving secrets...")
        all_clients = get_all_clients(token)
        for client in DATA_LIST:
            client_id = cast(str, client.get("clientId"))
            secret_config = cast(str, client.get("clientSecret"))
            secret = get_client_secret(client_id, all_clients)
            if secret is None:
                print(f"{client_id} secret not found, skip.")
                continue
            
            target_path = Path(secret_config.get("path"))

            with open(target_path, "w", encoding="utf-8") as fp:
                _ = fp.write(secret)
                uid = pwd.getpwnam(secret_config.get("owner", "root")).pw_uid
                gid = grp.getgrnam(secret_config.get("group", "root")).gr_gid
                os.chown(target_path, uid, gid)
                target_path.chmod(int(secret_config.get("mode", "600"), 8))
                print(f"{client_id} saved to {secret_config}")


    if __name__ == "__main__":
        if wait_for_service(f"{BASE_URL}", MAX_RETRIES, TIMEOUT_SECONDS, WAIT_TIME):
            print("Service started.")
        else:
            sys.exit(1)

        main()
  ''
