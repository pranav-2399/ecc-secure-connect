import requests

class ServerAPI:
    """
    Client networking API for communicating with the Flask relay server
    and optionally sending direct payloads to peer client server endpoints.
    """
    def __init__(self, relay_url: str = "http://127.0.0.1:5000"):
        self.relay_url = relay_url.rstrip('/')

    def register(self, client_id: str, public_key_pem: str, client_server_url: str = None) -> bool:
        url = f"{self.relay_url}/register"
        payload = {
            "client_id": client_id,
            "public_key": public_key_pem,
            "client_server_url": client_server_url
        }
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return response.json().get("status") == "registered"

    def get_public_key(self, client_id: str) -> str:
        url = f"{self.relay_url}/public-key/{client_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 404:
            raise ValueError(f"Public key for '{client_id}' not found on central server.")
        response.raise_for_status()
        return response.json().get("public_key")

    def get_client_info(self, client_id: str) -> dict:
        url = f"{self.relay_url}/client/{client_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def send_message_to_relay(self, sender_id: str, recipient_id: str, ciphertext: str, nonce: str, tag: str) -> bool:
        url = f"{self.relay_url}/message"
        payload = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag
        }
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return response.json().get("status") == "message_relayed"

    def get_messages_from_relay(self, client_id: str) -> list:
        url = f"{self.relay_url}/messages/{client_id}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json().get("messages", [])

    def push_direct_to_client_server(self, target_url: str, sender_id: str, recipient_id: str, ciphertext: str, nonce: str, tag: str) -> bool:
        url = f"{target_url.rstrip('/')}/receive"
        payload = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag
        }
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return response.json().get("status") == "received"
