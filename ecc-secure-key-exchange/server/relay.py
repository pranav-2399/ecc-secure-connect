class RelayState:
    """
    Maintains in-memory relay communication state for clients, public keys,
    client server endpoint URLs, and pending encrypted message queues.
    
    IMPORTANT: The server strictly performs relay functions and stores raw strings/payloads.
    It does NOT perform cryptographic operations, key derivation, or decryption.
    """
    def __init__(self):
        self.registered_clients = set()
        self.public_keys = {}  # client_id -> public_key_pem
        self.client_urls = {}  # client_id -> client_server_url
        self.pending_messages = {}  # recipient_id -> list of message dicts

    def register_client(self, client_id: str, public_key_pem: str, client_server_url: str = None):
        self.registered_clients.add(client_id)
        if public_key_pem:
            self.public_keys[client_id] = public_key_pem
        if client_server_url:
            self.client_urls[client_id] = client_server_url
        if client_id not in self.pending_messages:
            self.pending_messages[client_id] = []

    def set_public_key(self, client_id: str, public_key_pem: str):
        self.registered_clients.add(client_id)
        self.public_keys[client_id] = public_key_pem

    def get_public_key(self, client_id: str):
        return self.public_keys.get(client_id)

    def get_client_url(self, client_id: str):
        return self.client_urls.get(client_id)

    def get_client_info(self, client_id: str):
        if client_id not in self.registered_clients:
            return None
        return {
            "client_id": client_id,
            "public_key": self.public_keys.get(client_id),
            "client_server_url": self.client_urls.get(client_id)
        }

    def store_message(self, sender_id: str, recipient_id: str, ciphertext: str, nonce: str, tag: str):
        message_packet = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag
        }
        if recipient_id not in self.pending_messages:
            self.pending_messages[recipient_id] = []
        self.pending_messages[recipient_id].append(message_packet)

    def retrieve_messages(self, client_id: str):
        messages = self.pending_messages.get(client_id, [])
        self.pending_messages[client_id] = []
        return messages

    def clear(self):
        """Clears all state (useful for tests and resetting relay)"""
        self.registered_clients.clear()
        self.public_keys.clear()
        self.client_urls.clear()
        self.pending_messages.clear()

# Global singleton relay state instance
relay = RelayState()
