import time
import threading
from datetime import datetime
from flask import Flask, request, jsonify
from werkzeug.serving import make_server

from client.crypto.ecc import generate_key_pair, serialize_public_key, deserialize_public_key
from client.crypto.ecdh import derive_shared_secret
from client.crypto.hkdf import derive_session_key
from client.crypto.aes import encrypt, decrypt
from client.network.api import ServerAPI

class ClientServer:
    """
    A Client Server Instance running its own HTTP server on a dedicated port.
    Combines local ECC/ECDH/HKDF/AES-GCM cryptography with an interval-based
    messaging thread that periodically communicates encrypted data with a peer client server.
    """
    def __init__(self, client_id: str, host: str = "127.0.0.1", port: int = 5001,
                 peer_id: str = "Bob", peer_port: int = 5002,
                 relay_url: str = "http://127.0.0.1:5000", interval: int = 5):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.client_server_url = f"http://{host}:{port}"
        
        self.peer_id = peer_id
        self.peer_port = peer_port
        self.peer_server_url = f"http://{host}:{peer_port}"
        
        self.relay_url = relay_url
        self.interval = interval
        
        # Network API client
        self.api = ServerAPI(relay_url)
        
        # Local cryptographic keys
        self.private_key, self.public_key = generate_key_pair()
        self.public_key_pem = serialize_public_key(self.public_key)
        
        # Session state
        self.peer_public_key = None
        self.session_key = None
        self.received_messages = []
        self.sent_messages_count = 0
        
        # Threading & Flask server state
        self.app = Flask(f"ClientServer_{client_id}")
        self._setup_routes()
        self.server_thread = None
        self.interval_thread = None
        self.running = False
        self.server_obj = None

    def _setup_routes(self):
        @self.app.route('/info', methods=['GET'])
        def get_info():
            return jsonify({
                "client_id": self.client_id,
                "client_server_url": self.client_server_url,
                "peer_id": self.peer_id,
                "peer_server_url": self.peer_server_url,
                "has_session_key": self.session_key is not None,
                "public_key": self.public_key_pem
            }), 200

        @self.app.route('/receive', methods=['POST'])
        def receive_encrypted_packet():
            data = request.get_json() or {}
            sender_id = data.get("sender_id")
            ciphertext = data.get("ciphertext")
            nonce = data.get("nonce")
            tag = data.get("tag")

            if not all([sender_id, ciphertext, nonce, tag]):
                return jsonify({"error": "Missing required encrypted packet fields"}), 400

            success, msg_or_err = self._process_incoming_packet(sender_id, ciphertext, nonce, tag)
            if success:
                return jsonify({"status": "received", "decrypted_message": msg_or_err}), 200
            else:
                return jsonify({"status": "rejected", "error": msg_or_err}), 400

        @self.app.route('/handshake', methods=['POST'])
        def trigger_handshake():
            try:
                session_key = self.perform_key_exchange()
                return jsonify({"status": "handshake_complete", "session_key_derived": session_key is not None}), 200
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route('/send', methods=['POST'])
        def send_manual_message():
            data = request.get_json() or {}
            message = data.get("message", "Manual test message")
            try:
                packet = self.send_encrypted_message(message)
                return jsonify({"status": "sent", "packet": packet}), 200
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route('/status', methods=['GET'])
        def get_status():
            return jsonify({
                "client_id": self.client_id,
                "session_key_established": self.session_key is not None,
                "sent_count": self.sent_messages_count,
                "received_messages": self.received_messages
            }), 200

    def register_with_relay(self):
        """Registers Client Server identity, public key, and server URL with Central Relay Server."""
        print(f"[{self.client_id} Server @ {self.port}] Registering with Central Relay Server ({self.relay_url})...")
        success = self.api.register(self.client_id, self.public_key_pem, self.client_server_url)
        if success:
            print(f"[{self.client_id} Server @ {self.port}] Registered successfully!")
        return success

    def perform_key_exchange(self):
        """
        Fetches peer's public key from Central Relay Server and computes:
        1. ECDH Shared Secret
        2. HKDF 256-bit Session Key
        """
        print(f"[{self.client_id} Server] Initiating Key Exchange for peer '{self.peer_id}'...")
        peer_pem = self.api.get_public_key(self.peer_id)
        self.peer_public_key = deserialize_public_key(peer_pem)
        
        # Derive ECDH shared secret
        shared_secret = derive_shared_secret(self.private_key, self.peer_public_key)
        
        # Derive HKDF 256-bit session key
        self.session_key = derive_session_key(shared_secret)
        
        print(f"[{self.client_id} Server] Key Exchange complete! Derived 256-bit AES Session Key with '{self.peer_id}' ✓")
        return self.session_key

    def send_encrypted_message(self, plaintext: str) -> dict:
        """Encrypts message using local session key and relays it to peer."""
        if not self.session_key:
            self.perform_key_exchange()

        encrypted_packet = encrypt(plaintext, self.session_key)
        self.sent_messages_count += 1

        print(f"[{self.client_id} Server -> {self.peer_id}] Sending encrypted message #{self.sent_messages_count}: \"{plaintext}\"")
        print(f"   Ciphertext: {encrypted_packet['ciphertext'][:30]}...")

        # 1. Store on central relay server
        self.api.send_message_to_relay(
            sender_id=self.client_id,
            recipient_id=self.peer_id,
            ciphertext=encrypted_packet["ciphertext"],
            nonce=encrypted_packet["nonce"],
            tag=encrypted_packet["tag"]
        )

        # 2. Try direct push to peer client server endpoint if accessible
        try:
            peer_info = self.api.get_client_info(self.peer_id)
            target_url = peer_info.get("client_server_url") if peer_info else self.peer_server_url
            if target_url:
                self.api.push_direct_to_client_server(
                    target_url,
                    sender_id=self.client_id,
                    recipient_id=self.peer_id,
                    ciphertext=encrypted_packet["ciphertext"],
                    nonce=encrypted_packet["nonce"],
                    tag=encrypted_packet["tag"]
                )
        except Exception:
            pass  # Peer will fetch via central relay server during polling if push unavailable

        return encrypted_packet

    def _process_incoming_packet(self, sender_id: str, ciphertext: str, nonce: str, tag: str):
        if not self.session_key:
            try:
                self.perform_key_exchange()
            except Exception as e:
                return False, f"Key exchange required: {e}"

        try:
            plaintext = decrypt(ciphertext, nonce, tag, self.session_key)
            record = {
                "timestamp": datetime.now().isoformat(),
                "sender_id": sender_id,
                "plaintext": plaintext,
                "status": "VALIDATED_DECRYPTED"
            }
            self.received_messages.append(record)
            print(f"[{self.client_id} Server] Received & Decrypted packet from '{sender_id}': \"{plaintext}\" ✓")
            return True, plaintext
        except ValueError as e:
            record = {
                "timestamp": datetime.now().isoformat(),
                "sender_id": sender_id,
                "error": str(e),
                "status": "AUTHENTICATION_FAILED"
            }
            self.received_messages.append(record)
            print(f"[{self.client_id} Server] ❌ TAMPERING DETECTED from '{sender_id}': {e}")
            return False, str(e)

    def check_and_decrypt_relay_messages(self):
        """Polls Central Relay Server for pending encrypted messages."""
        try:
            messages = self.api.get_messages_from_relay(self.client_id)
            for msg in messages:
                sender_id = msg["sender_id"]
                ct = msg["ciphertext"]
                nonce = msg["nonce"]
                tag = msg["tag"]
                self._process_incoming_packet(sender_id, ct, nonce, tag)
        except Exception:
            pass

    def _interval_loop(self):
        """Background thread executing periodic interval communication."""
        print(f"[{self.client_id} Server] Starting Interval Communication Loop (every {self.interval}s)...")
        time.sleep(2)  # Give startup time for peer
        
        while self.running:
            try:
                if not self.session_key:
                    try:
                        self.perform_key_exchange()
                    except Exception:
                        pass

                if self.session_key:
                    now_str = datetime.now().strftime("%H:%M:%S")
                    msg = f"Heartbeat payload #{self.sent_messages_count + 1} from {self.client_id} at {now_str}"
                    self.send_encrypted_message(msg)

                # Poll pending relay messages
                self.check_and_decrypt_relay_messages()

            except Exception as e:
                print(f"[{self.client_id} Server Interval Loop Error]: {e}")

            # Sleep for configured interval
            for _ in range(self.interval * 10):
                if not self.running:
                    break
                time.sleep(0.1)

    def start(self, run_interval_loop: bool = True):
        """Starts Flask Server instance and background interval messaging loop."""
        self.running = True
        
        # Werkzeug server in thread
        self.server_obj = make_server(self.host, self.port, self.app)
        self.server_thread = threading.Thread(target=self.server_obj.serve_forever, daemon=True)
        self.server_thread.start()
        print(f"[{self.client_id} Server Instance] Listening on http://{self.host}:{self.port}")

        # Register with Central Relay
        self.register_with_relay()

        # Start interval messaging loop if requested
        if run_interval_loop:
            self.interval_thread = threading.Thread(target=self._interval_loop, daemon=True)
            self.interval_thread.start()

    def stop(self):
        """Stops the Client Server instance and background loop."""
        self.running = False
        if self.server_obj:
            self.server_obj.shutdown()
        print(f"[{self.client_id} Server Instance] Stopped.")
