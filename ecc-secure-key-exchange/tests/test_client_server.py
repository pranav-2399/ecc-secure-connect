import sys
import os
import time
import threading
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.app import create_app as create_relay_app
from server.relay import relay
from client.client_server import ClientServer
from werkzeug.serving import make_server

@pytest.fixture(scope="module", autouse=True)
def setup_central_relay():
    relay.clear()
    relay_app = create_relay_app()
    relay_server = make_server("127.0.0.1", 5000, relay_app)
    relay_thread = threading.Thread(target=relay_server.serve_forever, daemon=True)
    relay_thread.start()
    time.sleep(0.5)
    yield
    relay_server.shutdown()

def test_client_server_instance_key_exchange_and_interval():
    relay.clear()

    alice_server = ClientServer(
        client_id="Alice",
        port=5091,
        peer_id="Bob",
        peer_port=5092,
        relay_url="http://127.0.0.1:5000",
        interval=1
    )
    
    bob_server = ClientServer(
        client_id="Bob",
        port=5092,
        peer_id="Alice",
        peer_port=5091,
        relay_url="http://127.0.0.1:5000",
        interval=1
    )

    try:
        # Start both client servers (without auto interval loop for controlled test)
        alice_server.start(run_interval_loop=False)
        bob_server.start(run_interval_loop=False)

        time.sleep(0.5)

        # Verify key exchange
        alice_key = alice_server.perform_key_exchange()
        bob_key = bob_server.perform_key_exchange()

        assert alice_key == bob_key
        assert len(alice_key) == 32

        # Send encrypted message from Alice to Bob (will push to Bob's http://127.0.0.1:5092/receive)
        packet = alice_server.send_encrypted_message("Interval test payload")

        assert "ciphertext" in packet
        assert "nonce" in packet
        assert "tag" in packet

        # Give small moment for HTTP push
        time.sleep(0.3)

        assert len(bob_server.received_messages) >= 1
        assert bob_server.received_messages[0]["plaintext"] == "Interval test payload"
        assert bob_server.received_messages[0]["status"] == "VALIDATED_DECRYPTED"

    finally:
        alice_server.stop()
        bob_server.stop()

def test_client_server_tampered_packet_rejection():
    relay.clear()

    alice_server = ClientServer(
        client_id="Alice",
        port=5093,
        peer_id="Bob",
        peer_port=5094,
        relay_url="http://127.0.0.1:5000"
    )
    bob_server = ClientServer(
        client_id="Bob",
        port=5094,
        peer_id="Alice",
        peer_port=5093,
        relay_url="http://127.0.0.1:5000"
    )

    try:
        alice_server.start(run_interval_loop=False)
        bob_server.start(run_interval_loop=False)

        alice_server.perform_key_exchange()
        bob_server.perform_key_exchange()

        packet = alice_server.send_encrypted_message("Confidential transaction")

        # Corrupt 1 byte in ciphertext
        ct_bytes = bytearray(bytes.fromhex(packet["ciphertext"]))
        ct_bytes[0] ^= 0xFF
        tampered_ciphertext = ct_bytes.hex()

        success, err_msg = bob_server._process_incoming_packet(
            sender_id="Alice",
            ciphertext=tampered_ciphertext,
            nonce=packet["nonce"],
            tag=packet["tag"]
        )

        assert success is False
        assert "authentication failed" in err_msg.lower()

    finally:
        alice_server.stop()
        bob_server.stop()
