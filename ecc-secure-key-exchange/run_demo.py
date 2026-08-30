#!/usr/bin/env python3
"""
Review 1 — Final Architecture Demonstration Script (Multi-Server Interval Edition)
Demonstrates:
1. Central Relay Server (Port 5000) startup
2. Two Client Server Instances: Client Server A (Alice, Port 5001) and Client Server B (Bob, Port 5002)
3. Public Key Registration & ECDH/HKDF Key Exchange across Client Server instances
4. Automated Interval-Based End-to-End Encrypted Messaging (AES-256-GCM)
5. Active Tampering Rejection on Client Server B
"""

import sys
import os
import time
import hashlib
import threading

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from server.app import create_app as create_relay_app
from server.relay import relay
from client.client_server import ClientServer
from werkzeug.serving import make_server

def print_header(title):
    print("\n" + "=" * 75)
    print(f"  {title}")
    print("=" * 75)

def main():
    print_header("REVIEW 1: MULTI-SERVER ARCHITECTURE WITH INTERVAL-BASED E2EE MESSAGING")

    relay.clear()

    # 1. Start Central Relay Server on port 5000
    print_header("STEP 1 — Central Relay Server Startup (Port 5000)")
    relay_app = create_relay_app()
    relay_server = make_server("127.0.0.1", 5000, relay_app)
    relay_thread = threading.Thread(target=relay_server.serve_forever, daemon=True)
    relay_thread.start()
    print("Central Relay Server active at http://127.0.0.1:5000 ✓")
    print("[Role]: Manages client registrations, public key directory, and zero-knowledge packet relay.")

    # 2. Instantiate and Start Client Server A (Alice, Port 5001) and Client Server B (Bob, Port 5002)
    print_header("STEP 2 — Launching Client Server Instances (Alice @ 5001, Bob @ 5002)")
    
    alice_server = ClientServer(
        client_id="Alice",
        port=5001,
        peer_id="Bob",
        peer_port=5002,
        relay_url="http://127.0.0.1:5000",
        interval=3
    )

    bob_server = ClientServer(
        client_id="Bob",
        port=5002,
        peer_id="Alice",
        peer_port=5001,
        relay_url="http://127.0.0.1:5000",
        interval=3
    )

    try:
        # Start both client servers
        alice_server.start(run_interval_loop=False)  # We will manually trigger interval loop
        bob_server.start(run_interval_loop=False)
        time.sleep(1)

        print("Client Server A (Alice) listening at http://127.0.0.1:5001 ✓")
        print("Client Server B (Bob)   listening at http://127.0.0.1:5002 ✓")

        # 3. Perform Key Exchange between Client Servers
        print_header("STEP 3 — Public Key Registration & Key Exchange (ECDH + HKDF)")
        
        alice_key = alice_server.perform_key_exchange()
        bob_key = bob_server.perform_key_exchange()

        print(f"Alice Session Key Derived: {alice_key.hex()[:16]}...")
        print(f"Bob   Session Key Derived: {bob_key.hex()[:16]}...")

        if alice_key == bob_key:
            print("SUCCESS: Both Client Servers established identical 256-bit Session Key ✓")
        else:
            print("FAILURE: Session Key Mismatch ❌")
            sys.exit(1)

        # 4. Demonstrate Automated Interval Messaging
        print_header("STEP 4 — Automated Interval-Based Encrypted Messaging (3s interval)")

        print("Starting interval messaging threads on Alice and Bob Client Servers...")
        alice_server.interval_thread = threading.Thread(target=alice_server._interval_loop, daemon=True)
        bob_server.interval_thread = threading.Thread(target=bob_server._interval_loop, daemon=True)
        
        alice_server.interval_thread.start()
        bob_server.interval_thread.start()

        # Let it communicate over 2 intervals (approx 7 seconds)
        print("Observing interval communication for 7 seconds...\n")
        time.sleep(7)

        print("\n--- Client Server Status Check ---")
        alice_status = alice_server.app.test_client().get('/status').get_json()
        bob_status = bob_server.app.test_client().get('/status').get_json()

        print(f"Client Server A (Alice) - Sent: {alice_status['sent_count']} packets | Received: {len(alice_status['received_messages'])} packets")
        print(f"Client Server B (Bob)   - Sent: {bob_status['sent_count']} packets | Received: {len(bob_status['received_messages'])} packets")

        if len(bob_status['received_messages']) > 0:
            latest_msg = bob_status['received_messages'][-1]
            print(f"Bob's Latest Received Message: \"{latest_msg.get('plaintext')}\" ✓")

        # 5. Active Tampering Demonstration
        print_header("STEP 5 — Active Ciphertext Tampering & Rejection on Client Server B")

        print("Sending tampered encrypted packet directly to Client Server B (http://127.0.0.1:5002/receive)...")
        normal_packet = alice_server.send_encrypted_message("Critical Security Alert")

        ct_bytes = bytearray(bytes.fromhex(normal_packet["ciphertext"]))
        ct_bytes[0] ^= 0xFF  # Corrupt first byte
        tampered_ct = ct_bytes.hex()

        print(f"  Original Ciphertext: {normal_packet['ciphertext'][:30]}...")
        print(f"  Tampered Ciphertext: {tampered_ct[:30]}...")

        # Push to Bob
        success, err = bob_server._process_incoming_packet(
            sender_id="Alice",
            ciphertext=tampered_ct,
            nonce=normal_packet["nonce"],
            tag=normal_packet["tag"]
        )

        if not success:
            print(f"  Client Server B Reaction: {err}")
            print("  Message rejected & authentication failed ✓")
        else:
            print("FAILURE: Tampered message was incorrectly accepted ❌")
            sys.exit(1)

        # 6. Information Exposure Matrix
        print_header("ARCHITECTURE MATRIX — ZERO-KNOWLEDGE SERVER RELAY")
        print(f"{'Component':<20} | {'Client Server A':<15} | {'Central Relay':<15} | {'Client Server B':<15}")
        print("-" * 75)
        print(f"{'HTTP Listening Port':<20} | {'5001':<15} | {'5000':<15} | {'5002':<15}")
        print(f"{'ECC Private Key':<20} | {'KEPT LOCAL':<15} | {'NEVER EXPOSED':<15} | {'KEPT LOCAL':<15}")
        print(f"{'AES Session Key':<20} | {'LOCAL DERIVED':<15} | {'NO ACCESS':<15} | {'LOCAL DERIVED':<15}")
        print(f"{'Plaintext Payload':<20} | {'LOCAL ORIGIN':<15} | {'NO ACCESS':<15} | {'LOCAL DECRYPTED':<15}")
        print(f"{'Ciphertext Relay':<20} | {'SENT VIA HTTP':<15} | {'RELAYED ONLY':<15} | {'RCVD VIA HTTP':<15}")
        print("-" * 75)

        print("\nMulti-Server Interval Architecture Demonstration Complete! 🎉\n")

    finally:
        alice_server.stop()
        bob_server.stop()
        relay_server.shutdown()

if __name__ == "__main__":
    main()
