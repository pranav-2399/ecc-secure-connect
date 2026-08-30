import sys
import os
import argparse
import time

# Ensure project directory is in Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.client_server import ClientServer

def main():
    parser = argparse.ArgumentParser(description="ECC Secure Key Exchange Client Server Instance")
    parser.add_argument("--client", type=str, default="Alice", help="Client ID (e.g. Alice, Bob)")
    parser.add_argument("--port", type=int, default=5001, help="Port for this Client Server instance (default: 5001)")
    parser.add_argument("--peer", type=str, default="Bob", help="Peer Client ID")
    parser.add_argument("--peer-port", type=int, default=5002, help="Port of peer Client Server instance (default: 5002)")
    parser.add_argument("--server", type=str, default="http://127.0.0.1:5000", help="Central Relay Server URL")
    parser.add_argument("--interval", type=int, default=5, help="Interval in seconds for periodic communication (default: 5)")
    parser.add_argument("--no-interval", action="store_true", help="Disable automatic interval messaging loop")
    args = parser.parse_args()

    CLIENT_ID = args.client
    PORT = args.port
    PEER_ID = args.peer
    PEER_PORT = args.peer_port
    RELAY_URL = args.server
    INTERVAL = args.interval
    RUN_INTERVAL = not args.no_interval

    print("=" * 70)
    print(f" Starting ECC E2EE Client Server Instance: {CLIENT_ID}")
    print(f" Listening Address: http://127.0.0.1:{PORT}")
    print(f" Central Relay Server: {RELAY_URL}")
    print(f" Peer Target: {PEER_ID} (http://127.0.0.1:{PEER_PORT})")
    print(f" Interval Messaging: {'Every ' + str(INTERVAL) + 's' if RUN_INTERVAL else 'Disabled'}")
    print("=" * 70)

    client_server = ClientServer(
        client_id=CLIENT_ID,
        host="127.0.0.1",
        port=PORT,
        peer_id=PEER_ID,
        peer_port=PEER_PORT,
        relay_url=RELAY_URL,
        interval=INTERVAL
    )

    # Start Flask server and interval loop thread
    client_server.start(run_interval_loop=RUN_INTERVAL)

    print("\nClient Server instance is active! Commands:")
    print("  handshake          - Trigger key exchange with peer")
    print("  send <message>     - Send encrypted AES-GCM message to peer")
    print("  status             - View session key status and received messages")
    print("  exit               - Stop client server instance")

    try:
        while True:
            cmd = input(f"\n[{CLIENT_ID} Server @ {PORT}]> ").strip()
            if not cmd:
                continue
            if cmd in ["exit", "quit"]:
                break
            elif cmd == "handshake":
                client_server.perform_key_exchange()
            elif cmd == "status":
                status = client_server.app.test_client().get('/status').get_json()
                print(f"Session Key Established: {status['session_key_established']}")
                print(f"Messages Sent: {status['sent_count']}")
                print(f"Messages Received ({len(status['received_messages'])}):")
                for m in status['received_messages']:
                    print(f"   [{m['timestamp']}] From {m['sender_id']}: {m.get('plaintext', m.get('error'))}")
            elif cmd.startswith("send "):
                msg = cmd[5:]
                client_server.send_encrypted_message(msg)
            else:
                print("Unknown command. Options: handshake, send <msg>, status, exit")
    except KeyboardInterrupt:
        pass
    finally:
        client_server.stop()
        print("Client Server shutdown cleanly.")

if __name__ == "__main__":
    main()
