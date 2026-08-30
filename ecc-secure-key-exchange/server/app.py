import sys
import os

# Ensure parent directory is in python sys.path for direct execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify

try:
    from server.relay import relay
except ImportError:
    from relay import relay

def create_app():
    app = Flask(__name__)

    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({"status": "ok", "service": "Central Security Relay Server"}), 200

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json() or {}
        client_id = data.get("client_id")
        public_key = data.get("public_key")
        client_server_url = data.get("client_server_url")

        if not client_id:
            return jsonify({"error": "client_id is required"}), 400

        relay.register_client(client_id, public_key, client_server_url)
        return jsonify({
            "status": "registered",
            "client_id": client_id,
            "client_server_url": client_server_url
        }), 200

    @app.route('/public-key', methods=['POST'])
    def post_public_key():
        data = request.get_json() or {}
        client_id = data.get("client_id")
        public_key = data.get("public_key")

        if not client_id or not public_key:
            return jsonify({"error": "client_id and public_key are required"}), 400

        relay.set_public_key(client_id, public_key)
        return jsonify({"status": "public_key_updated", "client_id": client_id}), 200

    @app.route('/public-key/<client_id>', methods=['GET'])
    def get_public_key(client_id):
        pub_key = relay.get_public_key(client_id)
        if pub_key is None:
            return jsonify({"error": f"Public key for client '{client_id}' not found"}), 404
        return jsonify({"client_id": client_id, "public_key": pub_key}), 200

    @app.route('/client/<client_id>', methods=['GET'])
    def get_client_info(client_id):
        info = relay.get_client_info(client_id)
        if not info:
            return jsonify({"error": f"Client '{client_id}' not registered"}), 404
        return jsonify(info), 200

    @app.route('/message', methods=['POST'])
    def send_message():
        data = request.get_json() or {}
        sender_id = data.get("sender_id")
        recipient_id = data.get("recipient_id")
        ciphertext = data.get("ciphertext")
        nonce = data.get("nonce")
        tag = data.get("tag")

        if not all([sender_id, recipient_id, ciphertext, nonce, tag]):
            return jsonify({"error": "sender_id, recipient_id, ciphertext, nonce, and tag are required"}), 400

        relay.store_message(sender_id, recipient_id, ciphertext, nonce, tag)
        return jsonify({"status": "message_relayed", "recipient_id": recipient_id}), 200

    @app.route('/messages/<client_id>', methods=['GET'])
    def get_messages(client_id):
        messages = relay.retrieve_messages(client_id)
        return jsonify({"client_id": client_id, "messages": messages}), 200

    return app

def run_server(host="127.0.0.1", port=5000, debug=False):
    app = create_app()
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_server(debug=True)
