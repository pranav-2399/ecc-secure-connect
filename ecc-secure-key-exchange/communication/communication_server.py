"""Communication-only Flask relay. It stores opaque keys and encrypted packets."""

from collections import defaultdict, deque
from threading import Lock

from flask import Flask, Response, abort, request


def create_app():
    app = Flask(__name__)
    public_keys = {}
    inboxes = defaultdict(deque)
    state_lock = Lock()

    @app.get("/health")
    def health():
        return "ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.post("/register/<client_id>")
    def register(client_id):
        key = request.get_data(as_text=True).strip()
        if not key:
            abort(400, "public key body is required")
        with state_lock:
            public_keys[client_id] = key
        return "registered\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.get("/public-key/<client_id>")
    def get_public_key(client_id):
        with state_lock:
            key = public_keys.get(client_id)
        if key is None:
            abort(404, "client has not registered")
        return key + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.post("/message/<sender_id>/<recipient_id>")
    def post_message(sender_id, recipient_id):
        # Payload fields are opaque to the relay: nonce, tag, ciphertext (hex), one per line.
        fields = request.get_data(as_text=True).splitlines()
        if len(fields) != 3:
            abort(400, "expected nonce, tag, and ciphertext fields")
        nonce, tag, ciphertext = fields
        with state_lock:
            inboxes[recipient_id].append((sender_id, nonce, tag, ciphertext))
        return "queued\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.get("/messages/<client_id>")
    def get_messages(client_id):
        with state_lock:
            messages = list(inboxes[client_id])
            inboxes[client_id].clear()
        if not messages:
            return Response(status=204)
        body = "".join("\t".join(message) + "\n" for message in messages)
        return body, 200, {"Content-Type": "text/plain; charset=utf-8"}

    return app


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Opaque communication relay for C++ clients")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, debug=False, threaded=True)
