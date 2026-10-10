# C++ ECC key exchange project

The cryptography and both interactive clients are C++. A small Flask application remains solely as an opaque communication relay for the laptop simulation; it stores public-key text and forwards encrypted packets without performing cryptographic operations.

## Source layout

| Path | Purpose |
|---|---|
| `host/src/ecc.cpp` | Laptop P-256 math: secure private-scalar generation, curve point add/double, scalar multiplication, SEC1 encoding, ECDH |
| `host/src/aead.cpp` | HKDF-SHA256 and AES-256-GCM for laptop simulation |
| `host/src/simulation.cpp` | Runs Alice and Bob in one process and simulates exchanging public keys through an in-memory relay |
| `host/src/client.cpp`, `host/src/transport.cpp` | Interactive C++ clients and replaceable communication transport (currently HTTP to Flask) |
| `communication/communication_server.py` | Communication-only Flask relay; stores public-key strings and forwards opaque encrypted packets |
| `esp32/main/crypto.cpp` | ESP-IDF version of the crypto modules, using mbedTLS MPI and RNG while keeping point arithmetic explicit |
| `esp32/main/crypto_demo.cpp` | On-device self-test for key generation, ECDH, HKDF, AES-GCM, and tag rejection |

Both C++ versions use the P-256 curve, 65-byte SEC1 uncompressed public points, HKDF-SHA256 context `ecc-secure-key-exchange/v1|ECDH-P256|HKDF-SHA256|AES-256-GCM`, AES-256-GCM, a 12-byte nonce, and a 16-byte tag. The Flask relay does no key generation, parsing, ECDH, key derivation, encryption, or decryption.

## What the program does internally

1. **Generate a private key.** The cryptographic random generator produces 32 bytes. Rejection sampling accepts only a scalar `d` where `1 <= d < n`; `n` is the P-256 base-point order. The private scalar remains local.
2. **Compute the public key.** P-256 uses the field prime `p` and curve equation `y² = x³ - 3x + b (mod p)`. The code initializes the published generator point `G` and computes `Q = dG`. It implements affine point addition and doubling, then uses double-and-add scalar multiplication. The point is checked against the curve before it is used.
3. **Encode the public key.** The point is sent as `04 || X || Y`, where each coordinate is 32 bytes. The private scalar is never sent.
4. **Exchange public points.** In the laptop application, each C++ client registers its encoded public point with Flask and fetches the peer point. Flask stores and returns the strings without interpreting their cryptographic meaning. The ESP32 self-test creates two local simulated peers; replacing the HTTP transport with serial is a later transport change.
5. **Derive the ECDH secret.** Each side multiplies its private scalar by the peer's validated public point. Both sides get the same 32-byte x-coordinate. The host implementation does this with its explicit point arithmetic; the firmware calls mbedTLS ECDH using the same P-256 values.
6. **Derive the AES key.** HKDF-SHA256 derives a 32-byte key using the shared protocol context. Both sides must use the same context and salt policy.
7. **Encrypt and authenticate.** AES-256-GCM encrypts the message with a fresh 12-byte nonce and produces a 16-byte authentication tag. Decryption verifies the tag before accepting plaintext.
8. **Check tampering.** The simulator and ESP32 self-test alter the tag and verify that authenticated decryption rejects the packet.

## Run the laptop crypto simulation

### Requirements

- A C++17 compiler, such as `g++`
- CMake 3.16 or later
- OpenSSL development libraries
- libcurl development files (used by the interactive C++ HTTP transport)
- Boost headers with Multiprecision (header-only)

On Debian or Ubuntu, install the dependencies with:

```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev libcurl4-openssl-dev libboost-dev
```

From the repository folder:

```bash
cd host
cmake -S . -B build
cmake --build build -j
./build/ecc_simulator
```

Expected output includes passing fixed `1G`/`2G` P-256 point tests, generated keypairs, public point exchange, matching ECDH and HKDF keys, a successful AES-GCM round trip, rejection of a modified tag, and `Simulation passed.` This standalone crypto test models relay forwarding in memory. To run separate interactive clients through the Flask relay, use the next section.

## Run Alice and Bob through the Flask relay

The Flask service is only a public-key directory and message queue. All private keys, ECDH, HKDF, and AES-GCM operations run in the C++ clients.

### 1. Start the relay

In terminal 1, from the project folder:

```bash
cd communication
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python communication_server.py --host 127.0.0.1 --port 5000
```

On Windows, activate the environment with `.venv\\Scripts\\activate` before installing Flask.

### 2. Build the C++ clients

In terminal 2, from the project folder:

```bash
cd host
cmake -S . -B build
cmake --build build -j
```

### 3. Start both C++ clients

In terminal 2, launch Alice:

```bash
./build/ecc_client Alice Bob http://127.0.0.1:5000
```

In terminal 3, from the project folder, launch Bob:

```bash
cd host
./build/ecc_client Bob Alice http://127.0.0.1:5000
```

Each client generates a fresh P-256 pair, registers only its public point, waits for the peer, validates the retrieved point, and derives the session key locally. Type a message in either client to send it. Use `/quit` to end that client. The relay queue lives in memory and is cleared when the server restarts.

### Run the automated two-client check

After installing the communication server's Flask requirement as above, from the project folder run:

```bash
PYTHON_BIN=communication/.venv/bin/python communication/run_local_smoke_test.sh
```

The script builds both C++ executables, starts the relay on loopback, launches Alice and Bob as separate processes, sends a message in both directions, checks that each is decrypted by the other client, and then shuts down the relay. If Flask is installed in your system Python, `PYTHON_BIN=python3` also works.

## Build and run the ESP32 self-test

### Requirements

- ESP-IDF installed and exported in the current terminal (`IDF_PATH` set)
- An ESP32-family board supported by that ESP-IDF release
- USB data cable and the board's serial device/COM port

From the repository folder, first build for the original ESP32 target:

```bash
cd esp32
idf.py set-target esp32
idf.py build
```

Connect the board, then flash and open its serial monitor (replace the port with the one for your machine):

```bash
idf.py -p /dev/ttyUSB0 flash monitor
```

On Linux the port may instead be `/dev/ttyACM0`; on Windows use the assigned `COM` port. The firmware runs the same crypto self-test on the device and prints public points plus pass/fail status. It does not print private scalars, shared secrets, or AES keys.

For another target, set it explicitly before building, for example:

```bash
idf.py set-target esp32c3
idf.py build
```

### What to verify on the board

- The printed SEC1 public points each represent 65 bytes and begin with `04` when hex encoded.
- The two ECDH computations match.
- HKDF derives identical 32-byte keys on both sides.
- AES-GCM decrypts the original message.
- Changing one tag byte causes authentication failure.

## What is implemented and what remains

- The laptop crypto simulation runs the crypto exchange in C++.
- Separate laptop C++ clients exchange public keys and encrypted messages through the Flask communication relay.
- The ESP32 firmware runs a complete crypto self-test in C++ on one board. ESP32 Wi-Fi/serial transport and persistent identity key storage are not implemented. The C++ transport is separated so it can be replaced with serial when the ESP32 is ready. Active key substitution remains possible because clients trust the public key returned by the relay.

## Security note

The point formulas are written explicitly to show how `Q = dG` is computed. They use affine coordinates and variable-time operations, so execution time can depend on the private scalar. Treat this implementation as a learning and project demonstration, not as production cryptography. For deployed devices, replace custom scalar multiplication with the audited constant-time ECC operations in mbedTLS while preserving the module interfaces and wire format.
