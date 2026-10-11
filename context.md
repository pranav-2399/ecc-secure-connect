# C++ ECC key exchange project

The cryptography and both interactive clients are C++. A small Flask application remains solely as an opaque communication relay. In the laptop-to-ESP32 setup, the relay runs on the laptop and both clients reach it over the same Wi-Fi LAN; USB is reserved for the ESP32 serial console.

## Source layout

| Path | Purpose |
|---|---|
| `host/src/ecc.cpp` | Laptop P-256 math: secure private-scalar generation, curve point add/double, scalar multiplication, SEC1 encoding, ECDH |
| `host/src/aead.cpp` | HKDF-SHA256 and AES-256-GCM for laptop simulation |
| `host/src/simulation.cpp` | Runs Alice and Bob in one process and simulates exchanging public keys through an in-memory relay |
| `host/src/client.cpp`, `host/src/transport.cpp` | Interactive C++ clients and replaceable communication transport (currently HTTP to Flask) |
| `communication/communication_server.py` | Communication-only Flask relay; stores public-key strings and forwards opaque encrypted packets |
| `esp32/main/crypto.cpp` | ESP-IDF version of the crypto modules, using mbedTLS MPI and RNG while keeping point arithmetic explicit |
| `esp32/main/secure_chat.cpp` | ESP32 Wi-Fi client, key exchange, encrypted message loop, and interactive USB serial console |
| `esp32/main/relay_client.cpp` | ESP-IDF HTTP adapter for the relay's existing REST endpoints |

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

## Run the laptop-to-ESP32 chat

### Requirements

- ESP-IDF installed and exported in the current terminal (`IDF_PATH` set)
- Original ESP32 board with Wi-Fi (the pictured ESP32-WROOM-based board is suitable)
- Laptop and ESP32 connected to the same 2.4 GHz Wi-Fi network
- USB data cable; USB carries firmware/logs/input, while Wi-Fi carries relay traffic
- A non-space copy of this project path for ESP-IDF (ESP-IDF does not support spaces in project paths)

The Flask relay runs only on the laptop. The ESP32 connects to it over Wi-Fi; no separate Bluetooth module or USB-UART adapter is used. Use three laptop terminals: relay server, ESP32 serial monitor, and laptop client. The monitor and client can run separately because the messages travel over Wi-Fi, not through the monitor's serial port.

### 1. Sync the updated source into the no-space build copy

If using the build copy under `~/projects`, sync source changes from the workspace copy while preserving its generated build and local configuration files:

```bash
rsync -a --exclude='.git/' --exclude='esp32/build/' --exclude='host/build/' \
  --exclude='communication/.venv/' \
  "/home/pranav-anandan/Documents/Pranav College/Semester 5 - Fall 2026-2027/7 ES/project/" \
  ~/projects/ecc-secure-key-exchange/
```

### 2. Find the laptop's Wi-Fi IPv4 address

Run `hostname -I` on the laptop and select its IPv4 address on the same Wi-Fi network as the ESP32. Do not use `127.0.0.1` for the ESP32 relay address; that address would refer to the ESP32 itself.

### 3. Start the relay (terminal 1)

```bash
cd ~/projects/ecc-secure-key-exchange/communication
source .venv/bin/activate
python communication_server.py --host 0.0.0.0 --port 5000
```

The laptop client can still use `127.0.0.1`; the ESP32 must use the laptop's Wi-Fi IPv4 address. Keep the laptop on the same network while chatting.

### 4. Configure, build, flash, and monitor the ESP32 (terminal 2)

```bash
cd ~/projects/ecc-secure-key-exchange/esp32
. ~/esp/esp-idf/export.sh
idf.py set-target esp32
idf.py menuconfig
```

if new terminal:
groups \\to check if dialout is there
newgrp dialout


In **ECC Secure Chat**, enter the 2.4 GHz Wi-Fi SSID/password and the laptop IPv4 address; keep port `5000`, ESP32 ID `ESP32`, and peer ID `Laptop` unless you also change the laptop client IDs. In **Component config → mbedTLS**, ensure HKDF is enabled. Under **Serial flasher config**, set flash size to **4 MB**; under **Partition Table**, select **Single factory app (large), no OTA**. The standard 1 MB app partition is too small for this Wi-Fi build; the large single-app table allocates 1.5 MB and fits it. Save and exit.

Then build and flash using the persistent serial path (adjust it if your device path differs):

```bash
idf.py build
idf.py -p /dev/serial/by-id/usb-1a86_USB_Single_Serial_5A7B056860-if00 flash monitor
```

If this terminal does not have serial-device permission, start a new shell with `newgrp dialout` first, then run the flash command there. The firmware runs Wi-Fi, ECC and chat setup in a dedicated 16 KB FreeRTOS task to avoid overflowing ESP-IDF's small default `main` task stack.

The monitor prints Wi-Fi connection status, key registration, and session status. It also serves as the ESP32 client's terminal: type a message and press Enter. Use `/quit` to end the session. The device generates a fresh P-256 keypair on each boot, registers only the public point, validates the laptop's point, and derives the session key locally.

### 5. Start the laptop client (terminal 3)

```bash
cd ~/projects/ecc-secure-key-exchange/host
cmake -S . -B build
cmake --build build -j
./build/ecc_client Laptop ESP32 http://127.0.0.1:5000
```

Once both clients report that the ECDH/HKDF session is established, type messages in either terminal. The relay forwards only public-key text and opaque nonce/tag/ciphertext fields. The ESP32 serial monitor and the laptop client each display their own received plaintext. Messages are limited to 512 bytes on the ESP32.

Stop the clients with `/quit`, the monitor with `Ctrl+]`, and the relay with `Ctrl+C`. If the ESP32 cannot reach the relay, confirm both devices are on the same LAN and that the laptop firewall permits TCP port 5000 on that network.

### Manual end-to-end checks

- Both clients display successful session establishment after exchanging public keys.
- Send a message laptop-to-ESP32 and another ESP32-to-laptop; each receiver should show the original plaintext.
- Restart the ESP32 or laptop client to generate a new keypair and establish a new session.
- Confirm the server terminal shows HTTP traffic only; it must not receive plaintext, private scalars, ECDH secrets, or AES session keys.

## What is implemented and what remains

- The laptop crypto simulation runs the crypto exchange in C++.
- Separate laptop C++ clients exchange public keys and encrypted messages through the Flask communication relay.
- The ESP32 firmware exchanges public keys and AES-GCM packets with the laptop C++ client through the Flask relay over Wi-Fi, while USB serial provides a separate interactive console.
- The ESP32 creates ephemeral keys per boot; persistent identity keys, authenticated peer identity, server TLS, retransmission/session recovery, and production-grade constant-time ECC are not implemented. Active key substitution remains possible because clients trust the public key returned by the relay.

## Security note

The point formulas are written explicitly to show how `Q = dG` is computed. They use affine coordinates and variable-time operations, so execution time can depend on the private scalar. Treat this implementation as a learning and project demonstration, not as production cryptography. For deployed devices, replace custom scalar multiplication with the audited constant-time ECC operations in mbedTLS while preserving the module interfaces and wire format.


. ~/esp/esp-idf/export.sh
rsync -a --exclude='.git/' --exclude='esp32/build/' --exclude='host/build/' \
  --exclude='communication/.venv/' \
  "/home/pranav-anandan/Documents/Pranav College/Semester 5 - Fall 2026-2027/7 ES/project/" \
  ~/projects/ecc-secure-key-exchange/
cd ~/projects/ecc-secure-key-exchange/esp32
idf.py build
