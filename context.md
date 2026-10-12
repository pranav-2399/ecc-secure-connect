# C++ ECC key exchange project

The cryptography and both interactive clients are C++. A small Flask application remains solely as an opaque communication relay. In the laptop-to-ESP32 setup, the relay runs on the laptop and both clients reach it over the same Wi-Fi LAN; USB is reserved for the ESP32 serial console.

## Source layout

| Path | Purpose |
|---|---|
| `host/src/ecc.cpp` | Laptop P-256 math: secure private-scalar generation, curve point add/double, scalar multiplication, SEC1 encoding, ECDH |
| `host/src/aead.cpp` | HKDF-SHA256 and AES-256-GCM for laptop simulation |
| `host/src/simulation.cpp` | Runs Alice and Bob in one process and simulates exchanging public keys through an in-memory relay |
| `host/src/client.cpp`, `host/src/transport.cpp` | Interactive C++ client, ATM PIN verification mode, and HTTP transport to Flask |
| `communication/communication_server.py` | Communication-only Flask relay; stores public-key strings and forwards opaque encrypted packets |
| `esp32/main/crypto.cpp` | ESP-IDF version of the crypto modules, using mbedTLS MPI and RNG while keeping point arithmetic explicit |
| `esp32/main/secure_chat.cpp` | ESP32 Wi-Fi key exchange, encrypted 4-8 digit PIN submission, and USB serial input/output |
| `esp32/main/relay_client.cpp` | ESP-IDF HTTP adapter for the relay's existing REST endpoints |

Both C++ versions use the P-256 curve, 65-byte SEC1 uncompressed public points, HKDF-SHA256 context `ecc-secure-key-exchange/v1|ECDH-P256|HKDF-SHA256|AES-256-GCM`, AES-256-GCM, a 12-byte nonce, and a 16-byte tag. The Flask relay does no key generation, parsing, ECDH, key derivation, encryption, or decryption.

## What the program does internally

1. **Generate a private key.** The cryptographic random generator produces 32 bytes. Rejection sampling accepts only a scalar `d` where `1 <= d < n`; `n` is the P-256 base-point order. The private scalar remains local.
2. **Compute the public key.** P-256 uses the field prime `p` and curve equation `y² = x³ - 3x + b (mod p)`. The code initializes the published generator point `G` and computes `Q = dG`. It implements affine point addition and doubling, then uses double-and-add scalar multiplication. The point is checked against the curve before it is used.
3. **Encode the public key.** The point is sent as `04 || X || Y`, where each coordinate is 32 bytes. The private scalar is never sent.
4. **Exchange public points.** Each C++ client, including the ESP32, registers its encoded public point with Flask and fetches the peer point over HTTP/Wi-Fi. Flask stores and returns the strings without interpreting their cryptographic meaning. USB serial is used for ESP32 console input/output, not for key exchange or message transport.
5. **Derive the ECDH secret.** Each side multiplies its private scalar by the peer's validated public point. Both sides get the same 32-byte x-coordinate. The host implementation does this with its explicit point arithmetic; the firmware calls mbedTLS ECDH using the same P-256 values.
6. **Derive the AES key.** HKDF-SHA256 derives a 32-byte key using the shared protocol context. Both sides must use the same context and salt policy.
7. **Encrypt and authenticate.** AES-256-GCM encrypts the message with a fresh 12-byte nonce and produces a 16-byte authentication tag. Decryption verifies the tag before accepting plaintext.
8. **Check tampering.** The simulator and ESP32 self-test alter the tag and verify that authenticated decryption rejects the packet.

## Mathematical walkthrough: P-256, ECDH, HKDF, and AES-GCM

This section follows the live C++ client order from fresh key pair to encrypted message. ECC and ECDH establish a secret; they do **not** directly encrypt the message. HKDF turns the ECDH result into a symmetric key, and AES-256-GCM performs the message encryption and authentication.

### 1. The finite field and P-256 curve

P-256 arithmetic uses two related moduli:

- The coordinate field is the finite field `F_p`, where `p` is the 256-bit prime
  `FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF`.
- The base point `G` has prime order `n`, where
  `n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`.
  Private scalars are taken modulo `n`.

The curve is the set of points `(x,y)` satisfying

```text
y² ≡ x³ + a·x + b (mod p)
a = p - 3
b = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
```

The point at infinity `O` is the identity for point addition: `P + O = P`. The fixed generator `G` is a distinguished point on this curve. The constants are standardized domain parameters; both clients must use the same parameters. The curve equation and group law are described in [RFC 6090](https://www.rfc-editor.org/rfc/rfc6090.html), and NIST lists recommended curve parameters in [SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final).

### 2. Generate a private scalar and public point

Each client obtains random candidate bytes from its cryptographic random generator and interprets them as an integer. Rejection sampling keeps drawing until the private scalar `d` satisfies

```text
1 ≤ d < n
```

This is a random integer in the scalar range. `d` must remain secret: if it is exposed, an attacker can compute the public point and the ECDH session secret.

The public key is the elliptic-curve scalar multiple

```text
Q = dG
```

Scalar multiplication means adding `G` to itself `d` times in the curve group. The implementation uses double-and-add: read the bits of `d`; conditionally add the current point into an accumulator for each set bit, and double the current point between bits. This reduces the work from `d` additions to a number of point operations proportional to the bit length of `d` (about 256 bits here).

For affine points `P=(x₁,y₁)` and `R=(x₂,y₂)`, the code computes sums modulo `p`. If `P ≠ R`, it uses

```text
λ = (y₂ - y₁) / (x₂ - x₁) mod p
x₃ = λ² - x₁ - x₂ mod p
y₃ = λ(x₁ - x₃) - y₁ mod p
```

For doubling `P = R` with `y₁ ≠ 0`, it uses

```text
λ = (3x₁² + a) / (2y₁) mod p
x₃ = λ² - 2x₁ mod p
y₃ = λ(x₁ - x₃) - y₁ mod p
```

Division modulo `p` means multiplication by a modular inverse: `u/v mod p = u·v⁻¹ mod p`. The host code obtains the inverse using Fermat's relation `v⁻¹ ≡ v^(p-2) mod p`; the ESP32 point arithmetic uses the mbedTLS MPI modular-inverse operation. Exceptional cases such as `P + O`, `P + (-P) = O`, and doubling a point with `y=0` are handled separately.

The map from `d` to `Q` is easy to compute, while recovering `d` from `Q` and `G` is the elliptic-curve discrete logarithm problem. That one-way property is what allows the public point to be sent while keeping the private scalar private. It does not by itself authenticate who owns a public point.

### 3. Encode and validate public points

For this protocol, a public point is serialized in SEC1 uncompressed form:

```text
04 || X || Y
```

`04` is the format marker; `X` and `Y` are each exactly 32-byte, big-endian field elements. The full point is therefore 65 bytes (130 hexadecimal characters when sent through the relay). The relay receives only this public encoding, never `d`.

On receipt, each client checks the encoding and verifies that the coordinates are in the allowed range and satisfy the selected curve equation. The ESP32 also calls the mbedTLS P-256 public-key check. Invalid encodings or points are rejected before ECDH. A valid point check prevents malformed inputs; it does not prove the point belongs to the intended person because this project has no certificate, signature, or trusted-key verification.

### 4. ECDH: both sides calculate the same curve point

Let User A have private scalar `d_A` and public point `Q_A = d_A G`; User B has `d_B` and `Q_B = d_B G`. They exchange only `Q_A` and `Q_B`. User A computes

```text
S_A = d_A Q_B = d_A(d_B G) = (d_A d_B)G
```

User B computes

```text
S_B = d_B Q_A = d_B(d_A G) = (d_B d_A)G = S_A
```

The shared value is a curve point. The code uses its x-coordinate as the ECDH shared secret and serializes it as exactly 32 big-endian bytes, including leading zero bytes when needed. The scalar multiplication has the same algebra on both clients; the laptop computes it with the project's point routines, and the ESP32 uses mbedTLS's ECDH computation with its private scalar and the validated peer point. The relay never sees this point or its x-coordinate.

The ECDH result is not used directly as the AES key. Its x-coordinate has structure and should be passed through a key-derivation function. The scheme is the elliptic-curve Diffie–Hellman key-agreement operation described in [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final).

### 5. HKDF-SHA256: turn the shared value into an AES key

Both sides call HKDF with the same input keying material (IKM), salt policy, hash, and context string. This implementation uses SHA-256, no explicit salt (`salt = nullptr`, length `0` on ESP32; an all-zero 32-byte salt on the host), and this exact `info` byte string:

```text
ecc-secure-key-exchange/v1|ECDH-P256|HKDF-SHA256|AES-256-GCM
```

For SHA-256, the hash output length is 32 bytes. RFC 5869 defines two stages:

```text
PRK = HMAC-SHA256(salt, IKM)
T(1) = HMAC-SHA256(PRK, info || 0x01)
OKM = first 32 bytes of T(1)
```

The salt is absent, so RFC 5869's rule is equivalent to using 32 zero bytes for `salt`. `info` labels the intended protocol/key use; it is public and is not a password or an additional secret. Since the requested output is 32 bytes and SHA-256 produces 32 bytes, one expand block (`T(1)`) is sufficient. The resulting 32-byte output is the 256-bit AES session key. Matching ECDH bytes and matching HKDF inputs yield identical keys on laptop and ESP32. See [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) for the extract-and-expand construction.

### 6. AES-256-GCM: encrypt and authenticate each message

For every message, the sender obtains a fresh random 12-byte (96-bit) nonce and encrypts the plaintext under the 32-byte session key with AES-256-GCM. GCM uses counter mode to produce ciphertext and a GHASH-based authentication calculation to produce a 16-byte (128-bit) tag. This code supplies no additional authenticated data (AAD), so the authenticated inputs are the ciphertext and GCM's nonce/key context.

The relay carries three fields that it can see but cannot decrypt:

```text
nonce:      12 bytes
tag:        16 bytes
ciphertext: same length as plaintext
```

The relay forwards them without learning the key or plaintext. At the receiver, AES-GCM checks the tag using the received nonce and ciphertext. The client displays plaintext only if this check succeeds; a modified or mismatched packet is rejected. The tag provides integrity/authenticity relative to possession of the shared session key; because public keys are unauthenticated in this demo, it does not establish a real-world identity. GCM's authenticated-encryption construction is specified in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

### 7. Full mathematical flow at a glance

```text
random d_A, d_B ∈ [1, n-1]
Q_A = d_A G                       Q_B = d_B G
        └──── exchange Q_A, Q_B ────┘
S_A = d_A Q_B = d_A d_B G = d_B Q_A = S_B
Z = fixed-width-32-byte x-coordinate of S_A/S_B
PRK = HMAC-SHA256(zero_salt_32, Z)
K = HMAC-SHA256(PRK, info || 0x01)  [32-byte AES-256 key]
(C, tag) = AES-256-GCM-Encrypt(K, random_nonce_12, plaintext)
```

The laptop and ESP32 implementations currently derive one session key for both message directions; a future protocol could derive separate directional keys with distinct `info` labels. The key pair is ephemeral per client run/boot, but the current relay protocol does not authenticate exchanged public keys or provide automatic session-liveness detection. Consequently, an active attacker able to replace public keys can establish separate sessions with each side (a man-in-the-middle attack), and clients should restart together with a fresh relay state during this demo.

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

## Run the two-laptop ATM PIN demo

This demo uses **Laptop A** as both the Flask relay and the ATM PIN verifier. **Laptop B** is only a USB-serial keyboard/terminal attached to the ESP32; it does not receive or verify the PIN. The ESP32 encrypts the entered PIN with its established ECDH/HKDF session key and sends it through Flask. Laptop A compares it with the configured demonstration PIN and sends an encrypted approved/denied result back. The PIN is not printed by either C++ client.

Use only a throwaway demonstration PIN, never a bank PIN. This is a learning demo with no attempt limit, account lockout, TLS, or authenticated public-key identity, so it is not an ATM-grade system.

### 1. Sync the source on Laptop A

```bash
rsync -a --exclude='.git/' --exclude='esp32/build/' --exclude='host/build/' \
  --exclude='communication/.venv/' \
  "/home/pranav-anandan/Documents/Pranav College/Semester 5 - Fall 2026-2027/7 ES/project/" \
  ~/projects/ecc-secure-key-exchange/
```

### 2. Build the host client and configure the ESP32

Build the host client before launching it. If this checkout was copied from a different path, remove its old generated CMake cache first:

```bash
cd ~/projects/ecc-secure-key-exchange/host
rm -rf build
cmake -S . -B build
cmake --build build -j
```

Find Laptop A's Wi-Fi IP with `hostname -I`; choose the address on the same Wi-Fi network as the ESP32. Configure the ESP32 relay host to this address, not `127.0.0.1`.

```bash
cd ~/projects/ecc-secure-key-exchange/esp32
. ~/esp/esp-idf/export.sh
idf.py set-target esp32
idf.py menuconfig
```

Under **ECC Secure Chat**, set the 2.4 GHz Wi-Fi SSID/password and Laptop A's Wi-Fi IPv4 address. Ensure HKDF is enabled, flash size is **4 MB**, and partition table is **Single factory app (large), no OTA**. Save and exit.

### 3. Start Flask on Laptop A (terminal 1)

```bash
cd ~/projects/ecc-secure-key-exchange/communication
source .venv/bin/activate
python communication_server.py --host 0.0.0.0 --port 5000
```

### 4. Flash from Laptop A, then attach the serial keyboard laptop

Keep Flask running. Connect the ESP32 to Laptop A, build, and flash it (adjust the persistent port if needed):

```bash
cd ~/projects/ecc-secure-key-exchange/esp32
. ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/serial/by-id/usb-1a86_USB_Single_Serial_5A7B056860-if00 flash
```

After flashing, disconnect USB from Laptop A and connect the ESP32 to Laptop B. The ESP32 reconnects to Wi-Fi and waits for the Laptop A client. Laptop B does not need the source code or ESP-IDF; it only runs a serial terminal.

On Laptop B, install and launch a serial terminal:

```bash
sudo apt update
sudo apt install picocom
ls -l /dev/serial/by-id/*
picocom -b 115200 /dev/serial/by-id/YOUR_ESP32_DEVICE
```

Replace `YOUR_ESP32_DEVICE` with the listed device name. If permission is denied, add the user to `dialout` and log out/in, or start a new shell with `newgrp dialout` and run `picocom` there. Wait for the ESP32 to print that it is waiting for the verifier.

### 5. Start the PIN verifier on Laptop A (terminal 2)

Start this within 60 seconds of the ESP32 waiting for its peer; otherwise reset the ESP32 and retry. Set the expected demo PIN without putting it in shell history, then launch ATM mode:

```bash
cd ~/projects/ecc-secure-key-exchange/host
read -s -p "Set demo verifier PIN (4-8 digits): " ECC_ATM_PIN; echo
export ECC_ATM_PIN
./build/ecc_client Laptop ESP32 http://127.0.0.1:5000 --atm
```

Keep this terminal open. It reports only whether each PIN was accepted or rejected, never the entered PIN. Wait for both sides to report the encrypted session is established. On Laptop B's serial terminal, type a 4-8 digit PIN and press Enter; input is not echoed by the firmware. The ESP32 displays the encrypted result (`Transaction approved` or `Transaction denied`). Exit picocom with **Ctrl+A**, then **Ctrl+X**.

### 6. Expected behavior

1. Enter the same 4-8 digit value set in `ECC_ATM_PIN`: Laptop A reports verified and the ESP32 reports approved.
2. Enter a different 4-8 digit value: Laptop A reports rejected and the ESP32 reports denied.
3. Restart Flask and both clients before starting a fresh session; this relay keeps keys and queued packets in memory.

The PIN travels from Laptop B to the ESP32 over the directly connected USB serial cable, then from ESP32 to Laptop A inside an AES-GCM encrypted packet. Flask sees public keys and ciphertext fields, not the PIN. The verifier stores the reference PIN in its process environment and compares it in memory. The current implementation does not rate-limit attempts; do not use a real or reused PIN.

## What is implemented and what remains

- The laptop crypto simulation runs the crypto exchange in C++.
- Separate laptop C++ clients exchange public keys and encrypted messages through the Flask communication relay.
- The ESP32 firmware exchanges public keys and AES-GCM packets with the laptop C++ client through the Flask relay over Wi-Fi, while USB serial provides a separate interactive console.
- ATM mode on the laptop client compares an encrypted ESP32 PIN submission against a verifier PIN supplied through `ECC_ATM_PIN`, then returns an encrypted approved/denied result.
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
