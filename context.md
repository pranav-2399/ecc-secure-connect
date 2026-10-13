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
sudo apt install build-essential cmake libssl-dev libcurl4-openssl-dev libboost-dev libsqlite3-dev
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

This is a **cash-withdrawal simulator**, not an ATM-grade or banking system. **Laptop A** runs the Flask relay and the C++ transaction verifier/ledger. **Laptop B** is only the USB-serial keyboard/terminal attached to the ESP32. The ESP32 encrypts the PIN and requested withdrawal; the Laptop A C++ client checks the PIN, maintains the account lockout and balance in SQLite, records successful withdrawals, and sends the result back encrypted. The Flask relay only queues ciphertext and public keys.

The demo account starts with **₹50,000**, permits withdrawals of **₹100–₹10,000** in ₹100 increments, and locks after **three consecutive incorrect PIN submissions**. Balance, lockout counter, and withdrawal records persist in `host/atm_demo.sqlite3`. The PIN itself is not stored in SQLite; provide it to the verifier via `ECC_ATM_PIN`. A successful PIN resets the failed-attempt counter. An operator must explicitly unlock an account after lockout.

Use only a throwaway demonstration PIN and fictitious balances. This project is not suitable for real funds or deployment as an ATM: its custom ECC arithmetic is variable-time, the relay is plain HTTP, exchanged public keys are unauthenticated, and it has no trusted secure PIN-entry device, payment-network PIN processing, HSM, tamper-resistant enclosure, certified cash dispenser, or production audit controls. The “withdrawal” only debits a local demo ledger; it does not control a cash dispenser. Real deployments must follow applicable payment-network rules and PCI PIN-security/device requirements, with independent assessment and approved hardware; see [PCI PIN Security](https://www.pcisecuritystandards.org/standards/pin-security/) and [PCI PTS HSM](https://www.pcisecuritystandards.org/standards/pts-hardware-security-module-hsm/).

### 1. Build the verifier on Laptop A (macOS)

Install the host dependencies once (install Xcode Command Line Tools first with `xcode-select --install` if needed):

```bash
brew install cmake pkg-config openssl curl boost sqlite3 python
```

Build from the Mac clone of this repository:

```bash
cd ~/projects/ecc-secure-key-exchange/host
export PKG_CONFIG_PATH="$(brew --prefix sqlite3)/lib/pkgconfig:$(brew --prefix curl)/lib/pkgconfig:$(brew --prefix openssl)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
cmake -S . -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl)" -DBOOST_ROOT="$(brew --prefix boost)"
cmake --build build --parallel
```

### 2. Find the Mac's Wi-Fi IP and start the relay (Laptop A, terminal 1)

```bash
ipconfig getifaddr en0
cd ~/projects/ecc-secure-key-exchange/communication
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python communication_server.py --host 0.0.0.0 --port 5000
```

Keep the relay running. If macOS asks whether Python may accept incoming connections, allow it on the trusted network. The Mac and ESP32 must be able to communicate on the same Wi-Fi/hotspot. The ESP32 uses the Mac's Wi-Fi IP; the Mac C++ client uses `127.0.0.1`.

### 3. Configure, flash, and monitor the ESP32 on Linux (Laptop B)

Connect the ESP32 to Linux. Set its relay host to the Mac IP found above, then build and flash:

```bash
cd ~/projects/ecc-secure-key-exchange/esp32
. ~/esp/esp-idf/export.sh
idf.py set-target esp32
idf.py menuconfig
```

Under **ECC Secure Chat**, set the 2.4 GHz Wi-Fi SSID/password and Laptop A's Wi-Fi IPv4 address. Ensure HKDF is enabled, flash size is **4 MB**, and partition table is **Single factory app (large), no OTA**. Save and exit.

```bash
idf.py build
ls -l /dev/serial/by-id/*
idf.py -p /dev/serial/by-id/YOUR_ESP32_DEVICE flash monitor
```

If serial permission is denied, add the user to `dialout` and log out/in, or start a shell with `newgrp dialout`. Leave the monitor open on Linux; it is the keyboard and output terminal. Once the ESP32 says it is waiting for the peer, start the Mac verifier within 60 seconds.

### 4. Start the ATM verifier on Laptop A (macOS, terminal 2)

The first withdrawal request creates the demo account with ₹50,000 in `host/atm_demo.sqlite3`. Optional settings are `ECC_ATM_ACCOUNT` (default `DEMO-001`), `ECC_ATM_INITIAL_BALANCE` (whole rupees, used only when the account is first created), and `ECC_ATM_DB` (database path). In macOS's default zsh shell:

```bash
cd ~/projects/ecc-secure-key-exchange/host
read -s "ECC_ATM_PIN?Set demo verifier PIN (4-8 digits): "
echo
export ECC_ATM_PIN
./build/ecc_client Laptop ESP32 http://127.0.0.1:5000 --atm
```

Keep this terminal open. It reports approval, rejection, lockout, and remaining demo balance without printing the entered PIN. On Laptop B's Linux serial monitor, enter a 4-8 digit PIN and press Enter, then enter the withdrawal amount.

The ESP32 asks for the PIN and then a withdrawal amount in whole rupees (₹100–₹10,000, multiples of ₹100). Use `/cancel` at the amount prompt to discard the pending PIN. The PIN and amount are submitted together in one AES-GCM-protected packet. On approval, the Laptop A ledger debits the amount atomically and records the transaction; the ESP32 displays the remaining demo balance. An insufficient-funds result leaves the balance unchanged. The current unauthenticated ECDH setup does not authenticate the peer or relay.

### 5. Expected behavior

1. A valid PIN plus an allowed amount within the balance: the transaction is approved and the balance decreases by that amount.
2. A valid PIN plus an amount above the balance: the transaction is declined and the balance does not change.
3. One and two incorrect PINs: the verifier reports one fewer remaining attempt each time. Stop and restart the verifier; the count must persist.
4. A third consecutive incorrect PIN: the account is locked. A subsequent correct PIN must also be declined, including after restarting Flask and both clients.
5. Unlock the demo account from Laptop A, then confirm a correct PIN works again. Run this from `host/` using the same `ECC_ATM_ACCOUNT` and `ECC_ATM_DB` settings as the verifier:

   ```bash
   ./build/ecc_client --unlock-account
   ```

6. Confirm zero, negative, non-₹100-multiple, and over-₹10,000 amounts are rejected at the ESP32 prompt; confirm an amount below ₹100 or above ₹10,000 cannot debit the account.

Restart Flask and both clients before a fresh cryptographic session; the relay's key registrations and message queues are in memory, while the SQLite demo account remains on disk.

The PIN travels from Laptop B to the ESP32 over the directly connected USB serial cable, then from ESP32 to Laptop A inside an AES-GCM encrypted packet. Flask sees public keys and ciphertext fields, not the PIN. The verifier compares the configured reference PIN in memory using a constant-time byte comparison; SQLite stores the account balance, failed-attempt count, lock flag, and withdrawal ledger, but not the PIN. The lockout counter persists across client/server restarts. The local `--unlock-account` operator command intentionally resets the lock flag and counter; it is not an authenticated bank-operator workflow.

## What is implemented and what remains

- The laptop crypto simulation runs the crypto exchange in C++.
- Separate laptop C++ clients exchange public keys and encrypted messages through the Flask communication relay.
- The ESP32 firmware exchanges public keys and AES-GCM packets with the laptop C++ client through the Flask relay over Wi-Fi, while USB serial provides a separate interactive console.
- ATM simulator mode checks encrypted PIN/withdrawal requests, locks an account after three consecutive failed PINs, persists that state in SQLite, and atomically debits/records successful withdrawals. It supports an operator-only local unlock command.
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
