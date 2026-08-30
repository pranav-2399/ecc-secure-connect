# Review 1 — Multi-Server Architecture & Interval Communication Guide

## Architecture Overview

The system consists of **three distinct Flask server instances**:

```
                  ┌───────────────────────────────┐
                  │    Central Relay Server       │
                  │    (http://127.0.0.1:5000)     │
                  │  Zero-Knowledge Directory     │
                  └──────────────┬────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │ Public Key Registration &     │
                 │ Packet Relay Routing          │
                 │                               │
        ┌────────┴────────┐             ┌────────┴────────┐
        │                 │             │                 │
        ▼                 ▼             ▼                 ▼
 ┌──────────────┐  Encrypted Push  ┌──────────────┐
 │Client Server A│ ────────────────►│Client Server B│
 │ (Alice:5001) │ ◄────────────────│  (Bob:5002)   │
 │              │  Interval Bytes  │              │
 │ ECC (P-256)  │                  │ ECC (P-256)  │
 │ ECDH / HKDF  │                  │ ECDH / HKDF  │
 │ AES-256-GCM  │                  │ AES-256-GCM  │
 └──────────────┘                  └──────────────┘
```

> [!IMPORTANT]
> **Key Architecture Highlights:**
> 1. **Central Relay Server (`:5000`)**: Facilitates public key directory discovery and zero-knowledge packet relay.
> 2. **Client Server A (`:5001`)**: Independent Flask server instance for Alice. Manages Alice's private key, performs key exchange, and runs a background thread for periodic interval messaging.
> 3. **Client Server B (`:5002`)**: Independent Flask server instance for Bob. Manages Bob's private key, performs key exchange, and runs a background thread for periodic interval messaging.

---

## Directory Structure

```
ecc-secure-key-exchange/
│
├── server/
│   ├── app.py           # Central Relay Server endpoints (/register, /public-key, /client, /message)
│   └── relay.py         # In-memory communication relay state (no cryptography)
│
├── client/
│   ├── client_server.py # Standalone Client Server Instance (Flask + Background Interval Thread)
│   ├── main.py          # CLI runner to launch individual Client Server instances
│   │
│   ├── crypto/
│   │   ├── ecc.py       # SECP256R1 key pair generation & PEM serialization
│   │   ├── ecdh.py      # ECDH shared secret derivation
│   │   ├── hkdf.py      # HKDF-SHA256 session key derivation (256-bit)
│   │   └── aes.py       # AES-256-GCM encryption & decryption with tag check
│   │
│   └── network/
│       └── api.py       # Client HTTP networking API for relay and client-server pushing
│
├── tests/
│   ├── test_client_server.py # Integration tests for multi-server interval communication
│   ├── test_ecc.py      # ECC tests
│   ├── test_ecdh.py     # ECDH tests
│   ├── test_hkdf.py     # HKDF tests
│   └── test_aes.py      # AES-GCM encryption/decryption & tampering tests
│
├── run_demo.py          # Automated multi-server interval demonstration runner
└── requirements.txt     # Dependencies (cryptography, flask, requests, pytest)
```

---

## Execution Instructions: Running 3 Separate Server Processes

### 1. Terminal 1 — Start Central Relay Server (Port 5000)

```bash
cd ecc-secure-key-exchange
python3 server/app.py
```
*Central Relay Server listens at `http://127.0.0.1:5000`.*

---

### 2. Terminal 2 — Start Client Server A (Alice @ Port 5001)

```bash
cd ecc-secure-key-exchange
python3 client/main.py --client Alice --port 5001 --peer Bob --peer-port 5002 --interval 5
```
*Client Server A starts listening at `http://127.0.0.1:5001`, registers with Central Relay, initiates key exchange with Bob, and starts its 5-second interval loop.*

---

### 3. Terminal 3 — Start Client Server B (Bob @ Port 5002)

```bash
cd ecc-secure-key-exchange
python3 client/main.py --client Bob --port 5002 --peer Alice --peer-port 5001 --interval 5
```
*Client Server B starts listening at `http://127.0.0.1:5002`, registers with Central Relay, initiates key exchange with Alice, and starts its 5-second interval loop.*

---

## Running Automated Multi-Server Demonstration & Tests

### Automated Demo Runner:
```bash
python3 run_demo.py
```

### Pytest Unit Suite:
```bash
pytest tests/
```
