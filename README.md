# ProtonVPN Keygen
You can use the [Github pages site](https://neovimium.github.io/protonvpn-keygen/) to test, or if you already have an automated solution, you can use [the python script](https://github.com/neovimium/protonvpn-keygen/blob/main/generate.py).

Turns out Proton uses different key generation functionality than normal Wireguard.
([found here](https://github.com/paulmillr/noble-ed25519))

# How?
Ed25519 → X25519 conversion:
1. Take the original Ed25519 private key (32 bytes)
2. Hash it again with SHA-512 and take the first 32 bytes
3. Apply X25519 clamping, which clears specific bits to ensure the key meets X25519 requirements
4. This produces an X25519 private key that WireGuard can use

# Why?
Ed25519 and X25519 use the same underlying Curve25519, but Ed25519 is for signatures while X25519 is for key exchange.\
The conversion essentially transforms the signing key format into a key exchange format while preserving the cryptographic relationship.

# Usage
Ed25519 Private keys are unused.
Ed25519 Public keys are for the ProtonVPN API.
X25519 Private keys are for your Wireguard Client.
