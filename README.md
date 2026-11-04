# Android Remote Key Provisioning (Software)

Software implementation of the Android RKP protocol that generates
`AuthenticatedRequest` CSRs, communicates with Google's production RKP server,
and exports `keybox.xml` for key attestation.

## Overview

Android devices with KeyMint 2.0+ use [Remote Key Provisioning][rkp-spec] to
obtain attestation certificates from Google. The on-device flow requires a
Trusted Execution Environment (TEE) to derive cryptographic keys and sign
provisioning requests.

This tool replicates that flow entirely in software, given a device's
32-byte CDI_Leaf seed.

[rkp-spec]: https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning

## Architecture

```
                        +-----------+
                        | RKP Server|  (Google production)
                        +-----+-----+
                              |
                 fetchEekChain / signCertificates
                              |
+-----------------------------+-----------------------------+
|                        rkp_sw.py                          |
|                                                           |
|  CDI_Leaf Seed ─── Signing Key ─── DICE Chain             |
|       |          (Ed25519 or P-256)     |                 |
|       |           ECDH-ES + HKDF ─── AES-256-GCM         |
|       |                |                                  |
|       v                v                                  |
|  COSE_Sign1     COSE_Encrypt0 (ProtectedData)            |
|       |                |                                  |
|       +-------+--------+                                  |
|               |                                           |
|     AuthenticatedRequest (CBOR)                           |
+-----------------------------------------------------------+
```

## Requirements

- Python 3.10+
- [cbor2](https://pypi.org/project/cbor2/)
- [cryptography](https://pypi.org/project/cryptography/) >= 41.0

```
pip install cbor2 cryptography
```

## Configuration

Copy `template.conf` to a private config file and fill in device-specific
values:

```
cp template.conf device_prop.conf
```

The config uses INI format with `[device]` and `[fingerprint]` sections.
See `template.conf` for all supported fields. Private config files
(`device_prop.conf`) are excluded from version control via `.gitignore`.

## Usage

### Show device and key information

```
python3 rkp_sw.py info --seed <64-hex> --config device_prop.conf
python3 rkp_sw.py info --seed <64-hex> --curve p256 --config device_prop.conf
```

### Provision attestation keys

Generate EC P-256 keypairs, build a CSR, and submit to Google's RKP server:

```
python3 rkp_sw.py provision --seed <64-hex> --config device_prop.conf
python3 rkp_sw.py provision --seed <64-hex> --curve p256 --config device_prop.conf -n 2
```

The `--curve` flag selects the DICE chain signing key type: `ed25519`
(default) or `p256`.

### Export keybox.xml

Provision a key and export the result as an Android `keybox.xml`:

```
python3 rkp_sw.py keybox --seed <64-hex> --config device_prop.conf -o keybox.xml
```

### Verify a CSR

```
python3 rkp_sw.py verify csr_output.cbor
```

## Protocol

The tool implements the full `generateCertificateRequestV2` protocol:

1. **EEK fetch** &mdash; `POST :fetchEekChain` returns the server's Endpoint
   Encryption Key chain and a challenge nonce.
2. **CSR build** &mdash; Constructs an `AuthenticatedRequest` containing:
   - `DeviceInfo` (CBOR map from config)
   - `DiceCertChain` (Degenerate DICE: UDS = CDI_Leaf, self-signed)
   - `ProtectedData` (COSE_Encrypt0 with ECDH-ES + AES-256-GCM)
   - `SignedData` (COSE_Sign1 over challenge + payload)
   - Unverified device info (outer map containing the build `fingerprint`)
3. **CSR submit** &mdash; `POST :signCertificates` returns X.509 certificate
   chains signed by Google's attestation root.

### References

| Specification | Use |
|---|---|
| [RFC 9052][rfc9052] | COSE_Sign1, COSE_Encrypt0 structures |
| [RFC 9053][rfc9053] | EdDSA, ES256, ECDH-ES, AES-256-GCM algorithm identifiers |
| [RFC 8392][rfc8392] | CWT claims (issuer, subject) |
| [Open DICE][dice] | DICE certificate chain profile |
| [Android RKP AIDL][rkp-aidl] | AuthenticatedRequest CDDL schema |

[rfc9052]: https://datatracker.ietf.org/doc/html/rfc9052
[rfc9053]: https://datatracker.ietf.org/doc/html/rfc9053
[rfc8392]: https://datatracker.ietf.org/doc/html/rfc8392
[dice]: https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md
[rkp-aidl]: https://cs.android.com/android/platform/superproject/+/main:hardware/interfaces/security/rkp/aidl/

## License

```
Copyright 2025 mhmrdd <1@mhmrdd.me>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
