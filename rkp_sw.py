#!/usr/bin/env python3
#
# Copyright 2025 mhmrdd <1@mhmrdd.me>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Software-side RKP (Remote Key Provisioning) without TEE involvement.

Generates AuthenticatedRequest CSRs per generateCertificateRequestV2.cddl,
communicates with Google's RKP server to obtain attestation certificates,
and exports keybox.xml for Android key attestation.

References:
  - IETF RFC 9052 (COSE Structures)
  - IETF RFC 9053 (COSE Algorithms)
  - IETF RFC 9393 (Entity Attestation Token)
  - Open DICE / Android DICE Chain spec
  - Android RemoteProvisioning AIDL
  - NIST SP 800-108 (KDF in Counter Mode)
"""

from __future__ import annotations

import argparse
import base64
import configparser
import os
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.dom import minidom

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# ---------------------------------------------------------------------------
# COSE / DICE Constants (RFC 9052, RFC 9053, Open DICE)
# ---------------------------------------------------------------------------

ALG_EDDSA = -8      # RFC 9053 Section 2.2
ALG_ES256 = -7       # RFC 9053 Section 2.1
ALG_A256GCM = 3      # RFC 9053 Section 4.1
ALG_HMAC256 = 5      # RFC 9053 Section 3.1

CWT_ISSUER = 1                # RFC 8392 Section 3
CWT_SUBJECT = 2               # RFC 8392 Section 3
DICE_SUBJECT_PUB_KEY = -4670552   # Open DICE profile
DICE_KEY_USAGE = -4670553         # Open DICE profile

RKP_SERVER_URL = 'https://remoteprovisioning.googleapis.com/v1'


# ---------------------------------------------------------------------------
# Device Configuration
# ---------------------------------------------------------------------------

_DEFAULT_DEVICE_INFO: dict[str, object] = {
    'brand': 'generic',
    'fused': 1,
    'model': 'default',
    'device': 'default',
    'product': 'default',
    'vb_state': 'green',
    'os_version': '13',
    'manufacturer': 'generic',
    'security_level': 'tee',
    'boot_patch_level': 20250101,
    'bootloader_state': 'locked',
    'system_patch_level': 202501,
    'vendor_patch_level': 20250101,
}


def load_device_config(path: str | None) -> dict[str, object]:
    """Load device configuration from an INI-style ``.conf`` file.

    Expected format (see ``template.conf``)::

        [device]
        brand = <OEM>
        model = <model>
        ...

        [fingerprint]
        value = <build fingerprint>
    """
    if not path:
        return dict(_DEFAULT_DEVICE_INFO)

    cfg = configparser.ConfigParser()
    cfg.read(path)

    info: dict[str, object] = {}
    if cfg.has_section('device'):
        # Load defaults first, then override from config
        info = dict(_DEFAULT_DEVICE_INFO)
        for key, raw in cfg.items('device'):
            if key == 'vbmeta_digest':
                info[key] = bytes.fromhex(raw)
            elif key == 'fused':
                info[key] = int(raw)
            elif key.endswith('_patch_level'):
                info[key] = int(raw)
            else:
                info[key] = raw
    else:
        info = dict(_DEFAULT_DEVICE_INFO)

    return info


def get_fingerprint(cfg_path: str | None) -> str:
    """Read build fingerprint from config, or return a generic default."""
    if cfg_path:
        cfg = configparser.ConfigParser()
        cfg.read(cfg_path)
        fp = cfg.get('fingerprint', 'value', fallback=None)
        if fp:
            return fp
    return 'generic/default/default:13/TP1A.220624.014/0:user/release-keys'


# ---------------------------------------------------------------------------
# Seed Resolution
# ---------------------------------------------------------------------------

def resolve_seed(*, seed_hex: str | None = None) -> bytes:
    """Resolve the 32-byte CDI_Leaf seed from ``--seed`` hex string."""
    if seed_hex:
        seed = bytes.fromhex(seed_hex)
        if len(seed) != 32:
            raise ValueError(f'Seed must be 32 bytes, got {len(seed)}')
        return seed

    print(
        'Error: No key material provided.\n'
        'Supply --seed <64-hex-chars>.',
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

class DeviceKeys:
    """UDS / CDI_Leaf key pair (Degenerate DICE chain).

    Args:
        seed: 32-byte CDI_Leaf seed.
        curve: ``'ed25519'`` (default) or ``'p256'``.
    """

    # secp256r1 group order (NIST P-256)
    _P256_ORDER = (
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    )

    def __init__(self, seed: bytes, curve: str = 'ed25519') -> None:
        self.seed = seed
        self.curve = curve
        self._pub_x: bytes = b''
        self._pub_y: bytes = b''

        if curve == 'ed25519':
            self._privkey = Ed25519PrivateKey.from_private_bytes(seed)
            self._pubkey = self._privkey.public_key()
            self.pub_raw: bytes = self._pubkey.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            self.alg = ALG_EDDSA
        elif curve == 'p256':
            scalar = int.from_bytes(seed, 'big') % self._P256_ORDER
            if scalar == 0:
                scalar = 1
            self._privkey = ec.derive_private_key(scalar, ec.SECP256R1())
            self._pubkey = self._privkey.public_key()
            nums = self._pubkey.public_numbers()
            self._pub_x = nums.x.to_bytes(32, 'big')
            self._pub_y = nums.y.to_bytes(32, 'big')
            self.pub_raw = self._pub_x + self._pub_y
            self.alg = ALG_ES256
        else:
            raise ValueError(f'Unsupported curve: {curve!r}')

    def sign(self, data: bytes) -> bytes:
        """Sign data and return raw signature bytes."""
        if self.curve == 'ed25519':
            return self._privkey.sign(data)
        else:
            sig_der = self._privkey.sign(data, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(sig_der)
            return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify a raw signature against data.  Raises on failure."""
        if self.curve == 'ed25519':
            self._pubkey.verify(signature, data)
        else:
            r = int.from_bytes(signature[:32], 'big')
            s = int.from_bytes(signature[32:], 'big')
            self._pubkey.verify(
                encode_dss_signature(r, s), data,
                ec.ECDSA(hashes.SHA256()),
            )

    def cose_key(self) -> dict:
        """COSE_Key map per RFC 9052 Section 7."""
        if self.curve == 'ed25519':
            return {1: 1, 3: ALG_EDDSA, -1: 6, -2: self.pub_raw}
        else:
            return {
                1: 2, 3: ALG_ES256, -1: 1,
                -2: self._pub_x, -3: self._pub_y,
            }


# ---------------------------------------------------------------------------
# COSE Primitives (RFC 9052)
# ---------------------------------------------------------------------------

def cose_sign1(
    sign_fn,
    protected: dict,
    payload: bytes,
) -> list:
    """Build a COSE_Sign1 structure (RFC 9052 Section 4.2)."""
    prot_bytes = cbor2.dumps(protected)
    sig_input = cbor2.dumps(['Signature1', prot_bytes, b'', payload])
    return [prot_bytes, {}, payload, sign_fn(sig_input)]


def cose_encrypt0_build(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    protected: dict,
) -> cbor2.CBORTag:
    """Build a COSE_Encrypt0 structure (RFC 9052 Section 5.2)."""
    prot_bytes = cbor2.dumps(protected)
    aad = cbor2.dumps(['Encrypt', prot_bytes, b''])
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return cbor2.CBORTag(96, [prot_bytes, {5: nonce}, ct])


# ---------------------------------------------------------------------------
# DICE Chain (Open DICE / Android BCC)
# ---------------------------------------------------------------------------

def build_dice_entry(keys: DeviceKeys, device_info: dict) -> list:
    payload = cbor2.dumps({
        CWT_ISSUER: device_info.get('dice_issuer', 'Android'),
        CWT_SUBJECT: device_info.get('dice_subject', 'KeyMint'),
        DICE_SUBJECT_PUB_KEY: cbor2.dumps(keys.cose_key()),
        DICE_KEY_USAGE: b'\x20',
    })
    return cose_sign1(keys.sign, {1: keys.alg}, payload)


def build_dice_chain(keys: DeviceKeys, device_info: dict) -> list:
    return [keys.cose_key(), build_dice_entry(keys, device_info)]


# ---------------------------------------------------------------------------
# ECDH + HKDF Key Derivation (RFC 9053 Section 6)
# ---------------------------------------------------------------------------

def ecdh_derive_key(
    eph_priv: X25519PrivateKey,
    server_pub_bytes: bytes,
    client_pub_bytes: bytes,
) -> bytes:
    """ECDH-ES + HKDF-SHA-256 → 32-byte AES-256 CEK."""
    shared = eph_priv.exchange(
        X25519PublicKey.from_public_bytes(server_pub_bytes)
    )
    ctx = cbor2.dumps([
        ALG_A256GCM,
        ['client', b'', client_pub_bytes],
        ['server', b'', server_pub_bytes],
        [256, b''],
    ])
    return HKDFExpand(hashes.SHA256(), 32, ctx).derive(shared)


# ---------------------------------------------------------------------------
# EC Key Generation
# ---------------------------------------------------------------------------

def generate_ec_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()
    cose_pub = {
        1: 2, 3: ALG_ES256, -1: 1,
        -2: nums.x.to_bytes(32, 'big'),
        -3: nums.y.to_bytes(32, 'big'),
    }
    return priv, cose_pub


# ---------------------------------------------------------------------------
# ProtectedData (COSE_Encrypt0)
# ---------------------------------------------------------------------------

def build_protected_data(
    keys: DeviceKeys,
    keys_to_sign: list,
    eek_pub_bytes: bytes,
    device_info: dict,
    eek_curve: int = 2,
):
    dice = build_dice_chain(keys, device_info)
    kt_cbor = cbor2.dumps(keys_to_sign)
    mac_prot = cbor2.dumps({1: keys.alg})
    mac_input = cbor2.dumps(['MAC0', mac_prot, b'', kt_cbor])
    signed_mac = [mac_prot, {}, kt_cbor, keys.sign(mac_input)]
    plaintext = cbor2.dumps([signed_mac, dice])

    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    aes_key = ecdh_derive_key(eph_priv, eek_pub_bytes, eph_pub)
    nonce = os.urandom(12)

    encrypted = cose_encrypt0_build(
        aes_key, nonce, plaintext, {1: ALG_A256GCM}
    )
    return encrypted, eph_pub, dice


# ---------------------------------------------------------------------------
# CSR / AuthenticatedRequest
# ---------------------------------------------------------------------------

def build_csr(
    keys: DeviceKeys,
    challenge: bytes,
    keys_to_sign: list,
    eek_pub_bytes: bytes,
    device_info: dict,
    eek_curve: int = 2,
    fingerprint: str | None = None,
) -> bytes:
    """Build an AuthenticatedRequest per generateCertificateRequestV2.cddl.

    Allow appending unverified device-info map after the HAL-generated
    AuthenticatedRequest.
    """
    csr_payload = cbor2.dumps([3, 'keymint', device_info, keys_to_sign])
    protected_data, _, dice = build_protected_data(
        keys, keys_to_sign, eek_pub_bytes, device_info, eek_curve
    )
    signed_payload = cbor2.dumps([challenge, csr_payload])
    signed_data = cose_sign1(keys.sign, {1: keys.alg}, signed_payload)
    request = [1, {}, dice, signed_data]
    if fingerprint is not None:
        request.append({'fingerprint': fingerprint})
    return cbor2.dumps(request)


# ---------------------------------------------------------------------------
# RKP Server Communication
# ---------------------------------------------------------------------------

def fetch_eek(
    fingerprint: str,
    server_url: str = RKP_SERVER_URL,
) -> tuple:
    """Fetch EEK chain and challenge from Google RKP server."""
    url = f'{server_url}:fetchEekChain'
    prov_info = cbor2.dumps({'fingerprint': fingerprint, 'id': 42})

    print(f'  Fetching EEK from {url}...')
    req = urllib.request.Request(url, data=prov_info, method='POST')
    req.add_header('Content-Type', 'application/cbor')

    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()
    result = cbor2.loads(data)

    eek_chains = result[0]
    challenge = result[1]
    config = result[2] if len(result) > 2 else {}

    print(f'  Challenge: {challenge.hex()[:20]}... ({len(challenge)}B)')
    print(f'  EEK chains: {len(eek_chains)} curves')
    if config:
        print(f'  Config: {config}')

    eek_pub = None
    eek_curve = None
    for chain_entry in eek_chains:
        curve = chain_entry[0]
        chain = chain_entry[1]
        last_cert = chain[-1]
        if isinstance(last_cert, list) and len(last_cert) >= 3:
            payload = cbor2.loads(last_cert[2])
            pub_bytes = payload.get(-2)
            crv = payload.get(-1)
            if pub_bytes and curve == 2 and crv == 4:
                eek_pub = pub_bytes
                eek_curve = curve

    if not eek_pub:
        for chain_entry in eek_chains:
            curve = chain_entry[0]
            chain = chain_entry[1]
            last_cert = chain[-1]
            if isinstance(last_cert, list) and len(last_cert) >= 3:
                payload = cbor2.loads(last_cert[2])
                pub_bytes = payload.get(-2)
                if pub_bytes and curve == 1:
                    eek_pub = pub_bytes
                    eek_curve = curve

    return challenge, eek_pub, eek_curve, eek_chains


class RkpError(Exception):
    """Base class for RKP provisioning errors."""


class DeviceNotRegisteredError(RkpError):
    """HTTP 444 — device DICE chain not endorsed by server."""


class RkpClientError(RkpError):
    """HTTP 4xx (except 444) — malformed request or auth failure."""


class RkpServerError(RkpError):
    """HTTP 5xx — server-side failure."""


def submit_csr(
    csr_bytes: bytes,
    challenge: bytes,
    server_url: str = RKP_SERVER_URL,
) -> list[bytes]:
    """Submit CSR to Google RKP server and return certificate chains.

    The response is a CBOR array(1) containing an inner array(2):
    ``[[shared_cert_bytes, [unique_cert_bytes, ...]]]``

    Each complete chain is ``shared_cert_bytes + unique_cert_bytes[i]``.

    Raises:
        DeviceNotRegisteredError: HTTP 444 from the server.
        urllib.error.HTTPError: Any other non-200 response.
    """
    challenge_b64 = base64.urlsafe_b64encode(challenge).decode()
    url = f'{server_url}:signCertificates?challenge={challenge_b64}'

    print(f'  Submitting CSR to server...')
    req = urllib.request.Request(url, data=csr_bytes, method='POST')
    req.add_header('Content-Type', 'application/cbor')

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        error_body = e.read(1024).decode(errors='replace')
        if e.code == 444:
            raise DeviceNotRegisteredError(error_body) from e
        if 400 <= e.code < 500:
            raise RkpClientError(
                f'HTTP {e.code}: {error_body}'
            ) from e
        if 500 <= e.code < 600:
            raise RkpServerError(
                f'HTTP {e.code}: {error_body}'
            ) from e
        raise

    result = cbor2.loads(data)
    print(f'  Response: {len(data)} bytes')

    # Outer array(1) → inner array(2): [shared_bytes, [unique_bytes, ...]]
    if not isinstance(result, list) or not result:
        return []
    inner = result[0] if isinstance(result[0], list) else result
    if not isinstance(inner, list) or len(inner) < 2:
        return []

    shared = inner[0] if isinstance(inner[0], bytes) else b''
    unique_list = inner[1] if isinstance(inner[1], list) else []

    chains = []
    for uc in unique_list:
        if isinstance(uc, bytes):
            chains.append(shared + uc)
    print(f'  Received {len(chains)} certificate chain(s)')
    return chains


# ---------------------------------------------------------------------------
# Keybox XML Export
# ---------------------------------------------------------------------------

def _sort_cert_chain(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    """Sort certificates into leaf-first, root-last order.

    The leaf is the certificate whose subject is not the issuer of any
    other certificate in the set. The root is self-signed.
    """
    if len(certs) <= 1:
        return list(certs)

    by_subject = {cert.subject: cert for cert in certs}

    # Subjects that appear as an issuer of at least one other cert.
    subjects_that_issue = set()
    for cert in certs:
        if cert.issuer != cert.subject:
            subjects_that_issue.add(cert.issuer)

    # Leaf: subject never appears as another cert's issuer.
    leaf = None
    for cert in certs:
        if cert.subject not in subjects_that_issue:
            leaf = cert
            break

    if leaf is None:
        return list(certs)

    # Walk from leaf to root via issuer links.
    ordered = [leaf]
    seen = {leaf.subject}
    current = leaf
    while len(ordered) < len(certs):
        if current.issuer in by_subject and current.issuer not in seen:
            current = by_subject[current.issuer]
            ordered.append(current)
            seen.add(current.subject)
        else:
            break

    # Append any unchained certs at the end.
    for cert in certs:
        if cert.subject not in seen:
            ordered.append(cert)

    return ordered


def _indent_pem(pem: str, indent: str) -> str:
    """Indent every line of a PEM block."""
    return '\n'.join(indent + line if line.strip() else ''
                     for line in pem.strip().splitlines())


def build_keybox_xml(
    *,
    ec_privkey,
    ec_cert_chain: list[x509.Certificate],
    device_id: str = 'generic-000000',
) -> str:
    """Build keybox.xml for Android key attestation.

    Args:
        ec_privkey: EC private key (P-256).
        ec_cert_chain: Unordered list of X.509 certificates.
        device_id: Device identifier string.

    Returns:
        Pretty-printed XML string with certificates in leaf-first order.
    """
    ec_cert_chain = _sort_cert_chain(ec_cert_chain)

    indent1 = '    '     # Keybox level
    indent2 = '        ' # Key level
    indent3 = '            ' # CertificateChain level

    lines = [
        '<?xml version="1.0"?>',
        '<AndroidAttestation>',
        f'{indent1}<NumberOfKeyboxes>1</NumberOfKeyboxes>',
        f'{indent1}<Keybox DeviceID="{device_id}">',
        f'{indent2}<Key algorithm="ecdsa">',
        f'{indent2}    <PrivateKey format="pem">',
    ]

    key_pem = ec_privkey.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    ).decode().strip()
    lines.append(_indent_pem(key_pem, indent2 + '    '))
    lines.append(f'{indent2}    </PrivateKey>')

    lines.append(f'{indent2}    <CertificateChain>')
    lines.append(
        f'{indent3}    <NumberOfCertificates>'
        f'{len(ec_cert_chain)}'
        f'</NumberOfCertificates>'
    )

    for cert in ec_cert_chain:
        cert_pem = cert.public_bytes(Encoding.PEM).decode().strip()
        lines.append(f'{indent3}    <Certificate format="pem">')
        lines.append(_indent_pem(cert_pem, indent3 + '    '))
        lines.append(f'{indent3}    </Certificate>')

    lines.append(f'{indent2}    </CertificateChain>')
    lines.append(f'{indent2}</Key>')
    lines.append(f'{indent1}</Keybox>')
    lines.append('</AndroidAttestation>')
    lines.append('')

    return '\n'.join(lines)


def parse_der_cert_chain(data: bytes) -> list[x509.Certificate]:
    """Parse concatenated DER certificates.

    Manually reads DER SEQUENCE headers to split certs, since
    ``load_der_x509_certificate`` rejects trailing data.
    """
    certs = []
    pos = 0
    while pos < len(data) and data[pos] == 0x30:
        # Parse DER SEQUENCE length
        if data[pos + 1] & 0x80:
            num_len_bytes = data[pos + 1] & 0x7F
            length = int.from_bytes(
                data[pos + 2 : pos + 2 + num_len_bytes], 'big'
            )
            header_len = 2 + num_len_bytes
        else:
            length = data[pos + 1]
            header_len = 2
        cert_len = header_len + length
        try:
            cert = x509.load_der_x509_certificate(data[pos : pos + cert_len])
            certs.append(cert)
        except Exception:
            break
        pos += cert_len
    return certs


# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------

def cmd_provision(args: argparse.Namespace) -> None:
    """Full provisioning: generate keys, fetch EEK, submit CSR, get certs."""
    seed = resolve_seed(seed_hex=args.seed)
    curve = args.curve
    keys = DeviceKeys(seed, curve=curve)
    device_info = load_device_config(args.config)
    fingerprint = get_fingerprint(args.config)

    print(f'CDI_Leaf pubkey: {keys.pub_raw.hex()}')

    num_keys = args.num_keys
    print(f'\n[1] Generating {num_keys} EC P-256 keypair(s)...')
    ec_keys = []
    cose_pubs = []
    for i in range(num_keys):
        priv, pub = generate_ec_keypair()
        ec_keys.append(priv)
        cose_pubs.append(pub)
        print(f'  Key {i}: P-256')

    url = args.server_url or RKP_SERVER_URL
    print(f'\n[2] Fetching EEK from RKP server...')
    try:
        challenge, eek_pub, eek_curve, _ = fetch_eek(fingerprint, url)
    except Exception as e:
        print(f'  Failed: {e}')
        print('  Falling back to local test mode...')
        challenge = os.urandom(32)
        eek_priv = X25519PrivateKey.generate()
        eek_pub = eek_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        eek_curve = 2

    print(f'\n[3] Building CSR...')
    csr_bytes = build_csr(
        keys, challenge, cose_pubs, eek_pub, device_info, eek_curve,
        fingerprint,
    )
    print(f'  CSR: {len(csr_bytes)} bytes')

    csr = cbor2.loads(csr_bytes)
    sd = csr[3]
    sig_struct = cbor2.dumps(['Signature1', sd[0], b'', sd[2]])
    keys.verify(sd[3], sig_struct)
    print(f'  Signature verification: OK')

    print(f'\n[4] Submitting CSR...')
    try:
        cert_chains = submit_csr(csr_bytes, challenge, url)
        for i, chain_der in enumerate(cert_chains):
            fname = f'cert_chain_{i}.der'
            with open(fname, 'wb') as f:
                f.write(chain_der)
            certs = parse_der_cert_chain(chain_der)
            print(f'  Chain {i}: {len(certs)} certs, saved to {fname}')
            for j, c in enumerate(certs):
                print(f'    [{j}] {c.subject}')

    except DeviceNotRegisteredError as e:
        print(f'  Device not registered: {e}')
        with open('csr_output.cbor', 'wb') as f:
            f.write(csr_bytes)
        print(f'  CSR saved to csr_output.cbor')

    except RkpClientError as e:
        print(f'  Client error: {e}')
        with open('csr_output.cbor', 'wb') as f:
            f.write(csr_bytes)
        print(f'  CSR saved to csr_output.cbor')

    except RkpServerError as e:
        print(f'  Server error: {e}')
        with open('csr_output.cbor', 'wb') as f:
            f.write(csr_bytes)
        print(f'  CSR saved to csr_output.cbor')


def cmd_keybox(args: argparse.Namespace) -> None:
    """Export attestation keys and certs as keybox.xml."""
    seed = resolve_seed(seed_hex=args.seed)
    curve = args.curve
    keys = DeviceKeys(seed, curve=curve)
    device_info = load_device_config(args.config)
    fingerprint = get_fingerprint(args.config)

    print(f'CDI_Leaf pubkey: {keys.pub_raw.hex()}')

    url = args.server_url or RKP_SERVER_URL

    # Generate EC key and provision
    ec_priv, ec_cose_pub = generate_ec_keypair()

    print('Fetching EEK...')
    try:
        challenge, eek_pub, eek_curve, _ = fetch_eek(fingerprint, url)
    except Exception as e:
        print(f'Error fetching EEK: {e}', file=sys.stderr)
        sys.exit(1)

    print('Building and submitting EC CSR...')
    csr_bytes = build_csr(
        keys, challenge, [ec_cose_pub], eek_pub, device_info, eek_curve,
        fingerprint,
    )
    try:
        ec_chains = submit_csr(csr_bytes, challenge, url)
    except RkpError as e:
        print(f'Provisioning failed: {e}', file=sys.stderr)
        sys.exit(1)

    if not ec_chains:
        print('Error: No certificate chains received.', file=sys.stderr)
        sys.exit(1)

    ec_certs = parse_der_cert_chain(ec_chains[0])
    print(f'EC chain: {len(ec_certs)} certificates')

    manufacturer = device_info.get('manufacturer', 'generic')
    device_id = f'{manufacturer}-{os.urandom(6).hex()}'

    xml_str = build_keybox_xml(
        ec_privkey=ec_priv,
        ec_cert_chain=ec_certs,
        device_id=device_id,
    )

    outfile = args.output or 'keybox.xml'
    with open(outfile, 'w') as f:
        f.write(xml_str)
    print(f'Keybox written to {outfile}')


def cmd_info(args: argparse.Namespace) -> None:
    """Show key and device information."""
    seed = resolve_seed(seed_hex=args.seed)
    curve = args.curve
    keys = DeviceKeys(seed, curve=curve)
    device_info = load_device_config(args.config)

    curve_label = 'Ed25519' if curve == 'ed25519' else 'P-256'
    print(f'Curve:          {curve_label}')
    print(f'Seed:           {keys.seed.hex()}')
    print(f'Public key:     {keys.pub_raw.hex()}')
    print(f'Device:         {device_info.get("brand")} '
          f'{device_info.get("model")} ({device_info.get("device")})')
    print(f'Fused:          {device_info.get("fused")}')
    print(f'VB state:       {device_info.get("vb_state")}')
    print(f'Bootloader:     {device_info.get("bootloader_state")}')
    print(f'Patches:        boot={device_info.get("boot_patch_level")} '
          f'system={device_info.get("system_patch_level")} '
          f'vendor={device_info.get("vendor_patch_level")}')



def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a CSR file."""
    with open(args.csr_file, 'rb') as f:
        csr_bytes = f.read()

    csr = cbor2.loads(csr_bytes)
    print(f'Version:        {csr[0]}')
    print(f'DiceCertChain:  {len(csr[2])} entries')

    uds_cose = csr[2][0]
    kty = uds_cose.get(1)
    if kty == 1:  # OKP (Ed25519)
        uds_pub = uds_cose[-2]
        print(f'UDS_Pub (Ed25519): {uds_pub.hex()}')
    elif kty == 2:  # EC2 (P-256)
        uds_pub_x = uds_cose[-2]
        uds_pub_y = uds_cose[-3]
        print(f'UDS_Pub (P-256):   X={uds_pub_x.hex()}, Y={uds_pub_y.hex()}')
    else:
        print(f'UDS_Pub (unknown kty={kty})')

    sd = csr[3]
    sig_struct = cbor2.dumps(['Signature1', sd[0], b'', sd[2]])
    try:
        if kty == 1:
            Ed25519PublicKey.from_public_bytes(uds_pub).verify(sd[3], sig_struct)
        elif kty == 2:
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(uds_pub_x, 'big'),
                int.from_bytes(uds_pub_y, 'big'),
                ec.SECP256R1(),
            ).public_key()
            r = int.from_bytes(sd[3][:32], 'big')
            s = int.from_bytes(sd[3][32:], 'big')
            pub.verify(
                encode_dss_signature(r, s), sig_struct,
                ec.ECDSA(hashes.SHA256()),
            )
        print('Signature:      VALID')
    except Exception as e:
        print(f'Signature:      INVALID ({e})')

    payload = cbor2.loads(sd[2])
    csr_payload = cbor2.loads(payload[1])
    print(f'CSR version:    {csr_payload[0]}')
    print(f'CertType:       {csr_payload[1]}')
    print(f'Brand:          {csr_payload[2].get("brand")}')
    print(f'KeysToSign:     {len(csr_payload[3])} keys')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _add_key_args(parser: argparse.ArgumentParser) -> None:
    """Add common key-material arguments to a subparser."""
    parser.add_argument(
        '--seed', type=str, metavar='HEX',
        help='32-byte CDI_Leaf seed (64 hex chars).',
    )
    parser.add_argument(
        '--curve', type=str.lower, choices=['ed25519', 'p256'],
        default='ed25519',
        help='DICE key curve: ed25519 (default) or p256.',
    )
    parser.add_argument(
        '--config', type=str, metavar='FILE',
        help='Device configuration file (INI format). '
             'See template.conf for format.',
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Software RKP — Remote Key Provisioning without TEE.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s info --seed <hex> --config device_prop.conf
              %(prog)s provision --seed <hex> --config device_prop.conf
              %(prog)s provision --seed <hex> --curve p256 --config device_prop.conf
              %(prog)s keybox --seed <hex> --config device_prop.conf -o keybox.xml
              %(prog)s verify csr_output.cbor

            See template.conf for device configuration format.
        """),
    )
    sub = parser.add_subparsers(dest='command')

    # info
    p_info = sub.add_parser('info', help='Show key and device info')
    _add_key_args(p_info)
    p_info.set_defaults(func=cmd_info)

    # provision
    p_prov = sub.add_parser('provision', help='Full RKP provisioning flow')
    _add_key_args(p_prov)
    p_prov.add_argument('-n', '--num-keys', type=int, default=1)
    p_prov.add_argument('-u', '--server-url', type=str)
    p_prov.set_defaults(func=cmd_provision)

    # keybox
    p_kb = sub.add_parser('keybox', help='Export keybox.xml')
    _add_key_args(p_kb)
    p_kb.add_argument('-o', '--output', type=str, default='keybox.xml')
    p_kb.add_argument('-u', '--server-url', type=str)
    p_kb.set_defaults(func=cmd_keybox)

    # verify
    p_ver = sub.add_parser('verify', help='Verify a CSR file')
    p_ver.add_argument('csr_file')
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == '__main__':
    main()
