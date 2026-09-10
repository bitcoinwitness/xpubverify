#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module: xpubverify.py
Purpose: Standalone watch-only Bitcoin address verification from an
         extended public key (xpub / ypub / zpub / tpub).
xpubverify v1.0.0, https://bitcoinwitness.org
The authoritative version is the XPUBVERIFY_VERSION constant below.

Public key in. Addresses out. No secret material ever enters this tool,
because it doesn't need to.

This script derives receive and change addresses from an account-level
extended public key using BIP32 public-child derivation (CKDpub). It
cannot derive hardened children (those require the matching extended
private key, which this tool deliberately has no code path for).

Supported input version bytes:
    0x0488B21E  xpub  -> BIP44 legacy P2PKH            (1...)
    0x049D7CB2  ypub  -> BIP49 nested SegWit P2SH-P2WPKH (3...)
    0x04B24746  zpub  -> BIP84 native SegWit P2WPKH     (bc1q...)
    0x043587CF  tpub  -> testnet BIP44 P2PKH           (m/n...)
    (xpub with --taproot) -> BIP86 Taproot P2TR        (bc1p...)

Dependencies: Python 3.8+ standard library only. No pip install required.

BIP references:
    BIP32, https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    BIP44, https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    BIP49, https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
    BIP84, https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
    BIP86, https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
    SLIP-132, https://github.com/satoshilabs/slips/blob/master/slip-0132.md

License: MIT (see LICENSE).
"""

import hashlib
import hmac
import json
import struct
import sys


XPUBVERIFY_VERSION = "1.0.0"


# ─────────────────────────────────────────────
# secp256k1 Elliptic Curve Parameters
# ─────────────────────────────────────────────

# Field prime
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# Generator point
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# Point at infinity (identity element for the elliptic-curve group).
POINT_AT_INFINITY = None


# ─────────────────────────────────────────────
# Elliptic Curve Arithmetic (secp256k1)
# ─────────────────────────────────────────────

def _extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a, m=P):
    """Modular multiplicative inverse."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def point_add(p1, p2):
    """Add two points on the secp256k1 curve."""
    if p1 is POINT_AT_INFINITY:
        return p2
    if p2 is POINT_AT_INFINITY:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2:
        if y1 != y2:
            return POINT_AT_INFINITY
        # Point doubling
        lam = (3 * x1 * x1 * modinv(2 * y1)) % P
    else:
        lam = ((y2 - y1) * modinv(x2 - x1)) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_multiply(k, point=G):
    """Scalar multiplication using double-and-add.

    Only ever called with public scalars (CKDpub chain-code offsets, BIP86
    taproot tweaks); there is no route in this tool for k to be derived
    from user-held key material.
    """
    result = POINT_AT_INFINITY
    addend = point

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def point_from_pubkey(pubkey_bytes):
    """Decompress a 33-byte compressed public key to a curve point (x, y)."""
    if len(pubkey_bytes) != 33:
        raise ValueError(
            f"Expected 33-byte compressed public key, got {len(pubkey_bytes)}"
        )
    prefix = pubkey_bytes[0]
    # Reject any non-compressed prefix (SEC1 2.3.4: a compressed point must
    # start with 0x02 or 0x03). Without this, a 0x04/0x00/0xff-prefixed 33-byte
    # input falls through the parity branch below and returns the right point or
    # its negation at coin-flip odds, so a caller who mis-slices an uncompressed
    # key would silently derive a child of the wrong point.
    if prefix not in (0x02, 0x03):
        raise ValueError(
            f"invalid compressed-pubkey prefix 0x{prefix:02x} "
            "(SEC1 2.3.4: a compressed point starts with 0x02 or 0x03)")
    x = int.from_bytes(pubkey_bytes[1:], 'big')
    # Reject x not in the field (SEC1 2.3.4). Pre-fix `pow(x, 3, P)`
    # silently reduced an out-of-range x mod P; subsequent on-curve check
    # could accidentally accept a tampered pubkey whose x value happened to
    # land on the curve after the implicit modular reduction. SEC1 §2.3.4
    # requires `0 < x < P` for a valid compressed point.
    if not (0 < x < P):
        raise ValueError("Invalid public key: x not in field (must be 0 < x < P)")
    # y^2 = x^3 + 7 (mod P)
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if y_sq != pow(y, 2, P):
        raise ValueError("Invalid public key: not on curve")
    if (prefix == 0x02 and y % 2 != 0) or (prefix == 0x03 and y % 2 == 0):
        y = P - y
    return (x, y)


def compress_pubkey(point):
    """Compress a curve point to 33 bytes."""
    x, y = point
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')


# ─────────────────────────────────────────────
# Hash Utilities
# ─────────────────────────────────────────────

def sha256(data):
    """SHA-256 hash."""
    return hashlib.sha256(data).digest()


# RIPEMD-160. Bitcoin addresses need HASH160 = RIPEMD160(SHA256(pubkey)).
# Modern OpenSSL 3 builds drop ripemd160 from the default provider, so
# hashlib.new('ripemd160') raises on some stock python.org / hardened installs.
# To keep the "stdlib-only, runs on any Python 3.8+" promise literally true, we
# fall back to a compact pure-Python RIPEMD-160, Pieter Wuille's reference
# implementation from Bitcoin Core's test framework (MIT, Copyright (c) 2021
# Pieter Wuille), byte-identical to OpenSSL, validated against the official
# RIPEMD vectors and the full address test suite. Reached only when hashlib
# lacks it.
#
# Third-party MIT notice for the RIPEMD-160 port, Copyright (c) 2021 Pieter
# Wuille: permission is granted, free of charge, to any person obtaining a copy
# of this software to use, copy, modify, merge, publish, distribute, sublicense,
# and sell it, provided the above copyright notice and this permission notice are
# included. The software is provided "as is", without warranty of any kind.
_RMD_ML = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
           7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
           3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
           1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
           4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
_RMD_MR = (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
           6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
           15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
           8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
           12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
_RMD_RL = (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
           7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
           11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
           11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
           9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
_RMD_RR = (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
           9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
           9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
           15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
           8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
_RMD_KL = (0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e)
_RMD_KR = (0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0)


def _rmd_f(x, y, z, i):
    """The f1..f5 nonlinear functions from the RIPEMD-160 specification."""
    if i == 0:
        return x ^ y ^ z
    if i == 1:
        return (x & y) | (~x & z)
    if i == 2:
        return (x | ~y) ^ z
    if i == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rmd_rol(x, i):
    """Rotate the bottom 32 bits of x left by i bits."""
    return ((x << i) | ((x & 0xffffffff) >> (32 - i))) & 0xffffffff


def _rmd_compress(h0, h1, h2, h3, h4, block):
    """Compress the 5-word state with one 64-byte block (dual left/right paths)."""
    al, bl, cl, dl, el = h0, h1, h2, h3, h4
    ar, br, cr, dr, er = h0, h1, h2, h3, h4
    x = [int.from_bytes(block[4 * i:4 * (i + 1)], 'little') for i in range(16)]
    for j in range(80):
        rnd = j >> 4
        al = _rmd_rol(al + _rmd_f(bl, cl, dl, rnd) + x[_RMD_ML[j]] + _RMD_KL[rnd], _RMD_RL[j]) + el
        al, bl, cl, dl, el = el, al, bl, _rmd_rol(cl, 10), dl
        ar = _rmd_rol(ar + _rmd_f(br, cr, dr, 4 - rnd) + x[_RMD_MR[j]] + _RMD_KR[rnd], _RMD_RR[j]) + er
        ar, br, cr, dr, er = er, ar, br, _rmd_rol(cr, 10), dr
    return ((h1 + cl + dr) & 0xffffffff, (h2 + dl + er) & 0xffffffff,
            (h3 + el + ar) & 0xffffffff, (h4 + al + br) & 0xffffffff,
            (h0 + bl + cr) & 0xffffffff)


def _ripemd160_pure(data):
    """Pure-Python RIPEMD-160 (no OpenSSL). Byte-identical to the C implementation."""
    st = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
    for b in range(len(data) >> 6):
        st = _rmd_compress(*st, data[64 * b:64 * (b + 1)])
    pad = b"\x80" + b"\x00" * ((119 - len(data)) & 63)
    fin = data[len(data) & ~63:] + pad + (8 * len(data)).to_bytes(8, 'little')
    for b in range(len(fin) >> 6):
        st = _rmd_compress(*st, fin[64 * b:64 * (b + 1)])
    return b"".join((h & 0xffffffff).to_bytes(4, 'little') for h in st)


def ripemd160(data):
    """RIPEMD-160 hash. Prefers the platform hashlib/OpenSSL; falls back to the
    pure-Python implementation above where OpenSSL 3 has dropped ripemd160."""
    try:
        return hashlib.new('ripemd160', data).digest()
    except (ValueError, TypeError):
        return _ripemd160_pure(data)


def hash160(data):
    """HASH160: RIPEMD160(SHA256(data))."""
    return ripemd160(sha256(data))


def tagged_hash(tag, data):
    """BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = sha256(tag.encode('utf-8'))
    return sha256(tag_hash + tag_hash + data)


# ─────────────────────────────────────────────
# Base58Check (xpub / ypub / zpub / tpub / P2PKH / P2SH)
# ─────────────────────────────────────────────

B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}


def base58_encode(data):
    """Encode bytes to Base58."""
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, remainder = divmod(n, 58)
        result = B58_ALPHABET[remainder] + result
    # Preserve leading zero bytes.
    for byte in data:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result


def base58_decode(s):
    """Decode a Base58 string to bytes. Rejects non-Base58 characters."""
    if not isinstance(s, str):
        raise ValueError(
            f"expected Base58 string, got {type(s).__name__}"
        )
    if s == '':
        raise ValueError("empty string is not a valid Base58 input")
    n = 0
    for char in s:
        if char not in _B58_INDEX:
            raise ValueError(
                f"invalid Base58 character {char!r}: extended keys use "
                f"the alphabet [1-9A-HJ-NP-Za-km-z] (no 0/O/I/l)."
            )
        n = n * 58 + _B58_INDEX[char]
    # Convert integer back to bytes.
    num_bytes = (n.bit_length() + 7) // 8
    decoded = n.to_bytes(num_bytes, 'big') if num_bytes else b''
    # Restore leading zero bytes lost by the integer round-trip.
    leading_ones = 0
    for c in s:
        if c == '1':
            leading_ones += 1
        else:
            break
    return b'\x00' * leading_ones + decoded


def base58check_encode(payload, version_byte):
    """Encode `payload` with a single version byte + 4-byte double-SHA256 checksum."""
    versioned = bytes([version_byte]) + payload
    checksum = sha256(sha256(versioned))[:4]
    return base58_encode(versioned + checksum)


# ─────────────────────────────────────────────
# Bech32 / Bech32m (BIP173 / BIP350)
# ─────────────────────────────────────────────

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2bc830a3


def _bech32_polymod(values):
    """Internal function for Bech32 checksum computation."""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    """Expand the HRP for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data, spec):
    """Create a Bech32 or Bech32m checksum."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ spec
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp, witver, witprog):
    """Encode a Bech32 address (witness version 0)."""
    # _convertbits returns None on invalid input;
    # pre-fix the `[witver] + None` concat raised an opaque TypeError from
    # deep in the call stack. Explicit ValueError surface matches the rest
    # of this module and gives the caller a useful error.
    converted = _convertbits(witprog, 8, 5)
    if converted is None:
        raise ValueError("invalid witness program (bit-conversion failed)")
    data = [witver] + converted
    checksum = _bech32_create_checksum(hrp, data, BECH32_CONST)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in data + checksum])


def bech32m_encode(hrp, witver, witprog):
    """Encode a Bech32m address (witness version 1+)."""
    # See bech32_encode above.
    converted = _convertbits(witprog, 8, 5)
    if converted is None:
        raise ValueError("invalid witness program (bit-conversion failed)")
    data = [witver] + converted
    checksum = _bech32_create_checksum(hrp, data, BECH32M_CONST)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in data + checksum])


# ─────────────────────────────────────────────
# Address encoders
# ─────────────────────────────────────────────

def encode_p2pkh(pubkey, version_byte=0x00):
    """BIP44 legacy P2PKH address.

    Mainnet version_byte = 0x00 → '1...' addresses.
    Testnet version_byte = 0x6F → 'm...' or 'n...' addresses.
    """
    return base58check_encode(hash160(pubkey), version_byte)


def encode_p2sh_p2wpkh(pubkey, version_byte=0x05):
    """BIP49 nested SegWit (P2SH-wrapped P2WPKH).

    Mainnet version_byte = 0x05 → '3...' addresses.
    Testnet version_byte = 0xC4 → '2...' addresses.
    """
    # Witness program: OP_0 <20-byte-key-hash>
    witness_program = b'\x00\x14' + hash160(pubkey)
    script_hash = hash160(witness_program)
    return base58check_encode(script_hash, version_byte)


def encode_p2wpkh(pubkey, hrp="bc"):
    """BIP84 native SegWit P2WPKH (bech32, witness version 0).

    hrp = 'bc' for mainnet (bc1q...), 'tb' for testnet (tb1q...).
    """
    return bech32_encode(hrp, 0, hash160(pubkey))


def encode_p2tr(pubkey, hrp="bc"):
    """BIP86 Taproot P2TR (bech32m, witness version 1).

    Implements the BIP86 key-path tweak: the output key is the
    internal public key tweaked by the BIP341 TapTweak hash computed
    from the internal key's x-coordinate.
    """
    # x-only internal key (drop the y-parity prefix byte).
    x_only = pubkey[1:]
    tweak = tagged_hash("TapTweak", x_only)
    # BIP341 is fail-closed: a tweak scalar t >= n is invalid and must be
    # rejected, not reduced mod n. Unreachable for any real key (Pr ~ 2^-128),
    # but reducing would silently accept an out-of-range tweak; rejecting matches
    # the Bitcoin Witness appliance's Schnorr path.
    tweak_int = int.from_bytes(tweak, 'big')
    if tweak_int >= N:
        raise ValueError("TapTweak scalar >= curve order (invalid; BIP341)")

    # Decompress the internal key. BIP340 requires an even-y internal key;
    # if y is odd, negate the point before tweaking.
    internal_point = point_from_pubkey(pubkey)
    x_int, y_int = internal_point
    if y_int % 2 != 0:
        internal_point = (x_int, P - y_int)

    tweak_point = point_multiply(tweak_int)
    output_point = point_add(internal_point, tweak_point)
    if output_point is POINT_AT_INFINITY:
        raise ValueError("Tweaked Taproot key is the point at infinity")

    output_x = output_point[0].to_bytes(32, 'big')
    return bech32m_encode(hrp, 1, output_x)


# ─────────────────────────────────────────────
# Extended-key version-byte table (SLIP-132)
# ─────────────────────────────────────────────
#
# The version bytes identify both the input prefix (first four chars of
# the Base58Check string) AND the intended address type. Multisig SLIP-132
# variants (Ypub / Zpub capitalised) and non-standard versions are not
# supported here and will be rejected with an explicit error.

VERSION_TABLE = {
    # version bytes  : (version_name, network,   address_type,    address_encoder,    encoder_args)
    bytes.fromhex('0488B21E'): ('xpub', 'mainnet', 'p2pkh',         encode_p2pkh,       {'version_byte': 0x00}),
    bytes.fromhex('049D7CB2'): ('ypub', 'mainnet', 'p2sh-p2wpkh',   encode_p2sh_p2wpkh, {'version_byte': 0x05}),
    bytes.fromhex('04B24746'): ('zpub', 'mainnet', 'p2wpkh',        encode_p2wpkh,      {'hrp': 'bc'}),
    bytes.fromhex('043587CF'): ('tpub', 'testnet', 'p2pkh',         encode_p2pkh,       {'version_byte': 0x6F}),
}


# ─────────────────────────────────────────────
# Extended public key decoder
# ─────────────────────────────────────────────

def decode_extended_pubkey(s):
    """Decode an extended public key string (xpub / ypub / zpub / tpub).

    Returns a dict with nine keys:
        version             (bytes, 4)   raw version bytes
        version_name        (str)        'xpub' / 'ypub' / 'zpub' / 'tpub'
        network             (str)        'mainnet' / 'testnet'
        address_type        (str)        'p2pkh' / 'p2sh-p2wpkh' / 'p2wpkh'
        depth               (int)        BIP32 depth
        parent_fingerprint  (bytes, 4)   parent key fingerprint
        child_index         (int)        child index at this depth
        chain_code          (bytes, 32)  chain code
        pubkey              (bytes, 33)  compressed public key (prefix 02/03)

    Raises ValueError on any structural or checksum problem, or if the
    input is actually an extended private key (version bytes for xprv /
    yprv / zprv / tprv are explicitly rejected with a helpful hint).
    """
    if not isinstance(s, str):
        raise ValueError(
            f"expected an extended public key string, got {type(s).__name__}"
        )
    if not s:
        raise ValueError("extended public key string is empty")

    raw = base58_decode(s)
    if len(raw) != 82:
        raise ValueError(
            f"expected 82-byte Base58Check payload, got {len(raw)} bytes "
            f"(extended public keys are always 78 bytes + 4-byte checksum)"
        )

    payload = raw[:78]
    checksum = raw[78:82]
    if sha256(sha256(payload))[:4] != checksum:
        raise ValueError(
            "Base58Check checksum does not match. The extended public key "
            "is mistyped, truncated, or corrupted."
        )

    version = payload[0:4]
    if version not in VERSION_TABLE:
        # Give a specific diagnostic for the common "pasted an xprv" case.
        if version.hex() in ('0488ade4', '049d7878', '04b2430c', '04358394'):
            raise ValueError(
                f"xprv-class version bytes detected ({version.hex()}). "
                f"This tool is watch-only: it reads only xpub / ypub / "
                f"zpub / tpub. Do not paste xprv / yprv / zprv / tprv."
            )
        raise ValueError(
            f"unrecognised extended key version {version.hex()}. "
            f"xpubverify supports xpub (0488B21E), ypub (049D7CB2), "
            f"zpub (04B24746), and tpub (043587CF)."
        )

    version_name, network, address_type, _enc, _enc_args = VERSION_TABLE[version]

    depth = payload[4]
    parent_fingerprint = payload[5:9]
    child_index = struct.unpack('>I', payload[9:13])[0]
    chain_code = payload[13:45]
    pubkey = payload[45:78]

    if pubkey[0] not in (0x02, 0x03):
        raise ValueError(
            f"key payload does not start with 0x02 or 0x03 (got "
            f"0x{pubkey[0]:02x}). This is not a compressed public key."
        )

    # Also sanity-check that the point lies on the curve.
    # `point_from_pubkey` raises if not on curve.
    point_from_pubkey(pubkey)

    # BIP32 test vector 5, structural header coherence guard. The checksum proves
    # transport integrity and
    # the on-curve check proves the key payload is a valid point, but neither
    # catches a self-contradictory header: a master key (depth 0) has no parent and
    # no child index. embit and Bitcoin Core both refuse these; a verify-don't-trust
    # tool must surface a checksum-valid-but-incoherent key as corruption rather than
    # silently derive addresses from it (vec5 "zero depth with non-zero parent
    # fingerprint" / "... non-zero index"). Note: the version/payload-mismatch vec5
    # cases are already refused above, the 0x02/0x03 pubkey-prefix check rejects an
    # xpub carrying a private payload, and the VERSION_TABLE allowlist rejects any
    # unknown version, so only this depth-0 coherence guard is added here.
    if depth == 0:
        if parent_fingerprint != b'\x00\x00\x00\x00':
            raise ValueError(
                "Invalid extended key: depth is 0 (a master key) but the parent "
                "fingerprint is non-zero, a master key has no parent (BIP32)."
            )
        if child_index != 0:
            raise ValueError(
                "Invalid extended key: depth is 0 (a master key) but the child "
                "index is non-zero, a master key has no child index (BIP32)."
            )

    return {
        'version':            version,
        'version_name':       version_name,
        'network':            network,
        'address_type':       address_type,
        'depth':              depth,
        'parent_fingerprint': parent_fingerprint,
        'child_index':        child_index,
        'chain_code':         chain_code,
        'pubkey':             pubkey,
    }


# ─────────────────────────────────────────────
# BIP32 public child key derivation (CKDpub)
# ─────────────────────────────────────────────

def derive_child_pubkey(parent_pubkey, parent_chain, index):
    """BIP32 CKDpub, non-hardened public child key derivation.

    Given a parent compressed public key (33 bytes), a parent chain code
    (32 bytes), and a non-hardened index in [0, 2^31), returns the tuple
    (child_pubkey_compressed, child_chain_code).

    Hardened derivation (index >= 2^31) requires the matching extended
    private key and is explicitly rejected, this tool has no code path
    that can produce a hardened child.
    """
    if not isinstance(index, int) or index < 0:
        raise ValueError(f"child index must be a non-negative int, got {index!r}")
    if index >= 0x80000000:
        raise ValueError(
            "cannot derive a hardened child (index >= 2^31) from a public "
            "key alone. Hardened derivation requires the matching xprv, "
            "which xpubverify does not accept."
        )

    data = parent_pubkey + struct.pack('>I', index)
    I = hmac.new(parent_chain, data, hashlib.sha512).digest()  # noqa: E741, BIP32 spec convention; uppercase I matches BIP-doc wording in the canonical key-derivation algorithm
    IL = int.from_bytes(I[:32], 'big')

    if IL >= N:
        raise ValueError("derived offset is out of range; try the next index")

    parent_point = point_from_pubkey(parent_pubkey)
    child_point = point_add(parent_point, point_multiply(IL))
    if child_point is POINT_AT_INFINITY:
        raise ValueError("derived point is at infinity; try the next index")

    child_pubkey = compress_pubkey(child_point)
    child_chain = I[32:]
    return child_pubkey, child_chain


# ─────────────────────────────────────────────
# High-level: derive a set of addresses from an extended public key
# ─────────────────────────────────────────────

def derive_addresses(xpub_string, receive_count=10, change_count=5, taproot=False):
    """Derive receive and change addresses from an extended public key.

    Args:
        xpub_string:     an xpub / ypub / zpub / tpub (SLIP-132 encoded).
        receive_count:   how many branch-0 addresses to emit (default 10).
        change_count:    how many branch-1 addresses to emit (default 5).
        taproot:         if True, force BIP86 P2TR output. Requires an xpub
                         (BIP86 convention uses the 0488B21E version bytes;
                         deriving taproot from ypub/zpub/tpub is nonsense
                         and is rejected).

    Returns a JSON-serialisable dict:
        {
          "version_name":        "zpub",
          "network":             "mainnet",
          "address_type":        "p2wpkh",
          "depth":               3,
          "parent_fingerprint":  "7ef32bdb",
          "account_fingerprint": "fd13aac9",  # hash160(account pubkey)[:4]
          "child_index":         2147483648,
          "source_extended_key": "<the input xpub_string verbatim>",
          "derivation_path":     "",           # always empty; see below
          "receive":             [str, ...],   # len == receive_count
          "change":              [str, ...],   # len == change_count
          "descriptors":         {"receive": "...", "change": "..."},
        }

    `source_extended_key` carries the input verbatim so a future verifier
    holding only the saved result can re-derive the `/0/i` and `/1/i` children
    independently. `account_fingerprint` is the BIP32 fingerprint of the
    account key itself (hash160 of its compressed pubkey, first 4 bytes),
    version-byte-independent, matching the appliance's "Account Key
    Fingerprint". `descriptors` are the BIP380 receive/change output
    descriptors, each with its checksum.

    `derivation_path` is always an empty string. A bare extended key cannot
    honestly attest a full `m/purpose'/coin'/account'` path: the account index
    lives in the key's child-number, but purpose' and coin' are not recoverable
    from a bare key, and the key carries no key-origin, so any full path would
    be partly fabricated. This matches Bitcoin Core, BDK, Electrum, and Specter,
    which all decline to reconstruct a full account path from a bare xpub. The
    field is kept (empty) for schema parity and to leave room for a future
    key-origin input; the `--report` shows the relative structure and a labeled
    child-number inference instead.
    """
    for label, count in (('receive_count', receive_count),
                         ('change_count', change_count)):
        # The second clause `isinstance(count,
        # bool)` is intentional, Python `bool` is a subclass of `int`,
        # so `True` and `False` would pass the first `isinstance(count,
        # int)` check and then evaluate as 1/0 in `count < 1`, silently
        # treating a programming-error `derive_addresses(xpub,
        # receive_count=True)` as `receive_count=1`. The `or
        # isinstance(count, bool)` short-circuits that path with a
        # ValueError. Test coverage in test_xpubverify.py.
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError(
                f"{label} must be a positive int, got {count!r}"
            )
        if count > 10000:
            raise ValueError(
                f"{label}={count} exceeds the 10000 safety cap"
            )

    info = decode_extended_pubkey(xpub_string)

    if taproot:
        if info['version_name'] != 'xpub':
            raise ValueError(
                "--taproot requires an xpub (BIP86 uses 0488B21E version "
                "bytes). Do not pass ypub / zpub / tpub with --taproot."
            )
        address_type = 'p2tr'
        encoder = encode_p2tr
        encoder_args = {'hrp': 'bc'}
    else:
        _, _, address_type, encoder, encoder_args = VERSION_TABLE[info['version']]

    def _branch(branch_idx, n):
        """Derive n addresses on the given branch (0=receive, 1=change)."""
        branch_pub, branch_chain = derive_child_pubkey(
            info['pubkey'], info['chain_code'], branch_idx
        )
        out = []
        for i in range(n):
            child_pub, _ = derive_child_pubkey(branch_pub, branch_chain, i)
            out.append(encoder(child_pub, **encoder_args))
        return out

    receive = _branch(0, receive_count)
    change = _branch(1, change_count)

    # source_extended_key carries the input verbatim. derivation_path is
    # always empty: a bare extended key cannot honestly attest a full
    # m/purpose'/coin'/account' path. The account index is in the key's own
    # child-number, but purpose' and coin' are not recoverable from a bare key
    # (only inferable from the version byte / network), and the key carries no
    # key-origin, so any full path would be partly fabricated. This matches
    # Bitcoin Core, BDK, Electrum, and Specter, which all decline to reconstruct
    # a full account path from a bare xpub (only Sparrow and BlueWallet assume
    # account 0, the antipattern this avoids). The report shows the relative
    # /0/* and /1/* structure and, for an account-level key, a clearly labeled
    # child-number inference (a hint, not a verified path). The field is kept
    # (always '') for schema parity with the appliance result dict and to leave
    # room for a future key-origin input. (verify-don't-trust: never derive a
    # confidently-wrong label, and never fabricate a field the operator never
    # supplied.)
    derivation_path = ''

    result = {
        'version_name':        info['version_name'],
        'network':             info['network'],
        'address_type':        address_type,
        'depth':               info['depth'],
        'parent_fingerprint':  info['parent_fingerprint'].hex(),
        # BIP32 fingerprint OF THIS account key itself, first 4 bytes of
        # hash160(compressed pubkey). Distinct from parent_fingerprint, and not
        # the wallet's master fingerprint (watch-only mode cannot see that).
        # Version-byte-independent (zpub/ypub/xpub share the same pubkey), so it
        # matches the appliance's "Account Key Fingerprint" for the same key.
        'account_fingerprint': hash160(info['pubkey'])[:4].hex(),
        'child_index':         info['child_index'],
        'source_extended_key': xpub_string,
        'derivation_path':     derivation_path,
        'receive':             receive,
        'change':              change,
    }
    # Attach the BIP380 single-sig output descriptors (receive + change,
    # each with its #checksum). These are real, re-importable descriptors; only
    # the human-readable `--report` that wraps them is a demo. None if the key
    # cannot be re-versioned (never a wrong descriptor).
    result['descriptors'] = build_descriptors(result)
    return result


# ─────────────────────────────────────────────
# BIP380 output-descriptor checksum
# ─────────────────────────────────────────────
#
# Verbatim the canonical Bitcoin Core algorithm, anchored to the official
# `raw(deadbeef)#89f8spxm` vector in the self-test. Ported from the Bitcoin
# Witness appliance so a descriptor xpubverify prints re-imports byte-for-byte
# into the same wallets the appliance targets. Pure stdlib.

_DESC_INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
)
_DESC_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_DESC_GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]


def _descsum_polymod(symbols):
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= _DESC_GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def descriptor_checksum(descriptor_body):
    """Return the 8-char BIP380 checksum for a descriptor body (no trailing '#')."""
    symbols, groups = [], []
    for c in descriptor_body:
        v = _DESC_INPUT_CHARSET.find(c)
        if v < 0:
            raise ValueError(f"character {c!r} not in descriptor charset")
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    symbols += [0] * 8
    checksum = _descsum_polymod(symbols) ^ 1
    return "".join(_DESC_CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31]
                   for i in range(8))


def descriptor_checksum_ok(desc_with_sum):
    """True iff '<body>#<8-char-sum>' carries a valid BIP380 checksum."""
    if "#" not in desc_with_sum:
        return False
    body, _, sum_part = desc_with_sum.rpartition("#")
    if len(sum_part) != 8 or any(c not in _DESC_CHECKSUM_CHARSET for c in sum_part):
        return False
    try:
        return descriptor_checksum(body) == sum_part
    except ValueError:
        return False


def _to_plain_xpub(extkey):
    """Re-version a SLIP-132 xpub/ypub/zpub (or tpub) to the plain extended key
    of the same network that BIP380 descriptors require: mainnet xpub
    (0x0488b21e) for xpub/ypub/zpub, testnet tpub (0x043587cf) for tpub. Key
    material, chain code, depth, parent-fp and child index are unchanged, only
    the 4 version bytes + the trailing base58check digest are recomputed. Returns
    None if the key is not decodable (the descriptor is then omitted, never wrong).

    Network-preserving: an earlier version forced the mainnet xpub byte for every
    input, so a tpub produced a descriptor carrying a mainnet xpub that did not
    round-trip to the testnet addresses this tool prints."""
    # Testnet extended-pubkey versions map to the plain testnet key (tpub); every
    # mainnet SLIP-132 variant maps to the plain mainnet xpub.
    _TESTNET_VERSIONS = {b"\x04\x35\x87\xcf"}  # tpub
    try:
        raw = base58_decode(extkey)
        payload, chk = raw[:-4], raw[-4:]
        if sha256(sha256(payload))[:4] != chk:
            return None
        target = (b"\x04\x35\x87\xcf" if payload[:4] in _TESTNET_VERSIONS
                  else b"\x04\x88\xb2\x1e")
        new = target + payload[4:]
        new_chk = sha256(sha256(new))[:4]
        return base58_encode(new + new_chk)
    except (ValueError, IndexError):
        return None


# address_type -> (descriptor-function prefix, suffix)
_DESC_WRAP = {
    'p2pkh':       ('pkh(', ')'),
    'p2sh-p2wpkh': ('sh(wpkh(', '))'),
    'p2wpkh':      ('wpkh(', ')'),
    'p2tr':        ('tr(', ')'),
}


def build_descriptors(result):
    """BIP380 single-sig output descriptors (receive branch 0 + change branch 1),
    each with its #checksum, from a derive_addresses() result.

    Returns {'receive': str, 'change': str} or None if the key cannot be
    re-versioned. The descriptors carry no key-origin `[fpr/path]`: an account
    xpub does not contain its master fingerprint or full derivation path, so none
    is claimed (inventing one would be a lie). They are still re-importable for
    watch-only use into Sparrow / Bitcoin Core / Specter, where each descriptor's
    own addresses cross-check against the ones printed alongside it."""
    wrap = _DESC_WRAP.get(result.get('address_type'))
    if wrap is None:
        return None
    xpub = _to_plain_xpub(result.get('source_extended_key', ''))
    if xpub is None:
        return None
    open_, close_ = wrap
    out = {}
    for name, branch in (('receive', 0), ('change', 1)):
        body = f"{open_}{xpub}/{branch}/*{close_}"
        out[name] = f"{body}#{descriptor_checksum(body)}"
    return out


# ─────────────────────────────────────────────
# demo verification report (--report)
# ─────────────────────────────────────────────
#
# A human-readable report that demonstrates the Bitcoin Witness Confidence
# Report format, produced by this free watch-only tool. It is deterministic
# (no clock, no randomness): re-running the identical command reproduces the
# bytes and the self-hash exactly, which is the property it exists to teach.
#
# It is a demo and it says so, at the top and again beside the hash. It is not
# the appliance's Confidence Report: not produced air-gapped, not GPG-signed.
# The self-hash is a self-checksum (re-run and compare), not a signature. Every
# path through render_demo_report() carries these statements; the test suite
# asserts they are present and that the report claims no assurance it lacks.

# DERIVATION RESULTS group header per script type (mirrors the appliance report).
_DEMO_GROUP_HEADER = {
    'p2pkh':       "Legacy (P2PKH)",
    'p2sh-p2wpkh': "Nested SegWit (P2SH-P2WPKH)",
    'p2wpkh':      "Native SegWit (P2WPKH)",
    'p2tr':        "Taproot (P2TR)",
}

# BIP number per script type, for the EXTENDED PUBLIC KEYS line.
_DEMO_BIP_NUM = {'p2pkh': 44, 'p2sh-p2wpkh': 49, 'p2wpkh': 84, 'p2tr': 86}

_DEMO_BANNER = "*** DEMO REPORT — NOT AIR-GAPPED, NOT GPG-SIGNED ***"
_HDR_W = 25  # header-grid label column width (matches the appliance report's label column)


def _hdr(label, value):
    """One aligned 'Label:            value' header-grid row (appliance-report alignment)."""
    return f"{(label + ':'):<{_HDR_W}}{value}"


def render_demo_report(result):
    """Render the demo watch-only verification report, mirroring the current
    Bitcoin Witness appliance Confidence Report format ("Extended Public Key
    Verification" type) so this free tool demonstrates the real layout: the
    aligned header grid, the account-key-fingerprint clarification, the
    derivation-path caveat, the OUTPUT DESCRIPTORS block, and the IMPORTANT +
    PRIVACY disclaimers.

    It stays a demo and says so (banner top and foot): not air-gapped, not
    GPG-signed; the Report SHA-256 is a self-checksum (re-run and compare), not
    a signature. It is deterministic (no clock, no randomness), re-running the
    identical command reproduces the bytes and the self-hash exactly, which is
    this demo's whole re-verify story (so the header grid carries no real
    timestamp)."""
    at = result['address_type']
    # An account-level key is depth 3 with a hardened child-number (the account
    # index). Branch on the key's own header, not on derivation_path (which is
    # always empty now, see derive_addresses).
    is_account = (result.get('depth') == 3
                  and result.get('child_index', 0) >= 0x80000000)
    L = []
    # Box header (mirrors the appliance report).
    L.append("╭" + "─" * 62 + "╮")
    L.append("         BITCOIN WITNESS — VERIFICATION CONFIDENCE REPORT")
    L.append("╰" + "─" * 62 + "╯")
    L.append("")
    # demo honesty banner + caveat (top).
    L.append(_DEMO_BANNER)
    L.append("  This demonstrates the Bitcoin Witness Confidence Report format,")
    L.append("  produced by the free, watch-only xpubverify tool. It proves only")
    L.append("  that the addresses below derive from the extended public key")
    L.append("  shown; not where that key came from, and nothing about funds.")
    L.append("  It is not air-gapped and not GPG-signed; the Report SHA-256 at the")
    L.append("  foot is a self-checksum (re-run and compare), not a signature. For")
    L.append("  a real air-gapped, GPG-signed Confidence Report, use the Bitcoin")
    L.append("  Witness appliance: https://bitcoinwitness.org")
    L.append("")
    # Header grid (aligned; deterministic values, no clock).
    net = "Bitcoin mainnet" if result.get('network') == 'mainnet' else "Bitcoin testnet"
    L.append(_hdr("Date", "(deterministic demo, no timestamp; the appliance stamps a real UTC time)"))
    L.append(_hdr("Device", "xpubverify (free watch-only tool)"))
    L.append(_hdr("Bitcoin Witness Version", f"xpubverify v{XPUBVERIFY_VERSION}"))
    L.append(_hdr("Network", net))
    L.append(_hdr("Air-Gap Status", "DEMO (online-capable free tool, not the air-gapped appliance)"))
    L.append("")
    L.append(_hdr("VERIFICATION TYPE", "Extended Public Key Verification"))
    L.append("─" * 66)
    L.append("")
    L.append(_hdr("What this is for", "import this extended public key to watch the funds"))
    L.append(" " * _HDR_W + "and confirm addresses. It cannot spend. Spending")
    L.append(" " * _HDR_W + "needs the seed backup, which is held separately and")
    L.append(" " * _HDR_W + "is deliberately not in this package.")
    L.append("")
    L.append(_hdr("Account Key Fingerprint", result.get('account_fingerprint', '').upper()))
    L.append("  (BIP32 fingerprint of this account key. It is not the wallet's")
    L.append("   master fingerprint, which watch-only mode cannot see.)")
    L.append("")
    # DERIVATION RESULTS
    L.append("DERIVATION RESULTS")
    L.append("─" * 66)
    L.append("")
    L.append("  " + _DEMO_GROUP_HEADER.get(at, at))
    for i, a in enumerate(result['receive']):
        L.append(f"    Receive  #{i}:  {a}")
    for i, a in enumerate(result['change']):
        L.append(f"    Change   #{i}:  {a}")
    L.append("")
    bipn = _DEMO_BIP_NUM.get(at)
    if is_account:
        acct = result.get('child_index', 0) - 0x80000000
        L.append("    Account-level key. The full derivation path is not "
                 "determinable from a bare")
        L.append("    extended key, so none is claimed. The addresses above are "
                 "this key's own")
        L.append("    /0/* (receive) and /1/* (change) children.")
        if bipn is not None:
            L.append(f"    The key's child-number implies account {acct} under the "
                     f"BIP{bipn} convention")
            L.append("    (a hint, not a verified path).")
    else:
        L.append(f"    Key depth {result.get('depth')}: not an account-level key, so no "
                 f"account path applies.")
    L.append("")
    # EXTENDED PUBLIC KEYS
    L.append("EXTENDED PUBLIC KEYS")
    L.append("─" * 66)
    L.append("")
    if is_account and bipn is not None:
        L.append(f"  {result['version_name']} (BIP{bipn}):")
    else:
        L.append(f"  {result['version_name']} (depth {result.get('depth')}):")
    L.append(f"    {result['source_extended_key']}")
    L.append("")
    # OUTPUT DESCRIPTORS
    descs = result.get('descriptors')
    if descs:
        L.append("OUTPUT DESCRIPTORS  (receive /0/*; change = same with /1/*)")
        L.append("─" * 66)
        L.append("")
        L.append(f"  {descs['receive']}")
        L.append("")
    # IMPORTANT + PRIVACY block (mirrors the appliance report verbatim).
    L.append("═" * 68)
    L.append("  IMPORTANT: This report contains zero seed or other secret material.")
    L.append("  Store alongside your seed backup. Hand to your estate attorney.")
    L.append("  Include in your inheritance package.")
    L.append("")
    L.append("  PRIVACY: The extended public keys and addresses above cannot spend,")
    L.append("  but they reveal every past transaction and every future address of")
    L.append("  this account to anyone who holds them. Treat this report as")
    L.append("  financially sensitive, and share it only with people you intend to")
    L.append("  have that visibility.")
    L.append("═" * 68)
    L.append("")
    # HOW TO RE-VERIFY (adapted for the standalone deterministic demo).
    L.append("  HOW TO RE-VERIFY (no seed required):")
    L.append("    1. Import the extended public key above into a watch-only wallet.")
    L.append("       Sparrow accepts every key form; for Bitcoin Core use the")
    L.append("       descriptor form; Electrum has no Taproot.")
    L.append("    2. Confirm Receive #0 matches the first receive address shown here.")
    L.append("    3. Recompute the Report SHA-256 below and confirm it matches. This")
    L.append("       report is deterministic, so re-running the identical command")
    L.append("       reproduces every byte above the hash and the hash itself; the")
    L.append("       hash is a self-checksum, not a signature.")
    L.append("")
    L.append("  Independently verified on [ verifier signs and dates here ]. Trust the math.")
    L.append("")
    L.append("  " + _DEMO_BANNER)
    body = "\n".join(L) + "\n"
    digest = sha256(body.encode("utf-8")).hex()
    return body + f"Report SHA-256: {digest}"


# ─────────────────────────────────────────────
# Self-test (embedded vectors)
# ─────────────────────────────────────────────
#
# Test Vector 1 comes from the canonical BIP39 12-word
# "abandon abandon ... about" (no passphrase). Extended public keys at
# m/44'/0'/0', m/49'/0'/0', m/84'/0'/0', m/86'/0'/0'. The first three
# receive addresses are published for BIP44 / BIP49 / BIP84 and the
# first BIP86 address matches the canonical Taproot vector.

_TV1_XPUB = ("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5W"
             "SWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj")
_TV1_YPUB = ("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDW"
             "CxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP")
_TV1_ZPUB = ("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3"
             "EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
_TV1_BIP86_XPUB = ("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxar"
                   "j2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj"
                   "92pReUsQ")

_TV1_BIP84_RECEIVE = [
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z",
]
_TV1_BIP44_RECEIVE = [
    "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP",
    "1MNF5RSaabFwcbtJirJwKnDytsXXEsVsNb",
]
_TV1_BIP49_RECEIVE_0 = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
_TV1_BIP86_RECEIVE_0 = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

# BIP32 Vector 1 master xpub. Used to confirm the decoder handles the
# "depth-0, empty parent fingerprint" corner correctly.
_BIP32_TV1_MASTER_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2g"
    "Z29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)


def _self_test():
    """Run the embedded test vectors. Returns 0 on all-green, 1 otherwise."""
    print("xpubverify.py v" + XPUBVERIFY_VERSION + ", self-test")
    print("-" * 55)

    failures = 0

    def _check(label, got, expected):
        nonlocal failures
        if got == expected:
            print(f"  [PASS] {label}")
        else:
            failures += 1
            print(f"  [FAIL] {label}")
            print(f"         expected: {expected!r}")
            print(f"         got:      {got!r}")

    def _check_raises(label, fn):
        nonlocal failures
        try:
            fn()
        except ValueError:
            print(f"  [PASS] {label}")
            return
        except Exception as e:
            failures += 1
            print(f"  [FAIL] {label}: expected ValueError, got {type(e).__name__}: {e}")
            return
        failures += 1
        print(f"  [FAIL] {label}: expected ValueError, no exception raised")

    # TV1 zpub → BIP84 native SegWit
    z = derive_addresses(_TV1_ZPUB, receive_count=3, change_count=1)
    _check("TV1 zpub version_name", z['version_name'], 'zpub')
    _check("TV1 zpub address_type", z['address_type'], 'p2wpkh')
    _check("TV1 BIP84 receive[0..2]", z['receive'], _TV1_BIP84_RECEIVE)
    # Schema-field assertions.
    _check("TV1 zpub source_extended_key", z['source_extended_key'], _TV1_ZPUB)
    _check("TV1 zpub derivation_path empty", z['derivation_path'], "")

    # TV1 xpub → BIP44 legacy
    x = derive_addresses(_TV1_XPUB, receive_count=3, change_count=1)
    _check("TV1 xpub address_type", x['address_type'], 'p2pkh')
    _check("TV1 BIP44 receive[0..2]", x['receive'], _TV1_BIP44_RECEIVE)
    _check("TV1 xpub derivation_path empty", x['derivation_path'], "")

    # TV1 ypub → BIP49 nested SegWit
    y = derive_addresses(_TV1_YPUB, receive_count=1, change_count=1)
    _check("TV1 ypub address_type", y['address_type'], 'p2sh-p2wpkh')
    _check("TV1 BIP49 receive[0]", y['receive'][0], _TV1_BIP49_RECEIVE_0)
    _check("TV1 ypub derivation_path empty", y['derivation_path'], "")

    # TV1 xpub + --taproot → BIP86 P2TR
    t = derive_addresses(_TV1_BIP86_XPUB, receive_count=1, change_count=1,
                         taproot=True)
    _check("TV1 BIP86 address_type", t['address_type'], 'p2tr')
    _check("TV1 BIP86 receive[0]", t['receive'][0], _TV1_BIP86_RECEIVE_0)
    _check("TV1 BIP86 derivation_path empty", t['derivation_path'], "")

    # BIP32 Vector 1 master, decode without deriving.
    m = decode_extended_pubkey(_BIP32_TV1_MASTER_XPUB)
    _check("BIP32 TV1 master depth", m['depth'], 0)
    _check("BIP32 TV1 master parent_fingerprint",
           m['parent_fingerprint'].hex(), '00000000')
    _check("BIP32 TV1 master child_index", m['child_index'], 0)
    _check("BIP32 TV1 master chain_code length", len(m['chain_code']), 32)
    _check("BIP32 TV1 master pubkey length", len(m['pubkey']), 33)

    # Bad-checksum rejection (flip last char).
    bad_cs = _TV1_ZPUB[:-1] + ('B' if _TV1_ZPUB[-1] != 'B' else 'C')
    _check_raises("rejects checksum-corrupted zpub",
                  lambda: decode_extended_pubkey(bad_cs))

    # xprv rejection (wrong version bytes, first 4 chars "xprv").
    _check_raises(
        "rejects xprv-class version bytes",
        lambda: decode_extended_pubkey(
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        ),
    )

    # Hardened CKDpub rejection.
    z_info = decode_extended_pubkey(_TV1_ZPUB)
    _check_raises(
        "rejects hardened child index",
        lambda: derive_child_pubkey(z_info['pubkey'], z_info['chain_code'],
                                    0x80000000),
    )

    # Invalid Base58 character.
    _check_raises(
        "rejects Base58 input containing '0'",
        lambda: decode_extended_pubkey(_TV1_ZPUB[:-1] + '0'),
    )

    # --taproot with a zpub should be rejected.
    _check_raises(
        "rejects --taproot on a zpub",
        lambda: derive_addresses(_TV1_ZPUB, taproot=True),
    )

    print("-" * 55)
    if failures == 0:
        print("ALL SELF-TEST CHECKS PASSED")
        return 0
    print(f"{failures} SELF-TEST CHECK(S) FAILED")
    return 1


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

_USAGE = """\
xpubverify v{version}. Public key in. Addresses out.

Usage:
  python3 xpubverify.py <xpub|ypub|zpub|tpub>
  python3 xpubverify.py --json <xpub|ypub|zpub|tpub>
  python3 xpubverify.py --report <xpub|ypub|zpub|tpub>
  python3 xpubverify.py --receive-count 20 --change-count 10 <zpub>
  python3 xpubverify.py --taproot <xpub-at-m/86'/0'/0'>
  python3 xpubverify.py --self-test

If the extended public key is not supplied as a positional argument and
stdin is not a terminal, it is read from stdin.

Flags:
  --receive-count N   Number of receive (branch 0) addresses. Default 10.
  --change-count N    Number of change (branch 1) addresses.  Default 5.
  --taproot           Force BIP86 P2TR output. Requires an xpub input.
  --json              Emit a single JSON object instead of a text report.
  --report            Emit a demo watch-only verification report: the addresses
                      plus BIP380 output descriptors and a deterministic
                      self-hash. It demonstrates the Bitcoin Witness Confidence
                      Report format, it is not air-gapped and not GPG-signed.
  --self-test         Run embedded test vectors and exit.
  --version           Print the tool version and exit.
  --help, -h          Show this help and exit.
"""


def _parse_value_flag(argv, name):
    """Pop `--name VALUE` from argv if present. Returns (value, remaining_argv)."""
    out = None
    i = 0
    filtered = []
    while i < len(argv):
        if argv[i] == name:
            if i + 1 >= len(argv):
                raise ValueError(f"{name} requires a value")
            out = argv[i + 1]
            i += 2
            continue
        filtered.append(argv[i])
        i += 1
    return out, filtered


def _parse_bool_flag(argv, *names):
    """Pop a bare boolean flag from argv. Returns (present, remaining_argv)."""
    present = False
    filtered = []
    for a in argv:
        if a in names:
            present = True
            continue
        filtered.append(a)
    return present, filtered


def _format_text(result):
    """Human-readable output block for non-JSON CLI mode."""
    lines = []
    lines.append("=" * 60)
    lines.append("  xpubverify v" + XPUBVERIFY_VERSION +
                 ", watch-only address derivation")
    lines.append("=" * 60)
    lines.append(f"  Source:             {result['version_name']} "
                 f"({result['address_type']}, {result['network']})")
    lines.append(f"  Depth:              {result['depth']}")
    lines.append(f"  Parent fingerprint: {result['parent_fingerprint']}")
    lines.append(f"  Child index:        {result['child_index']}")
    lines.append("")
    lines.append("  Receive addresses:")
    for i, a in enumerate(result['receive']):
        lines.append(f"    #{i:<3}  {a}")
    lines.append("")
    lines.append("  Change addresses:")
    for i, a in enumerate(result['change']):
        lines.append(f"    #{i:<3}  {a}")
    lines.append("")
    return "\n".join(lines)


def cli_mode(argv=None):
    """CLI entrypoint. Returns a process exit code."""
    if argv is None:
        argv = list(sys.argv[1:])
    else:
        argv = list(argv)

    if '--help' in argv or '-h' in argv:
        print(_USAGE.format(version=XPUBVERIFY_VERSION))
        return 0

    if '--version' in argv:
        print(XPUBVERIFY_VERSION)
        return 0

    if '--self-test' in argv:
        return _self_test()

    try:
        receive_raw, argv = _parse_value_flag(argv, '--receive-count')
        change_raw, argv = _parse_value_flag(argv, '--change-count')
        json_out, argv = _parse_bool_flag(argv, '--json')
        report_out, argv = _parse_bool_flag(argv, '--report')
        taproot, argv = _parse_bool_flag(argv, '--taproot')
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if json_out and report_out:
        print("ERROR: choose either --json or --report, not both.",
              file=sys.stderr)
        return 1

    # Reject unrecognised dash-prefixed flags up front.
    for a in argv:
        if a.startswith('--') or (a.startswith('-') and len(a) > 1 and not a[1].isdigit()):
            print(f"ERROR: unrecognised flag {a!r}. Run with --help for usage.",
                  file=sys.stderr)
            return 1

    try:
        receive_count = int(receive_raw) if receive_raw is not None else 10
        change_count = int(change_raw) if change_raw is not None else 5
    except ValueError:
        print("ERROR: --receive-count and --change-count must be integers.",
              file=sys.stderr)
        return 1

    if len(argv) > 1:
        print("ERROR: too many positional arguments. Pass exactly one "
              "extended public key, or pipe it on stdin.", file=sys.stderr)
        return 1

    if argv:
        xpub_string = argv[0].strip()
    elif sys.stdin is not None and not sys.stdin.isatty():
        try:
            # Read at most 202 bytes: an extended key is ~111 chars, and the
            # 200-char CLI cap below rejects anything longer, so there is no
            # reason to slurp an unbounded pipe (cat /dev/zero | ...) into RAM.
            xpub_string = sys.stdin.read(202).strip()
        except UnicodeDecodeError:
            print("ERROR: input is not text. An extended public key is an "
                  "ASCII string (xpub/ypub/zpub/tpub…), did you pipe a binary "
                  "file?", file=sys.stderr)
            return 1
    else:
        print("ERROR: no extended public key provided.", file=sys.stderr)
        print("Run 'python3 xpubverify.py --help' for usage.", file=sys.stderr)
        return 1

    if not xpub_string:
        print("ERROR: extended public key string is empty.", file=sys.stderr)
        return 1
    # An extended public key is a fixed ~111-char Base58 string; reject anything
    # far longer before the (quadratic) Base58 decode, so a huge accidental paste
    # is a fast clean error rather than a multi-second CPU grind.
    if len(xpub_string) > 200:
        print(f"ERROR: input too long for an extended public key "
              f"({len(xpub_string)} chars; expected ~111).", file=sys.stderr)
        return 1

    try:
        result = derive_addresses(
            xpub_string,
            receive_count=receive_count,
            change_count=change_count,
            taproot=taproot,
        )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Force UTF-8 on stdout before emitting: the --report box-drawing characters
    # are outside legacy code pages (e.g. Windows cp1252 on a `> file` redirect
    # before Python 3.15 / PEP 686), and SECURITY.md promises no tracebacks in CLI
    # mode. The hasattr guard matters because the test harness redirects stdout to
    # io.StringIO, which has no reconfigure().
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass
    try:
        if report_out:
            print(render_demo_report(result))
        elif json_out:
            print(json.dumps(result, indent=2))
        else:
            print(_format_text(result))
    except BrokenPipeError:
        # A downstream reader (e.g. `| head`) closed the pipe early. Exit quietly
        # rather than surface a traceback (SECURITY.md: no tracebacks in CLI mode);
        # close stdout so the interpreter's exit-time flush does not re-raise.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(cli_mode())
