#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xpubverify, test suite.

Hand-rolled test runner (no unittest framework) to keep the test file
dependency-free just like the tool it tests. Run with:

    python3 test_xpubverify.py

Sections:
    1. Module-level TV1 / TV2 / BIP32 vectors
    2. BIP32 test-vector decode round-trip
    3. Real-world xpub / ypub / zpub / taproot derivation
    4. Edge-case error handling
    5. Safety greps against the xpubverify.py source
    6. JSON schema
    7. CLI integration (--self-test, --json, --version)
    8. Independent-reference cross-validation

Section 8 imports a third-party BIP32 library (embit or bip32) and asserts that xpubverify and the reference
library agree on every derived address. If none of those libraries is
installed, the cross-check SKIPs with an install hint instead of
failing. The tool's zero-dep guarantee means default CI has no
reference lib available. Auditors are expected to install at least one
reference library before declaring the suite green.
"""

import ast
import contextlib
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xpubverify as xv


PASS = 0
FAIL = 0
SKIP = 0
TOTAL = 0


def section(name):
    print()
    print("-" * 60)
    print(f"  {name}")
    print("-" * 60)


def test(name, got, expected):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    if got == expected:
        PASS += 1
        print(f"  ok    {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")
        print(f"        expected: {expected!r}")
        print(f"        got:      {got!r}")


def test_raises(name, fn, exc=ValueError):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    try:
        fn()
    except exc:
        PASS += 1
        print(f"  ok    {name}")
        return
    except Exception as e:
        FAIL += 1
        print(f"  FAIL  {name}: expected {exc.__name__}, got "
              f"{type(e).__name__}: {e}")
        return
    FAIL += 1
    print(f"  FAIL  {name}: expected {exc.__name__}, no exception raised")


def skip(name, reason):
    global SKIP, TOTAL
    TOTAL += 1
    SKIP += 1
    print(f"  SKIP  {name}: {reason}")


# ─────────────────────────────────────────────
# Section 1, Test vectors
# ─────────────────────────────────────────────

# Test Vector 1, 12-word "abandon abandon ... about", no passphrase
TV1_XPUB = ("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5W"
            "SWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj")
TV1_YPUB = ("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDW"
            "CxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP")
TV1_ZPUB = ("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3"
            "EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
TV1_BIP86_XPUB = ("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxar"
                  "j2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj"
                  "92pReUsQ")

TV1_BIP84_RECEIVE = [
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z",
]
TV1_BIP84_CHANGE_0 = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"

TV1_BIP44_RECEIVE = [
    "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP",
    "1MNF5RSaabFwcbtJirJwKnDytsXXEsVsNb",
]
TV1_BIP44_CHANGE_0 = "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH"

TV1_BIP49_RECEIVE_0 = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
TV1_BIP49_CHANGE_0 = "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7"

TV1_BIP86_RECEIVE = [
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    "bc1p0d0rhyynq0awa9m8cqrcr8f5nxqx3aw29w4ru5u9my3h0sfygnzs9khxz8",
]
TV1_BIP86_CHANGE_0 = "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"

# Test Vector 2, "abandon abandon ... about" with passphrase "TREZOR"
TV2_ZPUB = ("zpub6rXDN3yuixCtvAyzKn3uWLDr8qXKEQ2orduEL5AAysdHZmuPVUL2vbMQ"
            "DEhp8L9hRsgM8J8idDNPdZjrob8R5e7x7UoYXVdfjDG96TLa7La")
TV2_BIP84_RECEIVE_0 = "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu"

# BIP32 Vector 1 master xpub (depth 0, empty parent fingerprint).
BIP32_V1_MASTER_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2g"
    "Z29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)
# BIP32 Vector 1 at m/0'.
BIP32_V1_M0H_XPUB = (
    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6"
    "LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
)
# BIP32 Vector 2 master xpub.
BIP32_V2_MASTER_XPUB = (
    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCG"
    "u8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
)
# BIP32 Vector 3 master xpub (leading-zero edge case).
BIP32_V3_MASTER_XPUB = (
    "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRo"
    "P7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
)


# ─────────────────────────────────────────────
# Section 2, BIP32 decode round-trip
# ─────────────────────────────────────────────

def test_bip32_decode():
    section("BIP32 test vector decode round-trip")

    m1 = xv.decode_extended_pubkey(BIP32_V1_MASTER_XPUB)
    test("BIP32 V1 master depth",             m1['depth'], 0)
    test("BIP32 V1 master parent_fingerprint",
         m1['parent_fingerprint'].hex(), "00000000")
    test("BIP32 V1 master child_index",       m1['child_index'], 0)
    test("BIP32 V1 master chain_code length", len(m1['chain_code']), 32)
    test("BIP32 V1 master pubkey length",     len(m1['pubkey']), 33)
    test("BIP32 V1 master pubkey prefix",     m1['pubkey'][0] in (0x02, 0x03), True)

    m1h = xv.decode_extended_pubkey(BIP32_V1_M0H_XPUB)
    test("BIP32 V1 m/0' depth",           m1h['depth'], 1)
    test("BIP32 V1 m/0' child_index",     m1h['child_index'], 0x80000000)
    test("BIP32 V1 m/0' parent != zero",
         m1h['parent_fingerprint'] != b'\x00\x00\x00\x00', True)

    m2 = xv.decode_extended_pubkey(BIP32_V2_MASTER_XPUB)
    test("BIP32 V2 master depth", m2['depth'], 0)
    test("BIP32 V2 master version_name", m2['version_name'], 'xpub')

    m3 = xv.decode_extended_pubkey(BIP32_V3_MASTER_XPUB)
    test("BIP32 V3 master depth", m3['depth'], 0)


# ─────────────────────────────────────────────
# Section 3, Real-world derivation (TV1 / TV2)
# ─────────────────────────────────────────────

def test_derive_tv1():
    section("TV1 derivation (xpub / ypub / zpub)")

    z = xv.derive_addresses(TV1_ZPUB, receive_count=3, change_count=1)
    test("TV1 zpub version_name", z['version_name'], 'zpub')
    test("TV1 zpub network",      z['network'], 'mainnet')
    test("TV1 zpub address_type", z['address_type'], 'p2wpkh')
    test("TV1 zpub depth",        z['depth'], 3)
    test("TV1 BIP84 receive[0]",  z['receive'][0], TV1_BIP84_RECEIVE[0])
    test("TV1 BIP84 receive[1]",  z['receive'][1], TV1_BIP84_RECEIVE[1])
    test("TV1 BIP84 receive[2]",  z['receive'][2], TV1_BIP84_RECEIVE[2])
    test("TV1 BIP84 change[0]",   z['change'][0],  TV1_BIP84_CHANGE_0)

    x = xv.derive_addresses(TV1_XPUB, receive_count=3, change_count=1)
    test("TV1 xpub address_type", x['address_type'], 'p2pkh')
    test("TV1 BIP44 receive[0]",  x['receive'][0], TV1_BIP44_RECEIVE[0])
    test("TV1 BIP44 receive[1]",  x['receive'][1], TV1_BIP44_RECEIVE[1])
    test("TV1 BIP44 receive[2]",  x['receive'][2], TV1_BIP44_RECEIVE[2])
    test("TV1 BIP44 change[0]",   x['change'][0],  TV1_BIP44_CHANGE_0)

    y = xv.derive_addresses(TV1_YPUB, receive_count=1, change_count=1)
    test("TV1 ypub address_type", y['address_type'], 'p2sh-p2wpkh')
    test("TV1 BIP49 receive[0]",  y['receive'][0], TV1_BIP49_RECEIVE_0)
    test("TV1 BIP49 change[0]",   y['change'][0],  TV1_BIP49_CHANGE_0)


def test_derive_tv1_taproot():
    section("TV1 BIP86 taproot derivation")
    t = xv.derive_addresses(TV1_BIP86_XPUB, receive_count=3, change_count=1,
                            taproot=True)
    test("TV1 BIP86 address_type", t['address_type'], 'p2tr')
    test("TV1 BIP86 receive[0]",   t['receive'][0], TV1_BIP86_RECEIVE[0])
    test("TV1 BIP86 receive[1]",   t['receive'][1], TV1_BIP86_RECEIVE[1])
    test("TV1 BIP86 receive[2]",   t['receive'][2], TV1_BIP86_RECEIVE[2])
    test("TV1 BIP86 change[0]",    t['change'][0],  TV1_BIP86_CHANGE_0)


def test_derive_tv2():
    section("TV2 derivation (passphrase TREZOR)")
    z = xv.derive_addresses(TV2_ZPUB, receive_count=1, change_count=1)
    test("TV2 zpub address_type", z['address_type'], 'p2wpkh')
    test("TV2 BIP84 receive[0]",  z['receive'][0], TV2_BIP84_RECEIVE_0)
    # Guard the serialization's provenance: the parent fingerprint is that of
    # m/84'/0' (a40176dc), not the grandparent m/84'. A wrong value here means
    # the fixture string is not what any conformant wallet serializes.
    test("TV2 parent_fingerprint (m/84'/0')", z['parent_fingerprint'], "a40176dc")


# ─────────────────────────────────────────────
# Section 4, Edge-case error handling
# ─────────────────────────────────────────────

def test_edge_cases():
    section("Edge cases and error paths")

    # Bad checksum: flip the last char.
    bad_cs = TV1_ZPUB[:-1] + ('B' if TV1_ZPUB[-1] != 'B' else 'C')
    test_raises("bad checksum",
                lambda: xv.decode_extended_pubkey(bad_cs))

    # Non-Base58 characters.
    for ch in ('0', 'O', 'I', 'l'):
        test_raises(f"rejects non-Base58 char {ch!r}",
                    lambda ch=ch: xv.decode_extended_pubkey(TV1_ZPUB[:-1] + ch))

    # Truncated input.
    test_raises("rejects truncated zpub",
                lambda: xv.decode_extended_pubkey(TV1_ZPUB[:-8]))

    # Non-string types.
    test_raises("rejects bytes input",
                lambda: xv.decode_extended_pubkey(TV1_ZPUB.encode()))
    test_raises("rejects None",
                lambda: xv.decode_extended_pubkey(None))
    test_raises("rejects empty string",
                lambda: xv.decode_extended_pubkey(""))

    # xprv input with matching checksum (BIP32 V1 master xprv).
    test_raises(
        "rejects xprv-class version bytes",
        lambda: xv.decode_extended_pubkey(
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        ),
    )

    # Bad counts.
    for bad in (0, -1, 'five', 20000, None, 1.5, True):
        test_raises(f"rejects receive_count={bad!r}",
                    lambda bad=bad: xv.derive_addresses(TV1_ZPUB, receive_count=bad))
        test_raises(f"rejects change_count={bad!r}",
                    lambda bad=bad: xv.derive_addresses(TV1_ZPUB, change_count=bad))

    # Hardened index on derive_child_pubkey.
    info = xv.decode_extended_pubkey(TV1_ZPUB)
    test_raises("rejects hardened index on CKDpub",
                lambda: xv.derive_child_pubkey(info['pubkey'],
                                                info['chain_code'],
                                                0x80000000))
    test_raises("rejects negative index on CKDpub",
                lambda: xv.derive_child_pubkey(info['pubkey'],
                                                info['chain_code'],
                                                -1))

    # --taproot on non-xpub.
    test_raises("rejects --taproot on zpub",
                lambda: xv.derive_addresses(TV1_ZPUB, taproot=True))
    test_raises("rejects --taproot on ypub",
                lambda: xv.derive_addresses(TV1_YPUB, taproot=True))


def test_bip32_vec5_invalid():
    """BIP32 official test vector 5, every invalid extended key is refused.

    A verify-don't-trust tool must never derive an address from a
    checksum-valid-but-structurally-invalid key: it must refuse the detectable
    wrong input rather than silently derive a wrong output. These are the 16
    canonical vec5 invalids from the BIP32 spec. xpubverify is watch-only and the
    version-allowlist authority (VERSION_TABLE), so it refuses ALL 16 with no
    deferral: xprv-class versions by the xprv guard, unknown versions by the
    allowlist, bad pubkey prefixes / not-on-curve by the 0x02|0x03 + curve check,
    and, via the depth-0 header-coherence guard (added 2026-08-12), the two xpub
    'zero depth with non-zero parent fingerprint / index' cases. The class, not
    just these samples, is covered: the guards test structural properties
    (depth==0 ⇒ parent_fp==0 ∧ index==0; prefix ∈ {0x02,0x03}; version ∈ allowlist),
    not a blocklist of these specific strings."""
    section("BIP32 test vector 5, invalid extended keys refused")
    BIP32_TV5_INVALID = [
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",   # pubkey version / prvkey mismatch
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",   # prvkey version / pubkey mismatch
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",   # invalid pubkey prefix 04
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",   # invalid prvkey prefix 04
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",   # invalid pubkey prefix 01
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",   # invalid prvkey prefix 01
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",   # zero depth, non-zero parent fp (xprv)
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",   # zero depth, non-zero parent fp (xpub)
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",   # zero depth, non-zero index (xprv)
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",   # zero depth, non-zero index (xpub)
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",   # unknown version (1)
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",   # unknown version (2)
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",   # privkey 0
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",   # privkey n
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",   # pubkey not on curve
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",   # invalid checksum
    ]
    test("feeds all 16 official vec5 vectors", len(BIP32_TV5_INVALID), 16)
    for i, key in enumerate(BIP32_TV5_INVALID):
        test_raises(f"vec5[{i}] refused", lambda key=key: xv.decode_extended_pubkey(key))
    # Paired non-regression: a valid master xpub still decodes (guards do not
    # over-refuse a legitimate depth-0 key whose parent_fp==0 and index==0).
    test("valid master xpub still decodes (no over-refusal)",
         xv.decode_extended_pubkey(BIP32_V1_MASTER_XPUB)['depth'], 0)
    # Class coverage (not just these strings): freshly mutate a good xpub's header
    # to depth 0 + non-zero parent fp and confirm refusal, proves the guard keys on
    # the structural property, not the sample.
    _raw = bytearray(xv.base58_decode(BIP32_V1_M0H_XPUB))  # a real depth-1 key
    _raw[4] = 0                                            # force depth 0…
    # …but leave its (non-zero) parent fingerprint in place → now incoherent.
    _payload = bytes(_raw[:78])
    _bad = xv.base58_encode(_payload + xv.sha256(xv.sha256(_payload))[:4])  # fresh checksum
    test_raises("freshly-mutated depth0+nonzero-parent refused (class, not sample)",
                lambda: xv.decode_extended_pubkey(_bad))


# ─────────────────────────────────────────────
# Section 5, Safety greps on xpubverify.py source
# ─────────────────────────────────────────────

_SRC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xpubverify.py')


def _strip_comments_and_docstrings(src):
    """Return functional code only: strip # comments, triple-quoted docstrings,
    and the contents of ordinary string literals (delimiters kept, so ""/'' remain
    and line numbers are preserved).

    Why blank string contents too: this safety grep proves xpubverify has no
    secret-handling code. Real secret handling appears as identifiers, imports,
    attributes, or calls, not as display text. Display copy is prose about the
    tool, the same case as a docstring (already stripped): the demo report's
    IMPORTANT / PRIVACY / "no seed required" disclaimers are mirrored verbatim
    from the appliance and legitimately contain the words "seed" and "secret" as
    English, telling the operator the tool is seed-free. Grepping code-only keeps
    every real tripwire (a `mnemonic_to_seed`, a `PrivateKey`, a `pbkdf2_hmac`
    is caught) while not false-firing on honest display text.

    Known limitation: an identifier smuggled inside an f-string (`f"{seed_bytes}"`)
    is blanked too, so this grep alone does not catch it. That gap is closed by
    the ast-based import allowlist (test_import_allowlist) plus the
    getattr/__import__/importlib call and import blocklists: a secret-handling
    path needs an import, an identifier definition, or a dynamic-access primitive,
    and those are all covered. test_safety_grep_catches_real_code() below pins
    both the catches and this f-string known-miss."""
    no_docstrings = re.sub(r'(\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\')', '', src)
    out_lines = []
    for line in no_docstrings.split('\n'):
        in_q = False
        quote = None
        chars = []
        i = 0
        while i < len(line):
            c = line[i]
            if not in_q:
                if c in ('"', "'"):
                    in_q = True
                    quote = c
                    chars.append(c)          # keep the opening delimiter
                elif c == '#':
                    break
                else:
                    chars.append(c)
            else:
                # Inside a string literal: blank the content, but detect and keep
                # the closing delimiter so code structure (and quote balance) holds.
                if c == quote and (i == 0 or line[i - 1] != '\\'):
                    chars.append(c)          # keep the closing delimiter
                    in_q = False
                    quote = None
                # else: drop the character (display text is not functional code)
            i += 1
        out_lines.append(''.join(chars))
    return '\n'.join(out_lines)


def test_no_secret_material_in_code():
    section("Safety grep, no secret-material terms in functional code")

    src = open(_SRC_PATH, encoding='utf-8').read()
    code_only = _strip_comments_and_docstrings(src)

    forbidden = ('private', 'secret', 'seed', 'mnemonic', 'pbkdf')
    for term in forbidden:
        pattern = re.compile(r'\b' + term + r'\w*', re.IGNORECASE)
        hits = []
        for ln, line in enumerate(code_only.split('\n'), 1):
            for m in pattern.finditer(line):
                hits.append((ln, m.group(), line.strip()[:80]))
        test(f"no {term!r} in functional code", hits, [])


def test_safety_grep_catches_real_code():
    section("Safety grep, tripwire still fires on real code (mutation proof)")
    # test_no_secret_material_in_code() now blanks string-literal contents so the
    # demo report's honest "seed"/"secret" disclaimer copy does not false-fire.
    # Prove that exemption did not blind the tripwire (make the green prove
    # itself by making it red): the shipped source greps clean, a real
    # secret-handling identifier in code is caught, and the same words inside a
    # display string are not caught.
    src = open(_SRC_PATH, encoding='utf-8').read()

    def _grep_forbidden(text):
        code = _strip_comments_and_docstrings(text)
        found = []
        for term in ('private', 'secret', 'seed', 'mnemonic', 'pbkdf'):
            pat = re.compile(r'\b' + term + r'\w*', re.IGNORECASE)
            if any(pat.search(ln) for ln in code.split('\n')):
                found.append(term)
        return found

    # Baseline: the shipped source greps clean (what the real test asserts).
    test("baseline: real source has no forbidden term in functional code",
         _grep_forbidden(src), [])
    # Mutations, a forbidden term used as code (identifier / call / attribute)
    # survives stripping and is caught, so the real test can still reach FAIL.
    test("mutation: 'seed_bytes =' identifier in code is caught",
         'seed' in _grep_forbidden(src + '\nseed_bytes = derive(w)\n'), True)
    test("mutation: 'PrivateKey(' call in code is caught",
         'private' in _grep_forbidden(src + '\npk = PrivateKey(raw)\n'), True)
    test("mutation: 'pbkdf2_hmac' attribute in code is caught",
         'pbkdf' in _grep_forbidden(src + '\nh = hashlib.pbkdf2_hmac(a)\n'), True)
    # Exemption: the same words inside a display string are not caught, so the
    # mirrored disclaimer copy is exempt (the whole reason for the change).
    test("exemption: 'seed'/'secret' inside a display string is not caught",
         _grep_forbidden(src + '\nx = "zero seed or other secret material"\n'), [])
    # Pinned known-miss (state what the check does not cover). An
    # identifier smuggled inside an f-string is blanked with the string content,
    # so the plain grep does not catch it. This is not a practical hole (the ast
    # import allowlist + the getattr/__import__/importlib blocklists cover how
    # such code would actually reach a secret); pinned so a future reader does not
    # "fix" the grep and reintroduce the overclaim.
    test("known-miss: an identifier inside an f-string is not caught by the grep",
         _grep_forbidden(src + '\ny = f"{seed_bytes.hex()}"\n'), [])


def test_import_allowlist():
    section("Safety grep, module imports exactly the five allowed stdlib modules")
    # Enforce the README "imports exactly five stdlib modules" claim structurally.
    # Walk the AST (covers `import os as o`, `import os, sys`, indented imports,
    # and cannot false-hit commented or quoted text) and assert the import set is
    # exactly {hashlib, hmac, json, struct, sys} with no `from X import`. This
    # closes the dynamic-import bypass (importlib / os / random / time) a source
    # grep would miss.
    src = open(_SRC_PATH, encoding='utf-8').read()
    tree = ast.parse(src)
    imported = set()
    from_modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            from_modules.append(node.module)
    test("imports are exactly {hashlib, hmac, json, struct, sys}",
         imported, {'hashlib', 'hmac', 'json', 'struct', 'sys'})
    test("no 'from X import' anywhere in the module", from_modules, [])


def test_no_dangerous_imports():
    section("Safety grep, no dangerous imports or calls")

    src = open(_SRC_PATH, encoding='utf-8').read()

    dangerous_imports = [
        'socket', 'urllib', 'http', 'requests', 'ssl',
        'subprocess', 'pickle', 'marshal', 'ctypes', 'cffi', 'importlib',
    ]
    for mod in dangerous_imports:
        pattern = re.compile(
            r'^\s*(import\s+' + mod + r'\b|from\s+' + mod + r'\b)',
            re.MULTILINE,
        )
        test(f"no 'import {mod}'", pattern.search(src), None)

    dangerous_calls = ['exec(', 'eval(', 'compile(', '__import__(', 'getattr(',
                       'os.system', 'os.popen', 'subprocess.']
    for call in dangerous_calls:
        test(f"no {call!r} in source", call in src, False)


def test_no_file_writes():
    section("Safety grep, no file writes")

    src = open(_SRC_PATH, encoding='utf-8').read()
    code_only = _strip_comments_and_docstrings(src)

    # Any open(...) with a write-mode argument.
    write_open = re.search(
        r"open\([^)]*['\"][warx+][warx+]*['\"]", code_only)
    test("no open(..., 'w'|'a'|'x'|'+')", write_open, None)

    # Any .write( call on anything other than stdout (which xpubverify uses print for).
    # xpubverify uses print() exclusively; .write() should not appear.
    test("no .write( call", '.write(' in code_only, False)


# ─────────────────────────────────────────────
# Section 6, JSON schema
# ─────────────────────────────────────────────

def test_json_schema():
    section("JSON schema sanity")

    result = xv.derive_addresses(TV1_ZPUB, receive_count=3, change_count=2)
    test("result is dict", type(result).__name__, 'dict')
    # Schema fields source_extended_key + derivation_path
    # added (parity with the Bitcoin Witness appliance's derivation output).
    expected_keys = {'version_name', 'network', 'address_type', 'depth',
                     'parent_fingerprint', 'child_index',
                     'source_extended_key', 'derivation_path',
                     'receive', 'change'}
    test("all expected keys present", set(result.keys()) >= expected_keys, True)
    test("receive count", len(result['receive']), 3)
    test("change count",  len(result['change']),  2)

    # Schema-field assertions.
    test("source_extended_key matches input", result['source_extended_key'], TV1_ZPUB)
    # derivation_path is always empty: a bare xpub cannot honestly attest a full
    # account path (no key-origin), so none is claimed (matches Bitcoin Core /
    # BDK / Electrum / Specter; only Sparrow / BlueWallet assume account 0).
    test("derivation_path always empty (no fabricated account path)",
         result['derivation_path'], "")

    for a in result['receive'] + result['change']:
        test(f"{a} starts with bc1q", a.startswith('bc1q'), True)

    # JSON round-trip.
    s = json.dumps(result)
    parsed = json.loads(s)
    test("JSON round-trip preserves receive", parsed['receive'], result['receive'])
    test("JSON round-trip preserves source_extended_key",
         parsed['source_extended_key'], result['source_extended_key'])
    test("JSON round-trip preserves derivation_path",
         parsed['derivation_path'], result['derivation_path'])

    # derivation_path stays empty for every version (no account path is claimed
    # from a bare key, whatever the script type).
    xres = xv.derive_addresses(TV1_XPUB, receive_count=1, change_count=1)
    test("TV1 xpub derivation_path empty", xres['derivation_path'], "")
    test("TV1 xpub source_extended_key", xres['source_extended_key'], TV1_XPUB)

    yres = xv.derive_addresses(TV1_YPUB, receive_count=1, change_count=1)
    test("TV1 ypub derivation_path empty", yres['derivation_path'], "")
    test("TV1 ypub source_extended_key", yres['source_extended_key'], TV1_YPUB)

    tres = xv.derive_addresses(TV1_BIP86_XPUB, receive_count=1, change_count=1,
                                taproot=True)
    test("TV1 BIP86 (--taproot) derivation_path empty", tres['derivation_path'],
         "")
    test("TV1 BIP86 (--taproot) source_extended_key", tres['source_extended_key'],
         TV1_BIP86_XPUB)


# ─────────────────────────────────────────────
# Section 7, CLI integration
# ─────────────────────────────────────────────

def _run_cli(argv, stdin_text=None):
    """Call cli_mode() with argv; return (exit_code, stdout_text, stderr_text)."""
    out = io.StringIO()
    err = io.StringIO()
    # Monkey-patch sys.stdin if needed.
    old_stdin = sys.stdin
    if stdin_text is not None:
        stdin = io.StringIO(stdin_text)
        # Make the fake stdin claim it's not a TTY.
        stdin.isatty = lambda: False
        sys.stdin = stdin
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = xv.cli_mode(argv)
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue(), err.getvalue()


def test_cli():
    section("CLI integration")

    rc, stdout, _ = _run_cli(['--version'])
    test("--version exit code", rc, 0)
    test("--version stdout",    stdout.strip(), xv.XPUBVERIFY_VERSION)

    rc, stdout, _ = _run_cli(['--self-test'])
    test("--self-test exit code", rc, 0)
    test("--self-test final line",
         "ALL SELF-TEST CHECKS PASSED" in stdout, True)

    rc, stdout, _ = _run_cli(['--json', TV1_ZPUB,
                              '--receive-count', '2', '--change-count', '1'])
    test("--json exit code", rc, 0)
    parsed = json.loads(stdout)
    test("--json address_type",    parsed['address_type'], 'p2wpkh')
    test("--json receive length",  len(parsed['receive']), 2)
    test("--json receive[0]",      parsed['receive'][0], TV1_BIP84_RECEIVE[0])
    # Schema-field assertions on the JSON CLI output.
    test("--json source_extended_key", parsed['source_extended_key'], TV1_ZPUB)
    test("--json derivation_path empty", parsed['derivation_path'], "")

    # Plain-text mode.
    rc, stdout, _ = _run_cli([TV1_XPUB, '--receive-count', '1',
                              '--change-count', '1'])
    test("text mode exit code", rc, 0)
    test("text mode includes first BIP44 address",
         TV1_BIP44_RECEIVE[0] in stdout, True)

    # Taproot mode.
    rc, stdout, _ = _run_cli(['--taproot', TV1_BIP86_XPUB,
                              '--receive-count', '1', '--change-count', '1'])
    test("--taproot exit code", rc, 0)
    test("--taproot emits BIP86 address",
         TV1_BIP86_RECEIVE[0] in stdout, True)

    # stdin input.
    rc, stdout, _ = _run_cli(['--json'], stdin_text=TV1_ZPUB + '\n')
    test("stdin input exit code", rc, 0)
    parsed = json.loads(stdout)
    test("stdin input receive[0]",
         parsed['receive'][0], TV1_BIP84_RECEIVE[0])

    # Error paths: missing value for flag.
    rc, _, stderr = _run_cli(['--receive-count'])
    test("missing --receive-count value exit code", rc, 1)
    test("missing --receive-count value stderr",
         "ERROR" in stderr, True)

    # Unknown flag.
    rc, _, stderr = _run_cli(['--nope', TV1_ZPUB])
    test("unknown flag exit code", rc, 1)
    test("unknown flag stderr", "ERROR" in stderr, True)

    # Too many positional args.
    rc, _, stderr = _run_cli([TV1_ZPUB, TV1_XPUB])
    test("too many positionals exit code", rc, 1)
    test("too many positionals stderr", "ERROR" in stderr, True)

    # Invalid xpub.
    rc, _, stderr = _run_cli(['definitely-not-an-xpub'])
    test("bad xpub exit code", rc, 1)
    test("bad xpub stderr", "ERROR" in stderr, True)


# ─────────────────────────────────────────────
# Section 8, Independent reference cross-validation
# ─────────────────────────────────────────────
#
# The addresses hard-coded in this file are pulled from published BIP
# specs. If xpubverify's primitives contain a bug that happens to match
# the spec's worked example, a bug-vs-bug match would pass. The
# cross-check below breaks that circularity: we ask a different codebase
# (embit or bip32) to derive the same addresses
# and require byte-for-byte agreement with xpubverify.
#
# If none of the reference libraries is importable the check SKIPs with
# an install hint, it does not fail. xpubverify's own runtime guarantee
# is zero deps; we do not want the default test suite to turn red on a
# fresh box. Release / audit procedure: install at least one reference
# library before declaring the suite green.


def _try_import_reference():
    """Return (impl_name, derive_fn) or None.

    derive_fn(xpub_string, branch, index, address_type, network) -> str
    """
    # 1. embit
    try:
        from embit import bip32 as _embit_bip32
        from embit.networks import NETWORKS as _embit_networks
        from embit import script as _embit_script

        def _embit_derive(xpub_s, branch, index, address_type, network):
            # embit auto-detects the SLIP-132 variant from the prefix.
            hd = _embit_bip32.HDKey.from_string(xpub_s)
            child = hd.derive([branch, index])
            pk = child.key
            net = (_embit_networks['test']
                   if network == 'testnet' else _embit_networks['main'])
            if address_type == 'p2pkh':
                return _embit_script.p2pkh(pk).address(net)
            if address_type == 'p2sh-p2wpkh':
                return _embit_script.p2sh(_embit_script.p2wpkh(pk)).address(net)
            if address_type == 'p2wpkh':
                return _embit_script.p2wpkh(pk).address(net)
            if address_type == 'p2tr':
                return _embit_script.p2tr(pk).address(net)
            raise ValueError(f"embit path: unknown address_type {address_type!r}")

        return ('embit', _embit_derive)
    except ImportError:
        pass

    # 2. bip32 (Darosior's minimal lib) + a manual address encoder via hashlib.
    try:
        from bip32 import BIP32
        # The bip32 library only accepts mainnet xpub / testnet tpub
        # version bytes. SLIP-132 ypub / zpub share the same BIP32 payload,
        # so we normalise the version bytes to xpub (0488B21E) before
        # handing the key to bip32 for derivation. The address encoder on
        # the way out still emits the correct mainnet address type.
        _XPUB_VERSION = bytes.fromhex('0488B21E')
        _TPUB_VERSION = bytes.fromhex('043587CF')

        def _normalize_to_xpub_or_tpub(xpub_s):
            raw = xv.base58_decode(xpub_s)
            payload = raw[:78]
            version = payload[0:4]
            if version.hex() == '043587cf':
                return xpub_s
            if version.hex() == '0488b21e':
                return xpub_s
            # Rewrite ypub / zpub to xpub bytes (their BIP32 payload is
            # version-agnostic; xpub and tpub already returned above). A fresh
            # checksum is computed over the rewritten payload.
            new_payload = _XPUB_VERSION + payload[4:]
            new_checksum = xv.sha256(xv.sha256(new_payload))[:4]
            return xv.base58_encode(new_payload + new_checksum)

        def _bip32_derive(xpub_s, branch, index, address_type, network):
            normalized = _normalize_to_xpub_or_tpub(xpub_s)
            hd = BIP32.from_xpub(normalized)
            pk = hd.get_pubkey_from_path([branch, index])
            if address_type == 'p2pkh':
                ver = 0x6F if network == 'testnet' else 0x00
                return xv.encode_p2pkh(pk, version_byte=ver)
            if address_type == 'p2sh-p2wpkh':
                ver = 0xC4 if network == 'testnet' else 0x05
                return xv.encode_p2sh_p2wpkh(pk, version_byte=ver)
            if address_type == 'p2wpkh':
                hrp = 'tb' if network == 'testnet' else 'bc'
                return xv.encode_p2wpkh(pk, hrp=hrp)
            if address_type == 'p2tr':
                hrp = 'tb' if network == 'testnet' else 'bc'
                return xv.encode_p2tr(pk, hrp=hrp)
            raise ValueError(f"bip32 path: unknown address_type {address_type!r}")

        return ('bip32', _bip32_derive)
    except ImportError:
        pass

    return None


def test_cross_validation():
    section("Independent-reference cross-validation")

    reference = _try_import_reference()
    if reference is None:
        skip("cross-validation",
             "no reference lib installed. Try: "
             "pip install embit   (or: pip install bip32)")
        return

    impl_name, derive_fn = reference
    print(f"  [using reference library: {impl_name}]")

    cases = [
        (TV1_ZPUB,       'p2wpkh',      'mainnet'),
        (TV1_XPUB,       'p2pkh',       'mainnet'),
        (TV1_YPUB,       'p2sh-p2wpkh', 'mainnet'),
        (TV1_BIP86_XPUB, 'p2tr',        'mainnet'),
    ]

    for xpub_s, address_type, network in cases:
        taproot = (address_type == 'p2tr')
        ours = xv.derive_addresses(xpub_s, receive_count=3, change_count=3,
                                   taproot=taproot)
        for branch_name, branch_idx in (('receive', 0), ('change', 1)):
            for i in range(3):
                ref_addr = derive_fn(xpub_s, branch_idx, i, address_type, network)
                our_addr = ours[branch_name][i]
                test(
                    f"{impl_name}: {address_type} {branch_name}[{i}]",
                    our_addr, ref_addr,
                )


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def test_demo_report_and_descriptors():
    section("BIP380 descriptors + demo report (mirrors appliance format)")

    # BIP380 checksum, the official raw(deadbeef)#89f8spxm vector.
    test("descriptor_checksum official vector",
         xv.descriptor_checksum("raw(deadbeef)"), "89f8spxm")
    test("descriptor_checksum_ok accepts valid",
         xv.descriptor_checksum_ok("raw(deadbeef)#89f8spxm"), True)
    test("descriptor_checksum_ok rejects corrupt checksum",
         xv.descriptor_checksum_ok("raw(deadbeef)#89f8spxn"), False)
    test("descriptor_checksum_ok rejects missing '#'",
         xv.descriptor_checksum_ok("raw(deadbeef)"), False)

    # Descriptors are attached to the derive result, valid + correctly wrapped
    # per script type, and the key is re-versioned to a plain xpub.
    rz = xv.derive_addresses(TV1_ZPUB, receive_count=3, change_count=2)
    test("result carries descriptors", 'descriptors' in rz, True)
    # Result field: the BIP32 fingerprint of the account key itself
    # (hash160(account pubkey)[:4]), version-byte-independent, and the value
    # the appliance report shows as "Account Key Fingerprint".
    test("result carries account_fingerprint (BIP32 fpr of account key)",
         rz.get('account_fingerprint'), 'fd13aac9')
    dz = rz['descriptors']
    test("zpub -> wpkh( over a plain xpub", dz['receive'].startswith('wpkh(xpub'), True)
    test("zpub receive descriptor checksum valid",
         xv.descriptor_checksum_ok(dz['receive']), True)
    test("zpub change descriptor checksum valid",
         xv.descriptor_checksum_ok(dz['change']), True)
    test("receive branch /0/*  +  change branch /1/*",
         ('/0/*)' in dz['receive'], '/1/*)' in dz['change']), (True, True))
    # No key-origin can be claimed from an account xpub, none is.
    test("descriptor claims no key-origin [..]", '[' in dz['receive'], False)

    ry = xv.derive_addresses(TV1_YPUB)
    test("ypub -> sh(wpkh( + valid checksum",
         (ry['descriptors']['receive'].startswith('sh(wpkh(xpub'),
          xv.descriptor_checksum_ok(ry['descriptors']['receive'])), (True, True))
    rx = xv.derive_addresses(TV1_XPUB)
    test("xpub -> pkh( + valid checksum",
         (rx['descriptors']['receive'].startswith('pkh(xpub'),
          xv.descriptor_checksum_ok(rx['descriptors']['receive'])), (True, True))
    rt = xv.derive_addresses(TV1_BIP86_XPUB, taproot=True)
    test("taproot -> tr( + valid checksum",
         (rt['descriptors']['receive'].startswith('tr(xpub'),
          xv.descriptor_checksum_ok(rt['descriptors']['receive'])), (True, True))

    # The demo report honesty markers (paired presence/absence).
    rep = xv.render_demo_report(rz)
    test("report marked demo (banner at top and foot)",
         rep.count("*** DEMO REPORT"), 2)
    test("report states not air-gapped / not GPG-signed",
         "NOT AIR-GAPPED, NOT GPG-SIGNED" in rep, True)
    # Case-insensitive for robustness; the report body says "not a signature".
    test("report states self-checksum, not a signature",
         "not a signature" in rep.lower(), True)
    test("report makes no false 'is air-gapped' claim",
         "is air-gapped" in rep.lower(), False)
    test("report makes no false 'gpg-signed report' claim",
         "gpg-signed report" in rep.lower(), False)

    # Report fidelity: the demo mirrors the appliance Confidence Report format:
    # box title, VERIFICATION TYPE, "What this is for", Account Key Fingerprint
    # + its clarification, the derivation-path caveat, and the OUTPUT DESCRIPTORS
    # header. Assert each fidelity element is actually present.
    test("report has the appliance box title",
         "BITCOIN WITNESS — VERIFICATION CONFIDENCE REPORT" in rep, True)
    test("report names the verification type",
         "VERIFICATION TYPE:       Extended Public Key Verification" in rep, True)
    test("report carries the 'What this is for' clause",
         "What this is for:" in rep and "It cannot spend." in rep, True)
    test("report shows Account Key Fingerprint label + value",
         "Account Key Fingerprint:" in rep and "FD13AAC9" in rep, True)
    test("report clarifies fpr is not the master fingerprint",
         "not the wallet's" in rep and
         "master fingerprint, which watch-only mode cannot see" in rep, True)
    test("report declines to claim a full path from a bare key",
         "not determinable from a bare" in rep, True)
    test("report gives the labeled child-number inference (a hint, not a path)",
         "child-number implies account" in rep and "a hint, not a verified path" in rep,
         True)
    # And it must not print a fabricated full account path for a bare key.
    test("report shows no fabricated m/.../account' path",
         "m/84'/0'/0'" in rep, False)
    test("report has the OUTPUT DESCRIPTORS section", "OUTPUT DESCRIPTORS" in rep, True)

    # The IMPORTANT + PRIVACY disclaimer block is carried verbatim from the
    # appliance report (deliberately mirrored from it); assert both blocks and
    # their load-bearing sentences.
    test("report carries the IMPORTANT (zero secret material) disclaimer",
         "IMPORTANT: This report contains zero seed or other secret material." in rep,
         True)
    test("report carries the PRIVACY disclaimer (reveals every past/future addr)",
         "PRIVACY: The extended public keys and addresses above cannot spend," in rep
         and "reveal every past transaction and every future address" in rep, True)
    test("PRIVACY disclaimer flags the report as financially sensitive",
         "Treat this report as" in rep and "financially sensitive" in rep, True)
    test("report has the HOW TO RE-VERIFY section (no seed required)",
         "HOW TO RE-VERIFY (no seed required):" in rep, True)

    # The self-hash actually covers the body and matches. The foot line is
    # 'Report SHA-256: <hex>' as the final line (mirrors the appliance); the
    # body it hashes is everything before that label.
    body, _, printed_line = rep.rpartition("Report SHA-256:")
    printed = printed_line.strip()
    test("self-hash == SHA-256 of the report body",
         xv.sha256(body.encode("utf-8")).hex(), printed)
    # ... and it is load-bearing: change one address, the hash changes.
    tampered = dict(rz)
    tampered['receive'] = ["bc1qtampered"] + list(rz['receive'][1:])
    printed2 = xv.render_demo_report(tampered).rpartition("Report SHA-256:")[2].strip()
    test("self-hash changes when an address changes", printed2 != printed, True)

    # Deterministic: same input -> byte-identical report (the re-verify story).
    test("report deterministic (re-render byte-identical)",
         xv.render_demo_report(
             xv.derive_addresses(TV1_ZPUB, receive_count=3, change_count=2)) == rep,
         True)
    test("report embeds the valid receive descriptor",
         dz['receive'] in rep, True)

    # CLI wiring.
    rc, stdout, _ = _run_cli(['--report', TV1_ZPUB,
                              '--receive-count', '2', '--change-count', '1'])
    test("--report exit code", rc, 0)
    test("--report stdout marked DEMO", "*** DEMO REPORT" in stdout, True)
    rc, _, stderr = _run_cli(['--report', '--json', TV1_ZPUB])
    test("--report + --json rejected", rc, 1)
    test("--report + --json error names the conflict", "not both" in stderr, True)


def test_regression_fixes():
    section("Regression fixes, p2tr tweak reject + tpub descriptor network")

    # encode_p2tr fail-closes on a TapTweak scalar >= n (BIP341), rather than
    # reducing it mod n. Force the tweak to n via a patched tagged_hash.
    _orig = xv.tagged_hash
    try:
        xv.tagged_hash = lambda tag, data: xv.N.to_bytes(32, 'big')  # tweak == n
        # On-curve fixture (the secp256k1 generator point) so the pubkey passes
        # point_from_pubkey and the test actually reaches the t>=n guard. An
        # off-curve fixture would raise earlier and pass even with the guard gone.
        _G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        test_raises("encode_p2tr rejects TapTweak >= n (not % n)",
                    lambda: xv.encode_p2tr(bytes.fromhex(_G)))
    finally:
        xv.tagged_hash = _orig
    rt = xv.derive_addresses(TV1_BIP86_XPUB, taproot=True)
    test("real taproot key still derives after the guard",
         rt['receive'][0].startswith('bc1p'), True)

    # F6: point_from_pubkey refuses a non-{0x02,0x03} prefix (SEC1 2.3.4). Use a
    # real on-curve x (the generator's) with the prefix overwritten to 0x04: only
    # the prefix guard makes this raise, since without it 0x04 falls through the
    # parity branch and returns a valid point. An off-curve x would raise at the
    # on-curve check even with the guard gone, so it could not prove the guard.
    _bad04 = bytes([0x04]) + bytes.fromhex(_G)[1:]
    test_raises("point_from_pubkey rejects a 0x04-prefixed 33-byte key",
                lambda: xv.point_from_pubkey(_bad04))
    # And a genuine compressed key still decompresses fine.
    test("point_from_pubkey accepts a real 0x02 key",
         isinstance(xv.point_from_pubkey(bytes.fromhex(_G)), tuple), True)

    # A tpub (testnet) must produce a testnet (tpub) descriptor that round-trips,
    # not a mainnet xpub. Build a valid tpub by re-versioning the TV1 xpub payload.
    payload = xv.base58_decode(TV1_XPUB)[:-4]
    tp = b"\x04\x35\x87\xcf" + payload[4:]
    tpub = xv.base58_encode(tp + xv.sha256(xv.sha256(tp))[:4])
    rt2 = xv.derive_addresses(tpub, receive_count=2, change_count=1)
    test("tpub input is testnet", rt2['network'], 'testnet')
    # tpub address values: the 0x6F testnet P2PKH version byte had zero value
    # coverage, so a mutation of it would otherwise leave the whole suite green.
    # Prefix check catches a version-byte swap; pinned values catch a derivation
    # regression (cross-checked against an independent reference during the audit).
    test("tpub receive addresses have a testnet prefix (m / n)",
         all(a[0] in 'mn' for a in rt2['receive']), True)
    test("tpub receive[0] value", rt2['receive'][0],
         'n1M8ZVQtL7QoFvGMg24D6b2ojWvFXCGpoS')
    test("tpub change[0] value", rt2['change'][0],
         'mxZFPJ1Nfwa5sGffCmhtJyHoX3ParNiL3D')
    dt = rt2['descriptors']
    test("tpub -> descriptor uses tpub (not mainnet xpub)",
         dt['receive'].split('(')[1][:4], 'tpub')
    test("tpub descriptor has a valid BIP380 checksum",
         xv.descriptor_checksum_ok(dt['receive']), True)
    dz = xv.derive_addresses(TV1_ZPUB)['descriptors']
    test("mainnet zpub -> descriptor still uses xpub",
         dz['receive'].split('(')[1][:4], 'xpub')


def test_account_path_depth_gating():
    section("Account-path honesty: no full account path is claimed from a bare key")
    # Option 3: derivation_path is always empty (a bare key cannot honestly
    # attest a full m/purpose'/coin'/account' path). The report distinguishes a
    # real account-level key (depth 3, hardened child-number) from a non-account
    # key, and for an account key gives the child-number as a labeled inference,
    # never a fabricated full path. Paired presence/absence, so reintroducing any
    # hardcode turns these red.

    # (1) A depth-0 master: not an account-level key.
    m = xv.derive_addresses(BIP32_V1_MASTER_XPUB, receive_count=1, change_count=1)
    test("depth-0 master: derivation_path empty", m['derivation_path'], '')
    rep_m = xv.render_demo_report(m)
    test("depth-0 report shows the real key depth", 'Key depth 0:' in rep_m, True)
    test("depth-0 report says it is not an account-level key",
         'not an account-level key' in rep_m, True)
    test("depth-0 report gives no child-number inference",
         'child-number implies account' in rep_m, False)

    # (2) A depth-3 account-0 key (TV1 zpub): positive control. The tempting
    # future regression is "account 0 would have been right anyway", so assert
    # the inference explicitly says account 0 and no full path string appears.
    z = xv.derive_addresses(TV1_ZPUB, receive_count=1, change_count=1)
    test("depth-3 account: derivation_path still empty", z['derivation_path'], '')
    rep_z = xv.render_demo_report(z)
    test("account-0 report labels it an account-level key",
         'Account-level key' in rep_z and 'not an account-level key' not in rep_z, True)
    test("account-0 report infers account 0 (a hint)",
         'child-number implies account 0 under the BIP84 convention' in rep_z, True)
    test("account-0 report shows no fabricated full path", "m/84'/0'/0'" in rep_z, False)

    # (3) A depth-3 account-2' key: the inferred account must track the key's own
    # child-number, and still no full path is fabricated. Build a re-checksummed
    # zpub with child-number 0x80000002 (chain code / pubkey unchanged; only the
    # label logic is under test, so the derived addresses are irrelevant here).
    _p = xv.base58_decode(TV1_ZPUB)[:-4]
    _p2 = _p[:9] + (0x80000002).to_bytes(4, 'big') + _p[13:]
    zpub_acct2 = xv.base58_encode(_p2 + xv.sha256(xv.sha256(_p2))[:4])
    z2 = xv.derive_addresses(zpub_acct2, receive_count=1, change_count=1)
    test("account-2 key: child_index reflects account 2", z2['child_index'], 0x80000002)
    test("account-2 key: derivation_path still empty", z2['derivation_path'], '')
    rep_z2 = xv.render_demo_report(z2)
    test("account-2 report infers account 2, not 0",
         'child-number implies account 2 under the BIP84 convention' in rep_z2, True)
    test("account-2 report fabricates no full path",
         ("m/84'/0'/2'" in rep_z2 or "m/84'/0'/0'" in rep_z2), False)


def test_bip32_ckdpub_spec_child():
    section("BIP32 CKDpub against a spec-published child (vector 1)")
    # The other BIP32-vector tests only DECODE the master xpubs; they never run
    # CKDpub against a spec-published child. Close that: BIP32 test vector 1,
    # chain m/0' -> CKDpub(1) -> m/0'/1 must re-serialize to the spec's exact
    # child xpub, using only the tool's own primitives. Index 1 is non-hardened,
    # so it is derivable from the public key.
    _V1_M0H = ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6"
               "LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
    _V1_M0H_1 = ("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKk"
                 "NAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
    p = xv.decode_extended_pubkey(_V1_M0H)
    cpub, cchain = xv.derive_child_pubkey(p['pubkey'], p['chain_code'], 1)
    payload = (bytes.fromhex('0488B21E')          # xpub mainnet version
               + bytes([p['depth'] + 1])          # child depth (m/0' is 1 -> 2)
               + xv.hash160(p['pubkey'])[:4]      # parent fingerprint
               + (1).to_bytes(4, 'big')           # child number 1
               + cchain + cpub)
    child_xpub = xv.base58_encode(payload + xv.sha256(xv.sha256(payload))[:4])
    test("BIP32 vec1 CKDpub m/0' -> m/0'/1 re-serializes to the spec child",
         child_xpub, _V1_M0H_1)


def test_ripemd160_pure_fallback():
    section("RIPEMD-160 pure-Python fallback (official vectors + differential)")
    # The pure-Python fallback backs the "runs on any Python 3.8+" promise and is
    # the path most CI runners use (OpenSSL 3 often drops ripemd160). Test it
    # directly against the 8 short official vectors, and differentially against
    # hashlib when it still has ripemd160. The 1M-'a' vector is deliberately left
    # out (pure-Python over 1 MB is ~15k compress calls, real CI minutes); the
    # short vectors plus the differential give the same regression power.
    official = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"abcdefghijklmnopqrstuvwxyz",
         "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         "b0e20b6e3116640286ed3a87a5713079b21f5189"),
        (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
    ]
    for data, expected in official:
        test(f"_ripemd160_pure official vector (len {len(data)})",
             xv._ripemd160_pure(data).hex(), expected)
    # One aggregate differential vs OpenSSL (kept count-stable: one check either
    # way) across the message-length / padding boundaries.
    try:
        import hashlib
        hashlib.new('ripemd160')
        diff_ok = all(
            xv._ripemd160_pure(b"a" * n).hex()
            == hashlib.new('ripemd160', b"a" * n).hexdigest()
            for n in (0, 55, 56, 63, 64, 127, 128, 200))
        test("_ripemd160_pure matches OpenSSL across padding boundaries",
             diff_ok, True)
    except (ValueError, TypeError):
        test("differential vs OpenSSL skipped (platform ripemd160 unavailable)",
             True, True)


def main():
    print("=" * 60)
    print("  xpubverify.py v" + xv.XPUBVERIFY_VERSION + ", test suite")
    print("=" * 60)

    test_bip32_decode()
    test_derive_tv1()
    test_derive_tv1_taproot()
    test_derive_tv2()
    test_edge_cases()
    test_bip32_vec5_invalid()
    test_account_path_depth_gating()
    test_no_secret_material_in_code()
    test_safety_grep_catches_real_code()
    test_import_allowlist()
    test_no_dangerous_imports()
    test_no_file_writes()
    test_json_schema()
    test_cli()
    test_demo_report_and_descriptors()
    test_regression_fixes()
    test_bip32_ckdpub_spec_child()
    test_ripemd160_pure_fallback()
    test_cross_validation()

    print()
    print("=" * 60)
    if FAIL == 0:
        if SKIP == 0:
            print(f"  ALL {TOTAL} CHECKS PASSED")
        else:
            print(f"  {PASS}/{TOTAL} passed, {SKIP} SKIPPED, 0 FAILED")
    else:
        print(f"  {PASS}/{TOTAL} passed, {SKIP} SKIPPED, {FAIL} FAILED")
    print("=" * 60)
    # Floor guard: CI gates only on the exit code, so a silently shrunk suite
    # (a deleted test block) would otherwise pass green even though the check
    # count is a headline claim in the docs. The floor tracks the run mode: with
    # a reference lib installed the cross-validation block must also be present,
    # so the floor is the full cross-validated baseline; without it, the
    # stdlib-only baseline. Raise these whenever the baselines rise.
    _min_checks = 258 if _try_import_reference() is not None else 235
    if TOTAL < _min_checks:
        print(f"  suite too small: ran {TOTAL} checks, expected at least "
              f"{_min_checks} (a shrunk suite must not pass silently)")
        return 1
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
