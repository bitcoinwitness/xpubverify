# xpubverify

[![Tests](https://github.com/BitcoinWitness/xpubverify/actions/workflows/test.yml/badge.svg)](https://github.com/BitcoinWitness/xpubverify/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python 3.8–3.13](https://img.shields.io/badge/python-3.8%E2%80%933.13-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)

**Verify your hardware wallet's addresses from its public key.**

*Public key in. Addresses out. Your seed never touches this script, because it doesn't need to.*

A standalone Python tool that derives Bitcoin addresses from an extended public key (xpub / ypub / zpub / tpub). Pure Python. Standard library only. No external dependencies. No network calls. No file writes. No private-key operations of any kind.

Part of [Bitcoin Witness](https://bitcoinwitness.org): verify your Bitcoin, trust the math.

---

## Verify in 60 seconds

```bash
git clone https://github.com/BitcoinWitness/xpubverify.git
cd xpubverify
python3 xpubverify.py zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs
```

Expected first receive address: `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`.

This is the canonical BIP84 vector for the 12-word "abandon abandon ... about" mnemonic. If the output matches, the script is working correctly. Now run it with your own extended public key.

---

## Why this exists

Every hardware wallet you own displays a list of addresses that, it claims, belong to you. But those addresses are computed by the wallet's own firmware, the same firmware you are trusting to sign transactions. If the firmware is compromised, the addresses you see on screen are exactly the ones the attacker wants you to see.

**Independent verification closes most of that loop.** Export the extended public key from your wallet, feed it to a small, auditable script running on separate hardware, and compare the output to what your wallet displays. A match proves your wallet's *display* is consistent with the key it *exported*, which defeats host-side or companion-app address substitution. It cannot prove the key itself came from your seed: a fully compromised wallet could export a consistent attacker-controlled key, so pair this with a second independent device or full-seed verification (see [SECURITY.md](SECURITY.md)) for that threat. If the addresses differ, something is wrong.

`xpubverify` is that small, auditable script. It is about 1,430 lines of commented Python with zero external dependencies, and it never asks you for anything more secret than a public key.

---

## What it does

Given an extended public key, `xpubverify` derives receive and change addresses for the matching BIP standard:

| Input prefix | Standard | Address type | Example address |
|---|---|---|---|
| `xpub...` | BIP44 | Legacy P2PKH | `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` |
| `ypub...` | BIP49 | Nested SegWit (P2SH-P2WPKH) | `37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf` |
| `zpub...` | BIP84 | Native SegWit (P2WPKH) | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| `xpub...` + `--taproot` | BIP86 | Taproot (P2TR) | `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr` |
| `tpub...` | BIP44 testnet | Legacy P2PKH (testnet) | `n1M8ZVQtL7QoFvGMg24D6b2ojWvFXCGpoS` |

Receive addresses come from branch 0, change addresses from branch 1, exactly as defined by BIP44.

> **Privacy:** an extended public key cannot spend, but anyone who holds it can see your account's entire past and future transaction history. Treat it as financially sensitive and share it deliberately.

---

## Usage

### Plain text

```bash
python3 xpubverify.py zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs
```

### JSON output

```bash
python3 xpubverify.py --json --receive-count 2 --change-count 1 zpub6rFR7y4Q2AijB...
```

```json
{
  "version_name": "zpub",
  "network": "mainnet",
  "address_type": "p2wpkh",
  "depth": 3,
  "parent_fingerprint": "7ef32bdb",
  "account_fingerprint": "fd13aac9",
  "child_index": 2147483648,
  "source_extended_key": "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
  "derivation_path": "",
  "receive": [
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
  ],
  "change": [
    "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
  ],
  "descriptors": {
    "receive": "wpkh(xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#kj7aqcx6",
    "change": "wpkh(xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#8xmuadkz"
  }
}
```

The `descriptors` object carries BIP380 output descriptors with checksums,
re-importable watch-only into Sparrow / Bitcoin Core / Specter. The
`source_extended_key` field lets a future verifier holding only the saved JSON
re-derive the children independently of this tool. `account_fingerprint` is the
BIP32 fingerprint of the account key itself (hash160 of its compressed pubkey,
first 4 bytes), version-byte-independent, matching the appliance's "Account Key
Fingerprint". `derivation_path` is always an empty string: a bare extended key
cannot honestly attest a full `m/purpose'/coin'/account'` path (it carries no
key-origin), so none is claimed, the same choice Bitcoin Core, BDK, Electrum,
and Specter make.

### Custom counts

```bash
python3 xpubverify.py --receive-count 20 --change-count 10 zpub6rFR7y4Q2AijB...
```

### Read from stdin

```bash
cat my-wallet.xpub | python3 xpubverify.py --json
```

### Taproot (BIP86)

```bash
python3 xpubverify.py --taproot xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ
```

### DEMO verification report (`--report`)

```bash
python3 xpubverify.py --report zpub6rFR7y4Q2AijB...
```

`--report` prints a formatted **demo** verification report: the derived
addresses, the matching **BIP380 output descriptors** (each with its
`#checksum`, re-importable watch-only into Sparrow / Bitcoin Core / Specter),
and a **deterministic self-hash** at the foot: re-run the identical command
and every byte, including the hash, reproduces exactly. That reproducibility
*is* the point: it is a self-checksum you can verify, not a signature you have
to trust.

The layout **mirrors the current Bitcoin Witness appliance Confidence Report**
for fidelity: the same box title, aligned header grid, `VERIFICATION TYPE:
Extended Public Key Verification`, Account Key Fingerprint line, and the verbatim
**IMPORTANT** and **PRIVACY** disclaimers, so the demo shows you exactly what the
appliance's report looks like. The values that must differ are the honest ones:
the demo says so at top and foot, carries no real timestamp (it is
deterministic), reports its air-gap status as DEMO, and claims no full derivation
path from a bare key (it shows the relative structure and a labeled child-number
hint instead).

> **This report is always a demo, and it says so.** It demonstrates the
> *format* of the Bitcoin Witness Confidence Report, produced by this free,
> internet-connected, watch-only tool. It is **not air-gapped** and **not
> GPG-signed**, and it proves only that the addresses derive from the extended
> public key you supplied, nothing about the backup phrase behind that key,
> and nothing about funds. For a real, air-gapped, GPG-signed Confidence
> Report, use the [Bitcoin Witness](https://bitcoinwitness.org) appliance.

The descriptors carry no key-origin `[fingerprint/path]`: a bare account xpub
does not contain its master fingerprint or full derivation path, so the tool
claims none rather than inventing one. The same honesty runs through the whole
tool: `derivation_path` is always empty, and the report never fabricates a full
`m/purpose'/coin'/account'` path from a bare key.

### Run the embedded self-test

```bash
python3 xpubverify.py --self-test
```

---

## What it does NOT do

- **It does not accept seeds, mnemonics, or passphrases.** There is no code path in the tool that reads secret material. If you pasted an xprv, yprv, zprv, or tprv by mistake, the script exits with an error and refuses to continue.
- **It does not sign transactions.** This is a derivation tool only. For signing, see the full [Bitcoin Witness](https://bitcoinwitness.org) appliance.
- **It does not make network calls.** The Python module imports exactly five stdlib modules: `hashlib`, `hmac`, `json`, `struct`, and `sys`. No `socket`, `urllib`, `http`, `requests`, `ssl`, or `subprocess`.
- **It does not write files.** Output goes to stdout; that is the only I/O the tool performs.
- **Its `--report` output is a demo, never a signed record.** It shows the Confidence Report *format*: it is not air-gapped and not GPG-signed, its self-hash is a checksum and not a signature, and the report itself states this. Do not treat it as the appliance's signed Confidence Report.

If you need full seed verification (checking that a mnemonic produces the xpub you expect), or a real air-gapped, GPG-signed Confidence Report, use the [Bitcoin Witness](https://bitcoinwitness.org) air-gapped appliance.

---

## How to audit

The whole tool is one file. Read it.

```bash
wc -l xpubverify.py        # ~1,430 lines of commented Python
python3 xpubverify.py --self-test
python3 test_xpubverify.py
```

Verify no dangerous imports:

```bash
grep -E "import (socket|urllib|http|requests|ssl|subprocess|pickle|marshal|ctypes|cffi)" xpubverify.py
# (no output expected)
```

Verify no code execution primitives:

```bash
grep -E "exec\(|eval\(|compile\(|__import__\(|os\.system|os\.popen" xpubverify.py
# (no output expected)
```

Verify no file writes:

```bash
grep -E "open\([^)]*['\"][wax+]|\.write\(" xpubverify.py
# (no output expected)
```

Verify no private-key-related code (case-insensitive):

```bash
grep -iE "\b(private|secret|seed|mnemonic|pbkdf)" xpubverify.py
# Matches appear only in prose, code comments, docstrings, and the demo
# report's IMPORTANT / PRIVACY disclaimer strings (which tell you the tool is
# seed-free), never in secret-handling code. The automated test proves this
# by stripping comments, docstrings, AND string-literal contents before
# grepping, so a real seed-handling identifier would still be caught.
```

The test suite (`test_xpubverify.py`) enforces all of these as automated assertions. The stdlib-only run produces **234 passed, 1 SKIPPED**; the SKIP is the independent-reference cross-validation, which only runs when a third-party BIP32 reference library is installed.

For the strongest possible verification, install `embit` (Stepan Snigirev's pure-Python lib) or `bip32` (Darosior's minimal lib) from PyPI. The cross-validation re-derives every TV1 address using the reference library and asserts byte-for-byte agreement with `xpubverify`:

```bash
pip install embit
python3 test_xpubverify.py
# final line: "ALL 258 CHECKS PASSED"  (234 stdlib + 24 cross-validation)
```

---

## BIP compatibility

| BIP | Name | Role in xpubverify |
|---|---|---|
| [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) | Hierarchical Deterministic Wallets | CKDpub (non-hardened public-child derivation) |
| [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) | Multi-account hierarchy | `xpub` version bytes, `1...` addresses |
| [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) | Derivation for P2WPKH-in-P2SH | `ypub` version bytes, `3...` addresses |
| [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) | Native SegWit P2WPKH | `zpub` version bytes, `bc1q...` addresses |
| [BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) | Key-path Taproot | `--taproot` flag, `bc1p...` addresses |
| [BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | Bech32 | Witness v0 encoding |
| [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) | Bech32m | Witness v1+ encoding |
| [SLIP-132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md) | Extended key version bytes | Input-prefix recognition |

The BIP32 master-key vectors 1–3, a spec-anchored CKDpub derivation check, the full BIP32 vector-5 invalid-key sweep, and the canonical BIP84 / BIP86 published address vectors are all included in the test suite.

---

## License

MIT. See `LICENSE`.
