# How to Verify `xpubverify`

Before running this script with a real extended public key, verify that the code you have is the code the project publishes and that it does what it claims. This document walks through the checks.

## 1. Check the file hashes

```bash
sha256sum xpubverify.py test_xpubverify.py
```

Each release is published as a **GPG-signed `git tag`** on the official repository, and the expected file hashes are recorded on that release. Compare the output above against the hashes on the signed release you cloned. If any hash does not match, stop here and re-download from the official source: [github.com/BitcoinWitness/xpubverify](https://github.com/BitcoinWitness/xpubverify).

## 2. Run the embedded self-test

```bash
python3 xpubverify.py --self-test
```

This runs a small set of internal vectors straight out of `xpubverify.py`:

- TV1 zpub → first three BIP84 addresses match `bc1qcr8te4...`, `bc1qnjg0jd8...`, `bc1qp59yckz...`
- TV1 xpub → first three BIP44 addresses match `1LqBGSKu...`, `1Ak8PffB...`, `1MNF5RSa...`
- TV1 ypub → first BIP49 address matches `37VucYSa...`
- TV1 `--taproot` → first BIP86 address matches `bc1p5cyxnux...`
- BIP32 Vector 1 master xpub decodes with depth 0 and empty parent fingerprint
- Corrupt-checksum zpub is rejected
- xprv-class version bytes are rejected
- Hardened child derivation from a public key is rejected

Final line must read `ALL SELF-TEST CHECKS PASSED`.

## 3. Run the full test suite

```bash
python3 test_xpubverify.py
```

This adds the BIP32 master-key decode for vectors 1 / 2 / 3, a spec-anchored CKDpub derivation check (m/0' to m/0'/1 for vector 1), the full BIP32 vector-5 invalid-key sweep, full receive-plus-change derivation for TV1 (plus receive[0] and parent-fingerprint provenance for TV2), comprehensive edge-case coverage, schema assertions for `source_extended_key`, `account_fingerprint`, and the always-empty `derivation_path`, the demo-report format assertions (it mirrors the appliance Confidence Report: verification type, Account Key Fingerprint, IMPORTANT / PRIVACY disclaimers, deterministic self-hash), the official RIPEMD-160 vectors against the pure-Python fallback, and automated safety-grep assertions over the source file (a secret-term grep, an AST import allowlist, and a mutation proof that the grep still catches a real seed-handling identifier). Without any reference library the suite reports `234/235 passed, 1 SKIPPED, 0 FAILED`.

## 4. Run the independent-reference cross-check

The derivation tests in step 3 assert against hard-coded expected addresses. If those addresses were copy-pasted from the same BIP spec that `xpubverify.py` is implementing, a bug in both the implementation and the spec's worked example would still pass. The cross-check closes that loop by asking a **different codebase** to derive the same addresses and asserting byte-for-byte agreement.

```bash
pip install embit
python3 test_xpubverify.py
```

With `embit` installed the final line becomes `ALL 258 CHECKS PASSED`. The 24 new cross-validation assertions are:

- `embit: p2wpkh receive[0..2]` and `change[0..2]`, TV1 zpub
- `embit: p2pkh receive[0..2]` and `change[0..2]`, TV1 xpub
- `embit: p2sh-p2wpkh receive[0..2]` and `change[0..2]`, TV1 ypub
- `embit: p2tr receive[0..2]` and `change[0..2]`, TV1 BIP86 xpub

`bip32` (Darosior's minimal lib) is also supported as the reference library:

```bash
pip install bip32
python3 test_xpubverify.py
```

### Running the cross-check offline

The reference library does not have to be installed on a network-connected machine. Once on an online box:

```bash
pip download embit -d vendored/
```

Copy the `vendored/` directory to the offline machine and install from there:

```bash
pip install --no-index --find-links vendored/ embit
```

## 5. Verify against a known test vector by hand

The canonical BIP84 12-word mnemonic is `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` (no passphrase). Its BIP84 account-level zpub is:

```
zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs
```

Feed it to `xpubverify`:

```bash
python3 xpubverify.py --receive-count 3 --change-count 1 \
    zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs
```

Expected receive addresses:

| Index | Address |
|---|---|
| 0 | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| 1 | `bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g` |
| 2 | `bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z` |

> This mnemonic is a publicly known test vector. Never type a real funded mnemonic into any of these tools.

You can cross-check these against:

- [Ian Coleman's BIP39 tool](https://iancoleman.io/bip39/) (download the HTML page and open it offline)
- [Sparrow Wallet](https://sparrowwallet.com/) with the same mnemonic, BIP84 / Native SegWit account
- [Electrum](https://electrum.org/) importing the BIP39 mnemonic, Native SegWit wallet type

If `xpubverify` produces different addresses for this zpub, the script is broken or tampered with and must not be used.

## 6. Verify the demo report and descriptors

`--report` produces a **demo** verification report: it demonstrates the format of the Bitcoin Witness appliance's Confidence Report but is **not air-gapped** and **not GPG-signed** (see [README.md](README.md)). It **mirrors the appliance's current layout** for fidelity: the box title, aligned header grid, `VERIFICATION TYPE: Extended Public Key Verification`, the Account Key Fingerprint line, and the verbatim **IMPORTANT** and **PRIVACY** disclaimers. Its integrity property is *determinism*: the same input always produces byte-identical output, so its `Report SHA-256` self-hash is reproducible.

```bash
python3 xpubverify.py --report zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs > r1.txt
python3 xpubverify.py --report zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs > r2.txt
diff r1.txt r2.txt        # (no output expected, byte-identical)
```

The report (and `--json`) embed **BIP380 output descriptors**, receive (`/0/*`) and change (`/1/*`), each with its `#checksum`. Confirm they are real by importing one into an independent wallet (Sparrow / Bitcoin Core / Specter) as a **watch-only** descriptor: the addresses that wallet derives must match the ones the report lists. The checksum algorithm itself is pinned in the test suite against the official BIP380 vector `raw(deadbeef)#89f8spxm`.

The report's self-hash is a **checksum, not a signature**: it proves the report reproduces, not who produced it. For a signed, air-gapped Confidence Report, use the [Bitcoin Witness](https://bitcoinwitness.org) appliance.

## 7. Read the code

The whole tool is roughly 1,430 lines of commented Python in one file. You should be able to audit it in a single sitting. Things you should confirm are absent:

- **No network imports.** Check `import` lines at the top, only `hashlib`, `hmac`, `json`, `struct`, `sys`.
- **No code execution primitives.** No `exec(`, `eval(`, `compile(`, `__import__(`.
- **No subprocess calls.** No `subprocess`, `os.system`, `os.popen`.
- **No file writes.** No `open(..., 'w')`, no `.write(` anywhere.
- **No private-key operations.** Case-insensitive search for `private|secret|seed|mnemonic|pbkdf` returns hits only in prose, code comments, docstrings, and the demo report's IMPORTANT / PRIVACY disclaimer strings (which state the tool is seed-free), never in secret-handling code. The test suite proves this by stripping comments, docstrings, and string-literal contents before grepping, with a mutation check that a real seed-handling identifier would still be caught.

You can verify each of these with `grep`:

```bash
grep -E "import (socket|urllib|http|requests|ssl|subprocess|pickle|marshal|ctypes|cffi)" xpubverify.py
grep -E "exec\(|eval\(|compile\(|__import__\(" xpubverify.py
grep -E "subprocess\.|os\.system|os\.popen" xpubverify.py
grep -E "open\([^)]*['\"][wax+]" xpubverify.py
grep -nE "\.write\(" xpubverify.py
```

All five commands should produce no output.

## 8. Air-gap checklist

Before running `xpubverify` with a real extended public key on a machine you want to keep clean:

- [ ] WiFi is disabled (hardware switch, BIOS, or `rfkill block all`)
- [ ] Bluetooth is disabled
- [ ] Ethernet is unplugged
- [ ] The script was transferred from a trusted source (USB drive, SD card, verified hash)
- [ ] File hashes match the values published with the release tag
- [ ] `python3 xpubverify.py --self-test` passes
- [ ] `python3 test_xpubverify.py` with a reference library installed reports `ALL 258 CHECKS PASSED`
- [ ] Cross-check the first receive address against a second wallet or BIP39 tool

## 9. Report issues

See [SECURITY.md](SECURITY.md) for how to report a vulnerability. Short version: email `security@bitcoinwitness.org`.
