# Changelog

All notable changes to `xpubverify` are documented here. This project follows
[Semantic Versioning](https://semver.org/) and the
[Keep a Changelog](https://keepachangelog.com/) format.

## [1.0.0] - 2026-08-31

Initial public release. `xpubverify` is a standalone, watch-only tool that
derives Bitcoin receive and change addresses from an extended public key, using
only the Python standard library. Public key in, addresses out; no secret
material ever enters the tool.

### What it does

- Derives addresses from `xpub` (BIP44, Legacy P2PKH), `ypub` (BIP49, Nested
  SegWit), `zpub` (BIP84, Native SegWit), and `tpub` (testnet), and from an
  `xpub` with `--taproot` (BIP86, P2TR).
- Emits BIP380 single-sig output descriptors (`receive` and `change`, each with
  its checksum), re-importable watch-only into Sparrow, Bitcoin Core, or Specter.
- `--json` for machine-readable output, including an `account_fingerprint` (the
  BIP32 fingerprint of the account key itself) and the descriptors.
- `--report` prints a deterministic demo verification report that mirrors the
  format of the Bitcoin Witness appliance's Confidence Report. It is a demo and
  says so at the top and beside the hash: it is produced by this free,
  online-capable tool, so it is not air-gapped and not GPG-signed, and its
  `Report SHA-256` line is a self-checksum (re-run and compare), not a signature.
- `--self-test` runs the embedded vectors from the single file.

### Honesty properties

- **No secret handling.** The tool imports exactly five stdlib modules
  (`hashlib`, `hmac`, `json`, `struct`, `sys`), makes no network calls, writes no
  files, and refuses an extended private key (xprv / yprv / zprv / tprv) with a
  clear message. The test suite enforces all of this: a safety grep for
  secret-material terms in functional code, an AST-based import allowlist, and
  blocklists for dangerous imports and calls.
- **No fabricated derivation path.** For a bare extended key the tool claims no
  full `m/purpose'/coin'/account'` path, because a bare key cannot attest one
  (it carries no key-origin). This matches Bitcoin Core, BDK, Electrum, and
  Specter. The report shows the relative `/0/*` and `/1/*` structure and, for an
  account-level key, a clearly labeled child-number inference (a hint, not a
  verified path).

### Verification (all re-runnable by the reader)

- Official vectors asserted in the suite: BIP32 test vectors 1 to 3 (master-key
  decode) plus a spec-anchored CKDpub check and the full vector-5 invalid-key
  sweep; the canonical BIP84 / BIP86 published address vectors; the BIP380
  descriptor checksum (`raw(deadbeef)#89f8spxm`); and the official RIPEMD-160
  vectors against the pure-Python fallback.
- Cross-validation: with a third-party BIP32 reference library installed
  (`embit` or `bip32`), the suite re-derives every TV1 address with that
  independent codebase and asserts byte-for-byte agreement.
- Release integrity: this release is published as a GPG-signed `git tag`, and
  the `sha256sum` of `xpubverify.py` and `test_xpubverify.py` is recorded on the
  release (see `VERIFY.md`).
