# Security Policy

## Scope

This policy covers `xpubverify.py` and supporting files in this repository, the standalone, MIT-licensed extended-public-key address-verification tool published at [github.com/BitcoinWitness/xpubverify](https://github.com/BitcoinWitness/xpubverify).

For the full Bitcoin Witness commercial product (the air-gapped Raspberry Pi signing appliance that bundles verification workflows, PSBT signing, LUKS-encrypted storage, and other product-side features), see [bitcoinwitness.org](https://bitcoinwitness.org).

### The `--report` output is a DEMO, not a signed record

The `--report` verification report **demonstrates the format** of the appliance's Confidence Report. It is produced by this free, internet-connected, watch-only tool: it is **not air-gapped** and **not GPG-signed**. Its `Report SHA-256` line is a **self-checksum** (re-run the identical command and the report reproduces byte-for-byte), **not a digital signature**; it attests nothing about the machine that produced it or the person who ran it. The report states this at the top and beside the hash, and the test suite asserts those statements are present. Do not accept an `xpubverify --report` output as evidence that a verification was performed on a trusted, air-gapped device; for that, use the appliance.

---

## Reporting a vulnerability

If you find a security issue, a bug in the cryptographic implementation, an address derivation error, an input that crashes the decoder, or anything that could cause incorrect verification results, please report it responsibly.

**Email:** `security@bitcoinwitness.org`. GPG public key: [bitcoinwitness.org/keys/bitcoinwitness-pub.asc](https://bitcoinwitness.org/keys/bitcoinwitness-pub.asc). After importing, confirm the key fingerprint matches the one pinned here before trusting any signature:

```
014B4C54914E2D6F3AC5D601D8AE5F9CA285E35D
```

Please include:

1. A description of the vulnerability.
2. Steps to reproduce (a specific extended public key or input and the expected vs. actual output).
3. The version of `xpubverify.py` (`python3 xpubverify.py --version`) and of Python you are using.
4. Your assessment of severity.

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

---

## Threat model

`xpubverify` is a **watch-only verification tool**. It has a deliberately tiny attack surface.

### Attacker goals we defend against

- **Incorrect address derivation**, either by accident (bug in CKDpub / BIP86 tweak / Bech32 encoder) or by malice (tampered copy of the script). Defence: a 234-check stdlib test suite (258 checks when an independent third-party BIP32 reference library is installed for cross-validation) covering the BIP32 master-key decode for vectors 1 / 2 / 3 plus a spec-anchored CKDpub check and the full vector-5 invalid-key sweep, the TV1 BIP44 / BIP49 / BIP84 / BIP86 published vectors and the TV2 BIP84 vector, the BIP380 descriptor checksum (official `raw(deadbeef)#89f8spxm` vector), the official RIPEMD-160 vectors, the error paths, and a cross-check against that independent BIP32 library.
- **Exfiltration of the extended public key** (not a secret, but still user data) over the network. Defence: zero network imports. `grep -E "import (socket|urllib|http|requests|ssl)"` returns nothing. The test suite asserts this.
- **Exfiltration via subprocess / file write.** Defence: no `subprocess`, `os.system`, `os.popen`. No `open(..., 'w')`. No `.write(` calls. The test suite asserts these.
- **Code execution via malicious input.** Defence: no `exec`, `eval`, `compile`, `__import__`, `pickle`, `marshal`, `ctypes`, `cffi`. All user input is parsed with explicit checks; no input is ever passed to the interpreter.
- **Misleading error messages.** Defence: error messages are plain English and tell the user what failed, why, and what to do next. Python tracebacks are never surfaced in CLI mode.
- **Accidentally pasted extended private key (xprv / yprv / zprv / tprv).** Defence: the decoder specifically recognises xprv-class version bytes and refuses with a clear explanation that this tool is watch-only. No code path in `xpubverify` can process an extended private key.

### Threats that are fundamentally out of scope

- **The xpub itself is a tracking tool.** Anyone with your account xpub can watch every UTXO in that account for all time. `xpubverify` does not introduce any new exposure (it reads the xpub and prints addresses; the xpub must already be in your hands). But users should treat extended public keys as sensitive per-account metadata and avoid publishing them.
- **Compromised host OS.** If the operating system `xpubverify` runs on is already malicious, it can display whatever addresses it wants regardless of what the script computes. Run `xpubverify` on an isolated machine if you care.
- **Physical / supply-chain attacks on your hardware wallet.** `xpubverify` verifies that an xpub produces a particular set of addresses. It cannot tell you whether the xpub your wallet exported is the one derived from your seed, only whether the wallet is deriving addresses consistently with the BIP standards. If the wallet firmware is malicious, it could export an attacker-controlled xpub; you need a second, independent hardware wallet (or a full-seed verification like [Bitcoin Witness](https://bitcoinwitness.org)) to catch that.

### Known limitations

#### 1. `point_multiply()` is not constant-time

The scalar multiplication inside `xpubverify.py` uses a straightforward double-and-add loop that branches on the bits of its scalar. This is fine for the scalars `xpubverify` actually computes, they are all public (CKDpub chain-code offsets and BIP86 taproot tweaks). There is no scalar inside this tool that a side-channel adversary could extract to compromise a secret.

Still, if you reuse any of the curve-math primitives outside `xpubverify` with secret scalars, switch to a constant-time implementation.

#### 2. `_extended_gcd()` is recursive

Maximum recursion depth is bounded by roughly 370 (Euclid's worst case is about 1.44 × log₂ of the field prime), well under Python's default stack. Not exploitable; hardening-only note.

#### 3. Error messages may include input strings

The full key is never echoed back: at most a single offending character (an invalid Base58 character), the four version-prefix bytes (for an xprv-class or unrecognised key), or one embedded key-prefix byte (for a malformed public key) appear in an error message. If your shell history or log retention is sensitive, be aware that anything you typed on the command line lands in your shell history regardless of this tool. The output never includes derived intermediate state (chain codes, tweaks), only what the user supplied.

---

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x   | Yes, current |

---

## Disclosure policy

We will credit reporters in the `CHANGELOG.md` unless they prefer to remain anonymous. For coordinated disclosure of critical vulnerabilities, we request a 30-day embargo while we prepare a fix.

---

## See also

- This policy covers `xpubverify.py` only.
- For the full Bitcoin Witness commercial product's threat model, security policy, and audit history, see [bitcoinwitness.org](https://bitcoinwitness.org).
- For BIP32 / BIP44 / BIP49 / BIP84 / BIP86 reference material, see the linked specs in [README.md](README.md).
