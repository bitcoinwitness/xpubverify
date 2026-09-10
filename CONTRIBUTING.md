# Contributing to xpubverify

Thanks for helping make `xpubverify` more trustworthy. This is a small,
security-sensitive tool; contributions are welcome, with a few ground rules.

## Ground rules

- **Standard library only.** `xpubverify.py` must import nothing outside the
  Python standard library. No `pip install` should ever be required to run it.
- **Watch-only.** The tool must never accept, read, or handle secret material
  (seeds, mnemonics, passphrases, or extended *private* keys). There is no code
  path for private keys, and there must not be one.
- **No network, no file writes, no code-execution primitives.** No `socket` /
  `urllib` / `requests`, no `subprocess` / `os.system`, no `exec` / `eval` /
  `compile` / `__import__`. The test suite asserts the absence of these.
- **Keep it auditable.** The whole tool is one readable, heavily commented file.
  Prefer clarity over cleverness.

## Before you open a pull request

1. Run the full suite and make sure it is green:
   ```bash
   python3 test_xpubverify.py          # stdlib-only
   pip install embit                    # optional independent cross-check
   python3 test_xpubverify.py           # runs the cross-validation too
   ```
2. Add a test for any behaviour you change or add. A change to derivation,
   encoding, or the descriptor/report output must come with an assertion that
   would fail without your change.
3. Cross-check any new address or descriptor output against an independent
   implementation (Sparrow, Bitcoin Core, or a reference BIP32 library), not
   just against this tool.
4. Keep the docs (`README.md`, `SECURITY.md`, `VERIFY.md`, `CHANGELOG.md`) in
   sync with the code, including any test-count figures.

## Reporting security issues

Do **not** open a public issue for a security vulnerability. Follow the private
disclosure process in [`SECURITY.md`](SECURITY.md).

## About the `--report` output

`xpubverify --report` produces a **demo** verification report: it demonstrates
the format of the Bitcoin Witness appliance's Confidence Report, but it is not
air-gapped and not GPG-signed, and its self-hash is a checksum, not a signature.
Keep that framing intact and honest in any change to the report.
