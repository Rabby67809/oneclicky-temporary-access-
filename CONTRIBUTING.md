# Contributing

Contributions and bug reports are welcome.

1. Open an issue describing a reproducible non-sensitive bug or proposed improvement.
2. Create a branch and keep each pull request focused.
3. Do not break compatibility with PHP 7.4+ and WordPress 6.2+ unless the project intentionally changes its minimum versions.
4. Use native WordPress APIs, sanitize and validate input, escape output, and apply nonces **and** capability checks to privileged actions.
5. Test on an isolated WordPress staging installation and run `php -l` and `scripts/build-plugin-zip.sh`.
6. Update `readme.txt` if a change affects user-facing behavior.
7. Never include credentials, invitation tokens/URLs, real recipient data, or database dumps in commits.

Report potential vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not as public issues.

**Important:** Internal `AMTA_` class names, `amta_` database keys, and user metadata are retained for backward compatibility with AccessMint releases. Do not rename them as part of cosmetic cleanup without a tested migration plan.
