# Changelog

All notable changes to this module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-04-09

### Security

- Updated `github.com/ethereum/go-ethereum` from v1.16.8 to v1.17.0
  - Fixes [CVE-2026-26313](https://github.com/advisories/GHSA-689v-6xwf-5jf3): DoS via malicious p2p message (medium)
  - Fixes [CVE-2026-26314](https://github.com/advisories/GHSA-2gjw-fg97-vg3r): DoS via malicious p2p message (high)
  - Fixes [CVE-2026-26315](https://github.com/advisories/GHSA-m6j8-rg6r-7mv8): Improper validation of ECIES public key in RLPx handshake (medium)
- Updated `github.com/cloudflare/circl` from v1.6.2 to v1.6.3
  - Fixes [CVE-2026-1229](https://github.com/advisories/GHSA-q9hv-hpm4-hj6x): Incorrect calculation in secp384r1 CombinedMult (low)

## [1.0.0] - Initial release
