# Changelog

## v0.0.2 - Unreleased

- Firefox multi-account containers: cookies now carry a `Container` and aren't merged across containers.

## v0.0.1 - 2026-06-10

- Initial Go library for reading, filtering, and deduplicating cookies from local Chrome-family, Firefox, Safari, and inline cookie sources.
- Add Chromium cookie decryption support for macOS Keychain, Windows DPAPI, and Linux keyring backends, with read-only DB snapshotting and coverage checks.
- Add Arc browser support for macOS and Windows. Thanks @Haknt.
- Add explicit opt-in Helium browser support for macOS. Thanks @fardeenxyz.
