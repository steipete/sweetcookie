# Changelog

## v0.0.3 - Unreleased

- Update the SQLite driver to v1.58.0 and its matching libc dependency; use Go 1.25.14 for development and CI while preserving Go 1.25.0 support.

## v0.0.2 - 2026-08-02

- Add Firefox Multi-Account Container metadata and preserve cookies across profile-scoped containers. Thanks @sudosubin.
- Add Dia, Comet, ChatGPT Atlas, Whale, Zen, Floorp, Waterfox, and LibreWolf browser support. Thanks @sudosubin.

## v0.0.1 - 2026-06-10

- Initial Go library for reading, filtering, and deduplicating cookies from local Chrome-family, Firefox, Safari, and inline cookie sources.
- Add Chromium cookie decryption support for macOS Keychain, Windows DPAPI, and Linux keyring backends, with read-only DB snapshotting and coverage checks.
- Add Arc browser support for macOS and Windows. Thanks @Haknt.
- Add explicit opt-in Helium browser support for macOS. Thanks @fardeenxyz.
