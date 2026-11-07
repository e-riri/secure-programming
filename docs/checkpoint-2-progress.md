# Checkpoint 2 Progress

Implemented for the Week 9 file-manager checkpoint:

- Interactive CLI with bounded input, quoted path arguments, help, and basic file commands.
- First-run password setup and login using a salted PBKDF2-HMAC-SHA256 verifier; the password is hidden at input and plaintext is not saved.
- AES-256-GCM file encryption/decryption using OpenSSL. Decryption publishes output only after its authentication tag verifies.
- Managed-directory path validation rejects absolute paths, `..`, symlink traversal, malformed arguments, and unintended overwrites.
- GCC/Make build instructions and OpenSSL dependency are documented in the README.

The implementation targets Linux/POSIX as specified by the design. Copy and move commands remain out of scope for this checkpoint. The current Windows workspace does not have `make` or POSIX headers, so a Linux build and runtime round-trip still need to be verified. No checkpoint commit has been made; commit this working session after reviewing and testing it.