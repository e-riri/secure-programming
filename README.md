# Secure File Manager

ICS0022 TalTech Secure Programming course project.

## Project Scope

This project is a small command-line file manager written in C17 for Linux/POSIX systems.

The application will provide basic file and directory operations within a configured managed directory. Security is a primary requirement, with protection against directory traversal, unsafe filesystem operations, authentication bypass, and insecure handling of passwords and secrets.

The application will run as a normal unprivileged user and will not require root or setuid privileges.

## Checkpoint 2 Commands

```text
setup
login
logout
list [directory]
read <file>
create <file>
mkdir <directory>
delete <file>
encrypt <source> <destination>
decrypt <source> <destination>
help
exit
```

The account is local to the current working directory. Run `setup` once, then
`login`; managed files live in `./managed`. Paths are relative to that directory,
and double quotes can be used around paths containing spaces. File creation and
encryption/decryption do not overwrite existing destinations.

Encryption uses OpenSSL AES-256-GCM. Each encrypted file contains a random salt,
nonce, and authentication tag; its key is derived from the logged-in password
using PBKDF2-HMAC-SHA256. Password verification data is stored in
`.file-manager.auth` with owner-only permissions, never as plaintext.

Copy and move are not part of this checkpoint implementation.

## Build and Run

The project uses GCC, Make, and the OpenSSL development headers/library. On
Debian or Ubuntu, install them with `sudo apt install build-essential libssl-dev`.

Build:

```bash
make
```

Run:

```bash
./file-manager
```

Run the application from the directory in which its managed files should live:

```bash
./file-manager
```

At the prompt, use `setup` to create the account and `login` to authenticate.
`make clean` removes the compiled executable; it does not remove account data or
managed files.

## Documentation

The design document and threat model are available in:

```text
docs/design.md
```
