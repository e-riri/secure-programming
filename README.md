# Secure File Manager

ICS0022 TalTech Secure Programming course project.

## Project Scope

This project is a small command-line file manager written in C17 for Linux/POSIX systems.

The application will provide basic file and directory operations within a configured managed directory. Security is a primary requirement, with protection against directory traversal, unsafe filesystem operations, authentication bypass, and insecure handling of passwords and secrets.

The application will run as a normal unprivileged user and will not require root or setuid privileges.

## Planned Commands

```text
login
list
read <file>
copy <source> <destination>
move <source> <destination>
delete <file>
create <file>
mkdir <directory>
logout
help
```

## Build and Run

The project will use GCC and Make.

Build:

```bash
make
```

Run:

```bash
./file-manager
```

The exact build and run commands may be updated as implementation progresses.

## Documentation

The design document and threat model are available in:

```text
docs/design.md
```
